//! This implements the `tfa.cfg` parser & TFA API calls for PVE.
//!
//! The exported `PVE::RS::TFA` perl package provides access to rust's `TfaConfig` as well as
//! transparently providing the old style TFA config so that as long as users only have a single
//! TFA entry, the old authentication API still works.
//!
//! NOTE: In PVE the tfa config is behind `PVE::Cluster`'s `ccache` and therefore must be clonable
//! via `Storable::dclone`, so we implement the storable hooks `STORABLE_freeze` and
//! `STORABLE_attach`. Note that we only allow *cloning*, not freeze/thaw.

use std::convert::TryFrom;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::{bail, format_err, Error};
use nix::errno::Errno;
use nix::sys::stat::Mode;
use serde_json::Value as JsonValue;

use proxmox_tfa::api::{
    RecoveryState, TfaChallenge, TfaConfig, TfaResponse, TfaUserData, U2fConfig,
    UserChallengeAccess, WebauthnConfig,
};

#[perlmod::package(name = "PVE::RS::TFA")]
pub mod pve_rs_tfa {
    //! The `PVE::RS::TFA` package.
    //!
    //! This provides the [`Tfa`] type to implement the TFA API side.
    //!
    //! # Note
    //!
    //! This package provides `STORABLE_freeze` and `STORABLE_attach` subs for `dclone` support,
    //! since this object will be put into `PVE::Cluster`'s `ccache`!

    use std::collections::HashMap;
    use std::convert::TryInto;
    use std::sync::Mutex;

    use anyhow::{bail, format_err, Error};
    use serde_bytes::ByteBuf;
    use url::Url;

    use perlmod::Value;
    use proxmox_tfa::api::{methods, TfaResult};

    use super::{TfaConfig, UserAccess};

    perlmod::declare_magic!(Box<Tfa> : &Tfa as "PVE::RS::TFA");

    /// A TFA Config instance.
    pub struct Tfa {
        inner: Mutex<TfaConfig>,
    }

    /// Method: Support `dclone` so this can be put into the `ccache` of `PVE::Cluster`.
    #[export(name = "STORABLE_freeze", raw_return)]
    pub fn storable_freeze(#[try_from_ref] this: &Tfa, cloning: bool) -> Result<Value, Error> {
        if !cloning {
            bail!("freezing TFA config not supported!");
        }

        // An alternative would be to literally just *serialize* the data, then we wouldn't even
        // need to restrict it to `cloning=true`, but since `clone=true` means we're immediately
        // attaching anyway, this should be safe enough...

        let mut cloned = Box::new(Tfa {
            inner: Mutex::new(this.inner.lock().unwrap().clone()),
        });
        let value = Value::new_pointer::<Tfa>(&mut *cloned);
        let _perl = Box::leak(cloned);
        Ok(value)
    }

    /// Class method: Instead of `thaw` we implement `attach` for `dclone`.
    #[export(name = "STORABLE_attach", raw_return)]
    pub fn storable_attach(
        #[raw] class: Value,
        cloning: bool,
        #[raw] serialized: Value,
    ) -> Result<Value, Error> {
        if !cloning {
            bail!("STORABLE_attach called with cloning=false");
        }
        let data = unsafe { Box::from_raw(serialized.pv_raw::<Tfa>()?) };

        let mut hash = perlmod::Hash::new();
        super::generate_legacy_config(&mut hash, &data.inner.lock().unwrap());
        let hash = Value::Hash(hash);
        let obj = Value::new_ref(&hash);
        obj.bless_sv(&class)?;
        hash.add_magic(MAGIC.with_value(data));
        Ok(obj)

        // Once we drop support for legacy authentication we can just do this:
        // Ok(perlmod::instantiate_magic!(&class, MAGIC => data))
    }

    type TfaInstance = Value;

    /// Class method: Parse a TFA configuration and produce a [`Tfa`] instance.
    #[export(raw_return)]
    pub fn new(#[raw] class: Value, config: &[u8]) -> Result<TfaInstance, Error> {
        let mut inner: TfaConfig = serde_json::from_slice(config)
            .map_err(Error::from)
            .or_else(|_err| super::parse_old_config(config))
            .map_err(|_err| {
                format_err!("failed to parse TFA file, neither old style nor valid json")
            })?;

        // In PVE, the U2F and Webauthn configurations come from `datacenter.cfg`. In case this
        // config was copied from PBS, let's clear it out:
        inner.u2f = None;
        inner.webauthn = None;

        let mut hash = perlmod::Hash::new();
        super::generate_legacy_config(&mut hash, &inner);
        let hash = Value::Hash(hash);
        let obj = Value::new_ref(&hash);
        obj.bless_sv(&class)?;
        hash.add_magic(MAGIC.with_value(Box::new(Tfa {
            inner: Mutex::new(inner),
        })));
        Ok(obj)

        // Once we drop support for legacy authentication we can just do this:
        // Ok(perlmod::instantiate_magic!(
        //     &class, MAGIC => Box::new(Tfa { inner: Mutex::new(inner) })
        // ))
    }

    /// Method: Write the configuration out into a JSON string.
    #[export]
    pub fn write(#[try_from_ref] this: &Tfa) -> Result<serde_bytes::ByteBuf, Error> {
        let mut inner = this.inner.lock().unwrap();
        let u2f = inner.u2f.take();
        let webauthn = inner.webauthn.take();
        let output = serde_json::to_vec(&*inner); // must not use `?` here
        inner.u2f = u2f;
        inner.webauthn = webauthn;
        Ok(ByteBuf::from(output?))
    }

    /// Method: Debug helper: serialize the TFA user data into a perl value.
    #[export]
    pub fn to_perl(#[try_from_ref] this: &Tfa) -> Result<Value, Error> {
        let mut inner = this.inner.lock().unwrap();
        let u2f = inner.u2f.take();
        let webauthn = inner.webauthn.take();
        let output = Ok(perlmod::to_value(&*inner)?);
        inner.u2f = u2f;
        inner.webauthn = webauthn;
        output
    }

    /// Method: Get a list of all the user names in this config.
    /// PVE uses this to verify users and purge the invalid ones.
    #[export]
    pub fn users(#[try_from_ref] this: &Tfa) -> Result<Vec<String>, Error> {
        Ok(this.inner.lock().unwrap().users.keys().cloned().collect())
    }

    /// Method: Remove a user from the TFA configuration.
    #[export]
    pub fn remove_user(#[try_from_ref] this: &Tfa, userid: &str) -> Result<bool, Error> {
        Ok(this.inner.lock().unwrap().users.remove(userid).is_some())
    }

    /// Method: Get the TFA data for a specific user.
    #[export(raw_return)]
    pub fn get_user(#[try_from_ref] this: &Tfa, userid: &str) -> Result<Value, perlmod::Error> {
        perlmod::to_value(&this.inner.lock().unwrap().users.get(userid))
    }

    /// Method: Add a u2f registration. This modifies the config (adds the user to it), so it needs
    /// be written out.
    #[export]
    pub fn add_u2f_registration(
        #[raw] raw_this: Value,
        //#[try_from_ref] this: &Tfa,
        userid: &str,
        description: String,
    ) -> Result<String, Error> {
        let this: &Tfa = (&raw_this).try_into()?;
        let mut inner = this.inner.lock().unwrap();
        inner.u2f_registration_challenge(&UserAccess::new(&raw_this)?, userid, description)
    }

    /// Method: Finish a u2f registration. This updates temporary data in `/run` and therefore the
    /// config needs to be written out!
    #[export]
    pub fn finish_u2f_registration(
        #[raw] raw_this: Value,
        //#[try_from_ref] this: &Tfa,
        userid: &str,
        challenge: &str,
        response: &str,
    ) -> Result<String, Error> {
        let this: &Tfa = (&raw_this).try_into()?;
        let mut inner = this.inner.lock().unwrap();
        inner.u2f_registration_finish(&UserAccess::new(&raw_this)?, userid, challenge, response)
    }

    /// Method: Check if a user has any TFA entries of a given type.
    #[export]
    pub fn has_type(
        #[try_from_ref] this: &Tfa,
        userid: &str,
        typename: &str,
    ) -> Result<bool, Error> {
        Ok(match this.inner.lock().unwrap().users.get(userid) {
            Some(user) => match typename {
                "totp" | "oath" => !user.totp.is_empty(),
                "u2f" => !user.u2f.is_empty(),
                "webauthn" => !user.webauthn.is_empty(),
                "yubico" => !user.yubico.is_empty(),
                "recovery" => match &user.recovery {
                    Some(r) => r.count_available() > 0,
                    None => false,
                },
                _ => bail!("unrecognized TFA type {:?}", typename),
            },
            None => false,
        })
    }

    /// Method: Generates a space separated list of yubico keys of this account.
    #[export]
    pub fn get_yubico_keys(
        #[try_from_ref] this: &Tfa,
        userid: &str,
    ) -> Result<Option<String>, Error> {
        Ok(this.inner.lock().unwrap().users.get(userid).map(|user| {
            user.enabled_yubico_entries()
                .fold(String::new(), |mut s, k| {
                    if !s.is_empty() {
                        s.push(' ');
                    }
                    s.push_str(k);
                    s
                })
        }))
    }

    /// Method: Set the U2F configuration for this [`Tfa`] instance.
    #[export]
    pub fn set_u2f_config(#[try_from_ref] this: &Tfa, config: Option<super::U2fConfig>) {
        this.inner.lock().unwrap().u2f = config;
    }

    /// Method: Set the WebAuthN configuration for this [`Tfa`] instance.
    #[export]
    pub fn set_webauthn_config(#[try_from_ref] this: &Tfa, config: Option<super::WebauthnConfig>) {
        this.inner.lock().unwrap().webauthn = config;
    }

    /// Method: Create an authentication challenge.
    ///
    /// Returns the challenge as a json string.
    /// Returns `undef` if no second factor is configured.
    #[export]
    pub fn authentication_challenge(
        #[raw] raw_this: Value,
        //#[try_from_ref] this: &Tfa,
        userid: &str,
        origin: Option<Url>,
    ) -> Result<Option<String>, Error> {
        let this: &Tfa = (&raw_this).try_into()?;
        let mut inner = this.inner.lock().unwrap();
        match inner.authentication_challenge(
            &UserAccess::new(&raw_this)?,
            userid,
            origin.as_ref(),
        )? {
            Some(challenge) => Ok(Some(serde_json::to_string(&challenge)?)),
            None => Ok(None),
        }
    }

    /// Method: Get the recovery state (suitable for a challenge object).
    #[export]
    pub fn recovery_state(
        #[try_from_ref] this: &Tfa,
        userid: &str,
    ) -> Option<super::RecoveryState> {
        this.inner
            .lock()
            .unwrap()
            .users
            .get(userid)
            .and_then(|user| user.recovery_state())
    }

    /// Method: Takes the TFA challenge string (which is a json object) and verifies ther esponse against
    /// it.
    ///
    /// # WARNING
    ///
    /// This method is now deprecated, as its failures were communicated via croaking.
    ///
    /// # NOTE
    ///
    /// This returns a boolean whether the config data needs to be *saved* after this call (to use
    /// up recovery keys!).
    #[export]
    pub fn authentication_verify(
        #[raw] raw_this: Value,
        //#[try_from_ref] this: &Tfa,
        userid: &str,
        challenge: &str, //super::TfaChallenge,
        response: &str,
        origin: Option<Url>,
    ) -> Result<bool, Error> {
        let this: &Tfa = (&raw_this).try_into()?;
        let challenge: super::TfaChallenge = serde_json::from_str(challenge)?;
        let response: super::TfaResponse = response.parse()?;
        let mut inner = this.inner.lock().unwrap();
        let result = inner.verify(
            &UserAccess::new(&raw_this)?,
            userid,
            &challenge,
            response,
            origin.as_ref(),
        );
        match result {
            TfaResult::Success { needs_saving } => Ok(needs_saving),
            _ => bail!("TFA authentication failed"),
        }
    }

    /// Method: Takes the TFA challenge string (which is a json object) and verifies ther esponse against
    /// it.
    ///
    /// Returns a result hash of the form:
    /// ```text
    /// {
    ///     "result": bool, // whether TFA was successful
    ///     "needs-saving": bool, // whether the user config needs saving
    ///     "tfa-limit-reached": bool, // whether the TFA limit was reached (config needs saving)
    ///     "totp-limit-reached": bool, // whether the TOTP limit was reached (config needs saving)
    /// }
    /// ```
    #[export]
    pub fn authentication_verify2(
        #[raw] raw_this: Value,
        //#[try_from_ref] this: &Tfa,
        userid: &str,
        challenge: &str, //super::TfaChallenge,
        response: &str,
        origin: Option<Url>,
    ) -> Result<TfaReturnValue, Error> {
        let this: &Tfa = (&raw_this).try_into()?;
        let challenge: super::TfaChallenge = serde_json::from_str(challenge)?;
        let response: super::TfaResponse = response.parse()?;
        let mut inner = this.inner.lock().unwrap();
        let result = inner.verify(
            &UserAccess::new(&raw_this)?,
            userid,
            &challenge,
            response,
            origin.as_ref(),
        );
        Ok(match result {
            TfaResult::Success { needs_saving } => TfaReturnValue {
                result: true,
                needs_saving,
                ..Default::default()
            },
            TfaResult::Locked => TfaReturnValue::default(),
            TfaResult::Failure {
                needs_saving,
                totp_limit_reached,
                tfa_limit_reached,
            } => TfaReturnValue {
                result: false,
                needs_saving,
                totp_limit_reached,
                tfa_limit_reached,
            },
        })
    }

    /// The return value from [`authentication_verify2`].
    #[derive(Default, serde::Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct TfaReturnValue {
        /// The authentication result (success/failure).
        pub result: bool,
        /// Whether the user config needs saving.
        pub needs_saving: bool,
        /// Whether the TOTP limit was reached (config needs saving).
        pub totp_limit_reached: bool,
        /// Whether the general TFA limit was reached (config needs saving).
        pub tfa_limit_reached: bool,
    }

    /// DEBUG HELPER: Get the current TOTP value for a given TOTP URI.
    #[export]
    pub fn get_current_totp_value(otp_uri: &str) -> Result<String, Error> {
        let totp: proxmox_tfa::totp::Totp = otp_uri.parse()?;
        Ok(totp.time(std::time::SystemTime::now())?.to_string())
    }

    /// Method: API call implementation for `GET /access/tfa/{userid}`
    ///
    /// See [`methods::list_user_tfa`].
    #[export]
    pub fn api_list_user_tfa(
        #[try_from_ref] this: &Tfa,
        userid: &str,
    ) -> Result<Vec<methods::TypedTfaInfo>, Error> {
        methods::list_user_tfa(&this.inner.lock().unwrap(), userid)
    }

    /// Method: API call implementation for `GET /access/tfa/{userid}/{ID}`.
    ///
    /// See [`methods::get_tfa_entry`].
    #[export]
    pub fn api_get_tfa_entry(
        #[try_from_ref] this: &Tfa,
        userid: &str,
        id: &str,
    ) -> Option<methods::TypedTfaInfo> {
        methods::get_tfa_entry(&this.inner.lock().unwrap(), userid, id)
    }

    /// Method: API call implementation for `DELETE /access/tfa/{userid}/{ID}`.
    ///
    /// Returns `true` if the user still has other TFA entries left, `false` if the user has *no*
    /// more tfa entries.
    ///
    /// See [`methods::delete_tfa`].
    #[export]
    pub fn api_delete_tfa(
        #[try_from_ref] this: &Tfa,
        userid: &str,
        id: String,
    ) -> Result<bool, Error> {
        let mut this = this.inner.lock().unwrap();
        match methods::delete_tfa(&mut this, userid, &id) {
            Ok(has_entries_left) => Ok(has_entries_left),
            Err(methods::EntryNotFound) => bail!("no such entry"),
        }
    }

    /// Method: API method implementation for `GET /access/tfa`.
    ///
    /// See [`methods::list_tfa`].
    #[export]
    pub fn api_list_tfa(
        #[try_from_ref] this: &Tfa,
        authid: &str,
        top_level_allowed: bool,
    ) -> Result<Vec<methods::TfaUser>, Error> {
        methods::list_tfa(&this.inner.lock().unwrap(), authid, top_level_allowed)
    }

    /// Method: API call implementation for `POST /access/tfa/{userid}`.
    ///
    /// See [`methods::add_tfa_entry`].
    #[allow(clippy::too_many_arguments)]
    #[export]
    pub fn api_add_tfa_entry(
        #[raw] raw_this: Value,
        //#[try_from_ref] this: &Tfa,
        userid: &str,
        description: Option<String>,
        totp: Option<String>,
        value: Option<String>,
        challenge: Option<String>,
        ty: methods::TfaType,
        origin: Option<Url>,
    ) -> Result<methods::TfaUpdateInfo, Error> {
        let this: &Tfa = (&raw_this).try_into()?;
        methods::add_tfa_entry(
            &mut this.inner.lock().unwrap(),
            &UserAccess::new(&raw_this)?,
            userid,
            description,
            totp,
            value,
            challenge,
            ty,
            origin.as_ref(),
        )
    }

    /// Method: Add a totp entry without validating it, used for user.cfg keys.
    ///
    /// Returns the ID.
    #[export]
    pub fn add_totp_entry(
        #[try_from_ref] this: &Tfa,
        userid: &str,
        description: String,
        totp: String,
    ) -> Result<String, Error> {
        Ok(this
            .inner
            .lock()
            .unwrap()
            .add_totp(userid, description, totp.parse()?))
    }

    /// Method: Add a yubico entry without validating it, used for user.cfg keys.
    ///
    /// Returns the ID.
    #[export]
    pub fn add_yubico_entry(
        #[try_from_ref] this: &Tfa,
        userid: &str,
        description: String,
        yubico: String,
    ) -> String {
        this.inner
            .lock()
            .unwrap()
            .add_yubico(userid, description, yubico)
    }

    /// API call implementation for `PUT /access/tfa/{userid}/{id}`.
    ///
    /// See [`methods::update_tfa_entry`].
    #[export]
    pub fn api_update_tfa_entry(
        #[try_from_ref] this: &Tfa,
        userid: &str,
        id: &str,
        description: Option<String>,
        enable: Option<bool>,
    ) -> Result<(), Error> {
        match methods::update_tfa_entry(
            &mut this.inner.lock().unwrap(),
            userid,
            id,
            description,
            enable,
        ) {
            Ok(()) => Ok(()),
            Err(methods::EntryNotFound) => bail!("no such entry"),
        }
    }

    /// Method: API call implementation for `PUT /users/{userid}/unlock-tfa`.
    ///
    /// See [`methods::unlock_and_reset_tfa`].
    #[export]
    pub fn api_unlock_tfa(#[raw] raw_this: Value, userid: &str) -> Result<bool, Error> {
        let this: &Tfa = (&raw_this).try_into()?;
        methods::unlock_and_reset_tfa(
            &mut this.inner.lock().unwrap(),
            &UserAccess::new(&raw_this)?,
            userid,
        )
    }

    /// TFA lockout information.
    #[derive(serde::Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct TfaLockStatus {
        /// Once a user runs into a TOTP limit they get locked out of TOTP until they successfully use
        /// a recovery key.
        #[serde(skip_serializing_if = "bool_is_false", default)]
        pub totp_locked: bool,

        /// If a user hits too many 2nd factor failures, they get completely blocked for a while.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(deserialize_with = "filter_expired_timestamp")]
        pub tfa_locked_until: Option<i64>,
    }

    impl From<&proxmox_tfa::api::TfaUserData> for TfaLockStatus {
        fn from(data: &proxmox_tfa::api::TfaUserData) -> Self {
            Self {
                totp_locked: data.totp_locked,
                tfa_locked_until: data.tfa_locked_until,
            }
        }
    }

    fn bool_is_false(b: &bool) -> bool {
        !*b
    }

    /// Method: Get the TFA lock-out status of either a user, or all users.
    ///
    /// This returns either a single [`TfaLockStatus`], or a hash mapping user ids to them.
    #[export]
    pub fn tfa_lock_status(
        #[try_from_ref] this: &Tfa,
        userid: Option<&str>,
    ) -> Result<Option<perlmod::Value>, Error> {
        let this = this.inner.lock().unwrap();
        if let Some(userid) = userid {
            if let Some(user) = this.users.get(userid) {
                Ok(Some(perlmod::to_value(&TfaLockStatus::from(user))?))
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(perlmod::to_value(
                &HashMap::<String, TfaLockStatus>::from_iter(
                    this.users
                        .iter()
                        .map(|(uid, data)| (uid.clone(), TfaLockStatus::from(data))),
                ),
            )?))
        }
    }
}

/// Version 1 format of `/etc/pve/priv/tfa.cfg`
/// ===========================================
///
/// The TFA configuration in priv/tfa.cfg format contains one line per user of the form:
///
///     USER:TYPE:DATA
///
/// DATA is a base64 encoded json object and its format depends on the type.
///
/// TYPEs
/// -----
///   - oath
///
///     This is a TOTP entry. In PVE, 1 such entry can contain multiple secrets, provided they use
///     the same configuration.
///
///     DATA: {
///       "keys" => "string of space separated TOTP secrets",
///       "config" => { "step", "digits" },
///     }
///
///   - yubico
///
///     Authentication using the Yubico API.
///
///     DATA: {
///       "keys" => "string list of yubico keys",
///     }
///
///   - u2f
///
///     Legacy U2F entry for the U2F browser API.
///
///     DATA: {
///       "keyHandle" => "u2f key handle",
///       "publicKey" => "u2f public key",
///     }
///
fn parse_old_config(data: &[u8]) -> Result<TfaConfig, Error> {
    let mut config = TfaConfig::default();

    for line in data.split(|&b| b == b'\n') {
        let line = trim_ascii_whitespace(line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }

        let mut parts = line.splitn(3, |&b| b == b':');
        let ((user, ty), data) = parts
            .next()
            .zip(parts.next())
            .zip(parts.next())
            .ok_or_else(|| format_err!("bad line in tfa config"))?;

        let user = std::str::from_utf8(user)
            .map_err(|_err| format_err!("bad non-utf8 username in tfa config"))?;

        let data = proxmox_base64::decode(data)
            .map_err(|err| format_err!("failed to decode data in tfa config entry - {}", err))?;

        let entry = decode_old_entry(ty, &data, user)?;
        config.users.insert(user.to_owned(), entry);
    }

    Ok(config)
}

fn decode_old_entry(ty: &[u8], data: &[u8], user: &str) -> Result<TfaUserData, Error> {
    let mut user_data = TfaUserData::default();

    let info = proxmox_tfa::api::TfaInfo {
        id: "v1-entry".to_string(),
        description: "<old version 1 entry>".to_string(),
        created: 0,
        enable: true,
    };

    let value: JsonValue = serde_json::from_slice(data)
        .map_err(|err| format_err!("failed to parse json data in tfa entry - {}", err))?;

    match ty {
        b"u2f" => {
            if let Some(entry) = decode_old_u2f_entry(value)? {
                user_data
                    .u2f
                    .push(proxmox_tfa::api::TfaEntry::from_parts(info, entry))
            }
        }
        b"oath" => user_data.totp.extend(
            decode_old_oath_entry(value, user)?
                .into_iter()
                .map(proxmox_tfa::api::TotpEntry::new)
                .map(move |entry| proxmox_tfa::api::TfaEntry::from_parts(info.clone(), entry)),
        ),
        b"yubico" => user_data.yubico.extend(
            decode_old_yubico_entry(value)?
                .into_iter()
                .map(move |entry| proxmox_tfa::api::TfaEntry::from_parts(info.clone(), entry)),
        ),
        other => match std::str::from_utf8(other) {
            Ok(s) => bail!("unknown tfa.cfg entry type: {:?}", s),
            Err(_) => bail!("unknown tfa.cfg entry type"),
        },
    };

    Ok(user_data)
}

fn decode_old_u2f_entry(data: JsonValue) -> Result<Option<proxmox_tfa::u2f::Registration>, Error> {
    let mut obj = match data {
        JsonValue::Object(obj) => obj,
        _ => bail!("bad json type for u2f registration"),
    };

    // discard old partial u2f registrations
    if obj.get("challenge").is_some() {
        return Ok(None);
    }

    let reg = proxmox_tfa::u2f::Registration {
        key: proxmox_tfa::u2f::RegisteredKey {
            key_handle: proxmox_base64::url::decode_no_pad(take_json_string(
                &mut obj,
                "keyHandle",
                "u2f",
            )?)
            .map_err(|_| format_err!("handle in u2f entry"))?,
            // PVE did not store this, but we only had U2F_V2 anyway...
            version: "U2F_V2".to_string(),
        },
        public_key: proxmox_base64::decode(take_json_string(&mut obj, "publicKey", "u2f")?)
            .map_err(|_| format_err!("bad public key in u2f entry"))?,
        certificate: Vec::new(),
    };

    if !obj.is_empty() {
        bail!("invalid extra data in u2f entry");
    }

    Ok(Some(reg))
}

fn decode_old_oath_entry(
    data: JsonValue,
    user: &str,
) -> Result<Vec<proxmox_tfa::totp::Totp>, Error> {
    let mut obj = match data {
        JsonValue::Object(obj) => obj,
        _ => bail!("bad json type for oath registration"),
    };

    let mut config = match obj.remove("config") {
        Some(JsonValue::Object(obj)) => obj,
        Some(_) => bail!("bad 'config' entry in oath tfa entry"),
        None => bail!("missing 'config' entry in oath tfa entry"),
    };

    let mut totp = proxmox_tfa::totp::Totp::builder().account_name(user.to_owned());
    if let Some(step) = config.remove("step") {
        totp = totp.period(
            usize_from_perl(step).ok_or_else(|| format_err!("bad 'step' value in oath config"))?,
        );
    }

    if let Some(digits) = config.remove("digits") {
        totp = totp.digits(
            usize_from_perl(digits)
                .and_then(|v| u8::try_from(v).ok())
                .ok_or_else(|| format_err!("bad 'digits' value in oath config"))?,
        );
    }

    if !config.is_empty() {
        bail!("unhandled totp config keys in oath entry");
    }

    let mut out = Vec::new();

    let keys = take_json_string(&mut obj, "keys", "oath")?;
    for key in keys.split([',', ';', ' ']) {
        let key = trim_ascii_whitespace(key.as_bytes());
        if key.is_empty() {
            continue;
        }

        // key started out as a `String` and we only trimmed ASCII white space:
        let key = unsafe { std::str::from_utf8_unchecked(key) };

        // See PVE::OTP::oath_verify_otp
        let key = if let Some(key) = key.strip_prefix("v2-0x") {
            hex::decode(key).map_err(|_| format_err!("bad v2 hex key in oath entry"))?
        } else if let Some(key) = key.strip_prefix("v2-") {
            base32::decode(base32::Alphabet::RFC4648 { padding: true }, key)
                .ok_or_else(|| format_err!("bad v2 base32 key in oath entry"))?
        } else if key.len() == 16 {
            base32::decode(base32::Alphabet::RFC4648 { padding: true }, key)
                .ok_or_else(|| format_err!("bad v1 base32 key in oath entry"))?
        } else if key.len() == 40 {
            hex::decode(key).map_err(|_| format_err!("bad v1 hex key in oath entry"))?
        } else {
            bail!("unrecognized key format, must be hex or base32 encoded");
        };

        out.push(totp.clone().secret(key).build());
    }

    Ok(out)
}

fn decode_old_yubico_entry(data: JsonValue) -> Result<Vec<String>, Error> {
    let mut obj = match data {
        JsonValue::Object(obj) => obj,
        _ => bail!("bad json type for yubico registration"),
    };

    let mut out = Vec::new();

    let keys = take_json_string(&mut obj, "keys", "yubico")?;
    for key in keys.split([',', ';', ' ']) {
        let key = trim_ascii_whitespace(key.as_bytes());
        if key.is_empty() {
            continue;
        }

        // key started out as a `String` and we only trimmed ASCII white space:
        out.push(unsafe { std::str::from_utf8_unchecked(key) }.to_owned());
    }

    Ok(out)
}

fn take_json_string(
    data: &mut serde_json::Map<String, JsonValue>,
    what: &'static str,
    in_what: &'static str,
) -> Result<String, Error> {
    match data.remove(what) {
        None => bail!("missing '{}' value in {} entry", what, in_what),
        Some(JsonValue::String(s)) => Ok(s),
        _ => bail!("bad '{}' value", what),
    }
}

fn usize_from_perl(value: JsonValue) -> Option<usize> {
    // we come from perl, numbers are strings!
    match value {
        JsonValue::Number(n) => n.as_u64().and_then(|n| usize::try_from(n).ok()),
        JsonValue::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn trim_ascii_whitespace_start(data: &[u8]) -> &[u8] {
    match data.iter().position(|&c| !c.is_ascii_whitespace()) {
        Some(from) => &data[from..],
        None => data,
    }
}

fn trim_ascii_whitespace_end(data: &[u8]) -> &[u8] {
    match data.iter().rposition(|&c| !c.is_ascii_whitespace()) {
        Some(to) => &data[..=to],
        None => data,
    }
}

fn trim_ascii_whitespace(data: &[u8]) -> &[u8] {
    trim_ascii_whitespace_start(trim_ascii_whitespace_end(data))
}

fn b64u_np_encode<T: AsRef<[u8]>>(data: T) -> String {
    proxmox_base64::url::encode_no_pad(data.as_ref())
}

// fn b64u_np_decode<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>, base64::DecodeError> {
//     base64::decode_config(data.as_ref(), base64::URL_SAFE_NO_PAD)
// }

fn generate_legacy_config(out: &mut perlmod::Hash, config: &TfaConfig) {
    use perlmod::{Hash, Value};

    let users = Hash::new();

    for (user, data) in &config.users {
        if let Some(u2f) = data.u2f.first() {
            let data = Hash::new();
            data.insert(
                "publicKey",
                Value::new_string(&proxmox_base64::encode(&u2f.entry.public_key)),
            );
            data.insert(
                "keyHandle",
                Value::new_string(&b64u_np_encode(&u2f.entry.key.key_handle)),
            );
            let data = Value::new_ref(&data);

            let entry = Hash::new();
            entry.insert("type", Value::new_string("u2f"));
            entry.insert("data", data);
            users.insert(user, Value::new_ref(&entry));
            continue;
        }

        if let Some(totp) = data.totp.first() {
            let totp = &totp.entry;
            let config = Hash::new();
            config.insert("digits", Value::new_int(isize::from(totp.digits())));
            config.insert("step", Value::new_int(totp.period().as_secs() as isize));

            let mut keys = format!("v2-0x{}", hex::encode(totp.secret()));
            for totp in data.totp.iter().skip(1) {
                keys.push_str(" v2-0x");
                keys.push_str(&hex::encode(totp.entry.secret()));
            }

            let data = Hash::new();
            data.insert("config", Value::new_ref(&config));
            data.insert("keys", Value::new_string(&keys));

            let entry = Hash::new();
            entry.insert("type", Value::new_string("oath"));
            entry.insert("data", Value::new_ref(&data));
            users.insert(user, Value::new_ref(&entry));
            continue;
        }

        if let Some(entry) = data.yubico.first() {
            let mut keys = entry.entry.clone();

            for entry in data.yubico.iter().skip(1) {
                keys.push(' ');
                keys.push_str(&entry.entry);
            }

            let data = Hash::new();
            data.insert("keys", Value::new_string(&keys));

            let entry = Hash::new();
            entry.insert("type", Value::new_string("yubico"));
            entry.insert("data", Value::new_ref(&data));
            users.insert(user, Value::new_ref(&entry));
            continue;
        }

        if data.is_empty() {
            continue;
        }

        // lock out the user:
        let entry = Hash::new();
        entry.insert("type", Value::new_string("incompatible"));
        users.insert(user, Value::new_ref(&entry));
    }

    out.insert("users", Value::new_ref(&users));
}

/// Attach the path to errors from [`nix::mkir()`].
fn mkdir<P: AsRef<Path>>(path: P, mode: libc::mode_t) -> Result<(), Error> {
    let path = path.as_ref();
    match nix::unistd::mkdir(path, unsafe { Mode::from_bits_unchecked(mode) }) {
        Ok(()) => Ok(()),
        Err(Errno::EEXIST) => Ok(()),
        Err(err) => bail!("failed to create directory {:?}: {}", path, err),
    }
}

#[cfg(debug_assertions)]
#[derive(Clone)]
#[repr(transparent)]
struct UserAccess(perlmod::Value);

#[cfg(debug_assertions)]
impl UserAccess {
    #[inline]
    fn new(value: &perlmod::Value) -> Result<Self, Error> {
        value
            .dereference()
            .ok_or_else(|| format_err!("bad TFA config object"))
            .map(Self)
    }

    #[inline]
    fn is_debug(&self) -> bool {
        self.0
            .as_hash()
            .and_then(|v| v.get("-debug"))
            .map(|v| v.iv() != 0)
            .unwrap_or(false)
    }
}

#[cfg(not(debug_assertions))]
#[derive(Clone, Copy)]
#[repr(transparent)]
struct UserAccess;

#[cfg(not(debug_assertions))]
impl UserAccess {
    #[inline]
    const fn new(_value: &perlmod::Value) -> Result<Self, std::convert::Infallible> {
        Ok(Self)
    }

    #[inline]
    const fn is_debug(&self) -> bool {
        false
    }
}

/// Build the path to the challenge data file for a user.
fn challenge_data_path(userid: &str, debug: bool) -> PathBuf {
    if debug {
        PathBuf::from(format!("./local-tfa-challenges/{}", userid))
    } else {
        PathBuf::from(format!("/run/pve-private/tfa-challenges/{}", userid))
    }
}

impl proxmox_tfa::api::OpenUserChallengeData for UserAccess {
    fn open(&self, userid: &str) -> Result<Box<dyn UserChallengeAccess>, Error> {
        if self.is_debug() {
            mkdir("./local-tfa-challenges", 0o700)?;
        } else {
            mkdir("/run/pve-private", 0o700)?;
            mkdir("/run/pve-private/tfa-challenges", 0o700)?;
        }

        let path = challenge_data_path(userid, self.is_debug());

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|err| format_err!("failed to create challenge file {:?}: {}", &path, err))?;

        UserChallengeData::lock_file(file.as_raw_fd())?;

        // the file may be empty, so read to a temporary buffer first:
        let mut data = Vec::with_capacity(4096);

        file.read_to_end(&mut data).map_err(|err| {
            format_err!("failed to read challenge data for user {}: {}", userid, err)
        })?;

        let inner = if data.is_empty() {
            Default::default()
        } else {
            match serde_json::from_slice(&data) {
                Ok(inner) => inner,
                Err(err) => {
                    eprintln!(
                        "failed to parse challenge data for user {}: {}",
                        userid, err
                    );
                    Default::default()
                }
            }
        };

        Ok(Box::new(UserChallengeData {
            inner,
            path,
            lock: file,
        }))
    }

    /// `open` without creating the file if it doesn't exist, to finish WA authentications.
    fn open_no_create(&self, userid: &str) -> Result<Option<Box<dyn UserChallengeAccess>>, Error> {
        let path = challenge_data_path(userid, self.is_debug());

        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };

        UserChallengeData::lock_file(file.as_raw_fd())?;

        let inner = serde_json::from_reader(&mut file).map_err(|err| {
            format_err!("failed to read challenge data for user {}: {}", userid, err)
        })?;

        Ok(Some(Box::new(UserChallengeData {
            inner,
            path,
            lock: file,
        })))
    }

    fn remove(&self, userid: &str) -> Result<bool, Error> {
        let path = challenge_data_path(userid, self.is_debug());
        match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    fn enable_lockout(&self) -> bool {
        true
    }
}

/// Container of `TfaUserChallenges` with the corresponding file lock guard.
///
/// Basically provides the TFA API to the REST server by persisting, updating and verifying active
/// challenges.
struct UserChallengeData {
    inner: proxmox_tfa::api::TfaUserChallenges,
    path: PathBuf,
    lock: File,
}

impl proxmox_tfa::api::UserChallengeAccess for UserChallengeData {
    fn get_mut(&mut self) -> &mut proxmox_tfa::api::TfaUserChallenges {
        &mut self.inner
    }

    fn save(&mut self) -> Result<(), Error> {
        UserChallengeData::save(self)
    }
}

impl UserChallengeData {
    fn lock_file(fd: RawFd) -> Result<(), Error> {
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };

        if rc != 0 {
            let err = io::Error::last_os_error();
            bail!("failed to lock tfa user challenge data: {}", err);
        }

        Ok(())
    }

    /// Rewind & truncate the file for an update.
    fn rewind(&mut self) -> Result<(), Error> {
        use std::io::{Seek, SeekFrom};

        let pos = self.lock.seek(SeekFrom::Start(0))?;
        if pos != 0 {
            bail!(
                "unexpected result trying to rewind file, position is {}",
                pos
            );
        }

        let rc = unsafe { libc::ftruncate(self.lock.as_raw_fd(), 0) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            bail!("failed to truncate challenge data: {}", err);
        }

        Ok(())
    }

    /// Save the current data. Note that we do not replace the file here since we lock the file
    /// itself, as it is in `/run`, and the typical error case for this particular situation
    /// (machine loses power) simply prevents some login, but that'll probably fail anyway for
    /// other reasons then...
    ///
    /// This currently consumes selfe as we never perform more than 1 insertion/removal, and this
    /// way also unlocks early.
    fn save(&mut self) -> Result<(), Error> {
        self.rewind()?;

        serde_json::to_writer(&mut &self.lock, &self.inner).map_err(|err| {
            format_err!("failed to update challenge file {:?}: {}", self.path, err)
        })?;

        Ok(())
    }
}
