//! This implements the `tfa.cfg` parser & TFA API calls for PMG.
//!
//! The exported `PMG::RS::TFA` perl package provides access to rust's `TfaConfig`.
//! Contrary to the PVE implementation, this does not need to provide any backward compatible
//! entries.
//!
//! NOTE: In PMG the tfa config is behind `PVE::INotify`'s `ccache`, so PMG sets it to `noclone` in
//! order to avoid losing the rust magic-ref.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::{bail, format_err, Error};
use nix::errno::Errno;
use nix::sys::stat::Mode;

use proxmox_tfa::api::{
    RecoveryState, TfaChallenge, TfaConfig, TfaResponse, U2fConfig, UserChallengeAccess,
    WebauthnConfig,
};

#[perlmod::package(name = "PMG::RS::TFA")]
mod export {
    use std::collections::HashMap;
    use std::convert::TryInto;
    use std::sync::Mutex;

    use anyhow::{bail, format_err, Error};
    use serde_bytes::ByteBuf;
    use url::Url;

    use perlmod::Value;
    use proxmox_tfa::api::{methods, TfaResult};

    use super::{TfaConfig, UserAccess};

    perlmod::declare_magic!(Box<Tfa> : &Tfa as "PMG::RS::TFA");

    /// A TFA Config instance.
    pub struct Tfa {
        inner: Mutex<TfaConfig>,
    }

    /// Prevent 'dclone'.
    #[export(name = "STORABLE_freeze", raw_return)]
    fn storable_freeze(#[try_from_ref] _this: &Tfa, _cloning: bool) -> Result<Value, Error> {
        bail!("freezing TFA config not supported!");
    }

    /// Parse a TFA configuration.
    #[export(raw_return)]
    fn new(#[raw] class: Value, config: &[u8]) -> Result<Value, Error> {
        let mut inner: TfaConfig = serde_json::from_slice(config)
            .map_err(|err| format_err!("failed to parse TFA file: {}", err))?;

        // PMG does not support U2F.
        inner.u2f = None;
        Ok(perlmod::instantiate_magic!(
            &class, MAGIC => Box::new(Tfa { inner: Mutex::new(inner) })
        ))
    }

    /// Write the configuration out into a JSON string.
    #[export]
    fn write(#[try_from_ref] this: &Tfa) -> Result<serde_bytes::ByteBuf, Error> {
        let inner = this.inner.lock().unwrap();
        Ok(ByteBuf::from(serde_json::to_vec(&*inner)?))
    }

    /// Debug helper: serialize the TFA user data into a perl value.
    #[export]
    fn to_perl(#[try_from_ref] this: &Tfa) -> Result<Value, Error> {
        let inner = this.inner.lock().unwrap();
        Ok(perlmod::to_value(&*inner)?)
    }

    /// Get a list of all the user names in this config.
    /// PMG uses this to verify users and purge the invalid ones.
    #[export]
    fn users(#[try_from_ref] this: &Tfa) -> Result<Vec<String>, Error> {
        Ok(this.inner.lock().unwrap().users.keys().cloned().collect())
    }

    /// Remove a user from the TFA configuration.
    #[export]
    fn remove_user(#[try_from_ref] this: &Tfa, userid: &str) -> Result<bool, Error> {
        Ok(this.inner.lock().unwrap().users.remove(userid).is_some())
    }

    /// Get the TFA data for a specific user.
    #[export(raw_return)]
    fn get_user(#[try_from_ref] this: &Tfa, userid: &str) -> Result<Value, perlmod::Error> {
        perlmod::to_value(&this.inner.lock().unwrap().users.get(userid))
    }

    /// Add a u2f registration. This modifies the config (adds the user to it), so it needs be
    /// written out.
    #[export]
    fn add_u2f_registration(
        #[raw] raw_this: Value,
        //#[try_from_ref] this: &Tfa,
        userid: &str,
        description: String,
    ) -> Result<String, Error> {
        let this: &Tfa = (&raw_this).try_into()?;
        let mut inner = this.inner.lock().unwrap();
        inner.u2f_registration_challenge(&UserAccess::new(&raw_this)?, userid, description)
    }

    /// Finish a u2f registration. This updates temporary data in `/run` and therefore the config
    /// needs to be written out!
    #[export]
    fn finish_u2f_registration(
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

    /// Check if a user has any TFA entries of a given type.
    #[export]
    fn has_type(#[try_from_ref] this: &Tfa, userid: &str, typename: &str) -> Result<bool, Error> {
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

    /// Generates a space separated list of yubico keys of this account.
    #[export]
    fn get_yubico_keys(#[try_from_ref] this: &Tfa, userid: &str) -> Result<Option<String>, Error> {
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

    #[export]
    fn set_u2f_config(#[try_from_ref] this: &Tfa, config: Option<super::U2fConfig>) {
        this.inner.lock().unwrap().u2f = config;
    }

    #[export]
    fn set_webauthn_config(
        #[try_from_ref] this: &Tfa,
        config: Option<super::WebauthnConfig>,
    ) -> Result<(), Error> {
        this.inner.lock().unwrap().webauthn = config.map(TryInto::try_into).transpose()?;
        Ok(())
    }

    #[export]
    fn get_webauthn_config(
        #[try_from_ref] this: &Tfa,
    ) -> Result<(Option<String>, Option<super::WebauthnConfig>), Error> {
        Ok(match this.inner.lock().unwrap().webauthn.clone() {
            Some(config) => (Some(hex::encode(&config.digest())), Some(config.into())),
            None => (None, None),
        })
    }

    #[export]
    fn has_webauthn_origin(#[try_from_ref] this: &Tfa) -> bool {
        match &this.inner.lock().unwrap().webauthn {
            Some(wa) => wa.origin.is_some(),
            None => false,
        }
    }

    /// Create an authentication challenge.
    ///
    /// Returns the challenge as a json string.
    /// Returns `undef` if no second factor is configured.
    #[export]
    fn authentication_challenge(
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

    /// Get the recovery state (suitable for a challenge object).
    #[export]
    fn recovery_state(#[try_from_ref] this: &Tfa, userid: &str) -> Option<super::RecoveryState> {
        this.inner
            .lock()
            .unwrap()
            .users
            .get(userid)
            .and_then(|user| user.recovery_state())
    }

    /// Takes the TFA challenge string (which is a json object) and verifies ther esponse against
    /// it.
    ///
    /// NOTE: This returns a boolean whether the config data needs to be *saved* after this call
    /// (to use up recovery keys!).
    #[export]
    fn authentication_verify(
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

    /// Takes the TFA challenge string (which is a json object) and verifies ther esponse against
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
    fn authentication_verify2(
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

    #[derive(Default, serde::Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct TfaReturnValue {
        result: bool,
        needs_saving: bool,
        totp_limit_reached: bool,
        tfa_limit_reached: bool,
    }

    /// DEBUG HELPER: Get the current TOTP value for a given TOTP URI.
    #[export]
    fn get_current_totp_value(otp_uri: &str) -> Result<String, Error> {
        let totp: proxmox_tfa::totp::Totp = otp_uri.parse()?;
        Ok(totp.time(std::time::SystemTime::now())?.to_string())
    }

    #[export]
    fn api_list_user_tfa(
        #[try_from_ref] this: &Tfa,
        userid: &str,
    ) -> Result<Vec<methods::TypedTfaInfo>, Error> {
        methods::list_user_tfa(&this.inner.lock().unwrap(), userid)
    }

    #[export]
    fn api_get_tfa_entry(
        #[try_from_ref] this: &Tfa,
        userid: &str,
        id: &str,
    ) -> Option<methods::TypedTfaInfo> {
        methods::get_tfa_entry(&this.inner.lock().unwrap(), userid, id)
    }

    /// Returns `true` if the user still has other TFA entries left, `false` if the user has *no*
    /// more tfa entries.
    #[export]
    fn api_delete_tfa(#[try_from_ref] this: &Tfa, userid: &str, id: String) -> Result<bool, Error> {
        let mut this = this.inner.lock().unwrap();
        match methods::delete_tfa(&mut this, userid, &id) {
            Ok(has_entries_left) => Ok(has_entries_left),
            Err(methods::EntryNotFound) => bail!("no such entry"),
        }
    }

    #[export]
    fn api_list_tfa(
        #[try_from_ref] this: &Tfa,
        authid: &str,
        top_level_allowed: bool,
    ) -> Result<Vec<methods::TfaUser>, Error> {
        methods::list_tfa(&this.inner.lock().unwrap(), authid, top_level_allowed)
    }

    #[export]
    fn api_add_tfa_entry(
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

    /// Add a totp entry without validating it, used for user.cfg keys.
    /// Returns the ID.
    #[export]
    fn add_totp_entry(
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

    /// Add a yubico entry without validating it, used for user.cfg keys.
    /// Returns the ID.
    #[export]
    fn add_yubico_entry(
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

    #[export]
    fn api_update_tfa_entry(
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

    #[export]
    fn api_unlock_tfa(#[raw] raw_this: Value, userid: &str) -> Result<bool, Error> {
        let this: &Tfa = (&raw_this).try_into()?;
        methods::unlock_and_reset_tfa(
            &mut this.inner.lock().unwrap(),
            &UserAccess::new(&raw_this)?,
            userid,
        )
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct TfaLockStatus {
        /// Once a user runs into a TOTP limit they get locked out of TOTP until they successfully use
        /// a recovery key.
        #[serde(skip_serializing_if = "bool_is_false", default)]
        totp_locked: bool,

        /// If a user hits too many 2nd factor failures, they get completely blocked for a while.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(deserialize_with = "filter_expired_timestamp")]
        tfa_locked_until: Option<i64>,
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

    #[export]
    fn tfa_lock_status(
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

/// Attach the path to errors from [`nix::mkir()`].
pub(crate) fn mkdir<P: AsRef<Path>>(path: P, mode: libc::mode_t) -> Result<(), Error> {
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
pub struct UserAccess(perlmod::Value);

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
pub struct UserAccess;

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
        PathBuf::from(format!("/run/pmg-private/tfa-challenges/{}", userid))
    }
}

impl proxmox_tfa::api::OpenUserChallengeData for UserAccess {
    fn open(&self, userid: &str) -> Result<Box<dyn UserChallengeAccess>, Error> {
        if self.is_debug() {
            mkdir("./local-tfa-challenges", 0o700)?;
        } else {
            mkdir("/run/pmg-private", 0o700)?;
            mkdir("/run/pmg-private/tfa-challenges", 0o700)?;
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
        match std::fs::remove_file(&path) {
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
pub struct UserChallengeData {
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
