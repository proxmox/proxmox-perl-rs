//! `PMG::RS::Acme` perl module.
//!
//! The functions in here are perl bindings.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{format_err, Error};
use serde::{Deserialize, Serialize};

use proxmox_acme::account::AccountData as AcmeAccountData;
use proxmox_acme::{Account, Client};

/// Our on-disk format inherited from PVE's proxmox-acme code.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountData {
    /// The account's location URL.
    location: String,

    /// The account dat.
    account: AcmeAccountData,

    /// The private key as PEM formatted string.
    key: String,

    /// ToS URL the user agreed to.
    #[serde(skip_serializing_if = "Option::is_none")]
    tos: Option<String>,

    #[serde(skip_serializing_if = "is_false", default)]
    debug: bool,

    /// The directory's URL.
    directory_url: String,
}

#[inline]
fn is_false(b: &bool) -> bool {
    !*b
}

struct Inner {
    client: Client,
    account_path: Option<String>,
    tos: Option<String>,
    debug: bool,
}

impl Inner {
    pub fn new(api_directory: String) -> Result<Self, Error> {
        Ok(Self {
            client: Client::new(api_directory),
            account_path: None,
            tos: None,
            debug: false,
        })
    }

    pub fn load(account_path: String) -> Result<Self, Error> {
        let data = std::fs::read(&account_path)?;
        let data: AccountData = serde_json::from_slice(&data)?;

        let mut client = Client::new(data.directory_url);
        client.set_account(Account::from_parts(data.location, data.key, data.account));

        Ok(Self {
            client,
            account_path: Some(account_path),
            tos: data.tos,
            debug: data.debug,
        })
    }

    pub fn new_account(
        &mut self,
        account_path: String,
        tos_agreed: bool,
        contact: Vec<String>,
        rsa_bits: Option<u32>,
        eab_creds: Option<(String, String)>,
    ) -> Result<(), Error> {
        self.tos = if tos_agreed {
            self.client.terms_of_service_url()?.map(str::to_owned)
        } else {
            None
        };

        let _account = self
            .client
            .new_account(contact, tos_agreed, rsa_bits, eab_creds)?;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&account_path)
            .map_err(|err| format_err!("failed to open {:?} for writing: {}", account_path, err))?;
        self.write_to(file).map_err(|err| {
            format_err!(
                "failed to write acme account to {:?}: {}",
                account_path,
                err
            )
        })?;
        self.account_path = Some(account_path);

        Ok(())
    }

    /// Convenience helper around `.client.account().ok_or_else(||...)`
    fn account(&self) -> Result<&Account, Error> {
        self.client
            .account()
            .ok_or_else(|| format_err!("missing account"))
    }

    fn to_account_data(&self) -> Result<AccountData, Error> {
        let account = self.account()?;

        Ok(AccountData {
            location: account.location.clone(),
            key: account.private_key.clone(),
            account: AcmeAccountData {
                only_return_existing: false, // don't actually write this out in case it's set
                ..account.data.clone()
            },
            tos: self.tos.clone(),
            debug: self.debug,
            directory_url: self.client.directory_url().to_owned(),
        })
    }

    fn write_to<T: io::Write>(&mut self, out: T) -> Result<(), Error> {
        let data = self.to_account_data()?;

        Ok(serde_json::to_writer_pretty(out, &data)?)
    }

    pub fn update_account<T: Serialize>(&mut self, data: &T) -> Result<(), Error> {
        let account_path = self
            .account_path
            .as_deref()
            .ok_or_else(|| format_err!("missing account path"))?;
        self.client.update_account(data)?;

        let tmp_path = format!("{}.tmp", account_path);
        // FIXME: move proxmox::tools::replace_file & make_temp out into a nice *little* crate...
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|err| format_err!("failed to open {:?} for writing: {}", tmp_path, err))?;
        self.write_to(&mut file).map_err(|err| {
            format_err!("failed to write acme account to {:?}: {}", tmp_path, err)
        })?;
        file.flush().map_err(|err| {
            format_err!("failed to flush acme account file {:?}: {}", tmp_path, err)
        })?;

        // re-borrow since we needed `self` as mut earlier
        let account_path = self.account_path.as_deref().unwrap();
        std::fs::rename(&tmp_path, account_path).map_err(|err| {
            format_err!(
                "failed to rotate temp file into place ({:?} -> {:?}): {}",
                &tmp_path,
                account_path,
                err
            )
        })?;
        drop(file);
        Ok(())
    }

    pub fn revoke_certificate(&mut self, data: &[u8], reason: Option<u32>) -> Result<(), Error> {
        Ok(self.client.revoke_certificate(data, reason)?)
    }

    pub fn set_proxy(&mut self, proxy: String) {
        self.client.set_proxy(proxy)
    }
}

#[perlmod::package(name = "PMG::RS::Acme")]
pub mod export {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use anyhow::Error;
    use serde_bytes::{ByteBuf, Bytes};

    use perlmod::Value;
    use proxmox_acme::directory::Meta;
    use proxmox_acme::order::OrderData;
    use proxmox_acme::{Authorization, Challenge, Order};

    use super::{AccountData, Inner};

    perlmod::declare_magic!(Box<Acme> : &Acme as "PMG::RS::Acme");

    /// An Acme client instance.
    pub struct Acme {
        inner: Mutex<Inner>,
    }

    /// Create a new ACME client instance given an account path and an API directory URL.
    #[export(raw_return)]
    pub fn new(#[raw] class: Value, api_directory: String) -> Result<Value, Error> {
        Ok(perlmod::instantiate_magic!(
            &class,
            MAGIC => Box::new(Acme {
                inner: Mutex::new(Inner::new(api_directory)?),
            })
        ))
    }

    /// Load an existing account.
    #[export(raw_return)]
    pub fn load(#[raw] class: Value, account_path: String) -> Result<Value, Error> {
        Ok(perlmod::instantiate_magic!(
            &class,
            MAGIC => Box::new(Acme {
                inner: Mutex::new(Inner::load(account_path)?),
            })
        ))
    }

    /// Create a new account.
    ///
    /// `tos_agreed` is usually not optional, but may be set later via an update.
    /// The `contact` list should be a list of `mailto:` strings (or others, if the directory
    /// allows the).
    ///
    /// In case an RSA key should be generated, an `rsa_bits` parameter should be provided.
    /// Otherwise a P-256 EC key will be generated.
    #[export]
    pub fn new_account(
        #[try_from_ref] this: &Acme,
        account_path: String,
        tos_agreed: bool,
        contact: Vec<String>,
        rsa_bits: Option<u32>,
        eab_kid: Option<String>,
        eab_hmac_key: Option<String>,
    ) -> Result<(), Error> {
        this.inner.lock().unwrap().new_account(
            account_path,
            tos_agreed,
            contact,
            rsa_bits,
            eab_kid.zip(eab_hmac_key),
        )
    }

    /// Get the directory's meta information.
    #[export]
    pub fn get_meta(#[try_from_ref] this: &Acme) -> Result<Option<Meta>, Error> {
        match this.inner.lock().unwrap().client.directory()?.meta() {
            Some(meta) => Ok(Some(meta.clone())),
            None => Ok(None),
        }
    }

    /// Get the account's directory URL.
    #[export]
    pub fn directory(#[try_from_ref] this: &Acme) -> Result<String, Error> {
        Ok(this.inner.lock().unwrap().client.directory()?.url.clone())
    }

    /// Serialize the account data.
    #[export]
    pub fn account(#[try_from_ref] this: &Acme) -> Result<AccountData, Error> {
        this.inner.lock().unwrap().to_account_data()
    }

    /// Get the account's location URL.
    #[export]
    pub fn location(#[try_from_ref] this: &Acme) -> Result<String, Error> {
        Ok(this.inner.lock().unwrap().account()?.location.clone())
    }

    /// Get the account's agreed-to ToS URL.
    #[export]
    pub fn tos_url(#[try_from_ref] this: &Acme) -> Option<String> {
        this.inner.lock().unwrap().tos.clone()
    }

    /// Get the debug flag.
    #[export]
    pub fn debug(#[try_from_ref] this: &Acme) -> bool {
        this.inner.lock().unwrap().debug
    }

    /// Get the debug flag.
    #[export]
    pub fn set_debug(#[try_from_ref] this: &Acme, on: bool) {
        this.inner.lock().unwrap().debug = on;
    }

    /// Place a new order.
    #[export]
    pub fn new_order(
        #[try_from_ref] this: &Acme,
        domains: Vec<String>,
    ) -> Result<(String, OrderData), Error> {
        let order: Order = this.inner.lock().unwrap().client.new_order(domains)?;
        Ok((order.location, order.data))
    }

    /// Get the authorization info given an authorization URL.
    ///
    /// This should be an URL found in the `authorizations` array in the `OrderData` returned from
    /// `new_order`.
    #[export]
    pub fn get_authorization(
        #[try_from_ref] this: &Acme,
        url: &str,
    ) -> Result<Authorization, Error> {
        Ok(this.inner.lock().unwrap().client.get_authorization(url)?)
    }

    /// Query an order given its URL.
    ///
    /// The corresponding URL is returned as first value from the `new_order` call.
    #[export]
    pub fn get_order(#[try_from_ref] this: &Acme, url: &str) -> Result<OrderData, Error> {
        Ok(this.inner.lock().unwrap().client.get_order(url)?)
    }

    /// Get the key authorization string for a challenge given a token.
    #[export]
    pub fn key_authorization(#[try_from_ref] this: &Acme, token: &str) -> Result<String, Error> {
        Ok(this.inner.lock().unwrap().client.key_authorization(token)?)
    }

    /// Get the key dns-01 TXT challenge value for a token.
    #[export]
    pub fn dns_01_txt_value(#[try_from_ref] this: &Acme, token: &str) -> Result<String, Error> {
        Ok(this.inner.lock().unwrap().client.dns_01_txt_value(token)?)
    }

    /// Request validation of a challenge by URL.
    ///
    /// Given an `Authorization`, it'll contain `challenges`. These contain `url`s pointing to a
    /// method used to request challenge authorization. This is the URL used for this method,
    /// *after* performing the necessary steps to satisfy the challenge. (Eg. after setting up a
    /// DNS TXT entry using the `dns-01` type challenge's key authorization.
    #[export]
    pub fn request_challenge_validation(
        #[try_from_ref] this: &Acme,
        url: &str,
    ) -> Result<Challenge, Error> {
        Ok(this
            .inner
            .lock()
            .unwrap()
            .client
            .request_challenge_validation(url)?)
    }

    /// Request finalization of an order.
    ///
    /// The `url` should be the 'finalize' URL of the order.
    #[export]
    pub fn finalize_order(
        #[try_from_ref] this: &Acme,
        url: &str,
        csr: &Bytes,
    ) -> Result<(), Error> {
        Ok(this.inner.lock().unwrap().client.finalize(url, csr)?)
    }

    /// Download the certificate for an order.
    ///
    /// The `url` should be the 'certificate' URL of the order.
    #[export]
    pub fn get_certificate(#[try_from_ref] this: &Acme, url: &str) -> Result<ByteBuf, Error> {
        Ok(ByteBuf::from(
            this.inner.lock().unwrap().client.get_certificate(url)?,
        ))
    }

    /// Update account data.
    ///
    /// This can be used for example to deactivate an account or agree to ToS later on.
    #[export]
    pub fn update_account(
        #[try_from_ref] this: &Acme,
        data: HashMap<String, serde_json::Value>,
    ) -> Result<(), Error> {
        this.inner.lock().unwrap().update_account(&data)?;
        Ok(())
    }

    /// Revoke an existing certificate using the certificate in PEM or DER form.
    #[export]
    pub fn revoke_certificate(
        #[try_from_ref] this: &Acme,
        data: &[u8],
        reason: Option<u32>,
    ) -> Result<(), Error> {
        this.inner
            .lock()
            .unwrap()
            .revoke_certificate(&data, reason)?;
        Ok(())
    }

    /// Set a proxy
    #[export]
    pub fn set_proxy(#[try_from_ref] this: &Acme, proxy: String) {
        this.inner.lock().unwrap().set_proxy(proxy)
    }
}
