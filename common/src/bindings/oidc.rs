#[perlmod::package(name = "Proxmox::RS::OIDC")]
pub mod proxmox_rs_oidc {
    //! The `Proxmox::RS::OIDC` package.
    //!
    //! Implements OpenID authentication support.
    //!
    //! See [`proxmox_openid`].

    use std::sync::Mutex;

    use anyhow::Error;

    use perlmod::{to_value, Value};

    use proxmox_openid::{OpenIdAuthenticator, OpenIdConfig, PrivateAuthState};

    perlmod::declare_magic!(Box<OIDC> : &OIDC as "Proxmox::RS::OIDC");

    /// An OpenIdAuthenticator client instance.
    ///
    /// See [`proxmox_openid::OpenIdAuthenticator`].
    pub struct OIDC {
        inner: Mutex<OpenIdAuthenticator>,
    }

    /// Class method: Create a new OIDC client instance
    ///
    /// See [`OpenIdAuthenticator::discover`].
    #[export(raw_return)]
    pub fn discover(
        #[raw] class: Value,
        config: OpenIdConfig,
        redirect_url: &str,
    ) -> Result<Value, Error> {
        let oidc = OpenIdAuthenticator::discover(&config, redirect_url)?;
        Ok(perlmod::instantiate_magic!(
            &class,
            MAGIC => Box::new(OIDC {
                inner: Mutex::new(oidc),
            })
        ))
    }

    // FIXME: There's no documentation in the proxmox_openid crate.
    /// Method: Authorize an URL.
    ///
    /// See [`OpenIdAuthenticator::authorize_url`].
    #[export]
    pub fn authorize_url(
        #[try_from_ref] this: &OIDC,
        state_dir: &str,
        realm: &str,
    ) -> Result<String, Error> {
        let oidc = this.inner.lock().unwrap();
        oidc.authorize_url(state_dir, realm)
    }

    // FIXME: There's no documentation in the proxmox_openid crate.
    /// Method: Verify public auth state.
    ///
    /// See [`OpenIdAuthenticator::verify_public_auth_state`].
    #[export]
    pub fn verify_public_auth_state(
        state_dir: &str,
        state: &str,
    ) -> Result<(String, PrivateAuthState), Error> {
        OpenIdAuthenticator::verify_public_auth_state(state_dir, state)
    }

    // FIXME: There's no documentation in the proxmox_openid crate.
    /// Method: Verify authorization code.
    ///
    /// See [`OpenIdAuthenticator::verify_authorization_code_simple_userinfo`].
    #[export(raw_return)]
    pub fn verify_authorization_code(
        #[try_from_ref] this: &OIDC,
        code: &str,
        private_auth_state: PrivateAuthState,
        query_userinfo: Option<bool>,
    ) -> Result<Value, Error> {
        let oidc = this.inner.lock().unwrap();
        let claims = oidc.verify_authorization_code_simple_userinfo(
            code,
            &private_auth_state,
            query_userinfo.unwrap_or(true),
        )?;

        Ok(to_value(&claims)?)
    }
}
