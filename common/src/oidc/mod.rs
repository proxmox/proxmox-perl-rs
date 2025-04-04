#[perlmod::package(name = "Proxmox::RS::OIDC")]
pub mod export {
    use std::sync::Mutex;

    use anyhow::Error;

    use perlmod::{Value, to_value};

    use proxmox_openid::{OpenIdAuthenticator, OpenIdConfig, PrivateAuthState};

    perlmod::declare_magic!(Box<OIDC> : &OIDC as "Proxmox::RS::OIDC");

    /// An OpenIdAuthenticator client instance.
    pub struct OIDC {
        inner: Mutex<OpenIdAuthenticator>,
    }

    /// Create a new OIDC client instance
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

    #[export]
    pub fn authorize_url(
        #[try_from_ref] this: &OIDC,
        state_dir: &str,
        realm: &str,
    ) -> Result<String, Error> {
        let oidc = this.inner.lock().unwrap();
        oidc.authorize_url(state_dir, realm)
    }

    #[export]
    pub fn verify_public_auth_state(
        state_dir: &str,
        state: &str,
    ) -> Result<(String, PrivateAuthState), Error> {
        OpenIdAuthenticator::verify_public_auth_state(state_dir, state)
    }

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
