#[perlmod::package(name = "PVE::RS::OpenId", lib = "pve_rs")]
mod export {
    use std::sync::Mutex;

    use anyhow::Error;

    use perlmod::{to_value, Value};

    use proxmox_openid::{OpenIdAuthenticator, OpenIdConfig, PrivateAuthState};

    perlmod::declare_magic!(Box<OpenId> : &OpenId as "PVE::RS::OpenId");

    /// An OpenIdAuthenticator client instance.
    pub struct OpenId {
        inner: Mutex<OpenIdAuthenticator>,
    }

    /// Create a new OpenId client instance
    #[export(raw_return)]
    pub fn discover(
        #[raw] class: Value,
        config: OpenIdConfig,
        redirect_url: &str,
    ) -> Result<Value, Error> {
        let open_id = OpenIdAuthenticator::discover(&config, redirect_url)?;
        Ok(perlmod::instantiate_magic!(
            &class,
            MAGIC => Box::new(OpenId {
                inner: Mutex::new(open_id),
            })
        ))
    }

    #[export]
    pub fn authorize_url(
        #[try_from_ref] this: &OpenId,
        state_dir: &str,
        realm: &str,
    ) -> Result<String, Error> {
        let open_id = this.inner.lock().unwrap();
        open_id.authorize_url(state_dir, realm)
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
        #[try_from_ref] this: &OpenId,
        code: &str,
        private_auth_state: PrivateAuthState,
    ) -> Result<Value, Error> {
        let open_id = this.inner.lock().unwrap();
        let claims = open_id.verify_authorization_code_simple(code, &private_auth_state)?;

        Ok(to_value(&claims)?)
    }
}
