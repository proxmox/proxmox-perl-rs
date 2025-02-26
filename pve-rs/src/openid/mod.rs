#[perlmod::package(name = "PVE::RS::OpenId", lib = "pve_rs")]
mod export {
    use anyhow::Error;

    use perlmod::Value;

    use proxmox_openid::{OpenIdConfig, PrivateAuthState};

    use crate::common::oidc::export as common;
    use crate::common::oidc::export::OIDC as OpenId;

    /// Create a new OpenId client instance
    #[export(raw_return)]
    pub fn discover(
        #[raw] class: Value,
        config: OpenIdConfig,
        redirect_url: &str,
    ) -> Result<Value, Error> {
        common::discover(class, config, redirect_url)
    }

    #[export]
    pub fn authorize_url(
        #[try_from_ref] this: &OpenId,
        state_dir: &str,
        realm: &str,
    ) -> Result<String, Error> {
        common::authorize_url(this, state_dir, realm)
    }

    #[export]
    pub fn verify_public_auth_state(
        state_dir: &str,
        state: &str,
    ) -> Result<(String, PrivateAuthState), Error> {
        common::verify_public_auth_state(state_dir, state)
    }

    #[export(raw_return)]
    pub fn verify_authorization_code(
        #[try_from_ref] this: &OpenId,
        code: &str,
        private_auth_state: PrivateAuthState,
    ) -> Result<Value, Error> {
        common::verify_authorization_code(this, code, private_auth_state)
    }
}
