#[perlmod::package(name = "PVE::RS::OpenId", lib = "pve_rs")]
pub mod pve_rs_open_id {
    //! The `PVE::RS::OpenId` package.
    //!
    //! Deprecated. Use `Proxmox::RS::OIDC` instead.
    //!
    //! See [`proxmo_rs_oidc`](crate::common::bindings::proxmox_rs_oidc).

    use anyhow::Error;

    use perlmod::Value;

    use proxmox_openid::{OpenIdConfig, PrivateAuthState};

    use crate::common::bindings::proxmox_rs_oidc;
    use crate::common::bindings::proxmox_rs_oidc::OIDC as OpenId;

    /// Class method: Create a new OIDC client instance
    ///
    /// See [`proxmox_rs_oidc::discover`].
    #[export(raw_return)]
    pub fn discover(
        #[raw] class: Value,
        config: OpenIdConfig,
        redirect_url: &str,
    ) -> Result<Value, Error> {
        proxmox_rs_oidc::discover(class, config, redirect_url)
    }

    /// Method: Authorize an URL.
    ///
    /// See [`proxmox_rs_oidc::authorize_url`].
    #[export]
    pub fn authorize_url(
        #[try_from_ref] this: &OpenId,
        state_dir: &str,
        realm: &str,
    ) -> Result<String, Error> {
        proxmox_rs_oidc::authorize_url(this, state_dir, realm)
    }

    /// Method: Verify public auth state.
    ///
    /// See [`proxmox_rs_oidc::verify_public_auth_state`].
    #[export]
    pub fn verify_public_auth_state(
        state_dir: &str,
        state: &str,
    ) -> Result<(String, PrivateAuthState), Error> {
        proxmox_rs_oidc::verify_public_auth_state(state_dir, state)
    }

    /// Method: Verify authorization code.
    ///
    /// See [`proxmox_rs_oidc::verify_authorization_code_simple_userinfo`].
    #[export(raw_return)]
    pub fn verify_authorization_code(
        #[try_from_ref] this: &OpenId,
        code: &str,
        private_auth_state: PrivateAuthState,
        query_userinfo: Option<bool>,
    ) -> Result<Value, Error> {
        proxmox_rs_oidc::verify_authorization_code(this, code, private_auth_state, query_userinfo)
    }
}
