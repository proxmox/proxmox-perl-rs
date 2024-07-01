#[perlmod::package(name = "PVE::RS::APT::Repositories", lib = "pve_rs")]
mod export {
    use anyhow::Error;

    use proxmox_apt_api_types::APTRepositoriesResult;
    use proxmox_config_digest::ConfigDigest;

    use crate::common::apt::repositories::export as common;

    /// Get information about configured and standard repositories.
    #[export]
    pub fn repositories() -> Result<APTRepositoriesResult, Error> {
        common::repositories("pve")
    }

    /// Add the repository identified by the `handle`.
    /// If the repository is already configured, it will be set to enabled.
    ///
    /// The `digest` parameter asserts that the configuration has not been modified.
    #[export]
    pub fn add_repository(handle: &str, digest: Option<ConfigDigest>) -> Result<(), Error> {
        common::add_repository(handle, "pve", digest)
    }

    /// Change the properties of the specified repository.
    ///
    /// The `digest` parameter asserts that the configuration has not been modified.
    #[export]
    pub fn change_repository(
        path: &str,
        index: usize,
        options: common::ChangeProperties,
        digest: Option<ConfigDigest>,
    ) -> Result<(), Error> {
        common::change_repository(path, index, options, digest)
    }
}
