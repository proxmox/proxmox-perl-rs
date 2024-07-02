#[perlmod::package(name = "Proxmox::RS::APT::Repositories")]
pub mod export {

    use anyhow::Error;

    use proxmox_apt_api_types::{
        APTChangeRepositoryOptions, APTRepositoriesResult, APTRepositoryHandle,
    };
    use proxmox_config_digest::ConfigDigest;

    /// Get information about configured repositories and standard repositories for `product`.
    #[export]
    pub fn repositories(product: &str) -> Result<APTRepositoriesResult, Error> {
        proxmox_apt::list_repositories(product)
    }

    /// Add the repository identified by the `handle` and `product`.
    /// If the repository is already configured, it will be set to enabled.
    ///
    /// The `digest` parameter asserts that the configuration has not been modified.
    #[export]
    pub fn add_repository(
        handle: APTRepositoryHandle,
        product: &str,
        digest: Option<ConfigDigest>,
    ) -> Result<(), Error> {
        proxmox_apt::add_repository_handle(product, handle, digest)
    }

    /// Change the properties of the specified repository.
    ///
    /// The `digest` parameter asserts that the configuration has not been modified.
    #[export]
    pub fn change_repository(
        path: &str,
        index: usize,
        options: APTChangeRepositoryOptions,
        digest: Option<ConfigDigest>,
    ) -> Result<(), Error> {
        proxmox_apt::change_repository(path, index, &options, digest)
    }
}
