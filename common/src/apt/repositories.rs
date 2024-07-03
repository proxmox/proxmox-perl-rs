#[perlmod::package(name = "Proxmox::RS::APT::Repositories")]
pub mod export {

    use anyhow::Error;

    use proxmox_apt_api_types::{
        APTChangeRepositoryOptions, APTGetChangelogOptions, APTRepositoriesResult,
        APTRepositoryHandle, APTUpdateInfo, APTUpdateOptions,
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

    /// Retrieve the changelog of the specified package.
    #[export]
    pub fn get_changelog(options: APTGetChangelogOptions) -> Result<String, Error> {
        proxmox_apt::get_changelog(&options)
    }

    /// List available APT updates
    ///
    /// Automatically updates an expired package cache.
    #[export]
    pub fn list_available_apt_update(apt_state_file: &str) -> Result<Vec<APTUpdateInfo>, Error> {
        proxmox_apt::list_available_apt_update(apt_state_file)
    }

    /// Update the APT database
    ///
    /// You should update the APT proxy configuration before running this.
    #[export]
    pub fn update_database(apt_state_file: &str, options: APTUpdateOptions) -> Result<(), Error> {
        proxmox_apt::update_database(
            apt_state_file,
            &options,
            |updates: &[&APTUpdateInfo]| -> Result<(), Error> {
                // fixme: howto send notifgications?
                crate::send_updates_available(updates)?;
                Ok(())
            },
        )
    }

    /// Get package information for a list of important product packages.
    #[export]
    pub fn get_package_versions(
        product_virtual_package: &str,
        api_server_package: &str,
        running_api_server_version: &str,
        package_list: Vec<String>,
    ) -> Result<Vec<APTUpdateInfo>, Error> {
        let package_list: Vec<&str> = package_list.iter().map(|s| s.as_ref()).collect();
        proxmox_apt::get_package_versions(
            product_virtual_package,
            api_server_package,
            running_api_server_version,
            &package_list,
        )
    }
}
