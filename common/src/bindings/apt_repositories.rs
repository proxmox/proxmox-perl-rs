#[perlmod::package(name = "Proxmox::RS::APT::Repositories")]
pub mod proxmox_rs_apt_repositories {
    //! The `Proxmox::RS::APT::Repositories` package.
    //!
    //! APT repository information access.

    use anyhow::Error;

    use proxmox_apt_api_types::{
        APTChangeRepositoryOptions, APTGetChangelogOptions, APTRepositoriesResult,
        APTRepositoryHandle, APTUpdateInfo, APTUpdateOptions,
    };
    use proxmox_config_digest::ConfigDigest;

    /// Get information about configured repositories and standard repositories for `product`.
    ///
    /// See [`proxmox_apt::list_repositories`].
    #[export]
    pub fn repositories(product: &str) -> Result<APTRepositoriesResult, Error> {
        proxmox_apt::list_repositories(product)
    }

    /// Add the repository identified by the `handle` and `product`.
    /// If the repository is already configured, it will be set to enabled.
    ///
    /// The `digest` parameter asserts that the configuration has not been modified.
    ///
    /// See [`proxmox_apt::add_repository_handle`].
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
    ///
    /// See [`proxmox_apt::change_repository`].
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
    ///
    /// See [`proxmox_apt::get_changelog`].
    #[export]
    pub fn get_changelog(options: APTGetChangelogOptions) -> Result<String, Error> {
        proxmox_apt::get_changelog(&options)
    }

    /// List available APT updates
    ///
    /// Automatically updates an expired package cache.
    ///
    /// See [`proxmox_apt::list_available_apt_update`].
    #[export]
    pub fn list_available_apt_update(apt_state_file: &str) -> Result<Vec<APTUpdateInfo>, Error> {
        proxmox_apt::list_available_apt_update(apt_state_file)
    }

    /// Update the APT database
    ///
    /// You should update the APT proxy configuration before running this.
    ///
    /// See [`proxmox_apt::update_database`].
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
    ///
    /// See [`proxmox_apt::get_package_versions`].
    #[export]
    pub fn get_package_versions(
        product_virtual_package: &str,
        api_server_package: &str,
        running_api_server_version: &str,
        package_list: Vec<&str>,
    ) -> Result<Vec<APTUpdateInfo>, Error> {
        proxmox_apt::get_package_versions(
            product_virtual_package,
            api_server_package,
            running_api_server_version,
            &package_list,
        )
    }
}
