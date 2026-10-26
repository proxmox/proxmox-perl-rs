#[perlmod::package(name = "Proxmox::RS::APT::Changelog")]
pub mod proxmox_rs_apt_changelog {
    //! The `Proxmox::RS::APT::Changelog` package.
    //!
    //! Access to the Debian changelogs that installed packages ship.

    use anyhow::Error;

    use proxmox_deb_changelog::ChangelogEntry;

    /// Get the Debian changelog of an installed package, optionally limited to the versions later
    /// than `since_version` and up to including `to_version`, or undef if it has none.
    ///
    /// See [`proxmox_deb_changelog::read_installed_changelog`].
    #[export]
    pub fn installed_changelog(
        name: &str,
        since_version: Option<&str>,
        to_version: Option<&str>,
    ) -> Result<Option<Vec<ChangelogEntry>>, Error> {
        let entries = match proxmox_deb_changelog::read_installed_changelog(name) {
            Ok(entries) => entries,
            Err(proxmox_deb_changelog::Error::NotFound(_)) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        Ok(Some(proxmox_deb_changelog::filter_versions(
            entries,
            since_version,
            to_version,
        )?))
    }

    /// Check whether a version is valid as limit of a version range, like `dpkg
    /// --validate-version` checks it, failing with the reason otherwise.
    #[export]
    pub fn check_version(version: &str) -> Result<(), Error> {
        proxmox_deb_version::validate_version(version)?;
        Ok(())
    }
}
