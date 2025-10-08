#[perlmod::package(name = "PVE::RS::OCI", lib = "pve_rs")]
pub mod pve_rs_oci {
    //! The `PVE::RS::OCI` package.
    //!
    //! Provides bindings for the [`proxmox_oci`] crate.

    use anyhow::Error;
    use proxmox_oci::Config;

    /// Extract the rootfs of an OCI image tar and return the image config.
    ///
    /// # Arguments
    ///
    /// * `oci_tar_path` - Path to the OCI image tar archive
    /// * `rootfs_path` - Destination path where the rootfs will be extracted to
    /// * `arch` - Optional CPU architecture used to pick the first matching manifest from a multi-arch
    ///   image index. If `None`, the first manifest will be used.
    #[export]
    pub fn parse_and_extract_image(
        oci_tar_path: &str,
        rootfs_path: &str,
        arch: Option<&str>,
    ) -> Result<Config, Error> {
        let arch = arch.map(Into::into);
        proxmox_oci::parse_and_extract_image(oci_tar_path, rootfs_path, arch.as_ref())
            .map(|config| config.unwrap_or_default())
            .map_err(Into::into)
    }
}
