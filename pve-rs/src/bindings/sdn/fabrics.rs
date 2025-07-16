#[perlmod::package(name = "PVE::RS::SDN::Fabrics", lib = "pve_rs")]
pub mod pve_rs_sdn_fabrics {
    //! The `PVE::RS::SDN::Fabrics` package.
    //!
    //! This provides the configuration for the SDN fabrics, as well as helper methods for reading
    //! / writing the configuration, as well as for generating ifupdown2 and FRR configuration.

    use std::collections::BTreeMap;
    use std::ops::Deref;
    use std::sync::Mutex;

    use anyhow::Error;
    use openssl::hash::{MessageDigest, hash};
    use serde::{Deserialize, Serialize};

    use perlmod::Value;
    use proxmox_section_config::typed::SectionConfigData;
    use proxmox_ve_config::common::valid::Validatable;

    use proxmox_ve_config::sdn::fabric::{FabricConfig, section_config::Section};

    /// A SDN Fabric config instance.
    #[derive(Serialize, Deserialize)]
    pub struct PerlFabricConfig {
        /// The fabric config instance
        pub fabric_config: Mutex<FabricConfig>,
    }

    perlmod::declare_magic!(Box<PerlFabricConfig> : &PerlFabricConfig as "PVE::RS::SDN::Fabrics::Config");

    /// Class method: Parse the raw configuration from `/etc/pve/sdn/fabrics.cfg`.
    #[export]
    pub fn config(#[raw] class: Value, raw_config: &[u8]) -> Result<perlmod::Value, Error> {
        let raw_config = std::str::from_utf8(raw_config)?;
        let config = FabricConfig::parse_section_config(raw_config)?;

        Ok(
            perlmod::instantiate_magic!(&class, MAGIC => Box::new(PerlFabricConfig {
                fabric_config: Mutex::new(config.into_inner()),
            })),
        )
    }

    /// Class method: Parse the configuration from `/etc/pve/sdn/.running_config`.
    #[export]
    pub fn running_config(
        #[raw] class: Value,
        fabrics: BTreeMap<String, Section>,
    ) -> Result<perlmod::Value, Error> {
        let fabrics = SectionConfigData::from_iter(fabrics);
        let config = FabricConfig::from_section_config(fabrics)?;

        Ok(
            perlmod::instantiate_magic!(&class, MAGIC => Box::new(PerlFabricConfig {
                fabric_config: Mutex::new(config.into_inner()),
            })),
        )
    }

    /// Method: Convert the configuration into the section config sections.
    ///
    /// Used for writing the running configuration.
    #[export]
    pub fn to_sections(
        #[try_from_ref] this: &PerlFabricConfig,
    ) -> Result<BTreeMap<String, Section>, Error> {
        let config = this
            .fabric_config
            .lock()
            .unwrap()
            .clone()
            .into_valid()?
            .into_section_config();

        Ok(BTreeMap::from_iter(config.clone()))
    }

    /// Method: Convert the configuration into the section config string.
    ///
    /// Used for writing `/etc/pve/sdn/fabrics.cfg`
    #[export]
    pub fn to_raw(#[try_from_ref] this: &PerlFabricConfig) -> Result<String, Error> {
        this.fabric_config.lock().unwrap().write_section_config()
    }

    /// Method: Generate a digest for the whole configuration
    #[export]
    pub fn digest(#[try_from_ref] this: &PerlFabricConfig) -> Result<String, Error> {
        let config = this.fabric_config.lock().unwrap();
        let data = serde_json::to_vec(config.deref())?;
        let hash = hash(MessageDigest::sha256(), &data)?;

        Ok(hex::encode(hash))
    }
}
