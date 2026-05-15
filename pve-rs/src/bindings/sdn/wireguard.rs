#[perlmod::package(name = "PVE::RS::SDN::WireGuard::PrivateKeys", lib = "pve_rs")]
pub mod pve_rs_sdn_wireguard {
    //! The `PVE::RS::SDN::WireGuard` package.
    //!
    //! This provides an abstraction for the WireGuard private key storage

    use std::{ops::Deref, sync::Mutex};

    use anyhow::Error;
    use proxmox_section_config::typed::{ApiSectionDataEntry, SectionConfigData};
    use proxmox_wireguard::PublicKey;
    use serde::{Deserialize, Serialize};

    use perlmod::Value;
    use proxmox_ve_config::sdn::fabric::section_config::{
        node::NodeId,
        protocol::wireguard::{
            WireGuardInterfaceName,
            private_keys::{FabricPrivateKeysSectionConfig, WireGuardPrivateKeys},
        },
    };

    use crate::bindings::pve_rs_sdn_fabrics::PerlFabricConfig;

    /// A WireGuard private key config instance.
    #[derive(Serialize, Deserialize)]
    pub struct PerlWireguardPrivateKeyConfig {
        /// The fabric config instance
        pub private_keys: Mutex<WireGuardPrivateKeys>,
    }

    /// Class method: Parse the raw configuration from `/etc/pve/priv/wg-keys.cfg`.
    #[export]
    pub fn config(#[raw] class: Value, raw_config: &[u8]) -> Result<perlmod::Value, Error> {
        let raw_config = std::str::from_utf8(raw_config)?;
        let config =
            FabricPrivateKeysSectionConfig::parse_section_config("wg-keys.cfg", raw_config)?;

        Ok(
            perlmod::instantiate_magic!(&class, MAGIC => Box::new(PerlWireguardPrivateKeyConfig {
                private_keys: Mutex::new(config.try_into()?),
            })),
        )
    }

    /// Method: Convert the configuration into the section config string.
    ///
    /// Used for writing `/etc/pve/priv/wg-keys.cfg`
    #[export]
    pub fn to_raw(#[try_from_ref] this: &PerlWireguardPrivateKeyConfig) -> Result<String, Error> {
        let private_keys = this.private_keys.lock().unwrap();

        let raw_config: SectionConfigData<FabricPrivateKeysSectionConfig> =
            private_keys.deref().clone().into();

        FabricPrivateKeysSectionConfig::write_section_config("wg-keys.cfg", &raw_config)
    }

    /// Method: Create a WireGuard key, if it doesn't exist.
    ///
    /// Returns the public key of the created / existing private key.
    #[export]
    pub fn upsert(
        #[try_from_ref] this: &PerlWireguardPrivateKeyConfig,
        node: NodeId,
        interface: WireGuardInterfaceName,
    ) -> Result<PublicKey, Error> {
        this.private_keys.lock().unwrap().upsert(node, interface)
    }

    /// Method: Delete a WireGuard private key.
    #[export]
    pub fn delete(
        #[try_from_ref] this: &PerlWireguardPrivateKeyConfig,
        node: NodeId,
        interface: WireGuardInterfaceName,
    ) -> Result<(), Error> {
        this.private_keys
            .lock()
            .unwrap()
            .remove(&node, &interface)
            .map(|_| ())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "could not find private_key for node {node} and interface {interface}"
                )
            })
    }

    #[export]
    /// Method: Deletes all private keys from `this` that do not exist in the `fabric_config`.
    ///
    /// Returns whether anything was actually removed, so callers can skip an unconditional
    /// rewrite of the cluster-replicated wg-keys.cfg on the steady-state apply path.
    pub fn cleanup(
        #[try_from_ref] this: &PerlWireguardPrivateKeyConfig,
        #[try_from_ref] fabric_config: &PerlFabricConfig,
    ) -> Result<bool, Error> {
        let mut private_key_config = this.private_keys.lock().unwrap();
        let fabric_config = fabric_config.fabric_config.lock().unwrap();

        private_key_config.cleanup(&fabric_config)
    }

    perlmod::declare_magic!(Box<PerlWireguardPrivateKeyConfig> : &PerlWireguardPrivateKeyConfig as "PVE::RS::SDN::WireGuard::Config");
}
