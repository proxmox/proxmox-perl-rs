pub(crate) mod fabrics;

#[perlmod::package(name = "PVE::RS::SDN", lib = "pve_rs")]
pub mod pve_rs_sdn {
    //! The `PVE::RS::SDN` package.
    //!
    //! This provides general methods for generating the frr config.

    use anyhow::Error;
    use proxmox_frr::ser::{FrrConfig, serializer::to_raw_config};

    use proxmox_ve_config::common::valid::Validatable;
    use proxmox_ve_config::sdn::fabric::section_config::node::NodeId;

    use crate::bindings::pve_rs_sdn_fabrics::PerlFabricConfig;

    /// Return the FRR configuration for the passed FrrConfig and the FabricsConfig as an array of
    /// strings, where each line represents a line in the FRR configuration.
    #[export]
    pub fn get_frr_raw_config(
        mut frr_config: FrrConfig,
        #[try_from_ref] cfg: &PerlFabricConfig,
        node_id: NodeId,
    ) -> Result<Vec<String>, Error> {
        let fabric_config = cfg.fabric_config.lock().unwrap().clone().into_valid()?;
        proxmox_ve_config::sdn::fabric::frr::build_fabric(node_id, fabric_config, &mut frr_config)?;
        to_raw_config(&frr_config)
    }
}
