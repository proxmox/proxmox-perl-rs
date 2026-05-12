pub(crate) mod fabrics;
pub(crate) mod prefix_lists;
pub(crate) mod route_maps;
pub(crate) mod wireguard;

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
    use crate::bindings::sdn::prefix_lists::pve_rs_sdn_prefix_lists::PerlPrefixListConfig;
    use crate::bindings::sdn::route_maps::pve_rs_sdn_route_maps::PerlRouteMapConfig;

    /// Return the FRR configuration for the passed FrrConfig and the FabricsConfig as an array of
    /// strings, where each line represents a line in the FRR configuration.
    #[export]
    pub fn get_frr_raw_config(
        mut frr_config: FrrConfig,
        #[try_from_ref] prefix_list_config: &PerlPrefixListConfig,
        #[try_from_ref] route_map_config: &PerlRouteMapConfig,
        #[try_from_ref] fabric_config: &PerlFabricConfig,
        node_id: NodeId,
    ) -> Result<Vec<String>, Error> {
        let prefix_list_config = prefix_list_config.prefix_lists.lock().unwrap();
        proxmox_ve_config::sdn::prefix_list::frr::build_frr_prefix_lists(
            prefix_list_config.values().cloned(),
            &mut frr_config,
        )?;

        let route_map_config = route_map_config.route_maps.lock().unwrap();
        proxmox_ve_config::sdn::route_map::frr::build_frr_route_maps(
            route_map_config.values().cloned(),
            &mut frr_config,
        )?;

        let fabric_config = fabric_config
            .fabric_config
            .lock()
            .unwrap()
            .clone()
            .into_valid()?;
        proxmox_ve_config::sdn::fabric::frr::build_fabric(node_id, fabric_config, &mut frr_config)?;

        to_raw_config(&frr_config)
    }
}
