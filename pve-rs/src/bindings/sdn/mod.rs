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
    use proxmox_frr::ser::{FrrConfig, IpRoute, serializer::to_raw_config};
    use proxmox_schema::property_string::PropertyString;

    use proxmox_ve_config::common::valid::Validatable;
    use proxmox_ve_config::sdn::fabric::section_config::node::NodeId;
    use proxmox_ve_config::sdn::static_route::{StaticRoute, ZoneRoutesConfig};

    use crate::bindings::pve_rs_sdn_fabrics::PerlFabricConfig;
    use crate::bindings::sdn::prefix_lists::pve_rs_sdn_prefix_lists::PerlPrefixListConfig;
    use crate::bindings::sdn::route_maps::pve_rs_sdn_route_maps::PerlRouteMapConfig;

    /// Validate a route property string before storing it in zones.cfg.
    #[export]
    pub fn validate_static_route(route: &str) -> Result<(), Error> {
        route.parse::<PropertyString<StaticRoute>>()?.validate()
    }

    /// Return static routes for simple zones participating on this node.
    ///
    /// Invalid routes are skipped with a warning.
    #[export]
    pub fn get_zone_routes(zones: ZoneRoutesConfig, node_id: NodeId) -> Vec<IpRoute> {
        zones.routes_for_node(node_id.as_ref())
    }

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
