use std::collections::{BTreeMap, HashMap, HashSet};

use proxmox_section_config::typed::SectionConfigData;
use serde::{Deserialize, Serialize};

use proxmox_frr::de::{self};
use proxmox_ve_config::{
    common::valid::Valid,
    sdn::fabric::{
        FabricConfig,
        section_config::{Section, fabric::FabricId, node::Node as ConfigNode},
    },
};

/// Protocol
#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Openfabric
    Openfabric,
    /// OSPF
    Ospf,
}

/// The status of a fabric.
#[derive(Debug, Serialize)]
pub enum FabricStatus {
    /// The fabric exists and has a route
    #[serde(rename = "ok")]
    Ok,
    /// The fabric does not exist or doesn't distribute any routes
    #[serde(rename = "not ok")]
    NotOk,
}

/// Status of a fabric.
///
/// Models the current state of the fabric, the status is determined by checking if any
/// routes are propagated. This will be inserted into the PVE resources.
#[derive(Debug, Serialize)]
pub struct Status {
    #[serde(rename = "type")]
    ty: String,
    status: FabricStatus,
    protocol: Protocol,
    network: FabricId,
    network_type: String,
}

/// Parsed routes for all protocols
///
/// These are the routes parsed from the json output of:
/// `vtysh -c 'show ip route <protocol> json'`.
#[derive(Debug, Serialize)]
pub struct RoutesParsed {
    /// All openfabric routes in FRR
    pub openfabric: de::Routes,
    /// All ospf routes in FRR
    pub ospf: de::Routes,
}

/// Config used to parse the fabric part of the running-config
#[derive(Deserialize)]
pub struct RunningConfig {
    pub fabrics: FabricsRunningConfig,
}

/// Map of ids for all the fabrics in the running-config
#[derive(Deserialize)]
pub struct FabricsRunningConfig {
    pub ids: BTreeMap<String, Section>,
}

/// Get the status for each fabric using the parsed routes from frr
///
/// Using the parsed routes we get from frr, filter and map them to a HashMap mapping every
/// fabric to a status struct containing basic info about the fabric and the status (if it
/// propagates a route).
pub fn get_status(
    config: Valid<FabricConfig>,
    routes: RoutesParsed,
) -> Result<HashMap<FabricId, Status>, anyhow::Error> {
    let hostname = proxmox_sys::nodename();

    let mut stats: HashMap<FabricId, Status> = HashMap::new();

    for (nodeid, node) in config.all_nodes() {
        if nodeid.as_str() != hostname {
            continue;
        }
        let fabric_id = node.id().fabric_id();

        let (current_protocol, all_routes) = match &node {
            ConfigNode::Openfabric(_) => (Protocol::Openfabric, &routes.openfabric.0),
            ConfigNode::Ospf(_) => (Protocol::Ospf, &routes.ospf.0),
        };

        // get interfaces
        let interface_names: HashSet<&str> = match node {
            ConfigNode::Openfabric(n) => n
                .properties()
                .interfaces()
                .map(|i| i.name().as_str())
                .collect(),
            ConfigNode::Ospf(n) => n
                .properties()
                .interfaces()
                .map(|i| i.name().as_str())
                .collect(),
        };

        // determine status by checking if any routes exist for our interfaces
        let has_routes = all_routes.values().any(|v| {
            v.iter().any(|route| {
                route.nexthops.iter().any(|nexthop| {
                    if let Some(iface_name) = &nexthop.interface_name {
                        interface_names.contains(iface_name.as_str())
                    } else {
                        false
                    }
                })
            })
        });

        let fabric = Status {
            ty: "network".to_owned(),
            status: if has_routes {
                FabricStatus::Ok
            } else {
                FabricStatus::NotOk
            },
            protocol: current_protocol,
            network: fabric_id.clone(),
            network_type: "fabric".to_string(),
        };
        stats.insert(fabric_id.clone(), fabric);
    }

    Ok(stats)
}
