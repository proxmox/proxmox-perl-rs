use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use proxmox_network_types::ip_address::Cidr;
use proxmox_network_types::mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use proxmox_frr::de::{self};
use proxmox_ve_config::sdn::fabric::section_config::protocol::ospf::{
    OspfNodeProperties, OspfProperties,
};
use proxmox_ve_config::{
    common::valid::Valid,
    sdn::fabric::{
        Entry, FabricConfig,
        section_config::{Section, fabric::FabricId, node::Node as ConfigNode, node::NodeId},
    },
};

// The status of a fabric interface
//
// Either up or down.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceState {
    Up,
    Down,
}

mod ospf {
    use proxmox_frr::de;
    use serde::Serialize;

    /// The status of a neighbor.
    ///
    /// Contains the neighbor name and the neighbor status.
    #[derive(Debug, Serialize)]
    pub struct NeighborStatus {
        pub neighbor: String,
        pub status: String,
        pub uptime: String,
    }

    /// The status of a fabric interface
    ///
    /// Contains the interface name, the interface state (so if the interface is up/down) and the type
    /// of the interface (e.g. point-to-point, broadcast, etc.).
    #[derive(Debug, Serialize)]
    pub struct InterfaceStatus {
        pub name: String,
        pub state: super::InterfaceState,
        #[serde(rename = "type")]
        pub ty: de::ospf::NetworkType,
    }
}
mod openfabric {
    use proxmox_frr::de;
    use serde::Serialize;

    /// The status of a neighbor.
    ///
    /// Contains the neighbor name and the neighbor status.
    #[derive(Debug, Serialize)]
    pub struct NeighborStatus {
        pub neighbor: String,
        pub status: de::openfabric::AdjacencyState,
        pub uptime: String,
    }

    /// The status of a fabric interface
    ///
    /// Contains the interface name, the interface state (so if the interface is up/down) and the type
    /// of the interface (e.g. point-to-point, broadcast, etc.).
    #[derive(Debug, Serialize)]
    pub struct InterfaceStatus {
        pub name: String,
        pub state: de::openfabric::CircuitState,
        #[serde(rename = "type")]
        pub ty: de::openfabric::NetworkType,
    }
}

/// Common NeighborStatus that contains either OSPF or Openfabric neighbors
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum NeighborStatus {
    Openfabric(Vec<openfabric::NeighborStatus>),
    Ospf(Vec<ospf::NeighborStatus>),
}

impl From<Vec<openfabric::NeighborStatus>> for NeighborStatus {
    fn from(value: Vec<openfabric::NeighborStatus>) -> Self {
        NeighborStatus::Openfabric(value)
    }
}
impl From<Vec<ospf::NeighborStatus>> for NeighborStatus {
    fn from(value: Vec<ospf::NeighborStatus>) -> Self {
        NeighborStatus::Ospf(value)
    }
}

/// Common InterfaceStatus that contains either OSPF or Openfabric interfaces
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum InterfaceStatus {
    Openfabric(Vec<openfabric::InterfaceStatus>),
    Ospf(Vec<ospf::InterfaceStatus>),
}

impl From<Vec<openfabric::InterfaceStatus>> for InterfaceStatus {
    fn from(value: Vec<openfabric::InterfaceStatus>) -> Self {
        InterfaceStatus::Openfabric(value)
    }
}
impl From<Vec<ospf::InterfaceStatus>> for InterfaceStatus {
    fn from(value: Vec<ospf::InterfaceStatus>) -> Self {
        InterfaceStatus::Ospf(value)
    }
}

/// The status of a route.
///
/// Contains the route and all the nexthops. This is common across all protocols.
#[derive(Debug, Serialize)]
pub struct RouteStatus {
    route: String,
    via: Vec<String>,
}

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

/// Converts the parsed `show ip route x` frr route output into a list of common [`RouteStatus`]
/// structs.
///
/// We always execute `show ip route <protocol>` so we only get routes generated from a specific
/// protocol. The problem is that we can't definitely link a specific route to a specific fabric.
/// To solve this, we retrieve all the interfaces configured on a fabric on this node and check
/// which route contains a output interface of the fabric.
pub fn get_routes(
    fabric_id: FabricId,
    config: Valid<FabricConfig>,
    routes: de::Routes,
) -> Result<Vec<RouteStatus>, anyhow::Error> {
    let hostname = proxmox_sys::nodename();

    let mut stats: Vec<RouteStatus> = Vec::new();

    if let Ok(node) = config
        .get_fabric(&fabric_id)?
        .get_node(&NodeId::from_string(hostname.to_string())?)
    {
        let mut interface_names: HashSet<&str> = match node {
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

        let dummy_interface = format!("dummy_{}", fabric_id.as_str());
        interface_names.insert(&dummy_interface);

        for (route_key, route_list) in routes.0 {
            let mut route_belongs_to_fabric = false;
            for route in &route_list {
                if !route.installed.unwrap_or_default() {
                    continue;
                }

                for nexthop in &route.nexthops {
                    if let Some(iface_name) = &nexthop.interface_name {
                        if interface_names.contains(iface_name.as_str()) {
                            route_belongs_to_fabric = true;
                            break;
                        }
                    }
                }
                if route_belongs_to_fabric {
                    break;
                }
            }

            if route_belongs_to_fabric {
                let mut via_list = Vec::new();
                for route in route_list {
                    for nexthop in &route.nexthops {
                        let via = if let Some(ip) = nexthop.ip {
                            ip.to_string()
                        } else if let Some(iface_name) = &nexthop.interface_name {
                            iface_name.clone()
                        } else if let Some(true) = &nexthop.unreachable {
                            "unreachable".to_string()
                        } else {
                            continue;
                        };
                        via_list.push(via);
                    }
                }

                stats.push(RouteStatus {
                    route: route_key.to_string(),
                    via: via_list,
                });
            }
        }
    }
    Ok(stats)
}

/// Convert the parsed openfabric neighbor neighbor information into a list of
/// [`openfabric::NeighborStatus`].
///
/// OpenFabric uses the name of the fabric as an "area", so simply match that to the fabric_id.
pub fn get_neighbors_openfabric(
    fabric_id: FabricId,
    neighbors: de::openfabric::Neighbors,
) -> Result<Vec<openfabric::NeighborStatus>, anyhow::Error> {
    let mut stats: Vec<openfabric::NeighborStatus> = Vec::new();

    for area in &neighbors.areas {
        if area.area != fabric_id.as_str() {
            continue;
        }
        for circuit in &area.circuits {
            let (Some(adj), Some(interface)) = (&circuit.adj, &circuit.interface) else {
                continue;
            };
            let Some(state) = interface.state else {
                continue;
            };
            stats.push(openfabric::NeighborStatus {
                neighbor: adj.clone(),
                status: state,
                uptime: interface.last_ago.clone(),
            });
        }
    }

    Ok(stats)
}

/// Convert the parsed ospf neighbor neighbor information into a list of [`ospf::NeighborStatus`].
///
/// Ospf does not use the name of the fabric at all, so we again need to retrieve the interfaces of
/// the fabric on this specific node and then match the neighbors to the fabric using the
/// interfaces.
pub fn get_neighbors_ospf(
    fabric_id: FabricId,
    fabric: &Entry<OspfProperties, OspfNodeProperties>,
    neighbors: de::ospf::Neighbors,
) -> Result<Vec<ospf::NeighborStatus>, anyhow::Error> {
    let hostname = proxmox_sys::nodename();

    let mut stats: Vec<ospf::NeighborStatus> = Vec::new();

    if let Ok(node) = fabric.node_section(&NodeId::from_string(hostname.to_string())?) {
        let mut interface_names: HashSet<&str> = node
            .properties()
            .interfaces()
            .map(|i| i.name().as_str())
            .collect();

        let dummy_interface = format!("dummy_{}", fabric_id.as_str());
        interface_names.insert(&dummy_interface);

        for neighbor_list in neighbors.neighbors.values() {
            // Find first neighbor whose interface is in our fabric
            if let Some(neighbor) = neighbor_list.iter().find(|n| {
                n.interface_name
                    .split_once(':')
                    .is_some_and(|(iface, _)| interface_names.contains(iface))
            }) {
                stats.push(ospf::NeighborStatus {
                    neighbor: neighbor.interface_address.clone(),
                    status: neighbor.neighbor_state.clone(),
                    uptime: neighbor.up_time.clone(),
                });
            }
        }
    }

    Ok(stats)
}

/// Conver the `show openfabric interface` output into a list of [`openfabric::InterfaceStatus`].
///
/// Openfabric uses the name of the fabric as an "area", so simply match that to the fabric_id.
pub fn get_interfaces_openfabric(
    fabric_id: FabricId,
    interfaces: de::openfabric::Interfaces,
) -> Result<Vec<openfabric::InterfaceStatus>, anyhow::Error> {
    let mut stats: Vec<openfabric::InterfaceStatus> = Vec::new();

    for area in &interfaces.areas {
        if area.area == fabric_id.as_str() {
            for circuit in &area.circuits {
                stats.push(openfabric::InterfaceStatus {
                    name: circuit.interface.name.clone(),
                    state: circuit.interface.state,
                    ty: circuit.interface.ty,
                });
            }
        }
    }

    Ok(stats)
}

/// Convert the `show ip ospf interface` output into a list of [`ospf::InterfaceStatus`].
///
/// Ospf does not use the name of the fabric at all, so we again need to retrieve the interfaces of
/// the fabric on this specific node and then match the interfaces to the fabric using the
/// interface names.
pub fn get_interfaces_ospf(
    fabric_id: FabricId,
    fabric: &Entry<OspfProperties, OspfNodeProperties>,
    neighbors: de::ospf::Interfaces,
) -> Result<Vec<ospf::InterfaceStatus>, anyhow::Error> {
    let hostname = proxmox_sys::nodename();

    let mut stats: Vec<ospf::InterfaceStatus> = Vec::new();

    if let Ok(node) = fabric.node_section(&NodeId::from_string(hostname.to_string())?) {
        let mut fabric_interface_names: HashSet<&str> = node
            .properties()
            .interfaces()
            .map(|i| i.name().as_str())
            .collect();

        let dummy_interface = format!("dummy_{}", fabric_id.as_str());
        fabric_interface_names.insert(&dummy_interface);

        for (interface_name, interface) in &neighbors.interfaces {
            if fabric_interface_names.contains(interface_name.as_str()) {
                stats.push(ospf::InterfaceStatus {
                    name: interface_name.to_string(),
                    state: if interface.if_up {
                        InterfaceState::Up
                    } else {
                        InterfaceState::Down
                    },
                    ty: interface.network_type,
                });
            }
        }
    }

    Ok(stats)
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
/// Common for nexthops, they can be either a interface name or a ip addr
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum IpAddrOrInterfaceName {
    /// IpAddr
    IpAddr(IpAddr),
    /// Interface Name
    InterfaceName(String),
}

/// One L3VPN route
#[derive(Debug, Serialize)]
pub struct L3VPNRoute {
    ip: Cidr,
    protocol: String,
    metric: i32,
    nexthops: Vec<IpAddrOrInterfaceName>,
}

/// All L3VPN routes of a zone
#[derive(Debug, Serialize)]
pub struct L3VPNRoutes(Vec<L3VPNRoute>);

/// Convert parsed routes from frr into l3vpn routes, this means we need to match against the vrf
/// name of the zone.
pub fn get_l3vpn_routes(vrf: &str, routes: de::Routes) -> Result<L3VPNRoutes, anyhow::Error> {
    let mut result = Vec::new();
    for (prefix, routes) in routes.0 {
        for route in routes {
            if route.vrf_name == vrf && route.installed.unwrap_or_default() {
                result.push(L3VPNRoute {
                    ip: prefix,
                    metric: route.metric,
                    protocol: route.protocol,
                    nexthops: route
                        .nexthops
                        .into_iter()
                        .filter_map(|nh| {
                            if nh.duplicate.unwrap_or_default() {
                                return None;
                            }

                            nh.ip.map(IpAddrOrInterfaceName::IpAddr).or_else(|| {
                                nh.interface_name.map(IpAddrOrInterfaceName::InterfaceName)
                            })
                        })
                        .collect(),
                });
            }
        }
    }
    Ok(L3VPNRoutes(result))
}

/// One L2VPN route
#[derive(Debug, Serialize)]
pub struct L2VPNRoute {
    mac: MacAddress,
    ip: IpAddr,
    nexthop: IpAddr,
}

/// All L2VPN routes of a specific vnet
#[derive(Debug, Serialize)]
pub struct L2VPNRoutes(Vec<L2VPNRoute>);

/// Convert the parsed frr evpn struct into an array of structured L2VPN routes
pub fn get_l2vpn_routes(routes: de::evpn::Routes) -> Result<L2VPNRoutes, anyhow::Error> {
    let mut result = Vec::new();
    for route in routes.0.values() {
        if let de::evpn::Entry::Route(r) = route {
            r.paths.iter().flatten().for_each(|path| {
                if path.bestpath.unwrap_or_default() {
                    if let (Some(mac), Some(ip), Some(nh)) =
                        (path.mac, path.ip, path.nexthops.first())
                    {
                        result.push(L2VPNRoute {
                            mac,
                            ip,
                            nexthop: nh.ip,
                        });
                    }
                }
            });
        }
    }

    Ok(L2VPNRoutes(result))
}
