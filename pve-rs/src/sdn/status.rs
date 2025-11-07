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
#[derive(Debug, Serialize, PartialEq, Eq)]
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
    #[derive(Debug, Serialize, PartialEq, Eq)]
    pub struct NeighborStatus {
        pub neighbor: String,
        pub status: String,
        pub uptime: String,
    }

    /// The status of a fabric interface
    ///
    /// Contains the interface name, the interface state (so if the interface is up/down) and the type
    /// of the interface (e.g. point-to-point, broadcast, etc.).
    #[derive(Debug, Serialize, PartialEq, Eq)]
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
    #[derive(Debug, Serialize, PartialEq, Eq)]
    pub struct NeighborStatus {
        pub neighbor: String,
        pub status: de::openfabric::AdjacencyState,
        pub uptime: String,
    }

    /// The status of a fabric interface
    ///
    /// Contains the interface name, the interface state (so if the interface is up/down) and the type
    /// of the interface (e.g. point-to-point, broadcast, etc.).
    #[derive(Debug, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Serialize, PartialEq, Eq)]
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
    hostname: &str,
) -> Result<Vec<RouteStatus>, anyhow::Error> {
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
    hostname: &str,
) -> Result<Vec<ospf::NeighborStatus>, anyhow::Error> {
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
    hostname: &str,
) -> Result<Vec<ospf::InterfaceStatus>, anyhow::Error> {
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
    hostname: &str,
) -> Result<HashMap<FabricId, Status>, anyhow::Error> {
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
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum IpAddrOrInterfaceName {
    /// IpAddr
    IpAddr(IpAddr),
    /// Interface Name
    InterfaceName(String),
}

/// One L3VPN route
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct L3VPNRoute {
    ip: Cidr,
    protocol: String,
    metric: i32,
    nexthops: Vec<IpAddrOrInterfaceName>,
}

/// All L3VPN routes of a zone
#[derive(Debug, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct L2VPNRoute {
    mac: MacAddress,
    ip: IpAddr,
    nexthop: IpAddr,
}

/// All L2VPN routes of a specific vnet
#[derive(Debug, Serialize, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use proxmox_section_config::typed::SectionConfigData;
    use proxmox_ve_config::sdn::fabric::FabricConfig;

    fn sample_two_fabric_config() -> Valid<FabricConfig> {
        let raw_config = r#"{
              "fabrics": {
                "ids": {
                  "test": {
                    "area": "0",
                    "type": "ospf_fabric",
                    "id": "test",
                    "ip_prefix": "172.16.6.0/24"
                  },
                  "test_node2": {
                    "ip": "172.16.6.2",
                    "type": "ospf_node",
                    "id": "test_node2",
                    "interfaces": [
                      "name=ens19",
                      "name=ens20"
                    ]
                  },
                  "test_node1": {
                    "interfaces": [
                      "name=ens19",
                      "name=ens20"
                    ],
                    "id": "test_node1",
                    "ip": "172.16.6.1",
                    "type": "ospf_node"
                  },
                  "test_node3": {
                    "ip": "172.16.6.3",
                    "type": "ospf_node",
                    "interfaces": [
                      "name=ens19",
                      "name=ens20"
                    ],
                    "id": "test_node3"
                  },
                  "test1": {
                    "area": "1",
                    "type": "ospf_fabric",
                    "id": "test1",
                    "ip_prefix": "172.16.7.0/24"
                  },
                  "test1_node2": {
                    "ip": "172.16.7.2",
                    "type": "ospf_node",
                    "id": "test1_node2",
                    "interfaces": [
                      "name=ens21",
                      "name=ens22"
                    ]
                  },
                  "test1_node1": {
                    "interfaces": [
                      "name=ens21",
                      "name=ens22"
                    ],
                    "id": "test1_node1",
                    "ip": "172.16.7.1",
                    "type": "ospf_node"
                  },
                  "test1_node3": {
                    "ip": "172.16.7.3",
                    "type": "ospf_node",
                    "interfaces": [
                      "name=ens21",
                      "name=ens22"
                    ],
                    "id": "test1_node3"
                  }
                }
              }
            }
            "#;

        let running_config: RunningConfig =
            serde_json::from_str(raw_config).expect("error parsing running-config");
        let section_config = SectionConfigData::from_iter(running_config.fabrics.ids);
        FabricConfig::from_section_config(section_config)
            .expect("error converting section config to fabricconfig")
    }

    fn sample_one_fabric_config() -> Valid<FabricConfig> {
        let raw_config = r#"{
              "fabrics": {
                "ids": {
                  "test": {
                    "area": "0",
                    "type": "ospf_fabric",
                    "id": "test",
                    "ip_prefix": "172.16.6.0/24"
                  },
                  "test_node2": {
                    "ip": "172.16.6.2",
                    "type": "ospf_node",
                    "id": "test_node2",
                    "interfaces": [
                      "name=ens19",
                      "name=ens20"
                    ]
                  },
                  "test_node1": {
                    "interfaces": [
                      "name=ens19",
                      "name=ens20"
                    ],
                    "id": "test_node1",
                    "ip": "172.16.6.1",
                    "type": "ospf_node"
                  },
                  "test_node3": {
                    "ip": "172.16.6.3",
                    "type": "ospf_node",
                    "interfaces": [
                      "name=ens19",
                      "name=ens20"
                    ],
                    "id": "test_node3"
                  }
                }
              }
            }
            "#;
        let running_config: RunningConfig =
            serde_json::from_str(raw_config).expect("error parsing running-config");
        let section_config = SectionConfigData::from_iter(running_config.fabrics.ids);
        FabricConfig::from_section_config(section_config)
            .expect("error converting section config to fabricconfig")
    }

    mod openfabric {
        use super::super::*;

        #[test]
        fn neighbors() {
            let json_output = r#"
                {
                  "areas":[
                    {
                      "area":"test",
                      "circuits":[
                        {
                          "circuit":0
                        },
                        {
                          "circuit":0,
                          "adj":"node2",
                          "interface":{
                            "name":"ens19",
                            "state":"Up",
                            "adj-flaps":1,
                            "last-ago":"11m5s",
                            "circuit-type":"L2",
                            "speaks":"IPv4",
                            "snpa":"2020.2020.2020",
                            "area-address":{
                              "isonet":"49.0001"
                            },
                            "ipv4-address":{
                              "ipv4":"172.16.6.2"
                            },
                            "adj-sid":{}
                          },
                          "level":2,
                          "expires-in":"29s"
                        }
                      ]
                    }
                  ]
                }
                "#;

            let neighbors: de::openfabric::Neighbors = if json_output.is_empty() {
                de::openfabric::Neighbors::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let output = get_neighbors_openfabric(
                FabricId::from_string("test".to_owned()).expect("error parsing fabricId"),
                neighbors,
            )
            .expect("error converting vtysh output");

            let reference = vec![openfabric::NeighborStatus {
                neighbor: "node2".to_owned(),
                status: de::openfabric::AdjacencyState::Up,
                uptime: "11m5s".to_owned(),
            }];
            assert_eq!(reference, output);
        }

        #[test]
        fn multiple_neighbors() {
            let json_output = r#"
            {
              "areas":[
                {
                  "area":"test",
                  "circuits":[
                    {
                      "circuit":0
                    },
                    {
                      "circuit":0,
                      "adj":"node1",
                      "interface":{
                        "name":"ens19",
                        "state":"Up",
                        "adj-flaps":1,
                        "last-ago":"25m26s",
                        "circuit-type":"L2",
                        "speaks":"IPv4",
                        "snpa":"2020.2020.2020",
                        "area-address":{
                          "isonet":"49.0001"
                        },
                        "ipv4-address":{
                          "ipv4":"172.16.6.1"
                        },
                        "adj-sid":{}
                      },
                      "level":2,
                      "expires-in":"28s"
                    },
                    {
                      "circuit":0,
                      "adj":"node3",
                      "interface":{
                        "name":"ens20",
                        "state":"Up",
                        "adj-flaps":1,
                        "last-ago":"25m21s",
                        "circuit-type":"L2",
                        "speaks":"IPv4",
                        "snpa":"2020.2020.2020",
                        "area-address":{
                          "isonet":"49.0001"
                        },
                        "ipv4-address":{
                          "ipv4":"172.16.6.3"
                        },
                        "adj-sid":{}
                      },
                      "level":2,
                      "expires-in":"29s"
                    }
                  ]
                }
              ]
            }
            "#;

            let neighbors: de::openfabric::Neighbors = if json_output.is_empty() {
                de::openfabric::Neighbors::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let output = get_neighbors_openfabric(
                FabricId::from_string("test".to_owned()).expect("error parsing fabricId"),
                neighbors,
            )
            .expect("error converting vtysh output");

            let reference = vec![
                openfabric::NeighborStatus {
                    neighbor: "node1".to_owned(),
                    status: de::openfabric::AdjacencyState::Up,
                    uptime: "25m26s".to_owned(),
                },
                openfabric::NeighborStatus {
                    neighbor: "node3".to_owned(),
                    status: de::openfabric::AdjacencyState::Up,
                    uptime: "25m21s".to_owned(),
                },
            ];
            assert_eq!(reference, output);
        }

        #[test]
        fn multiple_neighbors_multiple_areas() {
            let json_output = r#"
            {
              "areas":[
                {
                  "area":"test",
                  "circuits":[
                    {
                      "circuit":0
                    },
                    {
                      "circuit":0,
                      "adj":"node1",
                      "interface":{
                        "name":"ens19",
                        "state":"Up",
                        "adj-flaps":1,
                        "last-ago":"33m39s",
                        "circuit-type":"L2",
                        "speaks":"IPv4",
                        "snpa":"2020.2020.2020",
                        "area-address":{
                          "isonet":"49.0001"
                        },
                        "ipv4-address":{
                          "ipv4":"172.16.6.1"
                        },
                        "adj-sid":{}
                      },
                      "level":2,
                      "expires-in":"29s"
                    },
                    {
                      "circuit":0,
                      "adj":"node3",
                      "interface":{
                        "name":"ens20",
                        "state":"Up",
                        "adj-flaps":1,
                        "last-ago":"33m34s",
                        "circuit-type":"L2",
                        "speaks":"IPv4",
                        "snpa":"2020.2020.2020",
                        "area-address":{
                          "isonet":"49.0001"
                        },
                        "ipv4-address":{
                          "ipv4":"172.16.6.3"
                        },
                        "adj-sid":{}
                      },
                      "level":2,
                      "expires-in":"29s"
                    }
                  ]
                },
                {
                  "area":"test1",
                  "circuits":[
                    {
                      "circuit":0
                    },
                    {
                      "circuit":0,
                      "adj":"node1",
                      "interface":{
                        "name":"ens21",
                        "state":"Up",
                        "adj-flaps":1,
                        "last-ago":"56s",
                        "circuit-type":"L2",
                        "speaks":"IPv4",
                        "snpa":"2020.2020.2020",
                        "area-address":{
                          "isonet":"49.0001"
                        },
                        "ipv4-address":{
                          "ipv4":"172.16.7.1"
                        },
                        "adj-sid":{}
                      },
                      "level":2,
                      "expires-in":"28s"
                    },
                    {
                      "circuit":0,
                      "adj":"node3",
                      "interface":{
                        "name":"ens22",
                        "state":"Up",
                        "adj-flaps":1,
                        "last-ago":"1m2s",
                        "circuit-type":"L2",
                        "speaks":"IPv4",
                        "snpa":"2020.2020.2020",
                        "area-address":{
                          "isonet":"49.0001"
                        },
                        "ipv4-address":{
                          "ipv4":"172.16.7.3"
                        },
                        "adj-sid":{}
                      },
                      "level":2,
                      "expires-in":"28s"
                    }
                  ]
                }
              ]
            }
            "#;

            let neighbors: de::openfabric::Neighbors = if json_output.is_empty() {
                de::openfabric::Neighbors::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let output_node1 = get_neighbors_openfabric(
                FabricId::from_string("test".to_owned()).expect("error parsing fabricId"),
                neighbors.clone(),
            )
            .expect("error converting vtysh output");

            let reference_node1 = vec![
                openfabric::NeighborStatus {
                    neighbor: "node1".to_owned(),
                    status: de::openfabric::AdjacencyState::Up,
                    uptime: "33m39s".to_owned(),
                },
                openfabric::NeighborStatus {
                    neighbor: "node3".to_owned(),
                    status: de::openfabric::AdjacencyState::Up,
                    uptime: "33m34s".to_owned(),
                },
            ];
            assert_eq!(reference_node1, output_node1);

            let output_node2 = get_neighbors_openfabric(
                FabricId::from_string("test1".to_owned()).expect("error parsing fabricId"),
                neighbors,
            )
            .expect("error converting vtysh output");

            let reference_node2 = vec![
                openfabric::NeighborStatus {
                    neighbor: "node1".to_owned(),
                    status: de::openfabric::AdjacencyState::Up,
                    uptime: "56s".to_owned(),
                },
                openfabric::NeighborStatus {
                    neighbor: "node3".to_owned(),
                    status: de::openfabric::AdjacencyState::Up,
                    uptime: "1m2s".to_owned(),
                },
            ];
            assert_eq!(reference_node2, output_node2);
        }

        #[test]
        fn interfaces() {
            let json_output = r#"
            {
              "areas":[
                {
                  "area":"test1",
                  "circuits":[
                    {
                      "circuit":0,
                      "interface":{
                        "name":"dummy_test1",
                        "circuit-id":"0x0",
                        "state":"Up",
                        "type":"loopback",
                        "level":"L2"
                      }
                    },
                    {
                      "circuit":0,
                      "interface":{
                        "name":"ens21",
                        "circuit-id":"0x0",
                        "state":"Up",
                        "type":"p2p",
                        "level":"L2"
                      }
                    },
                    {
                      "circuit":0,
                      "interface":{
                        "name":"ens22",
                        "circuit-id":"0x0",
                        "state":"Up",
                        "type":"p2p",
                        "level":"L2"
                      }
                    }
                  ]
                }
              ]
            }
            "#;

            let interfaces: de::openfabric::Interfaces = if json_output.is_empty() {
                de::openfabric::Interfaces::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let output = get_interfaces_openfabric(
                FabricId::from_string("test1".to_owned()).expect("error parsing fabricId"),
                interfaces,
            )
            .expect("error converting vtysh output");

            let reference = vec![
                openfabric::InterfaceStatus {
                    name: "dummy_test1".to_owned(),
                    state: de::openfabric::CircuitState::Up,
                    ty: de::openfabric::NetworkType::Loopback,
                },
                openfabric::InterfaceStatus {
                    name: "ens21".to_owned(),
                    state: de::openfabric::CircuitState::Up,
                    ty: de::openfabric::NetworkType::PointToPoint,
                },
                openfabric::InterfaceStatus {
                    name: "ens22".to_owned(),
                    state: de::openfabric::CircuitState::Up,
                    ty: de::openfabric::NetworkType::PointToPoint,
                },
            ];
            assert_eq!(reference, output);
        }

        #[test]
        fn interfaces_multiple_areas() {
            let json_output = r#"
            {
              "areas":[
                {
                  "area":"test",
                  "circuits":[
                    {
                      "circuit":0,
                      "interface":{
                        "name":"dummy_test",
                        "circuit-id":"0x0",
                        "state":"Up",
                        "type":"loopback",
                        "level":"L2"
                      }
                    },
                    {
                      "circuit":0,
                      "interface":{
                        "name":"ens19",
                        "circuit-id":"0x0",
                        "state":"Up",
                        "type":"p2p",
                        "level":"L2"
                      }
                    },
                    {
                      "circuit":0,
                      "interface":{
                        "name":"ens20",
                        "circuit-id":"0x0",
                        "state":"Up",
                        "type":"p2p",
                        "level":"L2"
                      }
                    }
                  ]
                },
                {
                  "area":"test1",
                  "circuits":[
                    {
                      "circuit":0,
                      "interface":{
                        "name":"dummy_test1",
                        "circuit-id":"0x0",
                        "state":"Up",
                        "type":"loopback",
                        "level":"L2"
                      }
                    },
                    {
                      "circuit":0,
                      "interface":{
                        "name":"ens21",
                        "circuit-id":"0x0",
                        "state":"Up",
                        "type":"p2p",
                        "level":"L2"
                      }
                    },
                    {
                      "circuit":0,
                      "interface":{
                        "name":"ens22",
                        "circuit-id":"0x0",
                        "state":"Up",
                        "type":"p2p",
                        "level":"L2"
                      }
                    }
                  ]
                }
              ]
            }
            "#;

            let interfaces: de::openfabric::Interfaces = if json_output.is_empty() {
                de::openfabric::Interfaces::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let output_fabric1 = get_interfaces_openfabric(
                FabricId::from_string("test".to_owned()).expect("error parsing fabricId"),
                interfaces.clone(),
            )
            .expect("error converting vtysh output");

            let reference_fabric1 = vec![
                openfabric::InterfaceStatus {
                    name: "dummy_test".to_owned(),
                    state: de::openfabric::CircuitState::Up,
                    ty: de::openfabric::NetworkType::Loopback,
                },
                openfabric::InterfaceStatus {
                    name: "ens19".to_owned(),
                    state: de::openfabric::CircuitState::Up,
                    ty: de::openfabric::NetworkType::PointToPoint,
                },
                openfabric::InterfaceStatus {
                    name: "ens20".to_owned(),
                    state: de::openfabric::CircuitState::Up,
                    ty: de::openfabric::NetworkType::PointToPoint,
                },
            ];
            assert_eq!(reference_fabric1, output_fabric1);

            let output_fabric2 = get_interfaces_openfabric(
                FabricId::from_string("test1".to_owned()).expect("error parsing fabricId"),
                interfaces,
            )
            .expect("error converting vtysh output");

            let reference_fabric2 = vec![
                openfabric::InterfaceStatus {
                    name: "dummy_test1".to_owned(),
                    state: de::openfabric::CircuitState::Up,
                    ty: de::openfabric::NetworkType::Loopback,
                },
                openfabric::InterfaceStatus {
                    name: "ens21".to_owned(),
                    state: de::openfabric::CircuitState::Up,
                    ty: de::openfabric::NetworkType::PointToPoint,
                },
                openfabric::InterfaceStatus {
                    name: "ens22".to_owned(),
                    state: de::openfabric::CircuitState::Up,
                    ty: de::openfabric::NetworkType::PointToPoint,
                },
            ];
            assert_eq!(reference_fabric2, output_fabric2);
        }
    }

    mod ospf {
        use core::panic;

        use proxmox_ve_config::sdn::fabric::FabricEntry;

        use crate::sdn::status::tests::{sample_one_fabric_config, sample_two_fabric_config};

        use super::super::*;

        #[test]
        fn neighbors() {
            let json_output = r#"
            {
              "neighbors":{
                "172.16.6.1":[
                  {
                    "nbrState":"Full\/-",
                    "nbrPriority":1,
                    "converged":"Full",
                    "role":"DROther",
                    "upTimeInMsec":64606,
                    "routerDeadIntervalTimerDueMsec":37331,
                    "upTime":"1m04s",
                    "deadTime":"37.331s",
                    "ifaceAddress":"172.16.6.1",
                    "ifaceName":"ens19:172.16.6.2",
                    "linkStateRetransmissionListCounter":0,
                    "linkStateRequestListCounter":0,
                    "databaseSummaryListCounter":0
                  }
                ],
                "172.16.6.3":[
                  {
                    "nbrState":"Full\/-",
                    "nbrPriority":1,
                    "converged":"Full",
                    "role":"DROther",
                    "upTimeInMsec":67614,
                    "routerDeadIntervalTimerDueMsec":32384,
                    "upTime":"1m07s",
                    "deadTime":"32.384s",
                    "ifaceAddress":"172.16.6.3",
                    "ifaceName":"ens20:172.16.6.2",
                    "linkStateRetransmissionListCounter":0,
                    "linkStateRequestListCounter":0,
                    "databaseSummaryListCounter":0
                  }
                ]
              }
            }
            "#;

            let neighbors: de::ospf::Neighbors = if json_output.is_empty() {
                de::ospf::Neighbors::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let fabric_config = sample_one_fabric_config();

            let fabric_id =
                FabricId::from_string("test".to_owned()).expect("error parsing fabricId");
            let fabric = fabric_config
                .get_fabric(&fabric_id)
                .expect("can't find fabric in config");

            let FabricEntry::Ospf(fabric) = fabric else {
                panic!("not a ospf fabric");
            };

            let output = get_neighbors_ospf(fabric_id, fabric, neighbors, "node2")
                .expect("error converting vtysh output");

            let reference = vec![
                ospf::NeighborStatus {
                    neighbor: "172.16.6.1".to_owned(),
                    status: "Full/-".to_owned(),
                    uptime: "1m04s".to_owned(),
                },
                ospf::NeighborStatus {
                    neighbor: "172.16.6.3".to_owned(),
                    status: "Full/-".to_owned(),
                    uptime: "1m07s".to_owned(),
                },
            ];
            assert_eq!(reference, output);
        }

        #[test]
        fn neighbors_multiple_areas() {
            let json_output = r#"
            {
              "neighbors":{
                "172.16.6.1":[
                  {
                    "nbrState":"Full\/-",
                    "nbrPriority":1,
                    "converged":"Full",
                    "role":"DROther",
                    "upTimeInMsec":509026,
                    "routerDeadIntervalTimerDueMsec":32912,
                    "upTime":"8m29s",
                    "deadTime":"32.912s",
                    "ifaceAddress":"172.16.6.1",
                    "ifaceName":"ens19:172.16.6.2",
                    "linkStateRetransmissionListCounter":0,
                    "linkStateRequestListCounter":0,
                    "databaseSummaryListCounter":0
                  },
                  {
                    "nbrState":"Full\/-",
                    "nbrPriority":1,
                    "converged":"Full",
                    "role":"DROther",
                    "upTimeInMsec":88468,
                    "routerDeadIntervalTimerDueMsec":31531,
                    "upTime":"1m28s",
                    "deadTime":"31.531s",
                    "ifaceAddress":"172.16.7.1",
                    "ifaceName":"ens21:172.16.7.2",
                    "linkStateRetransmissionListCounter":0,
                    "linkStateRequestListCounter":0,
                    "databaseSummaryListCounter":0
                  }
                ],
                "172.16.6.3":[
                  {
                    "nbrState":"Full\/-",
                    "nbrPriority":1,
                    "converged":"Full",
                    "role":"DROther",
                    "upTimeInMsec":512034,
                    "routerDeadIntervalTimerDueMsec":37968,
                    "upTime":"8m32s",
                    "deadTime":"37.968s",
                    "ifaceAddress":"172.16.6.3",
                    "ifaceName":"ens20:172.16.6.2",
                    "linkStateRetransmissionListCounter":0,
                    "linkStateRequestListCounter":0,
                    "databaseSummaryListCounter":0
                  },
                  {
                    "nbrState":"Full\/-",
                    "nbrPriority":1,
                    "converged":"Full",
                    "role":"DROther",
                    "upTimeInMsec":92614,
                    "routerDeadIntervalTimerDueMsec":37384,
                    "upTime":"1m32s",
                    "deadTime":"37.384s",
                    "ifaceAddress":"172.16.7.3",
                    "ifaceName":"ens22:172.16.7.2",
                    "linkStateRetransmissionListCounter":0,
                    "linkStateRequestListCounter":0,
                    "databaseSummaryListCounter":0
                  }
                ]
              }
            }
            "#;

            let neighbors: de::ospf::Neighbors = if json_output.is_empty() {
                de::ospf::Neighbors::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let fabric_config = sample_two_fabric_config();

            let fabric_id =
                FabricId::from_string("test".to_owned()).expect("error parsing fabricId");
            let fabric = fabric_config
                .get_fabric(&fabric_id)
                .expect("can't find fabric in config");

            let FabricEntry::Ospf(fabric) = fabric else {
                panic!("not a ospf fabric");
            };

            let output_fabric1 = get_neighbors_ospf(fabric_id, fabric, neighbors.clone(), "node2")
                .expect("error converting vtysh output");

            let reference_fabric1 = vec![
                ospf::NeighborStatus {
                    neighbor: "172.16.6.1".to_owned(),
                    status: "Full/-".to_owned(),
                    uptime: "8m29s".to_owned(),
                },
                ospf::NeighborStatus {
                    neighbor: "172.16.6.3".to_owned(),
                    status: "Full/-".to_owned(),
                    uptime: "8m32s".to_owned(),
                },
            ];
            assert_eq!(reference_fabric1, output_fabric1);

            let fabric_id =
                FabricId::from_string("test1".to_owned()).expect("error parsing fabricId");
            let fabric = fabric_config
                .get_fabric(&fabric_id)
                .expect("can't find fabric in config");

            let FabricEntry::Ospf(fabric) = fabric else {
                panic!("not a ospf fabric");
            };

            let output_fabric2 = get_neighbors_ospf(fabric_id, fabric, neighbors.clone(), "node2")
                .expect("error converting vtysh output");

            let reference_fabric2 = vec![
                ospf::NeighborStatus {
                    neighbor: "172.16.7.1".to_owned(),
                    status: "Full/-".to_owned(),
                    uptime: "1m28s".to_owned(),
                },
                ospf::NeighborStatus {
                    neighbor: "172.16.7.3".to_owned(),
                    status: "Full/-".to_owned(),
                    uptime: "1m32s".to_owned(),
                },
            ];
            assert_eq!(reference_fabric2, output_fabric2);
        }

        #[test]
        fn interfaces() {
            let json_output = r#"
            {
              "interfaces":{
                "dummy_test":{
                  "ifUp":true,
                  "ifIndex":10,
                  "mtuBytes":1500,
                  "bandwidthMbit":0,
                  "ifFlags":"<UP,LOWER_UP,BROADCAST,RUNNING,NOARP>",
                  "ospfEnabled":true,
                  "ifUnnumbered":true,
                  "area":"0.0.0.0",
                  "routerId":"172.16.6.2",
                  "networkType":"BROADCAST",
                  "cost":10,
                  "transmitDelaySecs":1,
                  "state":"DR",
                  "priority":1,
                  "opaqueCapable":true,
                  "drId":"172.16.6.2",
                  "drAddress":"172.16.6.2",
                  "timerMsecs":10000,
                  "timerDeadSecs":40,
                  "timerWaitSecs":40,
                  "timerRetransmitSecs":5,
                  "timerRetransmitWindowMsecs":50,
                  "timerPassiveIface":true,
                  "nbrCount":0,
                  "nbrAdjacentCount":0,
                  "grHelloDelaySecs":10,
                  "prefixSuppression":false,
                  "nbrFilterPrefixList":"N/A",
                  "lsaRetransmissions":0
                },
                "ens19":{
                  "ifUp":true,
                  "ifIndex":3,
                  "mtuBytes":1500,
                  "bandwidthMbit":0,
                  "ifFlags":"<UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>",
                  "ospfEnabled":true,
                  "ifUnnumbered":true,
                  "area":"0.0.0.0",
                  "routerId":"172.16.6.2",
                  "networkType":"POINTOPOINT",
                  "cost":10,
                  "transmitDelaySecs":1,
                  "state":"Point-To-Point",
                  "priority":1,
                  "opaqueCapable":true,
                  "mcastMemberOspfAllRouters":true,
                  "timerMsecs":10000,
                  "timerDeadSecs":40,
                  "timerWaitSecs":40,
                  "timerRetransmitSecs":5,
                  "timerRetransmitWindowMsecs":50,
                  "timerHelloInMsecs":3648,
                  "nbrCount":1,
                  "nbrAdjacentCount":1,
                  "grHelloDelaySecs":10,
                  "prefixSuppression":false,
                  "nbrFilterPrefixList":"N/A",
                  "lsaRetransmissions":1
                },
                "ens20":{
                  "ifUp":true,
                  "ifIndex":4,
                  "mtuBytes":1500,
                  "bandwidthMbit":0,
                  "ifFlags":"<UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>",
                  "ospfEnabled":true,
                  "ifUnnumbered":true,
                  "area":"0.0.0.0",
                  "routerId":"172.16.6.2",
                  "networkType":"POINTOPOINT",
                  "cost":10,
                  "transmitDelaySecs":1,
                  "state":"Point-To-Point",
                  "priority":1,
                  "opaqueCapable":true,
                  "mcastMemberOspfAllRouters":true,
                  "timerMsecs":10000,
                  "timerDeadSecs":40,
                  "timerWaitSecs":40,
                  "timerRetransmitSecs":5,
                  "timerRetransmitWindowMsecs":50,
                  "timerHelloInMsecs":3648,
                  "nbrCount":1,
                  "nbrAdjacentCount":1,
                  "grHelloDelaySecs":10,
                  "prefixSuppression":false,
                  "nbrFilterPrefixList":"N/A",
                  "lsaRetransmissions":0
                }
              }
            }
            "#;

            let interfaces: de::ospf::Interfaces = if json_output.is_empty() {
                de::ospf::Interfaces::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let fabric_config = sample_one_fabric_config();

            let fabric_id =
                FabricId::from_string("test".to_owned()).expect("error parsing fabricId");
            let fabric = fabric_config
                .get_fabric(&fabric_id)
                .expect("can't find fabric in config");

            let FabricEntry::Ospf(fabric) = fabric else {
                panic!("not a ospf fabric");
            };

            let output = get_interfaces_ospf(fabric_id, fabric, interfaces, "node2")
                .expect("error converting vtysh output");

            let reference = vec![
                ospf::InterfaceStatus {
                    name: "dummy_test".to_owned(),
                    state: InterfaceState::Up,
                    ty: de::ospf::NetworkType::Broadcast,
                },
                ospf::InterfaceStatus {
                    name: "ens19".to_owned(),
                    state: InterfaceState::Up,
                    ty: de::ospf::NetworkType::PointToPoint,
                },
                ospf::InterfaceStatus {
                    name: "ens20".to_owned(),
                    state: InterfaceState::Up,
                    ty: de::ospf::NetworkType::PointToPoint,
                },
            ];
            assert_eq!(reference, output);
        }

        #[test]
        fn interfaces_multiple_areas() {
            let json_output = r#"
            {
              "interfaces":{
                "dummy_test":{
                  "ifUp":true,
                  "ifIndex":10,
                  "mtuBytes":1500,
                  "bandwidthMbit":0,
                  "ifFlags":"<UP,LOWER_UP,BROADCAST,RUNNING,NOARP>",
                  "ospfEnabled":true,
                  "ifUnnumbered":true,
                  "area":"0.0.0.0",
                  "routerId":"172.16.6.2",
                  "networkType":"BROADCAST",
                  "cost":10,
                  "transmitDelaySecs":1,
                  "state":"DR",
                  "priority":1,
                  "opaqueCapable":true,
                  "drId":"172.16.6.2",
                  "drAddress":"172.16.6.2",
                  "timerMsecs":10000,
                  "timerDeadSecs":40,
                  "timerWaitSecs":40,
                  "timerRetransmitSecs":5,
                  "timerRetransmitWindowMsecs":50,
                  "timerPassiveIface":true,
                  "nbrCount":0,
                  "nbrAdjacentCount":0,
                  "grHelloDelaySecs":10,
                  "prefixSuppression":false,
                  "nbrFilterPrefixList":"N/A",
                  "lsaRetransmissions":0
                },
                "dummy_test1":{
                  "ifUp":true,
                  "ifIndex":11,
                  "mtuBytes":1500,
                  "bandwidthMbit":0,
                  "ifFlags":"<UP,LOWER_UP,BROADCAST,RUNNING,NOARP>",
                  "ospfEnabled":true,
                  "ifUnnumbered":true,
                  "area":"0.0.0.1",
                  "routerId":"172.16.6.2",
                  "networkType":"BROADCAST",
                  "cost":10,
                  "transmitDelaySecs":1,
                  "state":"DR",
                  "priority":1,
                  "opaqueCapable":true,
                  "drId":"172.16.6.2",
                  "drAddress":"172.16.7.2",
                  "timerMsecs":10000,
                  "timerDeadSecs":40,
                  "timerWaitSecs":40,
                  "timerRetransmitSecs":5,
                  "timerRetransmitWindowMsecs":50,
                  "timerPassiveIface":true,
                  "nbrCount":0,
                  "nbrAdjacentCount":0,
                  "grHelloDelaySecs":10,
                  "prefixSuppression":false,
                  "nbrFilterPrefixList":"N/A",
                  "lsaRetransmissions":0
                },
                "ens19":{
                  "ifUp":true,
                  "ifIndex":3,
                  "mtuBytes":1500,
                  "bandwidthMbit":0,
                  "ifFlags":"<UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>",
                  "ospfEnabled":true,
                  "ifUnnumbered":true,
                  "area":"0.0.0.0",
                  "routerId":"172.16.6.2",
                  "networkType":"POINTOPOINT",
                  "cost":10,
                  "transmitDelaySecs":1,
                  "state":"Point-To-Point",
                  "priority":1,
                  "opaqueCapable":true,
                  "mcastMemberOspfAllRouters":true,
                  "timerMsecs":10000,
                  "timerDeadSecs":40,
                  "timerWaitSecs":40,
                  "timerRetransmitSecs":5,
                  "timerRetransmitWindowMsecs":50,
                  "timerHelloInMsecs":3648,
                  "nbrCount":1,
                  "nbrAdjacentCount":1,
                  "grHelloDelaySecs":10,
                  "prefixSuppression":false,
                  "nbrFilterPrefixList":"N/A",
                  "lsaRetransmissions":1
                },
                "ens20":{
                  "ifUp":true,
                  "ifIndex":4,
                  "mtuBytes":1500,
                  "bandwidthMbit":0,
                  "ifFlags":"<UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>",
                  "ospfEnabled":true,
                  "ifUnnumbered":true,
                  "area":"0.0.0.0",
                  "routerId":"172.16.6.2",
                  "networkType":"POINTOPOINT",
                  "cost":10,
                  "transmitDelaySecs":1,
                  "state":"Point-To-Point",
                  "priority":1,
                  "opaqueCapable":true,
                  "mcastMemberOspfAllRouters":true,
                  "timerMsecs":10000,
                  "timerDeadSecs":40,
                  "timerWaitSecs":40,
                  "timerRetransmitSecs":5,
                  "timerRetransmitWindowMsecs":50,
                  "timerHelloInMsecs":3648,
                  "nbrCount":1,
                  "nbrAdjacentCount":1,
                  "grHelloDelaySecs":10,
                  "prefixSuppression":false,
                  "nbrFilterPrefixList":"N/A",
                  "lsaRetransmissions":0
                },
                "ens21":{
                  "ifUp":true,
                  "ifIndex":5,
                  "mtuBytes":1500,
                  "bandwidthMbit":0,
                  "ifFlags":"<UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>",
                  "ospfEnabled":true,
                  "ifUnnumbered":true,
                  "area":"0.0.0.1",
                  "routerId":"172.16.6.2",
                  "networkType":"POINTOPOINT",
                  "cost":10,
                  "transmitDelaySecs":1,
                  "state":"Point-To-Point",
                  "priority":1,
                  "opaqueCapable":true,
                  "mcastMemberOspfAllRouters":true,
                  "timerMsecs":10000,
                  "timerDeadSecs":40,
                  "timerWaitSecs":40,
                  "timerRetransmitSecs":5,
                  "timerRetransmitWindowMsecs":50,
                  "timerHelloInMsecs":2708,
                  "nbrCount":1,
                  "nbrAdjacentCount":1,
                  "grHelloDelaySecs":10,
                  "prefixSuppression":false,
                  "nbrFilterPrefixList":"N/A",
                  "lsaRetransmissions":1
                },
                "ens22":{
                  "ifUp":true,
                  "ifIndex":6,
                  "mtuBytes":1500,
                  "bandwidthMbit":0,
                  "ifFlags":"<UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>",
                  "ospfEnabled":true,
                  "ifUnnumbered":true,
                  "area":"0.0.0.1",
                  "routerId":"172.16.6.2",
                  "networkType":"POINTOPOINT",
                  "cost":10,
                  "transmitDelaySecs":1,
                  "state":"Point-To-Point",
                  "priority":1,
                  "opaqueCapable":true,
                  "mcastMemberOspfAllRouters":true,
                  "timerMsecs":10000,
                  "timerDeadSecs":40,
                  "timerWaitSecs":40,
                  "timerRetransmitSecs":5,
                  "timerRetransmitWindowMsecs":50,
                  "timerHelloInMsecs":3449,
                  "nbrCount":1,
                  "nbrAdjacentCount":1,
                  "grHelloDelaySecs":10,
                  "prefixSuppression":false,
                  "nbrFilterPrefixList":"N/A",
                  "lsaRetransmissions":0
                }
              }
            }
            "#;

            let interfaces: de::ospf::Interfaces = if json_output.is_empty() {
                de::ospf::Interfaces::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let fabric_config = sample_two_fabric_config();

            let fabric_id =
                FabricId::from_string("test".to_owned()).expect("error parsing fabricId");
            let fabric = fabric_config
                .get_fabric(&fabric_id)
                .expect("can't find fabric in config");

            let FabricEntry::Ospf(fabric) = fabric else {
                panic!("not a ospf fabric");
            };

            let output_fabric1 =
                get_interfaces_ospf(fabric_id, fabric, interfaces.clone(), "node2")
                    .expect("error converting vtysh output");

            let reference_fabric1 = vec![
                ospf::InterfaceStatus {
                    name: "dummy_test".to_owned(),
                    state: InterfaceState::Up,
                    ty: de::ospf::NetworkType::Broadcast,
                },
                ospf::InterfaceStatus {
                    name: "ens19".to_owned(),
                    state: InterfaceState::Up,
                    ty: de::ospf::NetworkType::PointToPoint,
                },
                ospf::InterfaceStatus {
                    name: "ens20".to_owned(),
                    state: InterfaceState::Up,
                    ty: de::ospf::NetworkType::PointToPoint,
                },
            ];
            assert_eq!(reference_fabric1, output_fabric1);

            let fabric_id =
                FabricId::from_string("test1".to_owned()).expect("error parsing fabricId");
            let fabric = fabric_config
                .get_fabric(&fabric_id)
                .expect("can't find fabric in config");

            let FabricEntry::Ospf(fabric) = fabric else {
                panic!("not a ospf fabric");
            };

            let output_fabric2 = get_interfaces_ospf(fabric_id, fabric, interfaces, "node2")
                .expect("error converting vtysh output");

            let reference_fabric2 = vec![
                ospf::InterfaceStatus {
                    name: "dummy_test1".to_owned(),
                    state: InterfaceState::Up,
                    ty: de::ospf::NetworkType::Broadcast,
                },
                ospf::InterfaceStatus {
                    name: "ens21".to_owned(),
                    state: InterfaceState::Up,
                    ty: de::ospf::NetworkType::PointToPoint,
                },
                ospf::InterfaceStatus {
                    name: "ens22".to_owned(),
                    state: InterfaceState::Up,
                    ty: de::ospf::NetworkType::PointToPoint,
                },
            ];
            assert_eq!(reference_fabric2, output_fabric2);
        }
    }

    mod routes {
        use crate::sdn::status::tests::sample_two_fabric_config;

        use super::super::*;

        #[test]
        fn routes_ospf() {
            let json_output = r#"
            {
              "172.16.6.1/32": [
                {
                  "prefix": "172.16.6.1/32",
                  "prefixLen": 32,
                  "protocol": "ospf",
                  "vrfId": 0,
                  "vrfName": "default",
                  "selected": true,
                  "destSelected": true,
                  "distance": 110,
                  "metric": 20,
                  "installed": true,
                  "table": 254,
                  "internalStatus": 16,
                  "internalFlags": 8,
                  "internalNextHopNum": 1,
                  "internalNextHopActiveNum": 1,
                  "nexthopGroupId": 25,
                  "installedNexthopGroupId": 25,
                  "uptime": "00:40:22",
                  "nexthops": [
                    {
                      "flags": 11,
                      "fib": true,
                      "ip": "172.16.6.1",
                      "afi": "ipv4",
                      "interfaceIndex": 3,
                      "interfaceName": "ens19",
                      "active": true,
                      "onLink": true,
                      "rmapSource": "172.16.6.2",
                      "weight": 1
                    }
                  ]
                }
              ],
              "172.16.6.2/32": [
                {
                  "prefix": "172.16.6.2/32",
                  "prefixLen": 32,
                  "protocol": "ospf",
                  "vrfId": 0,
                  "vrfName": "default",
                  "distance": 110,
                  "metric": 10,
                  "table": 254,
                  "internalStatus": 0,
                  "internalFlags": 0,
                  "internalNextHopNum": 1,
                  "internalNextHopActiveNum": 1,
                  "nexthopGroupId": 20,
                  "uptime": "00:40:37",
                  "nexthops": [
                    {
                      "flags": 9,
                      "ip": "0.0.0.0",
                      "afi": "ipv4",
                      "interfaceIndex": 10,
                      "interfaceName": "dummy_test",
                      "active": true,
                      "onLink": true,
                      "rmapSource": "172.16.6.2",
                      "weight": 1
                    }
                  ]
                }
              ],
              "172.16.6.3/32": [
                {
                  "prefix": "172.16.6.3/32",
                  "prefixLen": 32,
                  "protocol": "ospf",
                  "vrfId": 0,
                  "vrfName": "default",
                  "selected": true,
                  "destSelected": true,
                  "distance": 110,
                  "metric": 20,
                  "installed": true,
                  "table": 254,
                  "internalStatus": 16,
                  "internalFlags": 8,
                  "internalNextHopNum": 1,
                  "internalNextHopActiveNum": 1,
                  "nexthopGroupId": 22,
                  "installedNexthopGroupId": 22,
                  "uptime": "00:40:27",
                  "nexthops": [
                    {
                      "flags": 11,
                      "fib": true,
                      "ip": "172.16.6.3",
                      "afi": "ipv4",
                      "interfaceIndex": 4,
                      "interfaceName": "ens20",
                      "active": true,
                      "onLink": true,
                      "rmapSource": "172.16.6.2",
                      "weight": 1
                    }
                  ]
                }
              ],
              "172.16.7.1/32": [
                {
                  "prefix": "172.16.7.1/32",
                  "prefixLen": 32,
                  "protocol": "ospf",
                  "vrfId": 0,
                  "vrfName": "default",
                  "selected": true,
                  "destSelected": true,
                  "distance": 110,
                  "metric": 20,
                  "installed": true,
                  "table": 254,
                  "internalStatus": 16,
                  "internalFlags": 8,
                  "internalNextHopNum": 1,
                  "internalNextHopActiveNum": 1,
                  "nexthopGroupId": 47,
                  "installedNexthopGroupId": 47,
                  "uptime": "00:33:21",
                  "nexthops": [
                    {
                      "flags": 11,
                      "fib": true,
                      "ip": "172.16.7.1",
                      "afi": "ipv4",
                      "interfaceIndex": 5,
                      "interfaceName": "ens21",
                      "active": true,
                      "onLink": true,
                      "rmapSource": "172.16.7.2",
                      "weight": 1
                    }
                  ]
                }
              ],
              "172.16.7.2/32": [
                {
                  "prefix": "172.16.7.2/32",
                  "prefixLen": 32,
                  "protocol": "ospf",
                  "vrfId": 0,
                  "vrfName": "default",
                  "distance": 110,
                  "metric": 10,
                  "table": 254,
                  "internalStatus": 0,
                  "internalFlags": 0,
                  "internalNextHopNum": 1,
                  "internalNextHopActiveNum": 1,
                  "nexthopGroupId": 34,
                  "uptime": "00:33:38",
                  "nexthops": [
                    {
                      "flags": 9,
                      "ip": "0.0.0.0",
                      "afi": "ipv4",
                      "interfaceIndex": 11,
                      "interfaceName": "dummy_test1",
                      "active": true,
                      "onLink": true,
                      "rmapSource": "172.16.7.2",
                      "weight": 1
                    }
                  ]
                }
              ],
              "172.16.7.3/32": [
                {
                  "prefix": "172.16.7.3/32",
                  "prefixLen": 32,
                  "protocol": "ospf",
                  "vrfId": 0,
                  "vrfName": "default",
                  "selected": true,
                  "destSelected": true,
                  "distance": 110,
                  "metric": 20,
                  "installed": true,
                  "table": 254,
                  "internalStatus": 16,
                  "internalFlags": 8,
                  "internalNextHopNum": 1,
                  "internalNextHopActiveNum": 1,
                  "nexthopGroupId": 45,
                  "installedNexthopGroupId": 45,
                  "uptime": "00:33:25",
                  "nexthops": [
                    {
                      "flags": 11,
                      "fib": true,
                      "ip": "172.16.7.3",
                      "afi": "ipv4",
                      "interfaceIndex": 6,
                      "interfaceName": "ens22",
                      "active": true,
                      "onLink": true,
                      "rmapSource": "172.16.7.2",
                      "weight": 1
                    }
                  ]
                }
              ]
            }
            "#;

            let routes: de::Routes = if json_output.is_empty() {
                de::Routes::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let fabric_config = sample_two_fabric_config();

            let fabric_id =
                FabricId::from_string("test".to_owned()).expect("error parsing fabricId");

            let output_fabric1 =
                get_routes(fabric_id, fabric_config.clone(), routes.clone(), "node2")
                    .expect("error converting vtysh output");

            let reference_fabric1 = vec![
                RouteStatus {
                    route: "172.16.6.1/32".to_owned(),
                    via: vec!["172.16.6.1".to_owned()],
                },
                RouteStatus {
                    route: "172.16.6.3/32".to_owned(),
                    via: vec!["172.16.6.3".to_owned()],
                },
            ];
            assert_eq!(reference_fabric1, output_fabric1);

            let fabric_id =
                FabricId::from_string("test1".to_owned()).expect("error parsing fabricId");

            let output_fabric2 = get_routes(fabric_id, fabric_config, routes, "node2")
                .expect("error converting vtysh output");

            let reference_fabric2 = vec![
                RouteStatus {
                    route: "172.16.7.1/32".to_owned(),
                    via: vec!["172.16.7.1".to_owned()],
                },
                RouteStatus {
                    route: "172.16.7.3/32".to_owned(),
                    via: vec!["172.16.7.3".to_owned()],
                },
            ];
            assert_eq!(reference_fabric2, output_fabric2);
        }

        #[test]
        fn routes_openfabric() {
            let json_output = r#"
            {
              "172.16.6.1/32": [
                {
                  "prefix": "172.16.6.1/32",
                  "prefixLen": 32,
                  "protocol": "openfabric",
                  "vrfId": 0,
                  "vrfName": "default",
                  "selected": true,
                  "destSelected": true,
                  "distance": 115,
                  "metric": 20,
                  "installed": true,
                  "table": 254,
                  "internalStatus": 16,
                  "internalFlags": 8,
                  "internalNextHopNum": 1,
                  "internalNextHopActiveNum": 1,
                  "nexthopGroupId": 74,
                  "installedNexthopGroupId": 74,
                  "uptime": "00:00:32",
                  "nexthops": [
                    {
                      "flags": 11,
                      "fib": true,
                      "ip": "172.16.6.1",
                      "afi": "ipv4",
                      "interfaceIndex": 3,
                      "interfaceName": "ens19",
                      "active": true,
                      "onLink": true,
                      "rmapSource": "172.16.6.2",
                      "weight": 1
                    }
                  ]
                }
              ],
              "172.16.6.3/32": [
                {
                  "prefix": "172.16.6.3/32",
                  "prefixLen": 32,
                  "protocol": "openfabric",
                  "vrfId": 0,
                  "vrfName": "default",
                  "selected": true,
                  "destSelected": true,
                  "distance": 115,
                  "metric": 20,
                  "installed": true,
                  "table": 254,
                  "internalStatus": 16,
                  "internalFlags": 8,
                  "internalNextHopNum": 1,
                  "internalNextHopActiveNum": 1,
                  "nexthopGroupId": 75,
                  "installedNexthopGroupId": 75,
                  "uptime": "00:00:32",
                  "nexthops": [
                    {
                      "flags": 11,
                      "fib": true,
                      "ip": "172.16.6.3",
                      "afi": "ipv4",
                      "interfaceIndex": 4,
                      "interfaceName": "ens20",
                      "active": true,
                      "onLink": true,
                      "rmapSource": "172.16.6.2",
                      "weight": 1
                    }
                  ]
                }
              ],
              "172.16.7.1/32": [
                {
                  "prefix": "172.16.7.1/32",
                  "prefixLen": 32,
                  "protocol": "openfabric",
                  "vrfId": 0,
                  "vrfName": "default",
                  "selected": true,
                  "destSelected": true,
                  "distance": 115,
                  "metric": 20,
                  "installed": true,
                  "table": 254,
                  "internalStatus": 16,
                  "internalFlags": 8,
                  "internalNextHopNum": 1,
                  "internalNextHopActiveNum": 1,
                  "nexthopGroupId": 76,
                  "installedNexthopGroupId": 76,
                  "uptime": "00:00:32",
                  "nexthops": [
                    {
                      "flags": 11,
                      "fib": true,
                      "ip": "172.16.7.1",
                      "afi": "ipv4",
                      "interfaceIndex": 5,
                      "interfaceName": "ens21",
                      "active": true,
                      "onLink": true,
                      "rmapSource": "172.16.7.2",
                      "weight": 1
                    }
                  ]
                }
              ],
              "172.16.7.3/32": [
                {
                  "prefix": "172.16.7.3/32",
                  "prefixLen": 32,
                  "protocol": "openfabric",
                  "vrfId": 0,
                  "vrfName": "default",
                  "selected": true,
                  "destSelected": true,
                  "distance": 115,
                  "metric": 20,
                  "installed": true,
                  "table": 254,
                  "internalStatus": 16,
                  "internalFlags": 8,
                  "internalNextHopNum": 1,
                  "internalNextHopActiveNum": 1,
                  "nexthopGroupId": 77,
                  "installedNexthopGroupId": 77,
                  "uptime": "00:00:32",
                  "nexthops": [
                    {
                      "flags": 11,
                      "fib": true,
                      "ip": "172.16.7.3",
                      "afi": "ipv4",
                      "interfaceIndex": 6,
                      "interfaceName": "ens22",
                      "active": true,
                      "onLink": true,
                      "rmapSource": "172.16.7.2",
                      "weight": 1
                    }
                  ]
                }
              ]
            }
            "#;

            let routes: de::Routes = if json_output.is_empty() {
                de::Routes::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let fabric_config = sample_two_fabric_config();

            let fabric_id =
                FabricId::from_string("test".to_owned()).expect("error parsing fabricId");

            let output_fabric1 =
                get_routes(fabric_id, fabric_config.clone(), routes.clone(), "node2")
                    .expect("error converting vtysh output");

            let reference_fabric1 = vec![
                RouteStatus {
                    route: "172.16.6.1/32".to_owned(),
                    via: vec!["172.16.6.1".to_owned()],
                },
                RouteStatus {
                    route: "172.16.6.3/32".to_owned(),
                    via: vec!["172.16.6.3".to_owned()],
                },
            ];
            assert_eq!(reference_fabric1, output_fabric1);

            let fabric_id =
                FabricId::from_string("test1".to_owned()).expect("error parsing fabricId");

            let output_fabric2 = get_routes(fabric_id, fabric_config, routes, "node2")
                .expect("error converting vtysh output");

            let reference_fabric2 = vec![
                RouteStatus {
                    route: "172.16.7.1/32".to_owned(),
                    via: vec!["172.16.7.1".to_owned()],
                },
                RouteStatus {
                    route: "172.16.7.3/32".to_owned(),
                    via: vec!["172.16.7.3".to_owned()],
                },
            ];
            assert_eq!(reference_fabric2, output_fabric2);
        }
    }

    mod evpn {
        use std::{
            net::{Ipv4Addr, Ipv6Addr},
            str::FromStr,
        };

        use super::super::*;

        #[test]
        fn routes_l3vpn() {
            let json_output = r#"
                {
                  "0.0.0.0/0": [
                    {
                      "prefix": "0.0.0.0/0",
                      "prefixLen": 0,
                      "protocol": "kernel",
                      "vrfId": 14,
                      "vrfName": "vrf_test",
                      "selected": true,
                      "destSelected": true,
                      "distance": 255,
                      "metric": 8192,
                      "installed": true,
                      "table": 1001,
                      "internalStatus": 16,
                      "internalFlags": 8,
                      "internalNextHopNum": 1,
                      "internalNextHopActiveNum": 1,
                      "nexthopGroupId": 82,
                      "installedNexthopGroupId": 82,
                      "uptime": "00:03:44",
                      "nexthops": [
                        {
                          "flags": 3,
                          "fib": true,
                          "unreachable": true,
                          "reject": true,
                          "active": true,
                          "weight": 1
                        }
                      ]
                    }
                  ],
                  "172.16.100.0/24": [
                    {
                      "prefix": "172.16.100.0/24",
                      "prefixLen": 24,
                      "protocol": "connected",
                      "vrfId": 14,
                      "vrfName": "vrf_test",
                      "selected": true,
                      "destSelected": true,
                      "distance": 0,
                      "metric": 0,
                      "installed": true,
                      "table": 1001,
                      "internalStatus": 16,
                      "internalFlags": 8,
                      "internalNextHopNum": 1,
                      "internalNextHopActiveNum": 1,
                      "nexthopGroupId": 80,
                      "installedNexthopGroupId": 80,
                      "uptime": "00:03:44",
                      "nexthops": [
                        {
                          "flags": 3,
                          "fib": true,
                          "directlyConnected": true,
                          "interfaceIndex": 13,
                          "interfaceName": "test",
                          "active": true,
                          "weight": 1
                        }
                      ]
                    },
                    {
                      "prefix": "172.16.100.0/24",
                      "prefixLen": 24,
                      "protocol": "kernel",
                      "vrfId": 14,
                      "vrfName": "vrf_test",
                      "distance": 0,
                      "metric": 0,
                      "installed": true,
                      "table": 1001,
                      "internalStatus": 16,
                      "internalFlags": 0,
                      "internalNextHopNum": 1,
                      "internalNextHopActiveNum": 1,
                      "nexthopGroupId": 78,
                      "uptime": "00:03:44",
                      "nexthops": [
                        {
                          "flags": 3,
                          "fib": true,
                          "directlyConnected": true,
                          "interfaceIndex": 13,
                          "interfaceName": "test",
                          "vrf": "default",
                          "active": true,
                          "weight": 1
                        }
                      ]
                    }
                  ],
                  "172.16.100.1/32": [
                    {
                      "prefix": "172.16.100.1/32",
                      "prefixLen": 32,
                      "protocol": "local",
                      "vrfId": 14,
                      "vrfName": "vrf_test",
                      "selected": true,
                      "destSelected": true,
                      "distance": 0,
                      "metric": 0,
                      "installed": true,
                      "table": 1001,
                      "internalStatus": 16,
                      "internalFlags": 8,
                      "internalNextHopNum": 1,
                      "internalNextHopActiveNum": 1,
                      "nexthopGroupId": 80,
                      "installedNexthopGroupId": 80,
                      "uptime": "00:03:44",
                      "nexthops": [
                        {
                          "flags": 3,
                          "fib": true,
                          "directlyConnected": true,
                          "interfaceIndex": 13,
                          "interfaceName": "test",
                          "active": true,
                          "weight": 1
                        }
                      ]
                    }
                  ],
                  "172.16.100.2/32": [
                    {
                      "prefix": "172.16.100.2/32",
                      "prefixLen": 32,
                      "protocol": "bgp",
                      "vrfId": 14,
                      "vrfName": "vrf_test",
                      "selected": true,
                      "destSelected": true,
                      "distance": 200,
                      "metric": 0,
                      "installed": true,
                      "table": 1001,
                      "internalStatus": 16,
                      "internalFlags": 13,
                      "internalNextHopNum": 1,
                      "internalNextHopActiveNum": 1,
                      "nexthopGroupId": 88,
                      "installedNexthopGroupId": 88,
                      "uptime": "00:01:22",
                      "nexthops": [
                        {
                          "flags": 267,
                          "fib": true,
                          "ip": "172.16.6.1",
                          "afi": "ipv4",
                          "interfaceIndex": 16,
                          "interfaceName": "vrfbr_test",
                          "active": true,
                          "onLink": true,
                          "weight": 1
                        }
                      ]
                    }
                  ]
                }

            "#;

            let routes: de::Routes = if json_output.is_empty() {
                de::Routes::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let zone = "test";

            let output = get_l3vpn_routes(&format!("vrf_{zone}"), routes)
                .expect("error converting vtysh output");

            let reference = L3VPNRoutes(vec![
                L3VPNRoute {
                    ip: Cidr::from_str("0.0.0.0/0").expect("valid cidr"),
                    protocol: "kernel".to_owned(),
                    metric: 8192,
                    nexthops: vec![],
                },
                L3VPNRoute {
                    ip: Cidr::from_str("172.16.100.0/24").expect("valid cidr"),
                    protocol: "connected".to_owned(),
                    metric: 0,
                    nexthops: vec![IpAddrOrInterfaceName::InterfaceName("test".to_owned())],
                },
                L3VPNRoute {
                    ip: Cidr::from_str("172.16.100.0/24").expect("valid cidr"),
                    protocol: "kernel".to_owned(),
                    metric: 0,
                    nexthops: vec![IpAddrOrInterfaceName::InterfaceName("test".to_owned())],
                },
                L3VPNRoute {
                    ip: Cidr::from_str("172.16.100.1/32").expect("valid cidr"),
                    protocol: "local".to_owned(),
                    metric: 0,
                    nexthops: vec![IpAddrOrInterfaceName::InterfaceName("test".to_owned())],
                },
                L3VPNRoute {
                    ip: Cidr::from_str("172.16.100.2/32").expect("valid cidr"),
                    protocol: "bgp".to_owned(),
                    metric: 0,
                    nexthops: vec![IpAddrOrInterfaceName::IpAddr(IpAddr::V4(
                        Ipv4Addr::from_str("172.16.6.1").expect("valid ip addr"),
                    ))],
                },
            ]);
            assert_eq!(reference, output);
        }

        #[test]
        fn routes_l2vpn() {
            let json_output = r#"
                {
                  "[2]:[0]:[48]:[00:00:00:00:00:00]:[32]:[172.16.100.2]":{
                    "prefix":"[2]:[0]:[48]:[00:00:00:00:00:00]:[32]:[172.16.100.2]",
                    "prefixLen":352,
                    "paths":[
                      [
                        {
                          "valid":true,
                          "bestpath":true,
                          "selectionReason":"First path received",
                          "pathFrom":"internal",
                          "routeType":2,
                          "ethTag":0,
                          "macLen":48,
                          "mac":"bc:24:11:02:45:ae",
                          "ipLen":32,
                          "ip":"172.16.100.2",
                          "locPrf":100,
                          "weight":0,
                          "peerId":"172.16.6.1",
                          "path":"",
                          "origin":"IGP",
                          "extendedCommunity":{
                            "string":"RT:65000:100 RT:65000:101 ET:8 Rmac:e2:44:0e:6f:78:72"
                          },
                          "nexthops":[
                            {
                              "ip":"172.16.6.1",
                              "hostname":"node1",
                              "afi":"ipv4",
                              "used":true
                            }
                          ]
                        }
                      ]
                    ]
                  },
                  "[2]:[0]:[48]:[00:00:00:00:00:00]:[128]:[fe80::be24:11ff:fe02:45ae]":{
                    "prefix":"[2]:[0]:[48]:[00:00:00:00:00:00]:[128]:[fe80::be24:11ff:fe02:45ae]",
                    "prefixLen":352,
                    "paths":[
                      [
                        {
                          "valid":true,
                          "bestpath":true,
                          "selectionReason":"First path received",
                          "pathFrom":"internal",
                          "routeType":2,
                          "ethTag":0,
                          "macLen":48,
                          "mac":"bc:24:11:02:45:ae",
                          "ipLen":128,
                          "ip":"fe80::be24:11ff:fe02:45ae",
                          "locPrf":100,
                          "weight":0,
                          "peerId":"172.16.6.1",
                          "path":"",
                          "origin":"IGP",
                          "extendedCommunity":{
                            "string":"RT:65000:100 ET:8"
                          },
                          "nexthops":[
                            {
                              "ip":"172.16.6.1",
                              "hostname":"node1",
                              "afi":"ipv4",
                              "used":true
                            }
                          ]
                        }
                      ]
                    ]
                  },
                  "numPrefix":2,
                  "numPaths":2
                }

            "#;

            let routes: de::evpn::Routes = if json_output.is_empty() {
                de::evpn::Routes::default()
            } else {
                serde_json::from_str(json_output).expect("error parsing json output")
            };

            let output = get_l2vpn_routes(routes).expect("error converting vtysh output");

            let reference = L2VPNRoutes(vec![
                L2VPNRoute {
                    mac: MacAddress::from_str("bc:24:11:02:45:ae").expect("valid mac address"),
                    ip: IpAddr::V6(
                        Ipv6Addr::from_str("fe80::be24:11ff:fe02:45ae").expect("valid ip address"),
                    ),
                    nexthop: IpAddr::V4(
                        Ipv4Addr::from_str("172.16.6.1").expect("valid ip address"),
                    ),
                },
                L2VPNRoute {
                    mac: MacAddress::from_str("bc:24:11:02:45:ae").expect("valid mac address"),
                    ip: IpAddr::V4(Ipv4Addr::from_str("172.16.100.2").expect("valid ip address")),
                    nexthop: IpAddr::V4(
                        Ipv4Addr::from_str("172.16.6.1").expect("valid ip address"),
                    ),
                },
            ]);
            assert_eq!(reference, output);
        }
    }
}
