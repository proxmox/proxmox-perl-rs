use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use proxmox_network_types::ip_address::Cidr;
use proxmox_network_types::mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use proxmox_frr::de::{self};
use proxmox_network_api::IpLink;
use proxmox_ve_config::sdn::fabric::section_config::protocol::bgp::BgpNode;
use proxmox_ve_config::sdn::fabric::section_config::protocol::ospf::{
    OspfNodeProperties, OspfProperties,
};
use proxmox_ve_config::{
    common::valid::Valid,
    sdn::fabric::{
        Entry, FabricConfig, FabricEntry,
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

pub mod wireguard {
    use std::collections::{HashMap, HashSet};

    use anyhow::Context;
    use proxmox_network_api::{IpLink, LinkFlag};
    use proxmox_ve_config::sdn::fabric::{
        Entry, WireGuardInterfacePeer,
        section_config::{
            node::{NodeId, NodeSection},
            protocol::wireguard::{WireGuardNode, WireGuardProperties},
        },
    };
    use proxmox_wireguard::PublicKey;
    use serde::Serialize;

    /// WireGuard does not use session keys that are older than this (`REJECT_AFTER_TIME`), so a
    /// peer with a more recent handshake has a working session.
    const REJECT_AFTER_TIME: u64 = 180;

    /// WireGuard retries a handshake for this long before giving up.
    const REKEY_ATTEMPT_TIME: u64 = 90;

    /// The status of a WireGuard peer, derived from its latest handshake.
    #[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(rename_all = "lowercase")]
    pub enum PeerStatus {
        /// The peer had a working session recently.
        Active,
        /// The peer is not reachable, which can only be determined with persistent keepalive.
        Down,
        /// Persistent keepalive is disabled and the peer has no recent session, so whether it is
        /// reachable is unknown.
        Idle,
    }

    impl PeerStatus {
        /// Determines the status of a peer at the time `now` (UNIX epoch).
        ///
        /// Without persistent keepalive, peers only exchange handshakes if traffic is sent, so a
        /// peer without a recent handshake cannot be distinguished from an unreachable one. With
        /// persistent keepalive, a reachable peer exchanges a new handshake before its session
        /// expires after `REJECT_AFTER_TIME`, delayed by at most the keepalive interval and
        /// `REKEY_ATTEMPT_TIME` of retries.
        pub fn from_handshake(
            latest_handshake: Option<u64>,
            persistent_keepalive: Option<u16>,
            now: i64,
        ) -> Self {
            let age = latest_handshake.map(|latest_handshake| {
                u64::try_from(now)
                    .unwrap_or(0)
                    .saturating_sub(latest_handshake)
            });

            match persistent_keepalive {
                None if age.is_some_and(|age| age < REJECT_AFTER_TIME) => PeerStatus::Active,
                None => PeerStatus::Idle,
                Some(interval)
                    if age.is_some_and(|age| {
                        age < REJECT_AFTER_TIME + u64::from(interval) + REKEY_ATTEMPT_TIME
                    }) =>
                {
                    PeerStatus::Active
                }
                Some(_) => PeerStatus::Down,
            }
        }
    }

    #[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(rename_all = "kebab-case")]
    pub struct NeighborStatus {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub neighbor: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        pub status: PeerStatus,
        pub interface: String,
        pub public_key: PublicKey,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub allowed_ips: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub latest_handshake: Option<u64>,
        pub bytes_rx: u64,
        pub bytes_tx: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub persistent_keepalive: Option<u16>,
    }

    /// The state of a WireGuard interface on the node.
    #[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(rename_all = "lowercase")]
    pub enum WireGuardInterfaceState {
        /// The interface exists and has the `UP` flag set.
        Up,
        /// The interface exists, but does not have the `UP` flag set.
        Down,
        /// The interface does not exist.
        Missing,
        /// The interface exists, but wg could not read its state.
        Unknown,
        /// The interface exists, but is not a WireGuard interface.
        Error,
    }

    #[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(rename_all = "kebab-case")]
    pub struct InterfaceStatus {
        pub name: String,
        #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
        pub ty: Option<String>,
        pub state: WireGuardInterfaceState,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub public_key: Option<PublicKey>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub listen_port: Option<u16>,
    }

    fn is_wireguard_interface(network_interface: &IpLink) -> bool {
        network_interface
            .linkinfo()
            .and_then(|link_info| link_info.info_kind())
            .is_some_and(|info_kind| info_kind == "wireguard")
    }

    /// Determines the state of an interface from its network interface and whether wg could read
    /// its state.
    fn interface_state(
        network_interface: Option<&IpLink>,
        is_running: bool,
    ) -> WireGuardInterfaceState {
        let Some(network_interface) = network_interface else {
            return WireGuardInterfaceState::Missing;
        };

        if !is_wireguard_interface(network_interface) {
            return WireGuardInterfaceState::Error;
        }

        if !is_running {
            return WireGuardInterfaceState::Unknown;
        }

        if network_interface.flags().any(|flag| *flag == LinkFlag::Up) {
            WireGuardInterfaceState::Up
        } else {
            WireGuardInterfaceState::Down
        }
    }

    /// Parses the lines describing the interfaces themselves in the `wg show all dump` output.
    ///
    /// Returns the public key, which is unset if the interface has no private key, and the listen
    /// port of each interface in `interfaces`. Lines of other interfaces are skipped without being
    /// parsed.
    fn parse_running_interfaces<'a>(
        wg_dump_output: &'a str,
        interfaces: &HashSet<&str>,
    ) -> Result<HashMap<&'a str, (Option<PublicKey>, u16)>, anyhow::Error> {
        let mut running_interfaces = HashMap::new();
        let mut last_interface = None;

        for line in wg_dump_output.lines() {
            let mut parts = line.split('\t');

            let interface = parts.next().ok_or_else(|| {
                anyhow::anyhow!("could not read interface name from `wg show all dump` output")
            })?;

            // the first line of each interface describes the interface itself, the following
            // lines describe its peers
            if last_interface == Some(interface) {
                continue;
            }

            last_interface = Some(interface);

            if !interfaces.contains(interface) {
                continue;
            }

            // skip the private key
            parts.next().ok_or_else(|| {
                anyhow::anyhow!("could not read private key from `wg show all dump` output")
            })?;

            // wg prints "(none)" as public key if no private key is set
            let public_key = match parts.next().ok_or_else(|| {
                anyhow::anyhow!("could not read public key from `wg show all dump` output")
            })? {
                "(none)" => None,
                public_key => Some(public_key.parse().with_context(
                    || "could not parse public key from `wg show all dump` output",
                )?),
            };

            let listen_port: u16 = parts
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("could not read listen port from `wg show all dump` output")
                })?
                .parse()
                .with_context(|| "could not parse listen_port from `wg show all dump` output")?;

            running_interfaces.insert(interface, (public_key, listen_port));
        }

        Ok(running_interfaces)
    }

    /// Returns the status of every interface the fabric configuration defines for the node.
    ///
    /// Interfaces that do not exist or whose state wg could not read are included as well.
    /// Properties that cannot be determined from the running state are omitted instead of being
    /// taken from the configuration.
    pub fn parse_wireguard_interfaces(
        wg_dump_output: &str,
        node_section: &NodeSection<WireGuardNode>,
        network_interfaces: &HashMap<String, IpLink>,
    ) -> Result<Vec<InterfaceStatus>, anyhow::Error> {
        let WireGuardNode::Internal(wireguard_node) = node_section.properties() else {
            anyhow::bail!("is not an internal node");
        };

        let interfaces: HashSet<&str> = wireguard_node
            .interfaces()
            .map(|interface| interface.name().as_ref())
            .collect();

        let running_interfaces = parse_running_interfaces(wg_dump_output, &interfaces)?;

        // Report every configured interface, so that interfaces which do not exist or whose
        // state could not be read by wg do not silently vanish from the status.
        let interface_status = wireguard_node
            .interfaces()
            .map(|interface| {
                let name = interface.name().as_ref();
                let running_interface = running_interfaces.get(name);
                let network_interface = network_interfaces.get(name);

                let state = interface_state(network_interface, running_interface.is_some());

                // do not report the kind of other interfaces, since anyone who can configure the
                // fabric could otherwise query it for any interface on the node
                let ty = network_interface
                    .is_some_and(is_wireguard_interface)
                    .then(|| "wireguard".to_string());

                let (public_key, listen_port) = match running_interface {
                    Some((public_key, listen_port)) => (*public_key, Some(*listen_port)),
                    None => (None, None),
                };

                InterfaceStatus {
                    name: name.to_string(),
                    ty,
                    state,
                    public_key,
                    listen_port,
                }
            })
            .collect();

        Ok(interface_status)
    }

    /// Returns the node section of `node_id` if it is an internal node of the fabric.
    ///
    /// An external peer can have the name of a node that is not part of the fabric, but does not
    /// make that node a member.
    fn internal_node_section<'a>(
        fabric: &'a Entry<WireGuardProperties, WireGuardNode>,
        node_id: &NodeId,
    ) -> Option<&'a NodeSection<WireGuardNode>> {
        fabric
            .node_section(node_id)
            .ok()
            .filter(|section| matches!(section.properties(), WireGuardNode::Internal(_)))
    }

    /// Returns the status of the interfaces of the node `node_id` in the fabric.
    ///
    /// If the node is not part of the fabric, an empty list is returned without querying WireGuard
    /// or the network interfaces.
    pub fn get_interfaces(
        fabric: &Entry<WireGuardProperties, WireGuardNode>,
        node_id: &NodeId,
        wg_dump: impl FnOnce() -> Result<String, anyhow::Error>,
        network_interfaces: impl FnOnce() -> Result<HashMap<String, IpLink>, anyhow::Error>,
    ) -> Result<Vec<InterfaceStatus>, anyhow::Error> {
        let Some(node_section) = internal_node_section(fabric, node_id) else {
            return Ok(Vec::new());
        };

        parse_wireguard_interfaces(&wg_dump()?, node_section, &network_interfaces()?)
    }

    /// Returns `None` for values that wg prints as "(none)".
    fn optional_value(value: &str) -> Option<&str> {
        (value != "(none)").then_some(value)
    }

    /// Parses the peers of the fabric interfaces in the `wg show all dump` output.
    ///
    /// `now` is the current time (UNIX epoch), which is used for determining the status of the
    /// peers.
    pub fn parse_wireguard_neighbors(
        wg_dump_output: &str,
        node_section: &NodeSection<WireGuardNode>,
        fabric: &Entry<WireGuardProperties, WireGuardNode>,
        now: i64,
    ) -> Result<Vec<NeighborStatus>, anyhow::Error> {
        let WireGuardNode::Internal(wireguard_node) = node_section.properties() else {
            anyhow::bail!("is not an internal node");
        };

        let mut neighbors = Vec::new();
        let mut last_interface = None;

        // the names of the configured peers of each interface, by their public key
        let mut peer_names = HashMap::new();

        for interface in wireguard_node.interfaces() {
            let interface_name: &str = interface.name().as_ref();

            let names: HashMap<PublicKey, String> = fabric
                .interface_peers(node_section.id().node_id(), interface_name)?
                .into_iter()
                .map(|peer| {
                    let name = match &peer {
                        WireGuardInterfacePeer::Internal {
                            node_id, interface, ..
                        } => format!("{node_id} ({})", interface.name()),
                        WireGuardInterfacePeer::External { node_id, .. } => node_id.to_string(),
                    };

                    (*peer.public_key(), name)
                })
                .collect();

            peer_names.insert(interface_name, names);
        }

        for line in wg_dump_output.lines() {
            let mut parts = line.split('\t');

            let interface = parts.next().ok_or_else(|| {
                anyhow::anyhow!("could not read interface name from `wg show all dump` output")
            })?;

            // the first line of each interface describes the interface itself, the following
            // lines describe its peers
            if last_interface != Some(interface) {
                last_interface = Some(interface);
                continue;
            }

            let Some(names) = peer_names.get(interface) else {
                continue;
            };

            let public_key: PublicKey = parts
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("could not read public key from `wg show all dump` output")
                })?
                .parse()
                .with_context(|| "could not parse public key from `wg show all dump` output")?;

            // skip the preshared key
            parts.next().ok_or_else(|| {
                anyhow::anyhow!("could not read preshared key from `wg show all dump` output")
            })?;

            // this is the endpoint currently used by WireGuard, which can differ from the
            // configured one, e.g. if the peer is behind NAT
            let neighbor = parts
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("could not read neighbor from `wg show all dump` output")
                })
                .map(optional_value)?
                .map(str::to_string);

            let allowed_ips = parts
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("could not read allowed ips from `wg show all dump` output")
                })
                .map(optional_value)?
                .map(str::to_string);

            // wg prints 0 if no handshake happened yet
            let latest_handshake = parts
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "could not read latest handshake from `wg show all dump` output"
                    )
                })?
                .parse()
                .map(|latest_handshake| (latest_handshake != 0).then_some(latest_handshake))
                .with_context(|| "could not parse latest_handshake timestamp")?;

            let bytes_rx = parts
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("could not read received bytes from `wg show all dump` output")
                })?
                .parse()
                .with_context(|| "could not parse received bytes")?;

            let bytes_tx = parts
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "could not read transmitted bytes from `wg show all dump` output"
                    )
                })?
                .parse()
                .with_context(|| "could not parse transmitted bytes")?;

            let persistent_keepalive = match parts.next().ok_or_else(|| {
                anyhow::anyhow!(
                    "could not read persistent_keepalive from `wg show all dump` output"
                )
            })? {
                "off" => None,
                persistent_keepalive => Some(
                    persistent_keepalive
                        .parse()
                        .with_context(|| "could not parse persistent_keepalive interval")?,
                ),
            };

            // peers that are not part of the fabric configuration, e.g. because applying it
            // failed on this node, are still reported, but without a name
            let name = names.get(&public_key).cloned();

            neighbors.push(NeighborStatus {
                neighbor,
                name,
                status: PeerStatus::from_handshake(latest_handshake, persistent_keepalive, now),
                interface: interface.to_string(),
                public_key,
                allowed_ips,
                latest_handshake,
                bytes_rx,
                bytes_tx,
                persistent_keepalive,
            });
        }

        Ok(neighbors)
    }

    /// Returns the status of the neighbors of the node `node_id` in the fabric.
    ///
    /// If the node is not part of the fabric, an empty list is returned without querying WireGuard.
    pub fn get_neighbors(
        fabric: &Entry<WireGuardProperties, WireGuardNode>,
        node_id: &NodeId,
        wg_dump: impl FnOnce() -> Result<String, anyhow::Error>,
        now: i64,
    ) -> Result<Vec<NeighborStatus>, anyhow::Error> {
        let Some(node_section) = internal_node_section(fabric, node_id) else {
            return Ok(Vec::new());
        };

        parse_wireguard_neighbors(&wg_dump()?, node_section, fabric, now)
    }

    /// Checks whether WireGuard on this node matches the fabric configuration.
    ///
    /// This is the case if all configured interfaces are up and use their configured public key
    /// and, unless it is 0, their configured listen port, and the running WireGuard configuration
    /// of each interface contains exactly the configured peers. Handshakes are not considered,
    /// since peers do not exchange any if no traffic is sent and persistent keepalive is disabled.
    pub fn is_node_ok(
        wg_dump_output: &str,
        node_section: &NodeSection<WireGuardNode>,
        fabric: &Entry<WireGuardProperties, WireGuardNode>,
        network_interfaces: &HashMap<String, IpLink>,
    ) -> Result<bool, anyhow::Error> {
        let interfaces =
            parse_wireguard_interfaces(wg_dump_output, node_section, network_interfaces)?;

        if interfaces
            .iter()
            .any(|interface| interface.state != WireGuardInterfaceState::Up)
        {
            return Ok(false);
        }

        let WireGuardNode::Internal(wireguard_node) = node_section.properties() else {
            anyhow::bail!("is not an internal node");
        };

        let interface_names: HashSet<&str> = wireguard_node
            .interfaces()
            .map(|interface| interface.name().as_ref())
            .collect();

        let running_interfaces = parse_running_interfaces(wg_dump_output, &interface_names)?;

        // peers only reach the interface with the configured public key and listen port, which can
        // differ from the running ones if e.g. a key rotation failed to apply or the private key is
        // unset
        for interface in wireguard_node.interfaces() {
            let Some((Some(public_key), listen_port)) =
                running_interfaces.get(interface.name().as_ref())
            else {
                return Ok(false);
            };

            // a configured listen port of 0 lets the kernel choose the port
            let other_listen_port =
                interface.listen_port() != 0 && *listen_port != interface.listen_port();

            if public_key != interface.public_key() || other_listen_port {
                return Ok(false);
            }
        }

        let mut running_peers: HashMap<String, HashSet<PublicKey>> = HashMap::new();

        // the status of the peers does not matter here, only whether they are present
        let now = proxmox_time::epoch_i64();

        for neighbor in parse_wireguard_neighbors(wg_dump_output, node_section, fabric, now)? {
            running_peers
                .entry(neighbor.interface)
                .or_default()
                .insert(neighbor.public_key);
        }

        for interface in interfaces {
            let configured_peers: HashSet<PublicKey> = fabric
                .interface_peers(node_section.id().node_id(), &interface.name)?
                .into_iter()
                .map(|peer| *peer.public_key())
                .collect();

            let running_peers = running_peers.remove(&interface.name).unwrap_or_default();

            // peers that are missing as well as stale ones, e.g. because applying the
            // configuration failed on this node, mean that the configuration is not in effect
            if configured_peers != running_peers {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

mod bgp {
    use serde::Serialize;

    /// The status of a BGP neighbor.
    #[derive(Debug, Serialize, PartialEq, Eq)]
    pub struct NeighborStatus {
        pub neighbor: String,
        pub status: String,
        pub uptime: String,
    }

    /// The status of a BGP fabric interface.
    #[derive(Debug, Serialize, PartialEq, Eq)]
    pub struct InterfaceStatus {
        pub name: String,
        pub state: super::InterfaceState,
    }
}

/// Common NeighborStatus that contains either OSPF, Openfabric, or BGP neighbors
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum NeighborStatus {
    Openfabric(Vec<openfabric::NeighborStatus>),
    Ospf(Vec<ospf::NeighborStatus>),
    WireGuard(Vec<wireguard::NeighborStatus>),
    Bgp(Vec<bgp::NeighborStatus>),
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
impl From<Vec<wireguard::NeighborStatus>> for NeighborStatus {
    fn from(value: Vec<wireguard::NeighborStatus>) -> Self {
        NeighborStatus::WireGuard(value)
    }
}
impl From<Vec<bgp::NeighborStatus>> for NeighborStatus {
    fn from(value: Vec<bgp::NeighborStatus>) -> Self {
        NeighborStatus::Bgp(value)
    }
}

/// Common InterfaceStatus that contains either OSPF, Openfabric, or BGP interfaces
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum InterfaceStatus {
    Openfabric(Vec<openfabric::InterfaceStatus>),
    Ospf(Vec<ospf::InterfaceStatus>),
    WireGuard(Vec<wireguard::InterfaceStatus>),
    Bgp(Vec<bgp::InterfaceStatus>),
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
impl From<Vec<wireguard::InterfaceStatus>> for InterfaceStatus {
    fn from(value: Vec<wireguard::InterfaceStatus>) -> Self {
        InterfaceStatus::WireGuard(value)
    }
}
impl From<Vec<bgp::InterfaceStatus>> for InterfaceStatus {
    fn from(value: Vec<bgp::InterfaceStatus>) -> Self {
        InterfaceStatus::Bgp(value)
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
    /// WireGuard
    WireGuard,
    /// BGP
    Bgp,
}

/// The status of a fabric.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub enum FabricStatus {
    /// The fabric exists and has a route, or for WireGuard, all interfaces are up and all peers
    /// are present
    #[serde(rename = "ok")]
    Ok,
    /// The fabric does not exist or doesn't distribute any routes, or for WireGuard, an interface
    /// is not up or a peer is missing
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
    #[serde(rename = "network-type")]
    network_type: String,
}

/// Runtime state of WireGuard on this node
///
/// Consists of the output of `wg show all dump` and the network interfaces as reported by
/// `ip link`.
pub struct WireGuardParsed {
    pub dump: String,
    pub network_interfaces: HashMap<String, IpLink>,
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
    /// All bgp routes in FRR
    pub bgp: de::Routes,
}

/// Config used to parse the fabric part of the running-config
#[derive(Deserialize)]
pub struct RunningConfig {
    pub fabrics: Option<FabricsRunningConfig>,
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
            ConfigNode::WireGuard(_) => HashSet::new(),
            ConfigNode::Bgp(n) => match n.properties() {
                BgpNode::Internal(props) => props.interfaces().map(|i| i.name().as_str()).collect(),
                BgpNode::External(_) => HashSet::new(),
            },
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

/// Extract status output nested under a VRF name, or return non-VRF output unchanged.
pub fn extract_vrf_status(
    mut output: serde_json::Value,
    vrf: Option<&str>,
) -> Result<serde_json::Value, anyhow::Error> {
    match vrf {
        Some(vrf) => output
            .get_mut(vrf)
            .map(serde_json::Value::take)
            .ok_or_else(|| anyhow::anyhow!("missing status for VRF '{vrf}'")),
        None => Ok(output),
    }
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

/// Convert the `show bgp neighbors json` output into a list of [`bgp::NeighborStatus`].
///
/// BGP neighbors are filtered by the fabric's peer-group name (which matches the fabric ID).
pub fn get_neighbors_bgp(
    fabric_id: FabricId,
    neighbors: BTreeMap<String, BgpNeighborInfo>,
) -> Result<Vec<bgp::NeighborStatus>, anyhow::Error> {
    let mut stats = Vec::new();

    for (peer_name, info) in &neighbors {
        if info.peer_group.as_deref() == Some(fabric_id.as_str()) {
            stats.push(bgp::NeighborStatus {
                neighbor: peer_name.clone(),
                status: info.bgp_state.clone(),
                uptime: info.bgp_timer_up_string.clone().unwrap_or_default(),
            });
        }
    }

    Ok(stats)
}

/// Convert the `show bgp neighbors json` output into a list of [`bgp::InterfaceStatus`].
///
/// For BGP unnumbered, each interface peer maps to a fabric interface.
pub fn get_interfaces_bgp(
    fabric_id: FabricId,
    neighbors: BTreeMap<String, BgpNeighborInfo>,
) -> Result<Vec<bgp::InterfaceStatus>, anyhow::Error> {
    let mut stats = Vec::new();

    for (peer_name, info) in &neighbors {
        if info.peer_group.as_deref() == Some(fabric_id.as_str()) {
            stats.push(bgp::InterfaceStatus {
                name: peer_name.clone(),
                state: if info.bgp_state == "Established" {
                    InterfaceState::Up
                } else {
                    InterfaceState::Down
                },
            });
        }
    }

    Ok(stats)
}

/// Minimal BGP neighbor info from `show bgp neighbors json`
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BgpNeighborInfo {
    pub bgp_state: String,
    pub peer_group: Option<String>,
    pub bgp_timer_up_string: Option<String>,
}

/// Get the status for each fabric using the parsed routes from frr
///
/// Using the parsed routes we get from frr, filter and map them to a HashMap mapping every
/// fabric to a status struct containing basic info about the fabric and the status (if it
/// propagates a route).
pub fn get_status(
    config: Valid<FabricConfig>,
    routes: RoutesParsed,
    wireguard: Option<&WireGuardParsed>,
    hostname: &str,
) -> Result<HashMap<FabricId, Status>, anyhow::Error> {
    let mut stats: HashMap<FabricId, Status> = HashMap::new();

    for (nodeid, node) in config.all_nodes() {
        if nodeid.as_str() != hostname {
            continue;
        }
        let fabric_id = node.id().fabric_id();
        let vrf_name = config
            .get_fabric(fabric_id)?
            .fabric_vrf_name()
            .unwrap_or_else(|| "default".to_string());

        let (current_protocol, all_routes) = match &node {
            ConfigNode::Openfabric(_) => (Protocol::Openfabric, &routes.openfabric.0),
            ConfigNode::Ospf(_) => (Protocol::Ospf, &routes.ospf.0),
            ConfigNode::WireGuard(_) => (Protocol::WireGuard, &BTreeMap::new()),
            ConfigNode::Bgp(_) => (Protocol::Bgp, &routes.bgp.0),
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
            ConfigNode::WireGuard(_n) => HashSet::new(),
            ConfigNode::Bgp(n) => match n.properties() {
                BgpNode::Internal(props) => props.interfaces().map(|i| i.name().as_str()).collect(),
                BgpNode::External(_) => HashSet::new(),
            },
        };

        // determine status by checking if any routes exist for our interfaces
        let has_routes = all_routes.values().any(|v| {
            v.iter().any(|route| {
                route.vrf_name == vrf_name
                    && route.nexthops.iter().any(|nexthop| {
                        if let Some(iface_name) = &nexthop.interface_name {
                            interface_names.contains(iface_name.as_str())
                        } else {
                            false
                        }
                    })
            })
        });

        let status = match current_protocol {
            Protocol::Openfabric if has_routes => FabricStatus::Ok,
            Protocol::Ospf if has_routes => FabricStatus::Ok,
            Protocol::Bgp if has_routes => FabricStatus::Ok,
            Protocol::WireGuard => get_wireguard_status(&config, node, wireguard),
            _ => FabricStatus::NotOk,
        };

        let fabric = Status {
            ty: "network".to_owned(),
            status,
            protocol: current_protocol,
            network: fabric_id.clone(),
            network_type: "fabric".to_string(),
        };
        stats.insert(fabric_id.clone(), fabric);
    }

    Ok(stats)
}

/// Determine the status of a WireGuard fabric on this node.
///
/// Errors only mark the WireGuard fabric as not ok, so that they do not affect the status of the
/// other fabrics.
fn get_wireguard_status(
    config: &FabricConfig,
    node: &ConfigNode,
    wireguard: Option<&WireGuardParsed>,
) -> FabricStatus {
    let (ConfigNode::WireGuard(node_section), Some(wireguard)) = (node, wireguard) else {
        return FabricStatus::NotOk;
    };

    let Ok(FabricEntry::WireGuard(fabric)) = config.get_fabric(node_section.id().fabric_id())
    else {
        return FabricStatus::NotOk;
    };

    match wireguard::is_node_ok(
        &wireguard.dump,
        node_section,
        fabric,
        &wireguard.network_interfaces,
    ) {
        Ok(true) => FabricStatus::Ok,
        _ => FabricStatus::NotOk,
    }
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
        let section_config = SectionConfigData::from_iter(
            running_config.fabrics.expect("no fabrics configured").ids,
        );
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
        let section_config = SectionConfigData::from_iter(
            running_config.fabrics.expect("no fabrics configured").ids,
        );
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

            let neighbors: de::ospf::Neighbors =
                serde_json::from_str(json_output).expect("error parsing json output");

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
        fn neighbors_vrf() {
            let json_output = r#"
            {
              "vrf_vrf": {
                "vrfName": "vrf_vrf",
                "vrfId": 6,
                "neighbors": {
                  "4.4.4.3": [{
                    "nbrState": "Full\/-",
                    "upTime": "13m35s",
                    "ifaceAddress": "4.4.4.3",
                    "ifaceName": "nic1:4.4.4.1"
                  }],
                  "4.4.4.2": [{
                    "nbrState": "Full\/-",
                    "upTime": "13m35s",
                    "ifaceAddress": "4.4.4.2",
                    "ifaceName": "nic2:4.4.4.1"
                  }]
                }
              },
              "other_vrf": { "neighbors": {} }
            }
            "#;

            let output = serde_json::from_str(json_output).unwrap();
            let output = extract_vrf_status(output, Some("vrf_vrf")).unwrap();
            let neighbors: de::ospf::Neighbors = serde_json::from_value(output).unwrap();
            assert_eq!(neighbors.neighbors.len(), 2);
            for (address, interface) in [("4.4.4.3", "nic1"), ("4.4.4.2", "nic2")] {
                let neighbor = &neighbors.neighbors[address];
                assert_eq!(neighbor.len(), 1);
                assert_eq!(neighbor[0].interface_address, address);
                assert_eq!(neighbor[0].interface_name, format!("{interface}:4.4.4.1"));
                assert_eq!(neighbor[0].neighbor_state, "Full/-");
                assert_eq!(neighbor[0].up_time, "13m35s");
            }
        }

        #[test]
        fn interfaces_vrf() {
            let json_output = r#"
            {
              "vrf_vrf": {
                "vrfName": "vrf_vrf",
                "vrfId": 6,
                "interfaces": {
                  "dummy_fabric": { "ifUp": true, "networkType": "BROADCAST" },
                  "nic1": { "ifUp": true, "networkType": "POINTOPOINT" },
                  "nic2": { "ifUp": true, "networkType": "POINTOPOINT" }
                }
              },
              "other_vrf": { "interfaces": {} }
            }
            "#;

            let output = serde_json::from_str(json_output).unwrap();
            let output = extract_vrf_status(output, Some("vrf_vrf")).unwrap();
            let interfaces: de::ospf::Interfaces = serde_json::from_value(output).unwrap();
            assert_eq!(interfaces.interfaces.len(), 3);
            for (name, ty) in [
                ("dummy_fabric", de::ospf::NetworkType::Broadcast),
                ("nic1", de::ospf::NetworkType::PointToPoint),
                ("nic2", de::ospf::NetworkType::PointToPoint),
            ] {
                let interface = &interfaces.interfaces[name];
                assert!(interface.if_up);
                assert_eq!(interface.network_type, ty);
            }
        }

        #[test]
        fn extract_non_vrf_status() {
            for output in [
                serde_json::json!({ "neighbors": {} }),
                serde_json::json!({ "interfaces": {} }),
            ] {
                assert_eq!(extract_vrf_status(output.clone(), None).unwrap(), output);
            }
        }

        #[test]
        fn extract_missing_vrf_status() {
            let output = serde_json::json!({ "other_vrf": { "neighbors": {} } });
            assert!(extract_vrf_status(output, Some("vrf_vrf")).is_err());
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

            let neighbors: de::ospf::Neighbors =
                serde_json::from_str(json_output).expect("error parsing json output");

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

            let interfaces: de::ospf::Interfaces =
                serde_json::from_str(json_output).expect("error parsing json output");

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

            let interfaces: de::ospf::Interfaces =
                serde_json::from_str(json_output).expect("error parsing json output");

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

    mod wireguard {
        use std::str::FromStr;

        use proxmox_network_api::IpLink;
        use proxmox_section_config::typed::ApiSectionDataEntry;
        use proxmox_ve_config::sdn::fabric::FabricEntry;
        use proxmox_ve_config::sdn::fabric::section_config::node::NodeSection;
        use proxmox_ve_config::sdn::fabric::section_config::protocol::wireguard::{
            WireGuardNode, WireGuardProperties,
        };

        use super::super::wireguard::{
            InterfaceStatus, NeighborStatus, PeerStatus, WireGuardInterfaceState, get_interfaces,
            get_neighbors, is_node_ok, parse_wireguard_interfaces, parse_wireguard_neighbors,
        };
        use super::super::*;

        /// Parses the fabric configuration that all tests use.
        ///
        /// The tests take the view of the node elementalist: it has the interfaces wg1 (with the
        /// external peer stormweaver) and wg0 (with the internal peers occultist and chronomancer).
        fn fabric_config() -> Valid<FabricConfig> {
            let raw_config = r#"wireguard_fabric: test

wireguard_node: test_chronomancer
        endpoint 172.31.1.4
        interfaces name=wg1,listen_port=51821,public_key=+RAKruThY8Qx/oLKRoqYZ4DZJwd9/BO3lVVAR6INNTo=
        interfaces name=wg0,listen_port=51820,public_key=8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=,ip=198.51.100.4/24
        peers type=internal,node=elementalist,node_iface=wg0,iface=wg0
        peers type=internal,node=occultist,node_iface=wg0,iface=wg0
        peers type=external,node=stormweaver,iface=wg1
        role internal

wireguard_node: test_elementalist
        endpoint 172.31.1.1
        interfaces name=wg1,listen_port=51821,public_key=Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=
        interfaces name=wg0,listen_port=51820,public_key=AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=,ip=198.51.100.1/24
        peers type=internal,node=occultist,node_iface=wg0,iface=wg0
        peers type=internal,node=chronomancer,node_iface=wg0,iface=wg0
        peers type=external,node=stormweaver,iface=wg1
        role internal

wireguard_node: test_occultist
        allowed_ips 203.0.113.0/28
        endpoint 172.31.1.2
        interfaces name=wg1,listen_port=51821,public_key=UBvDcsMICJLpy/+aRpJXFbDfU4eZrBeWnHimjzla/SI=
        interfaces name=wg0,listen_port=51820,public_key=+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=,ip=198.51.100.2/24
        peers type=external,node=stormweaver,iface=wg1
        peers type=internal,node=elementalist,node_iface=wg0,iface=wg0
        peers type=internal,node=chronomancer,node_iface=wg0,iface=wg0
        role internal

wireguard_node: test_stormweaver
        endpoint 172.31.1.10:51820
        public_key aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=
        role external"#;

            let section_config = Section::parse_section_config("fabrics.cfg", raw_config)
                .expect("valid section config");

            FabricConfig::from_section_config(section_config).expect("valid fabric configuration")
        }

        fn wireguard_fabric(config: &FabricConfig) -> &Entry<WireGuardProperties, WireGuardNode> {
            let fabric_id = FabricId::from_str("test").expect("valid fabric id");

            let Ok(FabricEntry::WireGuard(fabric)) = config.get_fabric(&fabric_id) else {
                panic!("fabric is not a wireguard fabric");
            };

            fabric
        }

        fn elementalist(
            fabric: &Entry<WireGuardProperties, WireGuardNode>,
        ) -> &NodeSection<WireGuardNode> {
            let node_id = NodeId::from_str("elementalist").expect("valid node id");

            fabric
                .node_section(&node_id)
                .expect("node exists in fabric")
        }

        /// Parses the output of `ip -details -json link show`.
        fn network_interfaces(ip_link_output: &str) -> HashMap<String, IpLink> {
            serde_json::from_str::<Vec<IpLink>>(ip_link_output)
                .expect("valid ip link output")
                .into_iter()
                .map(|ip_link| (ip_link.name().to_string(), ip_link))
                .collect()
        }

        #[test]
        fn interfaces_up_and_down() {
            // wg0 is up, wg1 is down
            let wg_dump = r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off
wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]},
                {"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "DOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            let expected = vec![
                InterfaceStatus {
                    name: "wg1".to_string(),
                    ty: Some("wireguard".to_string()),
                    state: WireGuardInterfaceState::Down,
                    public_key: Some(
                        "Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM="
                            .parse()
                            .expect("valid public key"),
                    ),
                    listen_port: Some(51821),
                },
                InterfaceStatus {
                    name: "wg0".to_string(),
                    ty: Some("wireguard".to_string()),
                    state: WireGuardInterfaceState::Up,
                    public_key: Some(
                        "AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M="
                            .parse()
                            .expect("valid public key"),
                    ),
                    listen_port: Some(51820),
                },
            ];

            assert_eq!(
                expected,
                parse_wireguard_interfaces(wg_dump, elementalist(fabric), &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn interface_missing() {
            // wg1 does not exist on the node, so there is no public key or listen port to report
            let wg_dump = r#"wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            let expected = vec![
                InterfaceStatus {
                    name: "wg1".to_string(),
                    ty: None,
                    state: WireGuardInterfaceState::Missing,
                    public_key: None,
                    listen_port: None,
                },
                InterfaceStatus {
                    name: "wg0".to_string(),
                    ty: Some("wireguard".to_string()),
                    state: WireGuardInterfaceState::Up,
                    public_key: Some(
                        "AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M="
                            .parse()
                            .expect("valid public key"),
                    ),
                    listen_port: Some(51820),
                },
            ];

            assert_eq!(
                expected,
                parse_wireguard_interfaces(wg_dump, elementalist(fabric), &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn interface_unknown() {
            // wg1 exists, but is missing from the wg output, since wg could not read it
            let wg_dump = r#"wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]},
                {"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            let expected = vec![
                InterfaceStatus {
                    name: "wg1".to_string(),
                    ty: Some("wireguard".to_string()),
                    state: WireGuardInterfaceState::Unknown,
                    public_key: None,
                    listen_port: None,
                },
                InterfaceStatus {
                    name: "wg0".to_string(),
                    ty: Some("wireguard".to_string()),
                    state: WireGuardInterfaceState::Up,
                    public_key: Some(
                        "AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M="
                            .parse()
                            .expect("valid public key"),
                    ),
                    listen_port: Some(51820),
                },
            ];

            assert_eq!(
                expected,
                parse_wireguard_interfaces(wg_dump, elementalist(fabric), &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn interface_without_private_key() {
            // wg0 has no private key, so wg reports no public key, and its running listen port
            // differs from the configured one
            let wg_dump = r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off
wg0	(none)	(none)	51830	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]},
                {"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            let expected = vec![
                InterfaceStatus {
                    name: "wg1".to_string(),
                    ty: Some("wireguard".to_string()),
                    state: WireGuardInterfaceState::Up,
                    public_key: Some(
                        "Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM="
                            .parse()
                            .expect("valid public key"),
                    ),
                    listen_port: Some(51821),
                },
                InterfaceStatus {
                    name: "wg0".to_string(),
                    ty: Some("wireguard".to_string()),
                    state: WireGuardInterfaceState::Up,
                    public_key: None,
                    listen_port: Some(51830),
                },
            ];

            assert_eq!(
                expected,
                parse_wireguard_interfaces(wg_dump, elementalist(fabric), &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn interface_not_wireguard() {
            // wg0 exists, but is not a WireGuard interface, so wg does not report it
            let wg_dump = r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off"#;

            let wg0_links = [
                // an interface of another kind
                r#"{"ifname": "wg0", "ifindex": 25, "link_type": "ether", "address": "a2:5f:3c:11:22:33", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "dummy"}, "flags": ["BROADCAST", "NOARP", "UP", "LOWER_UP"]}"#,
                // a physical NIC, which has no link kind
                r#"{"ifname": "wg0", "ifindex": 2, "link_type": "ether", "address": "bc:24:11:aa:bb:cc", "operstate": "UP", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"]}"#,
            ];

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            let expected = vec![
                InterfaceStatus {
                    name: "wg1".to_string(),
                    ty: Some("wireguard".to_string()),
                    state: WireGuardInterfaceState::Up,
                    public_key: Some(
                        "Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM="
                            .parse()
                            .expect("valid public key"),
                    ),
                    listen_port: Some(51821),
                },
                InterfaceStatus {
                    name: "wg0".to_string(),
                    ty: None,
                    state: WireGuardInterfaceState::Error,
                    public_key: None,
                    listen_port: None,
                },
            ];

            for wg0_link in wg0_links {
                let network_interfaces = network_interfaces(&format!(
                    r#"[
                    {wg0_link},
                    {{"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {{"info_kind": "wireguard"}}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}}
                ]"#,
                ));

                assert_eq!(
                    expected,
                    parse_wireguard_interfaces(wg_dump, elementalist(fabric), &network_interfaces)
                        .expect("can parse wireguard output")
                );
            }
        }

        #[test]
        fn interfaces_non_member_node() {
            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            // summoner is not part of the fabric, stormweaver is an external peer
            for node in ["summoner", "stormweaver"] {
                let interfaces = get_interfaces(
                    fabric,
                    &NodeId::from_str(node).expect("valid node id"),
                    || panic!("wg must not be queried"),
                    || panic!("network interfaces must not be queried"),
                )
                .expect("can get interfaces");

                assert!(interfaces.is_empty());
            }
        }

        #[test]
        fn neighbors() {
            // all configured peers are present, but there was no handshake yet
            let wg_dump = r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off
wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#;

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            let expected = vec![
                NeighborStatus {
                    neighbor: Some("172.31.1.10:51820".to_string()),
                    name: Some("stormweaver".to_string()),
                    status: PeerStatus::Idle,
                    interface: "wg1".to_string(),
                    public_key: "aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0="
                        .parse()
                        .expect("valid public key"),
                    allowed_ips: None,
                    latest_handshake: None,
                    bytes_rx: 0,
                    bytes_tx: 0,
                    persistent_keepalive: None,
                },
                NeighborStatus {
                    neighbor: Some("172.31.1.2:51820".to_string()),
                    name: Some("occultist (wg0)".to_string()),
                    status: PeerStatus::Idle,
                    interface: "wg0".to_string(),
                    public_key: "+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI="
                        .parse()
                        .expect("valid public key"),
                    allowed_ips: Some("198.51.100.2/32,203.0.113.0/28".to_string()),
                    latest_handshake: None,
                    bytes_rx: 0,
                    bytes_tx: 0,
                    persistent_keepalive: None,
                },
                NeighborStatus {
                    neighbor: Some("172.31.1.4:51820".to_string()),
                    name: Some("chronomancer (wg0)".to_string()),
                    status: PeerStatus::Idle,
                    interface: "wg0".to_string(),
                    public_key: "8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA="
                        .parse()
                        .expect("valid public key"),
                    allowed_ips: Some("198.51.100.4/32".to_string()),
                    latest_handshake: None,
                    bytes_rx: 0,
                    bytes_tx: 0,
                    persistent_keepalive: None,
                },
            ];

            assert_eq!(
                expected,
                parse_wireguard_neighbors(wg_dump, elementalist(fabric), fabric, 1781234627)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn neighbors_non_member_node() {
            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            // summoner is not part of the fabric, stormweaver is an external peer
            for node in ["summoner", "stormweaver"] {
                let neighbors = get_neighbors(
                    fabric,
                    &NodeId::from_str(node).expect("valid node id"),
                    || panic!("wg must not be queried"),
                    1781234627,
                )
                .expect("can get neighbors");

                assert!(neighbors.is_empty());
            }
        }

        #[test]
        fn neighbor_roamed() {
            // occultist is reachable via a different address than its configured endpoint, e.g. due to NAT
            let wg_dump = r#"wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	203.0.113.50:40123	198.51.100.2/32,203.0.113.0/28	1781234567	1024	2048	25"#;

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            let expected = vec![NeighborStatus {
                neighbor: Some("203.0.113.50:40123".to_string()),
                name: Some("occultist (wg0)".to_string()),
                status: PeerStatus::Active,
                interface: "wg0".to_string(),
                public_key: "+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI="
                    .parse()
                    .expect("valid public key"),
                allowed_ips: Some("198.51.100.2/32,203.0.113.0/28".to_string()),
                latest_handshake: Some(1781234567),
                bytes_rx: 1024,
                bytes_tx: 2048,
                persistent_keepalive: Some(25),
            }];

            assert_eq!(
                expected,
                parse_wireguard_neighbors(wg_dump, elementalist(fabric), fabric, 1781234627)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn neighbor_without_endpoint() {
            // chronomancer has no endpoint, since it has not connected yet
            let wg_dump = r#"wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	(none)	198.51.100.4/32	0	0	0	off"#;

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            let expected = vec![NeighborStatus {
                neighbor: None,
                name: Some("chronomancer (wg0)".to_string()),
                status: PeerStatus::Idle,
                interface: "wg0".to_string(),
                public_key: "8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA="
                    .parse()
                    .expect("valid public key"),
                allowed_ips: Some("198.51.100.4/32".to_string()),
                latest_handshake: None,
                bytes_rx: 0,
                bytes_tx: 0,
                persistent_keepalive: None,
            }];

            assert_eq!(
                expected,
                parse_wireguard_neighbors(wg_dump, elementalist(fabric), fabric, 1781234627)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn neighbor_not_configured() {
            // the peer is not part of the fabric configuration, so it has no name
            let wg_dump = r#"wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=	(none)	(none)	(none)	0	0	0	off"#;

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            let expected = vec![NeighborStatus {
                neighbor: None,
                name: None,
                status: PeerStatus::Idle,
                interface: "wg0".to_string(),
                public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    .parse()
                    .expect("valid public key"),
                allowed_ips: None,
                latest_handshake: None,
                bytes_rx: 0,
                bytes_tx: 0,
                persistent_keepalive: None,
            }];

            assert_eq!(
                expected,
                parse_wireguard_neighbors(wg_dump, elementalist(fabric), fabric, 1781234627)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn node_ok() {
            // all interfaces are up and have exactly the configured peers
            let wg_dump = r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off
wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]},
                {"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            assert!(
                is_node_ok(wg_dump, elementalist(fabric), fabric, &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn node_not_ok_interface_down() {
            // wg1 is down
            let wg_dump = r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off
wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]},
                {"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "DOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            assert!(
                !is_node_ok(wg_dump, elementalist(fabric), fabric, &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn node_not_ok_interface_missing() {
            // wg1 does not exist on the node
            let wg_dump = r#"wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            assert!(
                !is_node_ok(wg_dump, elementalist(fabric), fabric, &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn node_not_ok_peer_missing() {
            // chronomancer is missing from wg0
            let wg_dump = r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off
wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]},
                {"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            assert!(
                !is_node_ok(wg_dump, elementalist(fabric), fabric, &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn node_not_ok_stale_peer() {
            // wg0 has a peer that is not part of the configuration
            let wg_dump = r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off
wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off
wg0	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=	(none)	(none)	(none)	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]},
                {"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            assert!(
                !is_node_ok(wg_dump, elementalist(fabric), fabric, &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn node_not_ok_other_public_key() {
            // wg0 uses a different key pair than the configured one
            let wg_dump = r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off
wg0	YJ8M0XCvVUu1x1Y2fdLmSQ8w1qtlDgFr3cZyfW8ivUc=	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]},
                {"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            assert!(
                !is_node_ok(wg_dump, elementalist(fabric), fabric, &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn node_not_ok_without_private_key() {
            // wg0 has no private key
            let wg_dump = r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off
wg0	(none)	(none)	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]},
                {"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            assert!(
                !is_node_ok(wg_dump, elementalist(fabric), fabric, &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn node_not_ok_other_listen_port() {
            // wg0 listens on 51899 instead of the configured 51820
            let wg_dump = r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off
wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51899	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#;

            let network_interfaces = network_interfaces(
                r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]},
                {"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}
            ]"#,
            );

            let config = fabric_config();
            let fabric = wireguard_fabric(&config);

            assert!(
                !is_node_ok(wg_dump, elementalist(fabric), fabric, &network_interfaces)
                    .expect("can parse wireguard output")
            );
        }

        #[test]
        fn fabric_status_ok() {
            // the running WireGuard state matches the configuration
            let wireguard = WireGuardParsed {
                dump: r#"wg1	wF2D1my5Cj962/MOS2UXLvCddm3ozmCSSuBQ1Ey6v3I=	Um+Z4Ymq3r24txH2itVVtC86ra1PIrFs9AeMebESdWM=	51821	off
wg1	aHnKVQ4yTtTdfwsk+r4Z12FrRlUnXXksjRcV7x41+G0=	(none)	172.31.1.10:51820	(none)	0	0	0	off
wg0	GDHQ8ivFvwz53U0bSmQ7uTD2bJ8GpcFCCxGeU1G9m2U=	AQkUKUJXOxR/QH6fjZLx8GO1ZnnD8PueRYMJNOCzc2M=	51820	off
wg0	+PA/xNCZ3G+Wy1DeqF251Us5mcZhBTGc9CT3AaJ89HI=	(none)	172.31.1.2:51820	198.51.100.2/32,203.0.113.0/28	0	0	0	off
wg0	8ybxvVfiWqpBG160nMgH14acR3z31ZeceW7ita0zonA=	(none)	172.31.1.4:51820	198.51.100.4/32	0	0	0	off"#.to_string(),
                network_interfaces: network_interfaces(r#"[
                {"ifname": "wg0", "ifindex": 25, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]},
                {"ifname": "wg1", "ifindex": 24, "link_type": "none", "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}, "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}
            ]"#),
            };

            let routes = RoutesParsed {
                openfabric: de::Routes::default(),
                ospf: de::Routes::default(),
                bgp: de::Routes::default(),
            };

            let status = get_status(fabric_config(), routes, Some(&wireguard), "elementalist")
                .expect("can determine fabric status");

            let fabric_id = FabricId::from_str("test").expect("valid fabric id");
            assert_eq!(FabricStatus::Ok, status[&fabric_id].status);
        }

        #[test]
        fn fabric_status_not_ok_without_wireguard_state() {
            // the WireGuard state could not be determined, e.g. because wg failed
            let routes = RoutesParsed {
                openfabric: de::Routes::default(),
                ospf: de::Routes::default(),
                bgp: de::Routes::default(),
            };

            let status = get_status(fabric_config(), routes, None, "elementalist")
                .expect("can determine fabric status");

            let fabric_id = FabricId::from_str("test").expect("valid fabric id");
            assert_eq!(FabricStatus::NotOk, status[&fabric_id].status);
        }

        #[test]
        fn peer_status_without_keepalive() {
            // without persistent keepalive, only a handshake within the last 180 seconds counts
            let now = 1781234567;

            assert_eq!(
                PeerStatus::from_handshake(Some(now as u64 - 179), None, now),
                PeerStatus::Active
            );
            assert_eq!(
                PeerStatus::from_handshake(Some(now as u64 - 180), None, now),
                PeerStatus::Idle
            );
            assert_eq!(
                PeerStatus::from_handshake(None, None, now),
                PeerStatus::Idle
            );
        }

        #[test]
        fn peer_status_with_keepalive() {
            // with a keepalive interval of 25 seconds, a reachable peer exchanges a handshake
            // within 180 + 25 + 90 seconds
            let now = 1781234567;

            assert_eq!(
                PeerStatus::from_handshake(Some(now as u64 - 294), Some(25), now),
                PeerStatus::Active
            );
            assert_eq!(
                PeerStatus::from_handshake(Some(now as u64 - 295), Some(25), now),
                PeerStatus::Down
            );
            assert_eq!(
                PeerStatus::from_handshake(None, Some(25), now),
                PeerStatus::Down
            );
        }

        #[test]
        fn peer_status_handshake_in_future() {
            // a handshake in the future, e.g. due to clock adjustments, counts as recent
            let now = 1781234567;

            assert_eq!(
                PeerStatus::from_handshake(Some(now as u64 + 10), None, now),
                PeerStatus::Active
            );
        }
    }
}
