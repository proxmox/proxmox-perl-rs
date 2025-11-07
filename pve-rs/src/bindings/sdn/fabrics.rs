#[perlmod::package(name = "PVE::RS::SDN::Fabrics", lib = "pve_rs")]
pub mod pve_rs_sdn_fabrics {
    //! The `PVE::RS::SDN::Fabrics` package.
    //!
    //! This provides the configuration for the SDN fabrics, as well as helper methods for reading
    //! / writing the configuration, as well as for generating ifupdown2 and FRR configuration.

    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::fmt::Write;
    use std::net::IpAddr;
    use std::ops::Deref;
    use std::process::Command;
    use std::sync::Mutex;

    use anyhow::{Context, Error, format_err};
    use openssl::hash::{MessageDigest, hash};
    use serde::{Deserialize, Serialize};

    use perlmod::Value;
    use proxmox_frr::ser::serializer::to_raw_config;
    use proxmox_network_types::ip_address::{Cidr, Ipv4Cidr, Ipv6Cidr};
    use proxmox_section_config::typed::SectionConfigData;
    use proxmox_ve_config::common::valid::{Valid, Validatable};

    use proxmox_ve_config::sdn::config::{SdnConfig, ZoneConfig};
    use proxmox_ve_config::sdn::fabric::section_config::Section;
    use proxmox_ve_config::sdn::fabric::section_config::fabric::{
        Fabric as ConfigFabric, FabricId,
        api::{Fabric, FabricUpdater},
    };
    use proxmox_ve_config::sdn::fabric::section_config::interface::InterfaceName;
    use proxmox_ve_config::sdn::fabric::section_config::node::{
        Node as ConfigNode, NodeId,
        api::{Node, NodeUpdater},
    };
    use proxmox_ve_config::sdn::fabric::{FabricConfig, FabricEntry};
    use proxmox_ve_config::sdn::frr::FrrConfigBuilder;

    use crate::sdn::status::{self, RunningConfig};

    /// A SDN Fabric config instance.
    #[derive(Serialize, Deserialize)]
    pub struct PerlFabricConfig {
        /// The fabric config instance
        pub fabric_config: Mutex<FabricConfig>,
    }

    perlmod::declare_magic!(Box<PerlFabricConfig> : &PerlFabricConfig as "PVE::RS::SDN::Fabrics::Config");

    /// Represents an interface as returned by the `GET /nodes/{node}/network` endpoint in PVE.
    ///
    /// This is used for returning fabrics in the endpoint, so they can be used from various places
    /// in the PVE UI (e.g. migration network settings).
    #[derive(Serialize)]
    pub struct PveInterface {
        iface: String,
        #[serde(rename = "type")]
        ty: String,
        active: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        cidr: Option<Ipv4Cidr>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cidr6: Option<Ipv6Cidr>,
    }

    impl From<ConfigFabric> for PveInterface {
        fn from(fabric: ConfigFabric) -> Self {
            Self {
                iface: fabric.id().to_string(),
                ty: "fabric".to_string(),
                active: true,
                cidr: fabric.ip_prefix(),
                cidr6: fabric.ip6_prefix(),
            }
        }
    }

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

    /// Method: Returns all fabrics and nodes from the configuration.
    #[export]
    pub fn list_all(
        #[try_from_ref] this: &PerlFabricConfig,
    ) -> (BTreeMap<String, Fabric>, BTreeMap<String, Node>) {
        let config = this.fabric_config.lock().unwrap();

        let mut fabrics = BTreeMap::new();
        let mut nodes = BTreeMap::new();

        for entry in config.values() {
            fabrics.insert(entry.fabric().id().to_string(), entry.fabric().clone());

            nodes.extend(
                entry
                    .nodes()
                    .map(|(_node_id, node)| (node.id().to_string(), node.clone().into())),
            );
        }

        (fabrics, nodes)
    }

    /// Method: Returns all fabrics from the configuration.
    #[export]
    pub fn list_fabrics(#[try_from_ref] this: &PerlFabricConfig) -> BTreeMap<String, Fabric> {
        this.fabric_config
            .lock()
            .unwrap()
            .iter()
            .map(|(id, entry)| (id.to_string(), entry.fabric().clone()))
            .collect()
    }

    /// Method: Returns all fabrics configured on a specific node in the cluster.
    #[export]
    pub fn list_fabrics_by_node(
        #[try_from_ref] this: &PerlFabricConfig,
        node_id: NodeId,
    ) -> BTreeMap<String, Fabric> {
        this.fabric_config
            .lock()
            .unwrap()
            .iter()
            .filter(|(_id, entry)| entry.get_node(&node_id).is_ok())
            .map(|(id, entry)| (id.to_string(), entry.fabric().clone()))
            .collect()
    }

    /// Method: Adds a new Fabric to the configuration.
    ///
    /// See [`FabricConfig::add_fabric`]
    #[export]
    pub fn add_fabric(
        #[try_from_ref] this: &PerlFabricConfig,
        fabric: Fabric,
    ) -> Result<(), Error> {
        this.fabric_config
            .lock()
            .unwrap()
            .add_fabric(fabric)
            .map_err(anyhow::Error::from)
    }

    /// Method: Read a Fabric from the configuration.
    #[export]
    pub fn get_fabric(
        #[try_from_ref] this: &PerlFabricConfig,
        id: FabricId,
    ) -> Result<Fabric, Error> {
        this.fabric_config
            .lock()
            .unwrap()
            .get_fabric(&id)
            .map(|entry| entry.fabric().clone())
            .map_err(anyhow::Error::from)
    }

    /// Method: Update a fabric in the configuration.
    #[export]
    pub fn update_fabric(
        #[try_from_ref] this: &PerlFabricConfig,
        id: FabricId,
        updater: FabricUpdater,
    ) -> Result<(), Error> {
        this.fabric_config
            .lock()
            .unwrap()
            .update_fabric(&id, updater)
            .map_err(anyhow::Error::from)
    }

    /// Method: Delete a fabric from the configuration.
    #[export]
    pub fn delete_fabric(
        #[try_from_ref] this: &PerlFabricConfig,
        id: FabricId,
    ) -> Result<FabricEntry, Error> {
        this.fabric_config
            .lock()
            .unwrap()
            .delete_fabric(&id)
            .map_err(anyhow::Error::from)
    }

    /// Method: List all nodes in the configuraiton.
    #[export]
    pub fn list_nodes(
        #[try_from_ref] this: &PerlFabricConfig,
    ) -> Result<BTreeMap<String, Node>, Error> {
        Ok(this
            .fabric_config
            .lock()
            .unwrap()
            .values()
            .flat_map(|entry| {
                entry
                    .nodes()
                    .map(|(id, node)| (id.to_string(), node.clone().into()))
            })
            .collect())
    }

    /// Method: List all nodes for a specific fabric.
    #[export]
    pub fn list_nodes_fabric(
        #[try_from_ref] this: &PerlFabricConfig,
        fabric_id: FabricId,
    ) -> Result<BTreeMap<String, Node>, Error> {
        Ok(this
            .fabric_config
            .lock()
            .unwrap()
            .get_fabric(&fabric_id)
            .map_err(anyhow::Error::from)?
            .nodes()
            .map(|(id, node)| (id.to_string(), node.clone().into()))
            .collect())
    }

    /// Method: Get a node from a fabric.
    #[export]
    pub fn get_node(
        #[try_from_ref] this: &PerlFabricConfig,
        fabric_id: FabricId,
        node_id: NodeId,
    ) -> Result<Node, Error> {
        this.fabric_config
            .lock()
            .unwrap()
            .get_fabric(&fabric_id)
            .map_err(anyhow::Error::from)?
            .get_node(&node_id)
            .map(|node| node.clone().into())
            .map_err(anyhow::Error::from)
    }

    /// Method: Add a node to a fabric.
    #[export]
    pub fn add_node(#[try_from_ref] this: &PerlFabricConfig, node: Node) -> Result<(), Error> {
        let node = ConfigNode::from(node);

        this.fabric_config
            .lock()
            .unwrap()
            .get_fabric_mut(node.id().fabric_id())
            .map_err(anyhow::Error::from)?
            .add_node(node)
            .map_err(anyhow::Error::from)
    }

    /// Method: Update a node in a fabric.
    #[export]
    pub fn update_node(
        #[try_from_ref] this: &PerlFabricConfig,
        fabric_id: FabricId,
        node_id: NodeId,
        updater: NodeUpdater,
    ) -> Result<(), Error> {
        this.fabric_config
            .lock()
            .unwrap()
            .get_fabric_mut(&fabric_id)
            .map_err(anyhow::Error::from)?
            .update_node(&node_id, updater)
            .map_err(anyhow::Error::from)
    }

    /// Method: Delete a node in a fabric.
    #[export]
    pub fn delete_node(
        #[try_from_ref] this: &PerlFabricConfig,
        fabric_id: FabricId,
        node_id: NodeId,
    ) -> Result<Node, Error> {
        this.fabric_config
            .lock()
            .unwrap()
            .get_fabric_mut(&fabric_id)
            .map_err(anyhow::Error::from)?
            .delete_node(&node_id)
            .map(Node::from)
            .map_err(anyhow::Error::from)
    }

    fn map_name(
        mapping: &HashMap<String, String>,
        name: &str,
    ) -> Result<Option<InterfaceName>, Error> {
        match name.split_once('.') {
            Some((interface_name, vlan_id))
                if !vlan_id.is_empty() && vlan_id.chars().all(char::is_numeric) =>
            {
                mapping
                    .get(interface_name)
                    .map(|mapped_name| {
                        InterfaceName::from_string(format!("{mapped_name}.{vlan_id}"))
                    })
                    .transpose()
            }
            _ => mapping
                .get(name)
                .cloned()
                .map(InterfaceName::from_string)
                .transpose(),
        }
    }

    /// Method: Map all interface names of a node to a different one, according to the given
    /// mapping.
    ///
    /// Used by proxmox-network-interface-pinning
    #[export]
    pub fn map_interfaces(
        #[try_from_ref] this: &PerlFabricConfig,
        node_id: NodeId,
        mapping: HashMap<String, String>,
    ) -> Result<(), Error> {
        let mut config = this.fabric_config.lock().unwrap();

        for entry in config.get_fabrics_mut() {
            let Ok(node) = entry.get_node_mut(&node_id) else {
                continue;
            };

            match node {
                ConfigNode::Openfabric(node_section) => {
                    for interface in node_section.properties_mut().interfaces_mut() {
                        if let Some(mapped_name) = map_name(&mapping, interface.name())? {
                            interface.set_name(mapped_name);
                        }
                    }
                }
                ConfigNode::Ospf(node_section) => {
                    for interface in node_section.properties_mut().interfaces_mut() {
                        if let Some(mapped_name) = map_name(&mapping, interface.name())? {
                            interface.set_name(mapped_name);
                        }
                    }
                }
            }
        }

        Ok(())
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

    /// Method: Return all interfaces of a node, that are part of a fabric.
    #[export]
    pub fn get_interfaces_for_node(
        #[try_from_ref] this: &PerlFabricConfig,
        node_id: NodeId,
    ) -> BTreeMap<String, PveInterface> {
        let config = this.fabric_config.lock().unwrap();

        let mut ifaces = BTreeMap::new();

        for entry in config.values() {
            if entry.get_node(&node_id).is_ok() {
                ifaces.insert(
                    entry.fabric().id().to_string(),
                    entry.fabric().clone().into(),
                );
            }
        }

        ifaces
    }

    /// Method: Return all FRR daemons that need to be enabled for this fabric configuration
    /// instance.
    ///
    /// FRR is a single service and different protocols are implement in daemons which can be
    /// activated using the `/etc/frr/daemons` file.
    ///
    /// <https://docs.frrouting.org/en/latest/setup.html#daemons-configuration-file>
    #[export]
    pub fn enabled_daemons(
        #[try_from_ref] this: &PerlFabricConfig,
        node_id: NodeId,
    ) -> Vec<String> {
        let config = this.fabric_config.lock().unwrap();

        let node_fabrics = config
            .values()
            .filter(|fabric| fabric.get_node(&node_id).is_ok());

        let mut daemons = HashSet::new();

        for fabric in node_fabrics {
            match fabric {
                FabricEntry::Ospf(_) => {
                    daemons.insert("ospfd");
                }
                FabricEntry::Openfabric(_) => {
                    daemons.insert("fabricd");
                }
            };
        }

        daemons.into_iter().map(String::from).collect()
    }

    /// Method: Return the FRR configuration for this config instance, as an array of
    /// strings, where each line represents a line in the FRR configuration.
    #[export]
    pub fn get_frr_raw_config(
        #[try_from_ref] this: &PerlFabricConfig,
        node_id: NodeId,
    ) -> Result<Vec<String>, Error> {
        let config = this.fabric_config.lock().unwrap();

        let frr_config = FrrConfigBuilder::default()
            .add_fabrics(config.clone().into_valid()?)
            .build(node_id)?;

        to_raw_config(&frr_config)
    }

    /// Helper function to generate the default `/etc/network/interfaces` config for a given CIDR.
    fn render_interface(name: &str, cidr: Cidr, is_dummy: bool) -> Result<String, Error> {
        let mut interface = String::new();

        writeln!(interface, "auto {name}")?;
        match cidr {
            Cidr::Ipv4(_) => writeln!(interface, "iface {name} inet static")?,
            Cidr::Ipv6(_) => writeln!(interface, "iface {name} inet6 static")?,
        }
        writeln!(interface, "\taddress {cidr}")?;
        if is_dummy {
            writeln!(interface, "\tlink-type dummy")?;
        }
        writeln!(interface, "\tip-forward 1")?;

        Ok(interface)
    }

    /// Method: Generate the ifupdown2 configuration for a given node.
    #[export]
    pub fn get_interfaces_etc_network_config(
        #[try_from_ref] this: &PerlFabricConfig,
        node_id: NodeId,
    ) -> Result<String, Error> {
        let config = this.fabric_config.lock().unwrap();
        let mut interfaces = String::new();

        let node_fabrics = config.values().filter_map(|entry| {
            entry
                .get_node(&node_id)
                .map(|node| (entry.fabric(), node))
                .ok()
        });

        for (fabric, node) in node_fabrics {
            // dummy interface
            if let Some(ip) = node.ip() {
                let interface = render_interface(
                    &format!("dummy_{}", fabric.id()),
                    Cidr::new_v4(ip, 32)?,
                    true,
                )?;
                writeln!(interfaces)?;
                write!(interfaces, "{interface}")?;
            }
            if let Some(ip6) = node.ip6() {
                let interface = render_interface(
                    &format!("dummy_{}", fabric.id()),
                    Cidr::new_v6(ip6, 128)?,
                    true,
                )?;
                writeln!(interfaces)?;
                write!(interfaces, "{interface}")?;
            }
            match node {
                ConfigNode::Openfabric(node_section) => {
                    for interface in node_section.properties().interfaces() {
                        if let Some(ip) = interface.ip() {
                            let interface =
                                render_interface(interface.name(), Cidr::from(ip), false)?;
                            writeln!(interfaces)?;
                            write!(interfaces, "{interface}")?;
                        }
                        if let Some(ip) = interface.ip6() {
                            let interface =
                                render_interface(interface.name(), Cidr::from(ip), false)?;
                            writeln!(interfaces)?;
                            write!(interfaces, "{interface}")?;
                        }

                        // If no ip is configured, add auto and iface with node ip to bring interface up
                        // OpenFabric doesn't really need an ip on the interface, but the problem
                        // is that arp can't tell which source address to use in some cases, so
                        // it's better if we set the node address on all the fabric interfaces.
                        if let (None, None) = (interface.ip(), interface.ip6()) {
                            let cidr = Cidr::from(if let Some(ip) = node.ip() {
                                IpAddr::from(ip)
                            } else if let Some(ip) = node.ip6() {
                                IpAddr::from(ip)
                            } else {
                                anyhow::bail!("there has to be a ipv4 or ipv6 node address");
                            });
                            let interface = render_interface(interface.name(), cidr, false)?;
                            writeln!(interfaces)?;
                            write!(interfaces, "{interface}")?;
                        }
                    }
                }
                ConfigNode::Ospf(node_section) => {
                    for interface in node_section.properties().interfaces() {
                        if let Some(ip) = interface.ip() {
                            let interface =
                                render_interface(interface.name(), Cidr::from(ip), false)?;
                            writeln!(interfaces)?;
                            write!(interfaces, "{interface}")?;
                        } else {
                            let interface = render_interface(
                                interface.name(),
                                Cidr::from(IpAddr::from(node.ip().ok_or_else(|| {
                                    anyhow::anyhow!("there has to be a ipv4 address")
                                })?)),
                                false,
                            )?;
                            writeln!(interfaces)?;
                            write!(interfaces, "{interface}")?;
                        }
                    }
                }
            }
        }

        Ok(interfaces)
    }

    /// Read and parse the running-config and get the fabrics section
    ///
    /// This will return a valid FabricConfig. Note that we read the file manually and not through
    /// the cluster filesystem as with perl, so this will be slower.
    fn get_fabrics_config() -> Result<Valid<FabricConfig>, anyhow::Error> {
        let raw_config = std::fs::read_to_string("/etc/pve/sdn/.running-config")?;
        let running_config: RunningConfig =
            serde_json::from_str(&raw_config).with_context(|| "error parsing running-config")?;
        let section_config = SectionConfigData::from_iter(running_config.fabrics.ids);
        FabricConfig::from_section_config(section_config)
            .with_context(|| "error converting section config to fabricconfig")
    }

    /// Get the routes that have been learned and distributed by this specific fabric on this node.
    ///
    /// Read and parse the fabric config to get the protocol and the interfaces. Parse the vtysh
    /// output and assign the routes to a fabric by using the interface list. Return a list of
    /// common route structs.
    #[export]
    fn routes(fabric_id: FabricId) -> Result<Vec<status::RouteStatus>, Error> {
        // Read fabric config to get protocol of fabric
        let config = get_fabrics_config()?;

        let fabric = config.get_fabric(&fabric_id)?;
        match fabric {
            FabricEntry::Openfabric(_) => {
                let openfabric_ipv4_routes_string = String::from_utf8(
                    Command::new("sh")
                        .args(["-c", "vtysh -c 'show ip route openfabric json'"])
                        .output()?
                        .stdout,
                )?;

                let openfabric_ipv6_routes_string = String::from_utf8(
                    Command::new("sh")
                        .args(["-c", "vtysh -c 'show ipv6 route openfabric json'"])
                        .output()?
                        .stdout,
                )?;

                let mut openfabric_routes: proxmox_frr::de::Routes =
                    if openfabric_ipv4_routes_string.is_empty() {
                        proxmox_frr::de::Routes::default()
                    } else {
                        serde_json::from_str(&openfabric_ipv4_routes_string)
                            .with_context(|| "error parsing openfabric ipv4 routes")?
                    };
                if !openfabric_ipv6_routes_string.is_empty() {
                    let openfabric_ipv6_routes: proxmox_frr::de::Routes =
                        serde_json::from_str(&openfabric_ipv6_routes_string)
                            .with_context(|| "error parsing openfabric ipv6 routes")?;
                    openfabric_routes.0.extend(openfabric_ipv6_routes.0);
                }
                status::get_routes(
                    fabric_id,
                    config,
                    openfabric_routes,
                    proxmox_sys::nodename(),
                )
            }
            FabricEntry::Ospf(_) => {
                let ospf_routes_string = String::from_utf8(
                    Command::new("sh")
                        .args(["-c", "vtysh -c 'show ip route ospf json'"])
                        .output()?
                        .stdout,
                )?;
                let ospf_routes: proxmox_frr::de::Routes = if ospf_routes_string.is_empty() {
                    proxmox_frr::de::Routes::default()
                } else {
                    serde_json::from_str(&ospf_routes_string)
                        .with_context(|| "error parsing ospf routes")?
                };

                status::get_routes(fabric_id, config, ospf_routes, proxmox_sys::nodename())
            }
        }
    }

    /// Get the neighbors for this specific fabric on this node
    ///
    /// Read and parse the fabric config to get the fabric protocol and the interfaces (ospf).
    /// Parse the frr output of the neighbor commands and return a common format.
    #[export]
    fn neighbors(fabric_id: FabricId) -> Result<status::NeighborStatus, Error> {
        // Read fabric config to get protocol of fabric
        let config = get_fabrics_config()?;

        let fabric = config.get_fabric(&fabric_id)?;

        match fabric {
            FabricEntry::Openfabric(_) => {
                let openfabric_neighbors_string = String::from_utf8(
                    Command::new("sh")
                        .args(["-c", "vtysh -c 'show openfabric neighbor detail json'"])
                        .output()?
                        .stdout,
                )?;
                let openfabric_neighbors: proxmox_frr::de::openfabric::Neighbors =
                    if openfabric_neighbors_string.is_empty() {
                        proxmox_frr::de::openfabric::Neighbors::default()
                    } else {
                        serde_json::from_str(&openfabric_neighbors_string)
                            .with_context(|| "error parsing openfabric neighbors")?
                    };

                status::get_neighbors_openfabric(fabric_id, openfabric_neighbors).map(|v| v.into())
            }
            FabricEntry::Ospf(fabric) => {
                let ospf_neighbors_string = String::from_utf8(
                    Command::new("sh")
                        .args(["-c", "vtysh -c 'show ip ospf neighbor json'"])
                        .output()?
                        .stdout,
                )?;
                let ospf_neighbors: proxmox_frr::de::ospf::Neighbors =
                    if ospf_neighbors_string.is_empty() {
                        proxmox_frr::de::ospf::Neighbors::default()
                    } else {
                        serde_json::from_str(&ospf_neighbors_string)
                            .with_context(|| "error parsing ospf neighbors")?
                    };

                status::get_neighbors_ospf(
                    fabric_id,
                    fabric,
                    ospf_neighbors,
                    proxmox_sys::nodename(),
                )
                .map(|v| v.into())
            }
        }
    }

    /// Get the interfaces for this specific fabric on this node
    ///
    /// Read and parse the fabric config to get the protocol of the fabric and retrieve the
    /// interfaces (ospf). Convert the frr output into a common format of fabric interfaces.
    #[export]
    fn interfaces(fabric_id: FabricId) -> Result<status::InterfaceStatus, Error> {
        // Read fabric config to get protocol of fabric
        let config = get_fabrics_config()?;

        let fabric = config.get_fabric(&fabric_id)?;

        match fabric {
            FabricEntry::Openfabric(_) => {
                let openfabric_interface_string = String::from_utf8(
                    Command::new("sh")
                        .args(["-c", "vtysh -c 'show openfabric interface json'"])
                        .output()?
                        .stdout,
                )?;
                let openfabric_interfaces: proxmox_frr::de::openfabric::Interfaces =
                    if openfabric_interface_string.is_empty() {
                        proxmox_frr::de::openfabric::Interfaces::default()
                    } else {
                        serde_json::from_str(&openfabric_interface_string)
                            .with_context(|| "error parsing openfabric interfaces")?
                    };

                status::get_interfaces_openfabric(fabric_id, openfabric_interfaces)
                    .map(|v| v.into())
            }
            FabricEntry::Ospf(fabric) => {
                let ospf_interfaces_string = String::from_utf8(
                    Command::new("sh")
                        .args(["-c", "vtysh -c 'show ip ospf interface json'"])
                        .output()?
                        .stdout,
                )?;
                let ospf_interfaces: proxmox_frr::de::ospf::Interfaces =
                    if ospf_interfaces_string.is_empty() {
                        proxmox_frr::de::ospf::Interfaces::default()
                    } else {
                        serde_json::from_str(&ospf_interfaces_string)
                            .with_context(|| "error parsing ospf interfaces")?
                    };

                status::get_interfaces_ospf(
                    fabric_id,
                    fabric,
                    ospf_interfaces,
                    proxmox_sys::nodename(),
                )
                .map(|v| v.into())
            }
        }
    }

    /// Return the status of all fabrics on this node.
    ///
    /// Go through all fabrics in the config, then filter out the ones that exist on this node.
    /// Check if there are any routes in the routing table that use the interface specified in the
    /// config. If there are, show "ok" as status, otherwise "not ok".
    #[export]
    fn status() -> Result<HashMap<FabricId, status::Status>, Error> {
        let openfabric_ipv4_routes_string = String::from_utf8(
            Command::new("sh")
                .args(["-c", "vtysh -c 'show ip route openfabric json'"])
                .output()?
                .stdout,
        )?;

        let openfabric_ipv6_routes_string = String::from_utf8(
            Command::new("sh")
                .args(["-c", "vtysh -c 'show ipv6 route openfabric json'"])
                .output()?
                .stdout,
        )?;

        let ospf_routes_string = String::from_utf8(
            Command::new("sh")
                .args(["-c", "vtysh -c 'show ip route ospf json'"])
                .output()?
                .stdout,
        )?;

        let mut openfabric_routes: proxmox_frr::de::Routes =
            if openfabric_ipv4_routes_string.is_empty() {
                proxmox_frr::de::Routes::default()
            } else {
                serde_json::from_str(&openfabric_ipv4_routes_string)
                    .with_context(|| "error parsing openfabric ipv4 routes")?
            };
        if !openfabric_ipv6_routes_string.is_empty() {
            let openfabric_ipv6_routes: proxmox_frr::de::Routes =
                serde_json::from_str(&openfabric_ipv6_routes_string)
                    .with_context(|| "error parsing openfabric ipv6 routes")?;
            openfabric_routes.0.extend(openfabric_ipv6_routes.0);
        }

        let ospf_routes: proxmox_frr::de::Routes = if ospf_routes_string.is_empty() {
            proxmox_frr::de::Routes::default()
        } else {
            serde_json::from_str(&ospf_routes_string)
                .with_context(|| "error parsing ospf routes")?
        };

        let config = get_fabrics_config()?;

        let route_status = status::RoutesParsed {
            openfabric: openfabric_routes,
            ospf: ospf_routes,
        };

        status::get_status(config, route_status, proxmox_sys::nodename())
    }

    /// Get all the L3 routes for the passed zone.
    ///
    /// Every zone has a vrf named `vrf_{zone}`. Show all the L3 (IP) routes on the VRF of the
    /// zone.
    #[export]
    fn l3vpn_routes(zone: String) -> Result<status::L3VPNRoutes, Error> {
        let command = format!("vtysh -c 'show ip route vrf vrf_{zone} json'");
        let l3vpn_routes_string =
            String::from_utf8(Command::new("sh").args(["-c", &command]).output()?.stdout)?;
        let l3vpn_routes: proxmox_frr::de::Routes = if l3vpn_routes_string.is_empty() {
            proxmox_frr::de::Routes::default()
        } else {
            serde_json::from_str(&l3vpn_routes_string)
                .with_context(|| "error parsing l3vpn routes")?
        };

        status::get_l3vpn_routes(&format!("vrf_{zone}"), l3vpn_routes)
    }

    /// Get all the L2 routes for the passed vnet.
    ///
    /// When using VXLAN the vnet "stores" the L2 routes in it's FDB. The best way to retrieve them
    /// with additional metadata is to query FRR. Use the `show bgp l2vpn evpn route` command.
    /// To filter by vnet, get the VNI of the vnet from the config and use it in the command.
    #[export]
    fn l2vpn_routes(vnet: String) -> Result<status::L2VPNRoutes, Error> {
        // read config to get the vni of the vnet
        let raw_config = std::fs::read_to_string("/etc/pve/sdn/.running-config")?;
        let running_config: proxmox_ve_config::sdn::config::RunningConfig =
            serde_json::from_str(&raw_config)?;
        let parsed_config = SdnConfig::try_from(running_config)?;

        let vni = parsed_config
            .zones()
            .flat_map(ZoneConfig::vnets)
            .find(|vnet_config| vnet_config.name().as_ref() == vnet)
            .ok_or_else(|| format_err!("could not find vnet {vnet}"))?
            .tag()
            .ok_or_else(|| format_err!("vnet {vnet} has no tag"))?;

        let command = format!("vtysh -c 'show bgp l2vpn evpn route vni {vni} type 2 json'");
        let l2vpn_routes_string =
            String::from_utf8(Command::new("sh").args(["-c", &command]).output()?.stdout)?;

        let routes = serde_json::from_str(&l2vpn_routes_string)
            .with_context(|| "error parsing l2vpn routes")?;

        status::get_l2vpn_routes(routes)
    }
}
