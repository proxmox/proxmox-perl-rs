#[perlmod::package(name = "PVE::RS::SDN::Fabrics", lib = "pve_rs")]
pub mod pve_rs_sdn_fabrics {
    //! The `PVE::RS::SDN::Fabrics` package.
    //!
    //! This provides the configuration for the SDN fabrics, as well as helper methods for reading
    //! / writing the configuration, as well as for generating ifupdown2 and FRR configuration.

    use std::collections::{BTreeMap, HashSet};
    use std::fmt::Write;
    use std::net::IpAddr;
    use std::ops::Deref;
    use std::sync::Mutex;

    use anyhow::Error;
    use openssl::hash::{MessageDigest, hash};
    use serde::{Deserialize, Serialize};

    use perlmod::Value;
    use proxmox_frr::serializer::to_raw_config;
    use proxmox_network_types::ip_address::{Cidr, Ipv4Cidr, Ipv6Cidr};
    use proxmox_section_config::typed::SectionConfigData;
    use proxmox_ve_config::common::valid::Validatable;

    use proxmox_ve_config::sdn::fabric::section_config::Section;
    use proxmox_ve_config::sdn::fabric::section_config::fabric::{
        Fabric as ConfigFabric, FabricId,
        api::{Fabric, FabricUpdater},
    };
    use proxmox_ve_config::sdn::fabric::section_config::node::{
        Node as ConfigNode, NodeId,
        api::{Node, NodeUpdater},
    };
    use proxmox_ve_config::sdn::fabric::{FabricConfig, FabricEntry};
    use proxmox_ve_config::sdn::frr::FrrConfigBuilder;

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

                        // If not ip is configured, add auto and empty iface to bring interface up
                        if let (None, None) = (interface.ip(), interface.ip6()) {
                            writeln!(interfaces)?;
                            writeln!(interfaces, "auto {}", interface.name())?;
                            writeln!(interfaces, "iface {}", interface.name())?;
                            writeln!(interfaces, "\tip-forward 1")?;
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
}
