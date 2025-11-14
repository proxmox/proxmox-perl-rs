#[perlmod::package(name = "PVE::RS::ResourceScheduling::Static", lib = "pve_rs")]
pub mod pve_rs_resource_scheduling_static {
    //! The `PVE::RS::ResourceScheduling::Static` package.
    //!
    //! Provides bindings for the resource scheduling module.
    //!
    //! See [`proxmox_resource_scheduling`].

    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use anyhow::{Error, bail};

    use perlmod::Value;
    use proxmox_resource_scheduling::pve_static::{StaticNodeUsage, StaticServiceUsage};

    perlmod::declare_magic!(Box<Scheduler> : &Scheduler as "PVE::RS::ResourceScheduling::Static");

    struct StaticNodeInfo {
        name: String,
        maxcpu: usize,
        maxmem: usize,
        services: HashMap<String, StaticServiceUsage>,
    }

    struct Usage {
        nodes: HashMap<String, StaticNodeInfo>,
        service_nodes: HashMap<String, HashSet<String>>,
    }

    /// A scheduler instance contains the resource usage by node.
    pub struct Scheduler {
        inner: Mutex<Usage>,
    }

    /// Class method: Create a new [`Scheduler`] instance.
    #[export(raw_return)]
    pub fn new(#[raw] class: Value) -> Result<Value, Error> {
        let inner = Usage {
            nodes: HashMap::new(),
            service_nodes: HashMap::new(),
        };

        Ok(perlmod::instantiate_magic!(
            &class, MAGIC => Box::new(Scheduler { inner: Mutex::new(inner) })
        ))
    }

    /// Method: Add a node with its basic CPU and memory info.
    ///
    /// This inserts a [`StaticNodeInfo`] entry for the node into the scheduler instance.
    #[export]
    pub fn add_node(
        #[try_from_ref] this: &Scheduler,
        nodename: String,
        maxcpu: usize,
        maxmem: usize,
    ) -> Result<(), Error> {
        let mut usage = this.inner.lock().unwrap();

        if usage.nodes.contains_key(&nodename) {
            bail!("node {} already added", nodename);
        }

        let node = StaticNodeInfo {
            name: nodename.clone(),
            maxcpu,
            maxmem,
            services: HashMap::new(),
        };

        usage.nodes.insert(nodename, node);
        Ok(())
    }

    /// Method: Remove a node from the scheduler.
    #[export]
    pub fn remove_node(#[try_from_ref] this: &Scheduler, nodename: &str) -> Result<(), Error> {
        let mut usage = this.inner.lock().unwrap();

        if let Some(node) = usage.nodes.remove(nodename) {
            for (sid, _) in node.services.iter() {
                match usage.service_nodes.get_mut(sid) {
                    Some(service_nodes) => {
                        service_nodes.remove(nodename);
                    }
                    None => bail!(
                        "service '{}' not present in service_nodes hashmap while removing node '{}'",
                        sid,
                        nodename
                    ),
                }
            }
        }

        Ok(())
    }

    /// Method: Get a list of all the nodes in the scheduler.
    #[export]
    pub fn list_nodes(#[try_from_ref] this: &Scheduler) -> Vec<String> {
        let usage = this.inner.lock().unwrap();

        usage
            .nodes
            .keys()
            .map(|nodename| nodename.to_string())
            .collect()
    }

    /// Method: Check whether a node exists in the scheduler.
    #[export]
    pub fn contains_node(#[try_from_ref] this: &Scheduler, nodename: &str) -> bool {
        let usage = this.inner.lock().unwrap();

        usage.nodes.contains_key(nodename)
    }

    /// Method: Add service `sid` and its `service_usage` to the node.
    #[export]
    pub fn add_service_usage_to_node(
        #[try_from_ref] this: &Scheduler,
        nodename: &str,
        sid: &str,
        service_usage: StaticServiceUsage,
    ) -> Result<(), Error> {
        let mut usage = this.inner.lock().unwrap();

        match usage.nodes.get_mut(nodename) {
            Some(node) => {
                if node.services.contains_key(sid) {
                    bail!("service '{}' already added to node '{}'", sid, nodename);
                }

                node.services.insert(sid.to_string(), service_usage);
            }
            None => bail!("node '{}' not present in usage hashmap", nodename),
        }

        if let Some(service_nodes) = usage.service_nodes.get_mut(sid) {
            if service_nodes.contains(nodename) {
                bail!("node '{}' already added to service '{}'", nodename, sid);
            }

            service_nodes.insert(nodename.to_string());
        } else {
            let mut service_nodes = HashSet::new();
            service_nodes.insert(nodename.to_string());
            usage.service_nodes.insert(sid.to_string(), service_nodes);
        }

        Ok(())
    }

    /// Method: Remove service `sid` and its usage from all assigned nodes.
    #[export]
    fn remove_service_usage(#[try_from_ref] this: &Scheduler, sid: &str) -> Result<(), Error> {
        let mut usage = this.inner.lock().unwrap();

        if let Some(nodes) = usage.service_nodes.remove(sid) {
            for nodename in &nodes {
                match usage.nodes.get_mut(nodename) {
                    Some(node) => {
                        node.services.remove(sid);
                    }
                    None => bail!(
                        "service '{}' not present in usage hashmap on node '{}'",
                        sid,
                        nodename
                    ),
                }
            }
        }

        Ok(())
    }

    /// Scores all previously added nodes for starting a `service` on.
    ///
    /// Scoring is done according to the static memory and CPU usages of the nodes as if the
    /// service would already be running on each.
    ///
    /// Returns a vector of (nodename, score) pairs. Scores are between 0.0 and 1.0 and a higher
    /// score is better.
    ///
    /// See [`proxmox_resource_scheduling::pve_static::score_nodes_to_start_service`].
    #[export]
    pub fn score_nodes_to_start_service(
        #[try_from_ref] this: &Scheduler,
        service: StaticServiceUsage,
    ) -> Result<Vec<(String, f64)>, Error> {
        let usage = this.inner.lock().unwrap();
        let nodes = usage
            .nodes
            .values()
            .map(|node| {
                let mut node_usage = StaticNodeUsage {
                    name: node.name.to_string(),
                    cpu: 0.0,
                    maxcpu: node.maxcpu,
                    mem: 0,
                    maxmem: node.maxmem,
                };

                for service in node.services.values() {
                    node_usage.add_service_usage(service);
                }

                node_usage
            })
            .collect::<Vec<StaticNodeUsage>>();

        proxmox_resource_scheduling::pve_static::score_nodes_to_start_service(&nodes, &service)
    }
}
