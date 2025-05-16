#[perlmod::package(name = "PVE::RS::ResourceScheduling::Static", lib = "pve_rs")]
pub mod pve_rs_resource_scheduling_static {
    //! The `PVE::RS::ResourceScheduling::Static` package.
    //!
    //! Provides bindings for the resource scheduling module.
    //!
    //! See [`proxmox_resource_scheduling`].

    use std::collections::HashMap;
    use std::sync::Mutex;

    use anyhow::{bail, Error};

    use perlmod::Value;
    use proxmox_resource_scheduling::pve_static::{StaticNodeUsage, StaticServiceUsage};

    perlmod::declare_magic!(Box<Scheduler> : &Scheduler as "PVE::RS::ResourceScheduling::Static");

    struct Usage {
        nodes: HashMap<String, StaticNodeUsage>,
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
        };

        Ok(perlmod::instantiate_magic!(
            &class, MAGIC => Box::new(Scheduler { inner: Mutex::new(inner) })
        ))
    }

    /// Method: Add a node with its basic CPU and memory info.
    ///
    /// This inserts a [`StaticNodeUsage`] entry for the node into the scheduler instance.
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

        let node = StaticNodeUsage {
            name: nodename.clone(),
            cpu: 0.0,
            maxcpu,
            mem: 0,
            maxmem,
        };

        usage.nodes.insert(nodename, node);
        Ok(())
    }

    /// Method: Remove a node from the scheduler.
    #[export]
    pub fn remove_node(#[try_from_ref] this: &Scheduler, nodename: &str) {
        let mut usage = this.inner.lock().unwrap();

        usage.nodes.remove(nodename);
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

    /// Method: Add usage of `service` to the node's usage.
    #[export]
    pub fn add_service_usage_to_node(
        #[try_from_ref] this: &Scheduler,
        nodename: &str,
        service: StaticServiceUsage,
    ) -> Result<(), Error> {
        let mut usage = this.inner.lock().unwrap();

        match usage.nodes.get_mut(nodename) {
            Some(node) => {
                node.add_service_usage(&service);
                Ok(())
            }
            None => bail!("node '{}' not present in usage hashmap", nodename),
        }
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
        let nodes = usage.nodes.values().collect::<Vec<&StaticNodeUsage>>();

        proxmox_resource_scheduling::pve_static::score_nodes_to_start_service(&nodes, &service)
    }
}
