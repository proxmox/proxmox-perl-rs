#[perlmod::package(name = "PVE::RS::ResourceScheduling::Dynamic", lib = "pve_rs")]
pub mod pve_rs_resource_scheduling_dynamic {
    //! The `PVE::RS::ResourceScheduling::Dynamic` package.
    //!
    //! Provides bindings for the dynamic resource scheduling module.
    //!
    //! See [`proxmox_resource_scheduling`].

    use std::sync::Mutex;

    use anyhow::Error;
    use serde::{Deserialize, Serialize};

    use perlmod::Value;
    use proxmox_resource_scheduling::node::NodeStats;
    use proxmox_resource_scheduling::resource::ResourceStats;
    use proxmox_resource_scheduling::usage::Usage;

    use crate::bindings::resource_scheduling::resource::PveResource;
    use crate::bindings::resource_scheduling::usage::StartingAsStartedResourceAggregator;

    perlmod::declare_magic!(Box<Scheduler> : &Scheduler as "PVE::RS::ResourceScheduling::Dynamic");

    /// A scheduler instance contains the cluster usage.
    pub struct Scheduler {
        inner: Mutex<Usage>,
    }

    #[derive(Clone, Copy, Debug, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    /// Dynamic usage stats of a node.
    pub struct DynamicNodeStats {
        /// CPU utilization in CPU cores.
        pub cpu: f64,
        /// Total number of CPU cores.
        pub maxcpu: usize,
        /// Used memory in bytes.
        pub mem: usize,
        /// Total memory in bytes.
        pub maxmem: usize,
    }

    impl From<DynamicNodeStats> for NodeStats {
        fn from(value: DynamicNodeStats) -> Self {
            Self {
                cpu: value.cpu,
                maxcpu: value.maxcpu,
                mem: value.mem,
                maxmem: value.maxmem,
            }
        }
    }

    #[derive(Clone, Copy, Debug, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    /// Dynamic usage stats of a resource.
    pub struct DynamicResourceStats {
        /// CPU utilization in CPU cores.
        pub cpu: f64,
        /// Number of assigned CPUs or CPU limit.
        pub maxcpu: f64,
        /// Used memory in bytes.
        pub mem: usize,
        /// Maximum assigned memory in bytes.
        pub maxmem: usize,
    }

    impl From<DynamicResourceStats> for ResourceStats {
        fn from(value: DynamicResourceStats) -> Self {
            Self {
                cpu: value.cpu,
                maxcpu: value.maxcpu,
                mem: value.mem,
                maxmem: value.maxmem,
            }
        }
    }

    type DynamicResource = PveResource<DynamicResourceStats>;

    /// Class method: Create a new [`Scheduler`] instance.
    ///
    /// See [`proxmox_resource_scheduling::usage::Usage::new`].
    #[export(raw_return)]
    pub fn new(#[raw] class: Value) -> Result<Value, Error> {
        let inner = Usage::new();

        Ok(perlmod::instantiate_magic!(
            &class, MAGIC => Box::new(Scheduler { inner: Mutex::new(inner) })
        ))
    }

    /// Method: Add a node with its basic CPU and memory info.
    ///
    /// See [`proxmox_resource_scheduling::usage::Usage::add_node`].
    #[export]
    pub fn add_node(
        #[try_from_ref] this: &Scheduler,
        nodename: String,
        stats: DynamicNodeStats,
    ) -> Result<(), Error> {
        let mut usage = this.inner.lock().unwrap();

        usage.add_node(nodename, stats.into())
    }

    /// Method: Remove a node from the scheduler.
    ///
    /// See [`proxmox_resource_scheduling::usage::Usage::remove_node`].
    #[export]
    pub fn remove_node(#[try_from_ref] this: &Scheduler, nodename: &str) {
        let mut usage = this.inner.lock().unwrap();

        usage.remove_node(nodename);
    }

    /// Method: Get a list of all the nodes in the scheduler.
    #[export]
    pub fn list_nodes(#[try_from_ref] this: &Scheduler) -> Vec<String> {
        let usage = this.inner.lock().unwrap();

        usage
            .nodenames_iter()
            .map(|nodename| nodename.to_owned())
            .collect()
    }

    /// Method: Check whether a node exists in the scheduler.
    #[export]
    pub fn contains_node(#[try_from_ref] this: &Scheduler, nodename: &str) -> bool {
        let usage = this.inner.lock().unwrap();

        usage.contains_node(nodename)
    }

    /// Method: Add `resource` with identifier `sid` to the scheduler.
    ///
    /// See [`proxmox_resource_scheduling::usage::Usage::add_resource`].
    #[export]
    pub fn add_resource(
        #[try_from_ref] this: &Scheduler,
        sid: String,
        resource: DynamicResource,
    ) -> Result<(), Error> {
        let mut usage = this.inner.lock().unwrap();

        usage.add_resource(sid, resource.into())
    }

    /// Method: Remove resource `sid` and its usage from all assigned nodes.
    ///
    /// See [`proxmox_resource_scheduling::usage::Usage::remove_resource`].
    #[export]
    fn remove_resource(#[try_from_ref] this: &Scheduler, sid: &str) {
        let mut usage = this.inner.lock().unwrap();

        usage.remove_resource(sid);
    }

    /// Method: Scores nodes to start a resource with the usage statistics `resource_stats` on.
    ///
    /// See [`proxmox_resource_scheduling::scheduler::Scheduler::score_nodes_to_start_resource`].
    #[export]
    pub fn score_nodes_to_start_resource(
        #[try_from_ref] this: &Scheduler,
        resource_stats: DynamicResourceStats,
    ) -> Result<Vec<(String, f64)>, Error> {
        let usage = this.inner.lock().unwrap();

        usage
            .to_scheduler::<StartingAsStartedResourceAggregator>()
            .score_nodes_to_start_resource(resource_stats)
    }
}
