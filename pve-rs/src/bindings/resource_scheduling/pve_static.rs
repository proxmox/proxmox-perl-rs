#[perlmod::package(name = "PVE::RS::ResourceScheduling::Static", lib = "pve_rs")]
pub mod pve_rs_resource_scheduling_static {
    //! The `PVE::RS::ResourceScheduling::Static` package.
    //!
    //! Provides bindings for the static resource scheduling module.
    //!
    //! See [`proxmox_resource_scheduling`].

    use std::sync::Mutex;

    use anyhow::Error;
    use serde::{Deserialize, Serialize};

    use perlmod::Value;
    use proxmox_resource_scheduling::node::NodeStats;
    use proxmox_resource_scheduling::resource::ResourceStats;
    use proxmox_resource_scheduling::usage::Usage;

    use crate::bindings::resource_scheduling::{
        resource::PveResource, usage::StartedResourceAggregator,
    };

    perlmod::declare_magic!(Box<Scheduler> : &Scheduler as "PVE::RS::ResourceScheduling::Static");

    /// A scheduler instance contains the cluster usage.
    pub struct Scheduler {
        inner: Mutex<Usage>,
    }

    #[derive(Clone, Copy, Debug, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    /// Static usage stats of a resource.
    pub struct StaticResourceStats {
        /// Number of assigned CPUs or CPU limit.
        pub maxcpu: f64,
        /// Maximum assigned memory in bytes.
        pub maxmem: usize,
    }

    impl From<StaticResourceStats> for ResourceStats {
        fn from(stats: StaticResourceStats) -> Self {
            Self {
                cpu: stats.maxcpu,
                maxcpu: stats.maxcpu,
                mem: stats.maxmem,
                maxmem: stats.maxmem,
            }
        }
    }

    type StaticResource = PveResource<StaticResourceStats>;

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
        maxcpu: usize,
        maxmem: usize,
    ) -> Result<(), Error> {
        let mut usage = this.inner.lock().unwrap();

        let stats = NodeStats {
            cpu: 0.0,
            maxcpu,
            mem: 0,
            maxmem,
        };

        usage.add_node(nodename, stats)
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

    /// Method: Add `service` with identifier `sid` to the scheduler.
    ///
    /// See [`proxmox_resource_scheduling::usage::Usage::add_resource`].
    #[export]
    pub fn add_service(
        #[try_from_ref] this: &Scheduler,
        sid: String,
        service: StaticResource,
    ) -> Result<(), Error> {
        let mut usage = this.inner.lock().unwrap();

        usage.add_resource(sid, service.into())
    }

    /// Method: Add service `sid` and its `service_usage` to the node.
    ///
    /// See [`proxmox_resource_scheduling::usage::Usage::add_resource_usage_to_node`].
    #[export]
    pub fn add_service_usage_to_node(
        #[try_from_ref] this: &Scheduler,
        nodename: &str,
        sid: &str,
        service_stats: StaticResourceStats,
    ) -> Result<(), Error> {
        let mut usage = this.inner.lock().unwrap();

        // TODO Only for backwards compatibility, can be removed with a proper version bump
        #[allow(deprecated)]
        usage.add_resource_usage_to_node(nodename, sid, service_stats.into())
    }

    /// Method: Remove service `sid` and its usage from all assigned nodes.
    ///
    /// See [`proxmox_resource_scheduling::usage::Usage::remove_resource`].
    #[export]
    fn remove_service_usage(#[try_from_ref] this: &Scheduler, sid: &str) {
        let mut usage = this.inner.lock().unwrap();

        usage.remove_resource(sid);
    }

    /// Method: Scores nodes to start a service with the usage statistics `service_stats` on.
    ///
    /// See [`proxmox_resource_scheduling::scheduler::Scheduler::score_nodes_to_start_resource`].
    #[export]
    pub fn score_nodes_to_start_service(
        #[try_from_ref] this: &Scheduler,
        service_stats: StaticResourceStats,
    ) -> Result<Vec<(String, f64)>, Error> {
        let usage = this.inner.lock().unwrap();

        usage
            .to_scheduler::<StartedResourceAggregator>()
            .score_nodes_to_start_resource(service_stats)
    }
}
