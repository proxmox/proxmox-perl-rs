use proxmox_resource_scheduling::{
    scheduler::NodeUsage,
    usage::{Usage, UsageAggregator},
};

/// An aggregator, which adds any resource as a started resource.
///
/// This aggregator is useful if the node base stats do not have any current usage.
pub(crate) struct StartedResourceAggregator;

impl UsageAggregator for StartedResourceAggregator {
    fn aggregate(usage: &Usage) -> Vec<NodeUsage> {
        usage
            .nodes_iter()
            .map(|(nodename, node)| {
                let stats = node
                    .resources_iter()
                    .fold(node.stats(), |mut node_stats, sid| {
                        if let Some(resource) = usage.get_resource(sid) {
                            node_stats.add_started_resource(&resource.stats());
                        }

                        node_stats
                    });

                NodeUsage {
                    name: nodename.to_owned(),
                    stats,
                }
            })
            .collect()
    }
}
