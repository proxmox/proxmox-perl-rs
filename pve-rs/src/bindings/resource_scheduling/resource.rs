use proxmox_resource_scheduling::resource::{
    Resource, ResourcePlacement, ResourceState, ResourceStats,
};

use serde::{Deserialize, Serialize};

/// A PVE resource.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PveResource<T: Into<ResourceStats>> {
    /// The resource's usage statistics.
    stats: T,
    /// Whether the resource is running.
    running: bool,
    /// The resource's current node.
    current_node: String,
    /// The resource's optional migration target node.
    target_node: Option<String>,
}

impl<T: Into<ResourceStats>> From<PveResource<T>> for Resource {
    fn from(resource: PveResource<T>) -> Self {
        let state = if resource.running {
            ResourceState::Started
        } else {
            ResourceState::Starting
        };

        let current_node = resource.current_node;
        let placement = if let Some(target_node) = resource.target_node {
            ResourcePlacement::Moving {
                current_node,
                target_node,
            }
        } else {
            ResourcePlacement::Stationary { current_node }
        };

        Resource::new(resource.stats.into(), state, placement)
    }
}
