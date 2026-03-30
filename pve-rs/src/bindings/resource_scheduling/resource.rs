use anyhow::{Error, bail};
use proxmox_resource_scheduling::{
    resource::{Resource, ResourcePlacement, ResourceState, ResourceStats},
    scheduler::{Migration, MigrationCandidate},
    usage::Usage,
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

/// A compact representation of [`proxmox_resource_scheduling::scheduler::MigrationCandidate`].
#[derive(Serialize, Deserialize)]
pub struct CompactMigrationCandidate {
    /// The identifier of the leading resource.
    pub leader: String,
    /// The resources which are part of the leading resource's bundle.
    pub resources: Vec<String>,
    /// The nodes, which are possible to migrate to for the resources.
    pub nodes: Vec<String>,
}

/// Transforms a `Vec<CompactMigrationCandidate>` to a `Vec<MigrationCandidate>` with the cluster
/// usage from `usage`.
///
/// This function fails for any of the following conditions for a [`CompactMigrationCandidate`]:
///
/// - the `leader` is not present in the cluster usage
/// - the `leader` is non-stationary
/// - any resource in `resources` is not present in the cluster usage
/// - any resource in `resources` is non-stationary
/// - any resource in `resources` is on another node than the `leader`
pub(crate) fn decompose_compact_migration_candidates(
    usage: &Usage,
    compact_candidates: Vec<CompactMigrationCandidate>,
) -> Result<Vec<MigrationCandidate>, Error> {
    // The length of `compact_candidates` is at least a lower bound
    let mut candidates = Vec::with_capacity(compact_candidates.len());

    for candidate in compact_candidates.into_iter() {
        let leader_sid = candidate.leader;
        let leader = match usage.get_resource(&leader_sid) {
            Some(resource) => resource,
            _ => bail!("leader '{leader_sid}' is not present in the cluster usage"),
        };
        let leader_node = match leader.placement() {
            ResourcePlacement::Stationary { current_node } => current_node,
            _ => bail!("leader '{leader_sid}' is non-stationary"),
        };

        if !candidate.resources.contains(&leader_sid) {
            bail!("leader '{leader_sid}' is not present in the resources list");
        }

        let mut resource_stats = Vec::with_capacity(candidate.resources.len());

        for sid in candidate.resources.iter() {
            let resource = match usage.get_resource(sid) {
                Some(resource) => resource,
                _ => bail!("resource '{sid}' is not present in the cluster usage"),
            };

            match resource.placement() {
                ResourcePlacement::Stationary { current_node } => {
                    if current_node != leader_node {
                        bail!("resource '{sid}' is on other node than leader");
                    }

                    resource_stats.push(resource.stats());
                }
                _ => bail!("resource '{sid}' is non-stationary"),
            }
        }

        let bundle_stats = resource_stats.into_iter().sum();

        for target_node in candidate.nodes.into_iter() {
            let migration = Migration {
                sid: leader_sid.to_owned(),
                source_node: leader_node.to_owned(),
                target_node,
            };

            candidates.push(MigrationCandidate {
                migration,
                stats: bundle_stats,
            });
        }
    }

    Ok(candidates)
}
