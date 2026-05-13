#[perlmod::package(name = "PVE::RS::SDN::RouteMaps", lib = "pve_rs")]
pub mod pve_rs_sdn_route_maps {
    //! The `PVE::RS::SDN::RouteMaps` package.

    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::collections::hash_map::Entry;
    use std::ops::Deref;
    use std::sync::Mutex;

    use anyhow::{Error, anyhow};
    use openssl::hash::{MessageDigest, hash};
    use serde::{Deserialize, Serialize};

    use perlmod::Value;

    use proxmox_schema::Updater;
    use proxmox_section_config::typed::{ApiSectionDataEntry, SectionConfigData};
    use proxmox_ve_config::sdn::route_map::RouteMap as ConfigRouteMap;
    use proxmox_ve_config::sdn::route_map::RouteMapEntryId;
    use proxmox_ve_config::sdn::route_map::RouteMapId;
    use proxmox_ve_config::sdn::route_map::api::RouteMapDeletableProperties;
    use proxmox_ve_config::sdn::route_map::api::RouteMapEntry as ApiRouteMap;
    use proxmox_ve_config::sdn::route_map::api::RouteMapEntryUpdater;

    /// A SDN RouteMap config instance.
    #[derive(Serialize, Deserialize)]
    pub struct PerlRouteMapConfig {
        /// The route map config instance
        pub route_maps: Mutex<HashMap<String, ConfigRouteMap>>,
    }

    perlmod::declare_magic!(Box<PerlRouteMapConfig> : &PerlRouteMapConfig as "PVE::RS::SDN::RouteMaps::Config");

    /// Class method: Parse the raw configuration from `/etc/pve/sdn/route-maps.cfg`.
    #[export]
    pub fn config(#[raw] class: Value, raw_config: &[u8]) -> Result<perlmod::Value, Error> {
        let raw_config = std::str::from_utf8(raw_config)?;
        let config = ConfigRouteMap::parse_section_config("route-maps.cfg", raw_config)?;

        Ok(
            perlmod::instantiate_magic!(&class, MAGIC => Box::new(PerlRouteMapConfig {
                route_maps: Mutex::new(config.deref().clone()),
            })),
        )
    }

    /// Class method: Parse the configuration from `/etc/pve/sdn/.running_config`.
    #[export]
    pub fn running_config(
        #[raw] class: Value,
        route_maps: HashMap<String, ConfigRouteMap>,
    ) -> Result<perlmod::Value, Error> {
        Ok(
            perlmod::instantiate_magic!(&class, MAGIC => Box::new(PerlRouteMapConfig {
                route_maps: Mutex::new(route_maps.clone()),
            })),
        )
    }

    /// Method: Used for writing the running configuration.
    #[export]
    pub fn to_sections(
        #[try_from_ref] this: &PerlRouteMapConfig,
    ) -> Result<HashMap<String, ConfigRouteMap>, Error> {
        let config = this.route_maps.lock().unwrap();
        Ok(config.deref().clone())
    }

    /// Method: Convert the configuration into the section config string.
    ///
    /// Used for writing `/etc/pve/sdn/route-maps.cfg`
    #[export]
    pub fn to_raw(#[try_from_ref] this: &PerlRouteMapConfig) -> Result<String, Error> {
        let config = this.route_maps.lock().unwrap();
        let route_maps: SectionConfigData<ConfigRouteMap> =
            SectionConfigData::from_iter(config.deref().clone());

        ConfigRouteMap::write_section_config("route-maps.cfg", &route_maps)
    }

    /// Method: Generate a digest for the whole configuration.
    #[export]
    pub fn digest(#[try_from_ref] this: &PerlRouteMapConfig) -> Result<String, Error> {
        let config = to_raw(this)?;
        let hash = hash(MessageDigest::sha256(), config.as_bytes())?;

        Ok(hex::encode(hash))
    }

    #[derive(Clone, Serialize, Deserialize, Hash)]
    pub(crate) struct RouteMap {
        id: RouteMapId,
    }

    /// Method: Returns all route maps.
    #[export]
    pub fn list_route_maps(
        #[try_from_ref] this: &PerlRouteMapConfig,
    ) -> Result<Vec<RouteMap>, Error> {
        let route_maps = this.route_maps.lock().unwrap();

        let route_map_ids: HashSet<&RouteMapId> = route_maps
            .iter()
            .map(|(_id, route_map_entry)| {
                let ConfigRouteMap::RouteMapEntry(route_map) = route_map_entry;
                route_map.id().route_map_id()
            })
            .collect();

        Ok(route_map_ids
            .into_iter()
            .map(|id| RouteMap { id: id.clone() })
            .collect())
    }

    /// Method: Returns all route map entries as a hash indexed with the IDs of the entries.
    #[export]
    pub fn list(
        #[try_from_ref] this: &PerlRouteMapConfig,
    ) -> Result<HashMap<String, ApiRouteMap>, Error> {
        Ok(this
            .route_maps
            .lock()
            .unwrap()
            .iter()
            .map(|(id, route_map_entry)| {
                let ConfigRouteMap::RouteMapEntry(route_map) = route_map_entry;
                (id.clone(), route_map.clone().into())
            })
            .collect())
    }

    /// Method: Returns all entries of a given route map as a hash indexed with the IDs of the
    /// entries.
    #[export]
    pub fn list_route_map(
        #[try_from_ref] this: &PerlRouteMapConfig,
        route_map_id: RouteMapId,
    ) -> Result<HashMap<String, ApiRouteMap>, Error> {
        Ok(this
            .route_maps
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(id, route_map_entry)| {
                let ConfigRouteMap::RouteMapEntry(route_map) = route_map_entry;

                if route_map.id().route_map_id() == &route_map_id {
                    return Some((id.clone(), route_map.clone().into()));
                }

                None
            })
            .collect())
    }

    /// Method: Create a new RouteMap entry.
    #[export]
    pub fn create(
        #[try_from_ref] this: &PerlRouteMapConfig,
        route_map: ApiRouteMap,
    ) -> Result<(), Error> {
        let mut route_maps = this.route_maps.lock().unwrap();

        let id =
            RouteMapEntryId::new(route_map.route_map_id().clone(), route_map.order()).to_string();

        match route_maps.entry(id) {
            Entry::Occupied(entry) => {
                anyhow::bail!(
                    "route map entry already exists in configuration: {}",
                    entry.key()
                )
            }
            Entry::Vacant(vacancy) => {
                vacancy.insert(ConfigRouteMap::RouteMapEntry(route_map.into()))
            }
        };

        Ok(())
    }

    /// Method: Returns a specfic entry of a RouteMap.
    #[export]
    pub fn get(
        #[try_from_ref] this: &PerlRouteMapConfig,
        route_map_id: RouteMapId,
        order: u16,
    ) -> Result<Option<ApiRouteMap>, Error> {
        let id = RouteMapEntryId::new(route_map_id, order).to_string();

        Ok(this
            .route_maps
            .lock()
            .unwrap()
            .get(&id)
            .map(|route_map_entry| {
                let ConfigRouteMap::RouteMapEntry(route_map) = route_map_entry;
                route_map.clone().into()
            }))
    }

    /// Method: Update a RouteMap entry.
    #[export]
    pub fn update(
        #[try_from_ref] this: &PerlRouteMapConfig,
        route_map_id: RouteMapId,
        order: u16,
        updater: RouteMapEntryUpdater,
        delete: Option<Vec<RouteMapDeletableProperties>>,
    ) -> Result<(), Error> {
        if updater.is_empty() && delete.is_empty() {
            return Ok(());
        }

        let mut route_maps = this.route_maps.lock().unwrap();
        let id = RouteMapEntryId::new(route_map_id, order).to_string();

        let ConfigRouteMap::RouteMapEntry(route_map) = route_maps
            .get_mut(&id)
            .ok_or_else(|| anyhow!("Could not find route map with id: {}", id))?;

        let RouteMapEntryUpdater {
            action,
            set_actions,
            match_actions,
            exit_action,
            call,
        } = updater;

        if let Some(action) = action {
            route_map.set_action(action);
        }

        if let Some(match_actions) = match_actions {
            route_map.set_match_actions(match_actions);
        }

        if let Some(set_actions) = set_actions {
            route_map.set_set_actions(set_actions);
        }

        if exit_action.is_some() {
            route_map.set_exit_action(exit_action);
        }

        if call.is_some() {
            route_map.set_call(call);
        }

        for deletable_property in delete.unwrap_or_default() {
            match deletable_property {
                RouteMapDeletableProperties::Set => {
                    route_map.set_set_actions(Vec::new());
                }
                RouteMapDeletableProperties::Match => {
                    route_map.set_match_actions(Vec::new());
                }
                RouteMapDeletableProperties::ExitAction => {
                    route_map.set_exit_action(None);
                }
                RouteMapDeletableProperties::Call => {
                    route_map.set_call(None);
                }
            }
        }

        Ok(())
    }

    /// Method: Delete an entry in a RouteMap.
    #[export]
    pub fn delete(
        #[try_from_ref] this: &PerlRouteMapConfig,
        route_map_id: RouteMapId,
        order: u16,
    ) -> Result<(), Error> {
        let id = RouteMapEntryId::new(route_map_id, order).to_string();

        this.route_maps
            .lock()
            .unwrap()
            .remove(&id.to_string())
            .ok_or_else(|| anyhow!("could not find route map entry with id: {id}"))?;

        Ok(())
    }
}
