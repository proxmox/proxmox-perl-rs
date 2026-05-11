#[perlmod::package(name = "PVE::RS::SDN::PrefixLists", lib = "pve_rs")]
pub mod pve_rs_sdn_prefix_lists {
    //! The `PVE::RS::SDN::PrefixLists` package.
    //!
    //! This provides the configuration for the SDN fabrics, as well as helper methods for reading
    //! / writing the configuration, as well as for generating ifupdown2 and FRR configuration.

    use core::clone::Clone;
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::ops::Deref;
    use std::sync::Mutex;

    use anyhow::{anyhow, Error};
    use openssl::hash::{hash, MessageDigest};
    use serde::{Deserialize, Serialize};

    use perlmod::Value;
    use proxmox_section_config::typed::{ApiSectionDataEntry, SectionConfigData};
    use proxmox_ve_config::sdn::prefix_list::api::{
        PrefixList as ApiPrefixList, PrefixListDeletableProperties,
        PrefixListEntry as ApiPrefixListEntry, PrefixListEntryDeletableProperties,
        PrefixListEntryUpdater, PrefixListUpdater,
    };
    use proxmox_ve_config::sdn::prefix_list::{
        PrefixList as ConfigPrefixList, PrefixListEntry as ConfigPrefixListEntry, PrefixListId,
    };

    /// A SDN PrefixList config instance.
    #[derive(Serialize, Deserialize)]
    pub struct PerlPrefixListConfig {
        /// The fabric config instance
        pub prefix_lists: Mutex<HashMap<String, ConfigPrefixList>>,
    }

    perlmod::declare_magic!(Box<PerlPrefixListConfig> : &PerlPrefixListConfig as "PVE::RS::SDN::PrefixLists::Config");

    /// Class method: Parse the raw configuration from `/etc/pve/sdn/prefix-lists.cfg`.
    #[export]
    pub fn config(#[raw] class: Value, raw_config: &[u8]) -> Result<perlmod::Value, Error> {
        let raw_config = std::str::from_utf8(raw_config)?;
        let config = ConfigPrefixList::parse_section_config("prefix-lists.cfg", raw_config)?;

        Ok(
            perlmod::instantiate_magic!(&class, MAGIC => Box::new(PerlPrefixListConfig {
                prefix_lists: Mutex::new(config.deref().clone()),
            })),
        )
    }

    /// Class method: Parse the configuration from `/etc/pve/sdn/.running_config`.
    #[export]
    pub fn running_config(
        #[raw] class: Value,
        prefix_lists: HashMap<String, ConfigPrefixList>,
    ) -> Result<perlmod::Value, Error> {
        let prefix_lists: SectionConfigData<ConfigPrefixList> =
            SectionConfigData::from_iter(prefix_lists);

        Ok(
            perlmod::instantiate_magic!(&class, MAGIC => Box::new(PerlPrefixListConfig {
                prefix_lists: Mutex::new(prefix_lists.deref().clone()),
            })),
        )
    }

    /// Method: Used for writing the running configuration.
    #[export]
    pub fn to_sections(
        #[try_from_ref] this: &PerlPrefixListConfig,
    ) -> Result<HashMap<String, ConfigPrefixList>, Error> {
        let config = this.prefix_lists.lock().unwrap();
        Ok(config.deref().clone())
    }

    /// Method: Convert the configuration into the section config string.
    ///
    /// Used for writing `/etc/pve/sdn/prefix-lists.cfg`
    #[export]
    pub fn to_raw(#[try_from_ref] this: &PerlPrefixListConfig) -> Result<String, Error> {
        let config = this.prefix_lists.lock().unwrap();

        let prefix_lists: SectionConfigData<ConfigPrefixList> =
            SectionConfigData::from_iter(config.deref().clone());

        ConfigPrefixList::write_section_config("prefix-lists.cfg", &prefix_lists)
    }

    /// Method: Generate a digest for the whole configuration
    #[export]
    pub fn digest(#[try_from_ref] this: &PerlPrefixListConfig) -> Result<String, Error> {
        let config = to_raw(this)?;
        let hash = hash(MessageDigest::sha256(), config.as_bytes())?;

        Ok(hex::encode(hash))
    }

    /// Method: Returns all prefix lists as a hash indexed with the IDs of the prefix lists.
    #[export]
    pub fn list(#[try_from_ref] this: &PerlPrefixListConfig) -> HashMap<String, ConfigPrefixList> {
        this.prefix_lists
            .lock()
            .unwrap()
            .iter()
            .map(|(id, prefix_list)| (id.clone(), prefix_list.clone()))
            .collect()
    }

    /// Method: Create a new PrefixList.
    #[export]
    pub fn create(
        #[try_from_ref] this: &PerlPrefixListConfig,
        prefix_list: ApiPrefixList,
    ) -> Result<(), Error> {
        let mut prefix_lists = this.prefix_lists.lock().unwrap();

        match prefix_lists.entry(prefix_list.id().to_string()) {
            Entry::Occupied(_) => anyhow::bail!(
                "prefix list already exists in configuration: {}",
                prefix_list.id()
            ),
            Entry::Vacant(vacancy) => {
                vacancy.insert(ConfigPrefixList::PrefixList(prefix_list.try_into()?))
            }
        };

        Ok(())
    }

    /// Method: Get a specific PrefixList.
    #[export]
    pub fn get(
        #[try_from_ref] this: &PerlPrefixListConfig,
        id: PrefixListId,
    ) -> Option<ConfigPrefixList> {
        this.prefix_lists
            .lock()
            .unwrap()
            .get(&id.to_string())
            .cloned()
    }

    /// Method: Update a PrefixList.
    #[export]
    pub fn update(
        #[try_from_ref] this: &PerlPrefixListConfig,
        id: PrefixListId,
        updater: PrefixListUpdater,
        delete: Option<Vec<PrefixListDeletableProperties>>,
    ) -> Result<(), Error> {
        let mut prefix_lists = this.prefix_lists.lock().unwrap();

        let ConfigPrefixList::PrefixList(prefix_list) = prefix_lists
            .get_mut(id.as_str())
            .ok_or_else(|| anyhow!("Could not find prefix list with id: {}", id))?;

        prefix_list.try_update(updater, delete)
    }

    /// Method: Delete a PrefixList.
    #[export]
    pub fn delete(
        #[try_from_ref] this: &PerlPrefixListConfig,
        id: PrefixListId,
    ) -> Result<(), Error> {
        this.prefix_lists
            .lock()
            .unwrap()
            .remove(&id.to_string())
            .map(|_| ())
            .ok_or_else(|| anyhow!("could not find prefix list with id: {id}"))
    }

    /// Method: Get a specific prefix list entry.
    #[export]
    pub fn list_entries(
        #[try_from_ref] this: &PerlPrefixListConfig,
        id: PrefixListId,
    ) -> Result<Vec<ConfigPrefixListEntry>, Error> {
        let prefix_lists = this.prefix_lists.lock().unwrap();

        let ConfigPrefixList::PrefixList(prefix_list) = prefix_lists
            .get(&id.to_string())
            .ok_or_else(|| anyhow!("could not find prefix list with id: {id}"))?;

        Ok(prefix_list.entries().into_iter().cloned().collect())
    }

    /// Method: Get a specific prefix list entry.
    #[export]
    pub fn get_entry(
        #[try_from_ref] this: &PerlPrefixListConfig,
        id: PrefixListId,
        seq: u32,
    ) -> Option<ConfigPrefixListEntry> {
        this.prefix_lists
            .lock()
            .unwrap()
            .get(&id.to_string())
            .and_then(|prefix_list| {
                let ConfigPrefixList::PrefixList(prefix_list) = prefix_list;
                prefix_list.entry(seq)
            })
            .cloned()
    }

    /// Method: Get a specific prefix list entry.
    #[export]
    pub fn create_entry(
        #[try_from_ref] this: &PerlPrefixListConfig,
        id: PrefixListId,
        entry: ApiPrefixListEntry,
    ) -> Result<(), Error> {
        let mut prefix_lists = this.prefix_lists.lock().unwrap();

        let ConfigPrefixList::PrefixList(prefix_list) = prefix_lists
            .get_mut(&id.to_string())
            .ok_or_else(|| anyhow::anyhow!("could not find prefix list with id {id}"))?;

        prefix_list.try_insert_api_entry(entry)
    }

    /// Method: Get a specific prefix list entry.
    #[export]
    pub fn update_entry(
        #[try_from_ref] this: &PerlPrefixListConfig,
        id: PrefixListId,
        seq: u32,
        updater: PrefixListEntryUpdater,
        delete: Option<Vec<PrefixListEntryDeletableProperties>>,
    ) -> Result<(), Error> {
        let mut prefix_lists = this.prefix_lists.lock().unwrap();

        let ConfigPrefixList::PrefixList(prefix_list) = prefix_lists
            .get_mut(&id.to_string())
            .ok_or_else(|| anyhow::anyhow!("could not find prefix list with id {id}"))?;

        prefix_list.try_update_entry(seq, updater, delete.unwrap_or_default())
    }

    /// Method: Remove a specific prefix list entry.
    #[export]
    pub fn delete_entry(
        #[try_from_ref] this: &PerlPrefixListConfig,
        id: PrefixListId,
        seq: u32,
    ) -> Result<(), Error> {
        this.prefix_lists
            .lock()
            .unwrap()
            .get_mut(&id.to_string())
            .and_then(|prefix_list| {
                let ConfigPrefixList::PrefixList(prefix_list) = prefix_list;
                prefix_list.remove_entry(seq)
            })
            .map(|_| ())
            .ok_or_else(|| anyhow::anyhow!("could not find prefix list entry with seq {seq}"))
    }
}
