#[perlmod::package(name = "Proxmox::RS::SharedCache")]
pub mod proxmox_rs_shared_cache {
    //! The `Proxmox::RS::SharedCache` package.
    //!
    //! A simple cache that can be used from multiple processes concurrently.
    //!
    //! See [`proxmox_shared_cache::SharedCache`].

    use std::time::Duration;

    use anyhow::Error;
    use nix::sys::stat::Mode;
    use serde::Deserialize;
    use serde_json::Value as JSONValue;

    use perlmod::Value;

    use proxmox_shared_cache::SharedCache;
    use proxmox_sys::fs::CreateOptions;

    /// Wrapper for [`proxmox_shared_cache::SharedCache`].
    pub struct Cache(SharedCache);

    perlmod::declare_magic!(Box<Cache> : &Cache as "Proxmox::RS::SharedCache");

    /// Parameters for creating a shared cache.
    ///
    /// See [`SharedCache::new`](SharedCache::new()).
    #[derive(Deserialize)]
    pub struct Params {
        path: String,
        owner: u32,
        group: u32,
        entry_mode: u32,
        keep_old: u32,
    }

    /// Class method: Create a new shared cache instance.
    #[export(raw_return)]
    pub fn new(#[raw] class: Value, params: Params) -> Result<Value, Error> {
        let options = CreateOptions::new()
            .owner(params.owner.into())
            .group(params.group.into())
            .perm(Mode::from_bits_truncate(params.entry_mode));

        Ok(perlmod::instantiate_magic!(&class, MAGIC => Box::new(
            Cache (
                SharedCache::new(params.path, options, params.keep_old)?
            )
        )))
    }

    /// Method: Set the cached value.
    ///
    /// See [`SharedCache::set`](SharedCache::set()).
    #[export]
    pub fn set(
        #[try_from_ref] this: &Cache,
        value: JSONValue,
        lock_timeout: u64,
    ) -> Result<(), Error> {
        this.0.set(&value, Duration::from_secs(lock_timeout))
    }

    /// Method: Get the last cached value.
    ///
    /// See [`SharedCache::get`](SharedCache::get()).
    #[export]
    pub fn get(#[try_from_ref] this: &Cache) -> Result<Option<JSONValue>, Error> {
        this.0.get()
    }

    /// Method: Get any last stored item, including old entries.
    ///
    /// See [`SharedCache::get_last`](SharedCache::get_last()).
    #[export]
    pub fn get_last(
        #[try_from_ref] this: &Cache,
        number_of_old_entries: u32,
    ) -> Result<Vec<JSONValue>, Error> {
        this.0.get_last(number_of_old_entries)
    }

    /// Method: Removes all items from the cache.
    ///
    /// See [`SharedCache::delete`](SharedCache::delete()).
    #[export]
    pub fn delete(#[try_from_ref] this: &Cache, lock_timeout: u64) -> Result<(), Error> {
        this.0.delete(Duration::from_secs(lock_timeout))
    }
}
