#[perlmod::package(name = "Proxmox::RS::SharedCache")]
mod export {
    use std::time::Duration;

    use anyhow::Error;
    use nix::sys::stat::Mode;
    use perlmod::Value;
    use serde::Deserialize;
    use serde_json::Value as JSONValue;

    use proxmox_shared_cache::SharedCache;
    use proxmox_sys::fs::CreateOptions;

    pub struct CacheWrapper(SharedCache);

    perlmod::declare_magic!(Box<CacheWrapper> : &CacheWrapper as "Proxmox::RS::SharedCache");

    #[derive(Deserialize)]
    struct Params {
        path: String,
        owner: u32,
        group: u32,
        entry_mode: u32,
        keep_old: u32,
    }

    #[export(raw_return)]
    fn new(#[raw] class: Value, params: Params) -> Result<Value, Error> {
        let options = CreateOptions::new()
            .owner(params.owner.into())
            .group(params.group.into())
            .perm(Mode::from_bits_truncate(params.entry_mode));

        Ok(perlmod::instantiate_magic!(&class, MAGIC => Box::new(
            CacheWrapper (
                SharedCache::new(params.path, options, params.keep_old)?
            )
        )))
    }

    #[export]
    fn set(
        #[try_from_ref] this: &CacheWrapper,
        value: JSONValue,
        lock_timeout: u64,
    ) -> Result<(), Error> {
        this.0.set(&value, Duration::from_secs(lock_timeout))
    }

    #[export]
    fn get(#[try_from_ref] this: &CacheWrapper) -> Result<Option<JSONValue>, Error> {
        this.0.get()
    }

    #[export]
    fn get_last(
        #[try_from_ref] this: &CacheWrapper,
        number_of_old_entries: u32,
    ) -> Result<Vec<JSONValue>, Error> {
        this.0.get_last(number_of_old_entries)
    }

    #[export]
    fn delete(#[try_from_ref] this: &CacheWrapper, lock_timeout: u64) -> Result<(), Error> {
        this.0.delete(Duration::from_secs(lock_timeout))
    }
}
