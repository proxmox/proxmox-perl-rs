//! Provides access to the state of NVIDIA (v)GPU devices connected to the system.

#[perlmod::package(name = "PVE::RS::NVML", lib = "pve_rs")]
pub mod pve_rs_nvml {
    //! The `PVE::RS::NVML` package.
    //!
    //! Provides high level helpers to get info from the system with NVML.

    use anyhow::Result;
    use nvml_wrapper::Nvml;
    use perlmod::{Hash, Value};

    /// Retrieves a list of *creatable* vGPU types for the specified GPU by bus id.
    ///
    /// The [`bus_id`] is of format "\<domain\>:\<bus\>:\<device\>.\<function\>",
    /// e.g. "0000:01:01.0".
    ///
    /// # See also
    ///
    /// [`nvmlDeviceGetCreatableVgpus`]: <https://docs.nvidia.com/deploy/nvml-api/group__nvmlVgpu.html#group__nvmlVgpu_1ge86fff933c262740f7a374973c4747b6>
    /// [`nvmlDeviceGetHandleByPciBusId_v2`]: <https://docs.nvidia.com/deploy/nvml-api/group__nvmlDeviceQueries.html#group__nvmlDeviceQueries_1gea7484bb9eac412c28e8a73842254c05>
    /// [`struct nvmlPciInfo_t`]: <https://docs.nvidia.com/deploy/nvml-api/structnvmlPciInfo__t.html#structnvmlPciInfo__t_1a4d54ad9b596d7cab96ecc34613adbe4>
    #[export]
    fn creatable_vgpu_types_for_dev(bus_id: &str) -> Result<Vec<Value>> {
        let nvml = Nvml::init()?;
        let device = nvml.device_by_pci_bus_id(bus_id)?;

        Ok(build_vgpu_type_list(device.vgpu_creatable_types()?))
    }

    /// Retrieves a list of *supported* vGPU types for the specified GPU by bus id.
    ///
    /// The [`bus_id`] is of format "\<domain\>:\<bus\>:\<device\>.\<function\>",
    /// e.g. "0000:01:01.0".
    ///
    /// # See also
    ///
    /// [`nvmlDeviceGetSupportedVgpus`]: <https://docs.nvidia.com/deploy/nvml-api/group__nvmlVgpu.html#group__nvmlVgpu_1ge084b87e80350165859500ebec714274>
    /// [`nvmlDeviceGetHandleByPciBusId_v2`]: <https://docs.nvidia.com/deploy/nvml-api/group__nvmlDeviceQueries.html#group__nvmlDeviceQueries_1gea7484bb9eac412c28e8a73842254c05>
    /// [`struct nvmlPciInfo_t`]: <https://docs.nvidia.com/deploy/nvml-api/structnvmlPciInfo__t.html#structnvmlPciInfo__t_1a4d54ad9b596d7cab96ecc34613adbe4>
    #[export]
    fn supported_vgpu_types_for_dev(bus_id: &str) -> Result<Vec<Value>> {
        let nvml = Nvml::init()?;
        let device = nvml.device_by_pci_bus_id(bus_id)?;

        Ok(build_vgpu_type_list(device.vgpu_supported_types()?))
    }

    fn build_vgpu_type_list(vgpu_types: Vec<nvml_wrapper::vgpu::VgpuType>) -> Vec<Value> {
        let mut result = Vec::with_capacity(vgpu_types.len());
        for vgpu in vgpu_types {
            let id = vgpu.id();
            match build_vgpu_type_entry(&vgpu) {
                Ok(entry) => result.push(entry),
                Err(err) => tracing::warn!("skipping vGPU type {id}: {err:#}"),
            }
        }
        result
    }

    fn build_vgpu_type_entry(vgpu: &nvml_wrapper::vgpu::VgpuType) -> Result<Value> {
        let hash = Hash::new();
        hash.insert("id", Value::new_uint(vgpu.id() as usize));
        hash.insert("name", Value::new_string(&vgpu.name()?));
        hash.insert("description", Value::new_string(&description(vgpu)?));
        Ok(Value::new_ref(&hash))
    }

    // a description like it used to exist in the sysfs with the standard mdev interface
    fn description(vgpu_type: &nvml_wrapper::vgpu::VgpuType) -> Result<String> {
        let class_name = vgpu_type.class_name()?;
        let max_instances = vgpu_type.max_instances()?;
        let max_instances_per_vm = vgpu_type.max_instances_per_vm()?;

        let framebuffer_size_mb = vgpu_type.framebuffer_size()? / 1024 / 1024; // bytes to MiB
        let num_heads = vgpu_type.num_display_heads()?;

        let mut max_resolution = (0u32, 0u32);
        for head in 0..num_heads {
            match vgpu_type.resolution(head) {
                Ok(res) => max_resolution = max_resolution.max(res),
                Err(err) => tracing::warn!(
                    "vGPU type {}: failed to query resolution for head {head}: {err:#}",
                    vgpu_type.id(),
                ),
            }
        }
        let (max_res_x, max_res_y) = max_resolution;

        let license = vgpu_type.license()?;

        Ok(format!(
            "class={class_name}\n\
            max-instances={max_instances}\n\
            max-instances-per-vm={max_instances_per_vm}\n\
            framebuffer-size={framebuffer_size_mb}MiB\n\
            num-heads={num_heads}\n\
            max-resolution={max_res_x}x{max_res_y}\n\
            license={license}"
        ))
    }
}
