#[perlmod::package(name = "PVE::RS::Firewall::SDN", lib = "pve_rs")]
mod export {
    use std::collections::HashMap;
    use std::{fs, io};

    use anyhow::{bail, Context, Error};
    use serde::Serialize;

    use proxmox_ve_config::{
        common::Allowlist,
        firewall::types::ipset::{IpsetAddress, IpsetEntry},
        firewall::types::Ipset,
        guest::types::Vmid,
        sdn::{
            config::{RunningConfig, SdnConfig},
            ipam::{Ipam, IpamJson},
            VnetName,
        },
    };

    #[derive(Clone, Debug, Default, Serialize)]
    pub struct LegacyIpsetEntry {
        nomatch: bool,
        cidr: String,
        comment: Option<String>,
    }

    impl LegacyIpsetEntry {
        pub fn from_ipset_entry(entry: &IpsetEntry) -> Vec<LegacyIpsetEntry> {
            let mut entries = Vec::new();

            match &entry.address {
                IpsetAddress::Alias(name) => {
                    entries.push(Self {
                        nomatch: entry.nomatch,
                        cidr: name.to_string(),
                        comment: entry.comment.clone(),
                    });
                }
                IpsetAddress::Cidr(cidr) => {
                    entries.push(Self {
                        nomatch: entry.nomatch,
                        cidr: cidr.to_string(),
                        comment: entry.comment.clone(),
                    });
                }
                IpsetAddress::Range(range) => {
                    entries.extend(range.to_cidrs().into_iter().map(|cidr| Self {
                        nomatch: entry.nomatch,
                        cidr: cidr.to_string(),
                        comment: entry.comment.clone(),
                    }))
                }
            };

            entries
        }
    }

    #[derive(Clone, Debug, Default, Serialize)]
    pub struct SdnFirewallConfig {
        ipset: HashMap<String, Vec<LegacyIpsetEntry>>,
        ipset_comments: HashMap<String, String>,
    }

    impl SdnFirewallConfig {
        pub fn new() -> Self {
            Default::default()
        }

        pub fn extend_ipsets(&mut self, ipsets: impl IntoIterator<Item = Ipset>) {
            for ipset in ipsets {
                let entries = ipset
                    .iter()
                    .flat_map(LegacyIpsetEntry::from_ipset_entry)
                    .collect();

                self.ipset.insert(ipset.name().name().to_string(), entries);

                if let Some(comment) = &ipset.comment {
                    self.ipset_comments
                        .insert(ipset.name().name().to_string(), comment.to_string());
                }
            }
        }
    }

    const SDN_RUNNING_CONFIG: &str = "/etc/pve/sdn/.running-config";
    const SDN_IPAM: &str = "/etc/pve/priv/ipam.db";

    #[export]
    pub fn config(
        vnet_filter: Option<Vec<VnetName>>,
        vm_filter: Option<Vec<Vmid>>,
    ) -> Result<SdnFirewallConfig, Error> {
        let mut refs = SdnFirewallConfig::new();

        match fs::read_to_string(SDN_RUNNING_CONFIG) {
            Ok(data) => {
                let running_config: RunningConfig = serde_json::from_str(&data)?;
                let sdn_config = SdnConfig::try_from(running_config)
                    .with_context(|| "Failed to parse SDN config".to_string())?;

                let allowlist = vnet_filter.map(Allowlist::from_iter);
                refs.extend_ipsets(sdn_config.ipsets(allowlist.as_ref()));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => {
                bail!("Cannot open SDN running config: {e:#}");
            }
        };

        match fs::read_to_string(SDN_IPAM) {
            Ok(data) => {
                let ipam_json: IpamJson = serde_json::from_str(&data)?;
                let ipam: Ipam = Ipam::try_from(ipam_json)
                    .with_context(|| "Failed to parse IPAM".to_string())?;

                let allowlist = vm_filter.map(Allowlist::from_iter);
                refs.extend_ipsets(ipam.ipsets(allowlist.as_ref()));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => {
                bail!("Cannot open IPAM database: {e:#}");
            }
        };

        Ok(refs)
    }
}
