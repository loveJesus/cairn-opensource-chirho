// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Hosting status for a domain: one read-only, PII-free view that composes a domain's verified routing bindings and its desired DNS zone, so an owner or agent can ask "what is set up for cardshop.example?" and get the whole picture.

use crate::{dns_zone_chirho, domain_binding_chirho};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostingBindingViewChirho {
    pub host_chirho: String,
    pub path_prefix_chirho: String,
    pub app_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_base_chirho: Option<String>,
    pub live_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostingStatusChirho {
    pub schema_chirho: String,
    pub domain_chirho: String,
    /// True when at least one live routing binding serves this domain (host == domain).
    pub routed_chirho: bool,
    pub live_binding_count_chirho: usize,
    pub bindings_chirho: Vec<HostingBindingViewChirho>,
    pub has_dns_zone_chirho: bool,
    pub dns_record_count_chirho: usize,
    pub dns_record_types_chirho: Vec<String>,
    /// Honest reminder that this is desired/declared state, not a live-provider confirmation.
    pub note_chirho: String,
}

/// Compose a domain's hosting status from verified routing bindings and the verified desired DNS
/// zone. Pure read over fail-closed verified records; carries no private content.
pub fn hosting_status_chirho(
    root_chirho: &Path,
    domain_chirho: &str,
) -> Result<HostingStatusChirho> {
    let domain_lower_chirho = domain_chirho.to_ascii_lowercase();

    // Live routing bindings whose host is exactly this domain (latest active per host+path).
    let binding_records_chirho =
        domain_binding_chirho::verified_domain_bindings_chirho(root_chirho)?;
    let mut latest_seq_by_key_chirho: std::collections::BTreeMap<(String, String), u64> =
        std::collections::BTreeMap::new();
    for record_chirho in &binding_records_chirho {
        if record_chirho.host_chirho != domain_lower_chirho {
            continue;
        }
        let key_chirho = (
            record_chirho.host_chirho.clone(),
            record_chirho.path_prefix_chirho.clone(),
        );
        let entry_chirho = latest_seq_by_key_chirho.entry(key_chirho).or_insert(0);
        if record_chirho.seq_chirho >= *entry_chirho {
            *entry_chirho = record_chirho.seq_chirho;
        }
    }
    let mut bindings_chirho = Vec::new();
    for record_chirho in &binding_records_chirho {
        if record_chirho.host_chirho != domain_lower_chirho {
            continue;
        }
        let key_chirho = (
            record_chirho.host_chirho.clone(),
            record_chirho.path_prefix_chirho.clone(),
        );
        let is_latest_chirho =
            latest_seq_by_key_chirho.get(&key_chirho) == Some(&record_chirho.seq_chirho);
        let live_chirho = is_latest_chirho
            && record_chirho.status_chirho
                == domain_binding_chirho::DomainBindingStatusChirho::ActiveChirho;
        if live_chirho {
            bindings_chirho.push(HostingBindingViewChirho {
                host_chirho: record_chirho.host_chirho.clone(),
                path_prefix_chirho: record_chirho.path_prefix_chirho.clone(),
                app_chirho: record_chirho.app_chirho.clone(),
                route_base_chirho: record_chirho.route_base_chirho.clone(),
                live_chirho,
            });
        }
    }
    bindings_chirho.sort_by(|a_chirho, b_chirho| {
        a_chirho
            .path_prefix_chirho
            .cmp(&b_chirho.path_prefix_chirho)
    });
    let live_binding_count_chirho = bindings_chirho.len();

    // Desired DNS zone for this domain (latest verified record).
    let zone_records_chirho = dns_zone_chirho::verified_dns_zone_records_chirho(root_chirho)?;
    let desired_zone_chirho =
        dns_zone_chirho::desired_zone_for_domain_chirho(&zone_records_chirho, &domain_lower_chirho);
    let (has_dns_zone_chirho, dns_record_count_chirho, dns_record_types_chirho) =
        match &desired_zone_chirho {
            Some(zone_chirho) => {
                let mut types_chirho = BTreeSet::new();
                for record_chirho in &zone_chirho.records_chirho {
                    types_chirho.insert(record_chirho.type_chirho.to_ascii_uppercase());
                }
                (
                    true,
                    zone_chirho.records_chirho.len(),
                    types_chirho.into_iter().collect(),
                )
            }
            None => (false, 0, Vec::new()),
        };

    Ok(HostingStatusChirho {
        schema_chirho: "hosting-status-v1-chirho".to_string(),
        domain_chirho: domain_lower_chirho,
        routed_chirho: live_binding_count_chirho > 0,
        live_binding_count_chirho,
        bindings_chirho,
        has_dns_zone_chirho,
        dns_record_count_chirho,
        dns_record_types_chirho,
        note_chirho: "Desired/declared state from verified signed records. DNS records are the desired zone, not a live-provider confirmation; applying them live is a separate gated step.".to_string(),
    })
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_root_chirho() -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-hosting-status-test-{n_chirho}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d_chirho| d_chirho.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }

    #[test]
    fn composes_bindings_and_zone_for_a_domain_chirho() {
        let root_chirho = temp_root_chirho();
        domain_binding_chirho::emit_domain_binding_chirho(
            &root_chirho,
            domain_binding_chirho::DomainBindingInputChirho {
                owner_principal_chirho: "owner/t".to_string(),
                host_chirho: "cardshop.example".to_string(),
                path_prefix_chirho: "/".to_string(),
                app_chirho: "cardshop".to_string(),
                route_base_chirho: None,
                status_chirho: domain_binding_chirho::DomainBindingStatusChirho::ActiveChirho,
            },
        )
        .unwrap();
        dns_zone_chirho::emit_dns_zone_chirho(
            &root_chirho,
            dns_zone_chirho::DnsZoneInputChirho {
                owner_principal_chirho: "owner/t".to_string(),
                domain_chirho: "cardshop.example".to_string(),
                records_chirho: vec![
                    dns_zone_chirho::DnsRecordChirho {
                        type_chirho: "A".to_string(),
                        name_chirho: "@".to_string(),
                        value_chirho: "192.0.2.1".to_string(),
                        ttl_chirho: 3600,
                        priority_chirho: None,
                    },
                    dns_zone_chirho::DnsRecordChirho {
                        type_chirho: "TXT".to_string(),
                        name_chirho: "@".to_string(),
                        value_chirho: "v=spf1 -all".to_string(),
                        ttl_chirho: 3600,
                        priority_chirho: None,
                    },
                ],
            },
        )
        .unwrap();

        let status_chirho = hosting_status_chirho(&root_chirho, "CARDSHOP.example").unwrap();
        assert!(status_chirho.routed_chirho);
        assert_eq!(status_chirho.live_binding_count_chirho, 1);
        assert_eq!(status_chirho.bindings_chirho[0].app_chirho, "cardshop");
        assert!(status_chirho.has_dns_zone_chirho);
        assert_eq!(status_chirho.dns_record_count_chirho, 2);
        assert_eq!(
            status_chirho.dns_record_types_chirho,
            vec!["A".to_string(), "TXT".to_string()]
        );

        let empty_chirho = hosting_status_chirho(&root_chirho, "other.example").unwrap();
        assert!(!empty_chirho.routed_chirho);
        assert!(!empty_chirho.has_dns_zone_chirho);
        assert_eq!(empty_chirho.dns_record_count_chirho, 0);

        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
