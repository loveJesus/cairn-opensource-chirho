// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! CLI string-spec parsers: small, single-purpose helpers that turn --flag value specs into typed inputs (moved out of dispatch to keep it shrinking).

use anyhow::Context;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{dns_zone_chirho, resource_chirho, review_chirho};

pub(crate) fn parse_dns_record_spec_chirho(
    spec_chirho: &str,
) -> anyhow::Result<dns_zone_chirho::DnsRecordChirho> {
    let parts_chirho: Vec<&str> = spec_chirho.split(',').map(str::trim).collect();
    if parts_chirho.len() < 3 || parts_chirho.len() > 5 {
        anyhow::bail!("--record must be TYPE,NAME,VALUE[,TTL[,PRIORITY]]: got '{spec_chirho}'");
    }
    let ttl_chirho = match parts_chirho.get(3).copied() {
        Some("") => anyhow::bail!("DNS record TTL must not be empty in '{spec_chirho}'"),
        Some(ttl_text_chirho) => ttl_text_chirho
            .parse::<u32>()
            .with_context(|| format!("DNS record TTL must be u32 in '{spec_chirho}'"))?,
        None => 3600,
    };
    let priority_chirho = match parts_chirho.get(4).copied() {
        Some("") => anyhow::bail!("DNS record priority must not be empty in '{spec_chirho}'"),
        Some(priority_text_chirho) => Some(
            priority_text_chirho
                .parse::<u32>()
                .with_context(|| format!("DNS record priority must be u32 in '{spec_chirho}'"))?,
        ),
        None => None,
    };
    Ok(dns_zone_chirho::DnsRecordChirho {
        type_chirho: parts_chirho[0].to_string(),
        name_chirho: parts_chirho[1].to_string(),
        value_chirho: parts_chirho[2].to_string(),
        ttl_chirho,
        priority_chirho,
    })
}

pub(crate) fn parse_effect_prices_chirho(
    effect_prices_chirho: &[String],
) -> anyhow::Result<std::collections::BTreeMap<String, i64>> {
    let mut out_chirho = std::collections::BTreeMap::new();
    for raw_chirho in effect_prices_chirho {
        let (effect_chirho, price_chirho) = raw_chirho
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("effect price must look like effect_chirho=17"))?;
        if effect_chirho.trim().is_empty() {
            anyhow::bail!("effect price key must not be empty");
        }
        let price_chirho: i64 = price_chirho
            .parse()
            .map_err(|_| anyhow::anyhow!("bad price in effect price '{raw_chirho}'"))?;
        if out_chirho
            .insert(effect_chirho.to_string(), price_chirho)
            .is_some()
        {
            anyhow::bail!("duplicate effect price for '{effect_chirho}'");
        }
    }
    Ok(out_chirho)
}

pub(crate) fn review_source_evidence_chirho(
    source_review_report_chirho: Option<String>,
    source_manifest_chirho: Option<String>,
    raw_manifest_chirho: Option<String>,
) -> anyhow::Result<(
    Option<HashChirho>,
    Option<review_chirho::ReviewSourceManifestEvidenceChirho>,
)> {
    let source_review_report_chirho = source_review_report_chirho.map(HashChirho);
    let Some(source_manifest_chirho) = source_manifest_chirho else {
        if raw_manifest_chirho.is_some() {
            anyhow::bail!("--raw-manifest requires --source-manifest");
        }
        return Ok((source_review_report_chirho, None));
    };
    Ok((
        source_review_report_chirho,
        Some(review_chirho::ReviewSourceManifestEvidenceChirho {
            effective_manifest_hash_chirho: HashChirho(source_manifest_chirho),
            raw_manifest_hash_chirho: raw_manifest_chirho.map(HashChirho),
        }),
    ))
}

pub(crate) fn parse_resource_bridges_chirho(
    bridges_chirho: &[String],
) -> anyhow::Result<Vec<resource_chirho::ResourceBridgeRefChirho>> {
    let mut out_chirho = Vec::new();
    for raw_chirho in bridges_chirho {
        let (kind_chirho, seq_chirho) = raw_chirho.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("resource bridge must look like billing:0 or provider-invoice:0")
        })?;
        let seq_chirho: u64 = seq_chirho
            .parse()
            .map_err(|_| anyhow::anyhow!("bad seq in resource bridge '{raw_chirho}'"))?;
        let kind_chirho = match kind_chirho {
            "billing" | "billing-usage" => {
                resource_chirho::ResourceBridgeKindChirho::BillingUsageChirho
            }
            "provider-invoice" => resource_chirho::ResourceBridgeKindChirho::ProviderInvoiceChirho,
            other_chirho => anyhow::bail!(
                "unknown resource bridge kind '{other_chirho}' (use billing|provider-invoice)"
            ),
        };
        out_chirho.push(resource_chirho::ResourceBridgeRefChirho {
            kind_chirho,
            seq_chirho,
        });
    }
    Ok(out_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::parse_resource_bridges_chirho;

    #[test]
    fn legacy_external_resource_bridge_authoring_is_absent_chirho() {
        let error_chirho = parse_resource_bridges_chirho(&["external:0".to_string()])
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("unknown resource bridge kind 'external'"));
        assert_eq!(
            parse_resource_bridges_chirho(&[
                "billing:0".to_string(),
                "provider-invoice:1".to_string(),
            ])
            .unwrap()
            .len(),
            2
        );
    }
}
