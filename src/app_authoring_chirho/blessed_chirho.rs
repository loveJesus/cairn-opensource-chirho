// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The blessed-effect registry — the small, signed set of effect primitives. App code (pure WASM
//! nodes, capabilities == []) cannot create blessed modules: effects resolve ONLY through this
//! fixed set, and the registry is signed by the cairn instance key, so a forged registry (with
//! extra kinds) fails verification. Every blessed kind also declares how it can be compensated
//! during causal reversion. Extending the set is an in-tree, signed act — never app-level.

use crate::model_chirho::{CapabilityChirho, CompensationKindChirho};
use anyhow::{bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[path = "blessed_chirho/v2_registry_chirho.rs"]
mod v2_registry_chirho;
pub(crate) use v2_registry_chirho::effect_admission_chirho::{
    admit_legacy_operator_effect_chirho, admit_verified_node_effect_chirho, EffectAdmissionChirho,
};
pub(crate) use v2_registry_chirho::validate_registry_v2_node_effects_chirho;
pub use v2_registry_chirho::{
    canonical_registry_v2_message_bytes_chirho, inert_authoring_registry_v2_message_chirho,
    named_unreachable_registry_v1_retirements_chirho, parse_canonical_registry_v2_message_chirho,
    registry_v2_message_from_contract_set_chirho, validate_registry_v2_message_chirho,
    validate_registry_v2_transition_parity_chirho, BlessedEffectContractBindingV2Chirho,
    BlessedEffectCoordinateV2Chirho, BlessedRegistryTransitionCoordinateChirho,
    BlessedRegistryV2MessageChirho, BLESSED_REGISTRY_V2_MESSAGE_SCHEMA_CHIRHO,
};

#[cfg(test)]
#[path = "blessed_chirho/effect_admission_tests_chirho.rs"]
mod effect_admission_tests_chirho;
#[cfg(test)]
#[path = "blessed_chirho/v2_registry_tests_chirho.rs"]
mod v2_registry_tests_chirho;

/// The canonical blessed effect kinds — the ONLY effects cairn will resolve.
pub const BLESSED_KINDS_CHIRHO: &[&str] = &[
    "clock",
    "random",
    "read_store",
    "write_store",
    "paid_effect",
    "query",
    "net",
    "secret_ref",
    "realtime_session",
    "human_check",
    "write_blob",
    "invoke",
    "template_app_deploy",
];
const BLESSED_REGISTRY_SCHEMA_CHIRHO: &str = "blessed-registry-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlessedEffectSpecChirho {
    pub kind_chirho: String,
    pub compensation_kind_chirho: CompensationKindChirho,
}

/// The kind string for a capability — used by the registry + the effect-layer gate.
pub fn capability_kind_chirho(capability_chirho: &CapabilityChirho) -> &'static str {
    match capability_chirho {
        CapabilityChirho::ClockChirho => "clock",
        CapabilityChirho::RandomChirho => "random",
        CapabilityChirho::ReadStoreChirho { .. } => "read_store",
        CapabilityChirho::WriteStoreChirho { .. } => "write_store",
        CapabilityChirho::PaidEffectChirho { .. } => "paid_effect",
        CapabilityChirho::QueryChirho { .. } => "query",
        CapabilityChirho::UserIdentityChirho { .. } => "user_identity",
        CapabilityChirho::AppContextChirho { .. } => "app_context",
        CapabilityChirho::SecretRefChirho { .. } => "secret_ref",
        CapabilityChirho::RealtimeSessionChirho { .. } => "realtime_session",
        CapabilityChirho::SupportIssueChirho { .. } => "support_issue",
        CapabilityChirho::CausalReversionChirho { .. } => "causal_reversion",
        CapabilityChirho::NetChirho { .. } => "net",
        CapabilityChirho::InvokeChirho { .. } => "invoke",
        CapabilityChirho::TemplateAppDeployChirho { .. } => "template_app_deploy",
    }
}

/// Is this capability a blessed (resolvable) effect?
pub fn is_blessed_chirho(capability_chirho: &CapabilityChirho) -> bool {
    BLESSED_KINDS_CHIRHO.contains(&capability_kind_chirho(capability_chirho))
}

pub fn compensation_kind_for_capability_chirho(
    capability_chirho: &CapabilityChirho,
) -> Option<CompensationKindChirho> {
    match capability_chirho {
        CapabilityChirho::PaidEffectChirho { effect_chirho, .. } => {
            paid_effect_compensation_kind_chirho(effect_chirho)
                .or_else(|| compensation_kind_for_kind_chirho("paid_effect"))
        }
        _ => compensation_kind_for_kind_chirho(capability_kind_chirho(capability_chirho)),
    }
}

pub fn paid_effect_compensation_kind_chirho(effect_chirho: &str) -> Option<CompensationKindChirho> {
    match effect_chirho {
        "email_provider_chirho" => Some(CompensationKindChirho::CorrectiveForwardChirho),
        "card_charge_chirho" => Some(CompensationKindChirho::PartialChirho {
            unsupported_aspects_chirho: vec![
                "bank-statement visibility cannot be undone".to_string(),
            ],
        }),
        "package_dispatch_chirho" => Some(CompensationKindChirho::ManualRemediationChirho {
            template_chirho: "Open package remediation task for EffectChirho {effect_chirho}; inspect dispatch request {request_chirho} and response {response_chirho}; record carrier correction or customer contact".to_string(),
        }),
        _ => None,
    }
}

pub fn compensation_kind_for_kind_chirho(kind_chirho: &str) -> Option<CompensationKindChirho> {
    match kind_chirho {
        "clock" => Some(CompensationKindChirho::NotApplicableChirho {
            reason_chirho: "clock reads are observations only".to_string(),
        }),
        "random" => Some(CompensationKindChirho::NotApplicableChirho {
            reason_chirho: "random reads are recorded observations only".to_string(),
        }),
        "read_store" => Some(CompensationKindChirho::NotApplicableChirho {
            reason_chirho: "store reads do not mutate state".to_string(),
        }),
        "write_store" => Some(CompensationKindChirho::FullInverseChirho),
        "paid_effect" => Some(CompensationKindChirho::PartialChirho {
            unsupported_aspects_chirho: vec![
                "external provider work may already be consumed".to_string(),
            ],
        }),
        "query" => Some(CompensationKindChirho::PartialChirho {
            unsupported_aspects_chirho: vec![
                "data exposure to the caller cannot be undone".to_string(),
            ],
        }),
        "net" => Some(CompensationKindChirho::ManualRemediationChirho {
            template_chirho: "Review EffectChirho {effect_chirho} with request {request_chirho} and response {response_chirho}; issue a connector-specific corrective action".to_string(),
        }),
        "secret_ref" => Some(CompensationKindChirho::NotApplicableChirho {
            reason_chirho: "secret refs are authority handles, not external mutations".to_string(),
        }),
        "realtime_session" => Some(CompensationKindChirho::PartialChirho {
            unsupported_aspects_chirho: vec![
                "elapsed human/provider session time cannot be unspent".to_string(),
            ],
        }),
        "human_check" => Some(CompensationKindChirho::NotApplicableChirho {
            reason_chirho: "human checks are verification observations only".to_string(),
        }),
        "write_blob" => Some(CompensationKindChirho::FullInverseChirho),
        "invoke" => Some(CompensationKindChirho::NotApplicableChirho {
            reason_chirho: "invoke is a composition edge; target effects compensate individually"
                .to_string(),
        }),
        "template_app_deploy" => Some(CompensationKindChirho::PartialChirho {
            unsupported_aspects_chirho: vec![
                "published app URLs may already have been observed".to_string(),
                "client owner binding records are forward-only authority evidence".to_string(),
            ],
        }),
        _ => None,
    }
}

pub fn blessed_effect_specs_chirho() -> Vec<BlessedEffectSpecChirho> {
    let mut specs_chirho: Vec<BlessedEffectSpecChirho> = BLESSED_KINDS_CHIRHO
        .iter()
        .map(|kind_chirho| BlessedEffectSpecChirho {
            kind_chirho: (*kind_chirho).to_string(),
            compensation_kind_chirho: compensation_kind_for_kind_chirho(kind_chirho)
                .expect("every blessed effect kind declares compensation"),
        })
        .collect();
    specs_chirho.sort_by(|a_chirho, b_chirho| a_chirho.kind_chirho.cmp(&b_chirho.kind_chirho));
    specs_chirho
}

pub fn validate_compensation_kind_chirho(kind_chirho: &CompensationKindChirho) -> Result<()> {
    match kind_chirho {
        CompensationKindChirho::FullInverseChirho
        | CompensationKindChirho::CorrectiveForwardChirho => Ok(()),
        CompensationKindChirho::PartialChirho {
            unsupported_aspects_chirho,
        } => {
            if unsupported_aspects_chirho.is_empty() {
                bail!("PartialChirho compensation must list unsupported aspects");
            }
            if unsupported_aspects_chirho
                .iter()
                .any(|aspect_chirho| aspect_chirho.trim().is_empty())
            {
                bail!("PartialChirho unsupported aspects must be non-empty");
            }
            Ok(())
        }
        CompensationKindChirho::ManualRemediationChirho { template_chirho } => {
            if template_chirho.trim().is_empty() {
                bail!("ManualRemediationChirho template must be non-empty");
            }
            if !template_chirho.contains("{effect_chirho}") {
                bail!("ManualRemediationChirho template must include {{effect_chirho}}");
            }
            Ok(())
        }
        CompensationKindChirho::NotApplicableChirho { reason_chirho } => {
            if reason_chirho.trim().is_empty() {
                bail!("NotApplicableChirho reason must be non-empty");
            }
            Ok(())
        }
    }
}

pub fn compensation_kind_label_chirho(kind_chirho: &CompensationKindChirho) -> String {
    match kind_chirho {
        CompensationKindChirho::FullInverseChirho => "FullInverseChirho".to_string(),
        CompensationKindChirho::CorrectiveForwardChirho => "CorrectiveForwardChirho".to_string(),
        CompensationKindChirho::PartialChirho {
            unsupported_aspects_chirho,
        } => format!("PartialChirho({})", unsupported_aspects_chirho.join("; ")),
        CompensationKindChirho::ManualRemediationChirho { template_chirho } => {
            format!("ManualRemediationChirho({template_chirho})")
        }
        CompensationKindChirho::NotApplicableChirho { reason_chirho } => {
            format!("NotApplicableChirho({reason_chirho})")
        }
    }
}

/// The signed blessed registry: the kinds + the instance pubkey + a signature over them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlessedRegistryChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub kinds_chirho: Vec<String>,
    pub effects_chirho: Vec<BlessedEffectSpecChirho>,
    pub pubkey_chirho: String,
    pub sig_chirho: String,
}

/// Build the registry and sign the canonical kinds with the cairn instance key.
pub fn signed_registry_chirho(root_chirho: &Path) -> Result<BlessedRegistryChirho> {
    let effects_chirho = blessed_effect_specs_chirho();
    let kinds_chirho: Vec<String> = effects_chirho
        .iter()
        .map(|spec_chirho| spec_chirho.kind_chirho.clone())
        .collect();
    let message_chirho = registry_message_chirho(BLESSED_REGISTRY_SCHEMA_CHIRHO, &effects_chirho)?;
    Ok(BlessedRegistryChirho {
        schema_chirho: BLESSED_REGISTRY_SCHEMA_CHIRHO.to_string(),
        sig_chirho: signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?,
        pubkey_chirho: signer_chirho::pubkey_hex_chirho(root_chirho)?,
        kinds_chirho,
        effects_chirho,
    })
}

/// Verify the registry shape and its signature over effect specs with the instance pubkey.
pub fn verify_registry_chirho(registry_chirho: &BlessedRegistryChirho) -> bool {
    validate_registry_chirho(registry_chirho).is_ok()
}

fn validate_registry_chirho(registry_chirho: &BlessedRegistryChirho) -> Result<()> {
    validate_registry_schema_chirho(registry_chirho)?;
    let expected_chirho = blessed_effect_specs_chirho();
    if registry_chirho.effects_chirho != expected_chirho {
        bail!("blessed registry effect specs are not canonical");
    }
    let derived_kinds_chirho: Vec<String> = registry_chirho
        .effects_chirho
        .iter()
        .map(|spec_chirho| spec_chirho.kind_chirho.clone())
        .collect();
    if registry_chirho.kinds_chirho != derived_kinds_chirho {
        bail!("blessed registry kinds do not match effect specs");
    }
    let mut seen_chirho = BTreeSet::new();
    for spec_chirho in &registry_chirho.effects_chirho {
        if !seen_chirho.insert(spec_chirho.kind_chirho.clone()) {
            bail!(
                "duplicate blessed effect kind '{}'",
                spec_chirho.kind_chirho
            );
        }
        if !BLESSED_KINDS_CHIRHO.contains(&spec_chirho.kind_chirho.as_str()) {
            bail!("unknown blessed effect kind '{}'", spec_chirho.kind_chirho);
        }
        validate_compensation_kind_chirho(&spec_chirho.compensation_kind_chirho)?;
    }
    if seen_chirho.len() != BLESSED_KINDS_CHIRHO.len() {
        bail!("blessed registry is missing effect specs");
    }
    let message_chirho = registry_message_chirho(
        &registry_chirho.schema_chirho,
        &registry_chirho.effects_chirho,
    )?;
    if !signer_chirho::verify_with_pubkey_chirho(
        &registry_chirho.pubkey_chirho,
        &message_chirho,
        &registry_chirho.sig_chirho,
    )
    .unwrap_or(false)
    {
        bail!("blessed registry signature invalid");
    }
    Ok(())
}

fn validate_registry_schema_chirho(registry_chirho: &BlessedRegistryChirho) -> Result<()> {
    if !registry_chirho.schema_chirho.is_empty()
        && registry_chirho.schema_chirho != BLESSED_REGISTRY_SCHEMA_CHIRHO
    {
        bail!(
            "blessed registry has unsupported schema '{}'",
            registry_chirho.schema_chirho
        );
    }
    Ok(())
}

fn registry_message_chirho(
    schema_chirho: &str,
    effects_chirho: &[BlessedEffectSpecChirho],
) -> Result<Vec<u8>> {
    let mut canonical_chirho = effects_chirho.to_vec();
    canonical_chirho.sort_by(|a_chirho, b_chirho| a_chirho.kind_chirho.cmp(&b_chirho.kind_chirho));
    if schema_chirho.is_empty() {
        return serde_json::to_vec(&canonical_chirho)
            .context("encode legacy blessed registry specs");
    }
    #[derive(Serialize)]
    struct BlessedRegistryMessageChirho {
        schema_chirho: String,
        effects_chirho: Vec<BlessedEffectSpecChirho>,
    }
    serde_json::to_vec(&BlessedRegistryMessageChirho {
        schema_chirho: schema_chirho.to_string(),
        effects_chirho: canonical_chirho,
    })
    .context("encode blessed registry specs")
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-blessed-test-{nanos_chirho}-{n_chirho}"))
    }

    #[test]
    fn registry_signs_verifies_and_rejects_forgery_chirho() {
        let root_chirho = tmp_root_chirho();
        let registry_chirho = signed_registry_chirho(&root_chirho).unwrap();
        assert!(verify_registry_chirho(&registry_chirho));
        assert_eq!(
            registry_chirho.schema_chirho,
            BLESSED_REGISTRY_SCHEMA_CHIRHO
        );
        assert!(registry_chirho.kinds_chirho.contains(&"clock".to_string()));
        assert!(registry_chirho
            .kinds_chirho
            .contains(&"human_check".to_string()));
        assert!(registry_chirho
            .kinds_chirho
            .contains(&"write_blob".to_string()));
        assert!(registry_chirho
            .kinds_chirho
            .contains(&"secret_ref".to_string()));
        assert!(registry_chirho
            .kinds_chirho
            .contains(&"realtime_session".to_string()));
        assert!(registry_chirho.kinds_chirho.contains(&"net".to_string()));
        assert!(registry_chirho.kinds_chirho.contains(&"invoke".to_string()));
        assert!(registry_chirho.kinds_chirho.contains(&"query".to_string()));
        assert_eq!(
            registry_chirho.effects_chirho.len(),
            registry_chirho.kinds_chirho.len()
        );
        for kind_chirho in BLESSED_KINDS_CHIRHO {
            let compensation_chirho = compensation_kind_for_kind_chirho(kind_chirho)
                .unwrap_or_else(|| panic!("missing compensation for {kind_chirho}"));
            validate_compensation_kind_chirho(&compensation_chirho).unwrap();
        }
        assert_eq!(
            compensation_kind_for_kind_chirho("write_store").unwrap(),
            crate::model_chirho::CompensationKindChirho::FullInverseChirho
        );
        assert!(matches!(
            compensation_kind_for_kind_chirho("net").unwrap(),
            crate::model_chirho::CompensationKindChirho::ManualRemediationChirho { .. }
        ));
        assert!(matches!(
            compensation_kind_for_kind_chirho("query").unwrap(),
            crate::model_chirho::CompensationKindChirho::PartialChirho { .. }
        ));
        assert!(matches!(
            paid_effect_compensation_kind_chirho("package_dispatch_chirho").unwrap(),
            crate::model_chirho::CompensationKindChirho::ManualRemediationChirho { .. }
        ));
        assert_eq!(
            paid_effect_compensation_kind_chirho("email_provider_chirho").unwrap(),
            crate::model_chirho::CompensationKindChirho::CorrectiveForwardChirho
        );
        assert!(matches!(
            paid_effect_compensation_kind_chirho("card_charge_chirho").unwrap(),
            crate::model_chirho::CompensationKindChirho::PartialChirho { .. }
        ));
        assert!(validate_compensation_kind_chirho(
            &crate::model_chirho::CompensationKindChirho::PartialChirho {
                unsupported_aspects_chirho: vec![]
            }
        )
        .is_err());
        assert!(validate_compensation_kind_chirho(
            &crate::model_chirho::CompensationKindChirho::ManualRemediationChirho {
                template_chirho: " ".to_string()
            }
        )
        .is_err());
        assert!(validate_compensation_kind_chirho(
            &crate::model_chirho::CompensationKindChirho::ManualRemediationChirho {
                template_chirho: "manual fix without placeholder".to_string()
            }
        )
        .is_err());

        // A forged registry with an extra kind fails verification (no instance key).
        let mut forged_chirho = signed_registry_chirho(&root_chirho).unwrap();
        forged_chirho.kinds_chirho.push("evil_effect".to_string());
        assert!(!verify_registry_chirho(&forged_chirho));
        let mut forged_comp_chirho = signed_registry_chirho(&root_chirho).unwrap();
        forged_comp_chirho.effects_chirho[0].compensation_kind_chirho =
            crate::model_chirho::CompensationKindChirho::FullInverseChirho;
        assert!(!verify_registry_chirho(&forged_comp_chirho));
        let mut missing_spec_chirho = signed_registry_chirho(&root_chirho).unwrap();
        missing_spec_chirho.effects_chirho.pop();
        missing_spec_chirho.kinds_chirho.pop();
        assert!(!verify_registry_chirho(&missing_spec_chirho));
        let mut unsupported_schema_chirho = signed_registry_chirho(&root_chirho).unwrap();
        unsupported_schema_chirho.schema_chirho = "blessed-registry-v9-chirho".to_string();
        unsupported_schema_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            &root_chirho,
            &registry_message_chirho(
                &unsupported_schema_chirho.schema_chirho,
                &unsupported_schema_chirho.effects_chirho,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!verify_registry_chirho(&unsupported_schema_chirho));
        let mut legacy_schema_chirho = signed_registry_chirho(&root_chirho).unwrap();
        legacy_schema_chirho.schema_chirho.clear();
        legacy_schema_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            &root_chirho,
            &registry_message_chirho(
                &legacy_schema_chirho.schema_chirho,
                &legacy_schema_chirho.effects_chirho,
            )
            .unwrap(),
        )
        .unwrap();
        let legacy_json_chirho = serde_json::to_string(&legacy_schema_chirho).unwrap();
        assert!(!legacy_json_chirho.contains("schema_chirho"));
        assert!(verify_registry_chirho(&legacy_schema_chirho));

        // The gate: blessed kinds resolve.
        assert!(is_blessed_chirho(&CapabilityChirho::ClockChirho));
        assert!(is_blessed_chirho(&CapabilityChirho::PaidEffectChirho {
            effect_chirho: "echo_paid_chirho".to_string(),
            caller_chirho: "alice".to_string(),
        }));
        assert!(is_blessed_chirho(&CapabilityChirho::NetChirho {
            allowlist_chirho: vec![]
        }));
        assert!(is_blessed_chirho(&CapabilityChirho::InvokeChirho {
            node_chirho: crate::model_chirho::HashChirho("node".to_string()),
        }));
        assert!(is_blessed_chirho(&CapabilityChirho::QueryChirho {
            prefix_chirho: "user/".to_string(),
            caller_chirho: "alice".to_string(),
            max_rows_chirho: 10,
        }));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
