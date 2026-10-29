// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF7 brick-2: the signed SOURCE registry — where source families' schema refs and PRIVACY
//! FLOORS live, and the resolution that turns a descriptor's binding set into
//! `VerifiedProjectionSourceChirho` evidence (CF7 notes §2: app or operator input never chooses a
//! privacy floor; the composition RESOLVES it from this signed chain).
//!
//! The fifth chain-core consumer: same walk law as the projection registry (dense seq +
//! prev-binding + domain anchor + identity + root sig, torn tail fails closed). Op laws: first
//! registration wins per family; amends are FLOOR-MONOTONE — a privacy floor never lowers (the
//! K3/R5b downgrade-refusal class; raising a floor deliberately breaks descriptors registered
//! under the old floor, forcing re-registration at the higher floor); a retired family resolves
//! nothing. Resolution requires EXACT schema-ref equality per binding — schema drift refuses.

use crate::descriptor_chirho::{
    validate_digest_chirho, ProjectionDescriptorChirho, VerifiedProjectionSourceChirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_chain_core_chirho::{
    chain_anchor_hex_chirho, walk_verified_chain_chirho, ChainFamilyChirho, ChainWalkErrorChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_model_privacy_chirho::PrivacyClassChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SOURCE_REGISTRY_RECORD_SCHEMA_V1_CHIRHO: &str = "ledger-source-registry-record-v1-chirho";
pub const SOURCE_REGISTRY_CHAIN_DOMAIN_CHIRHO: &str = "source-registry-chain-v1-chirho";

/// One source family's signed declaration: schema revision + privacy floor + floor evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDeclarationChirho {
    pub family_id_chirho: String,
    pub schema_ref_chirho: DigestChirho,
    pub privacy_floor_chirho: PrivacyClassChirho,
    pub privacy_evidence_ref_chirho: DigestChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SourceRegistryOpChirho {
    #[serde(rename = "register-source-chirho")]
    RegisterSourceChirho {
        declaration_chirho: SourceDeclarationChirho,
    },
    #[serde(rename = "amend-source-chirho")]
    AmendSourceChirho {
        declaration_chirho: SourceDeclarationChirho,
    },
    #[serde(rename = "retire-source-chirho")]
    RetireSourceChirho { family_id_chirho: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRegistryRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub prev_chirho: String,
    pub registry_id_chirho: String,
    pub op_chirho: SourceRegistryOpChirho,
    pub root_sig_chirho: String,
}

/// One family's folded state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceStateChirho {
    pub current_chirho: SourceDeclarationChirho,
    pub retired_chirho: bool,
}

/// The fully verified source registry at one load.
#[derive(Debug)]
pub struct VerifiedSourceRegistryChirho {
    pub records_chirho: Vec<SourceRegistryRecordChirho>,
    pub tail_digest_hex_chirho: String,
    pub sources_chirho: BTreeMap<String, SourceStateChirho>,
}

fn validate_declaration_chirho(declaration_chirho: &SourceDeclarationChirho) -> Result<()> {
    if declaration_chirho.family_id_chirho.is_empty()
        || declaration_chirho.family_id_chirho.len() > 128
    {
        bail!("source family id must be nonempty and bounded");
    }
    validate_digest_chirho("source schema", &declaration_chirho.schema_ref_chirho)?;
    validate_digest_chirho(
        "source privacy evidence",
        &declaration_chirho.privacy_evidence_ref_chirho,
    )?;
    Ok(())
}

fn op_declaration_chirho(op_chirho: &SourceRegistryOpChirho) -> Option<&SourceDeclarationChirho> {
    match op_chirho {
        SourceRegistryOpChirho::RegisterSourceChirho { declaration_chirho }
        | SourceRegistryOpChirho::AmendSourceChirho { declaration_chirho } => {
            Some(declaration_chirho)
        }
        SourceRegistryOpChirho::RetireSourceChirho { .. } => None,
    }
}

pub fn canonical_source_registry_line_chirho(
    record_chirho: &SourceRegistryRecordChirho,
) -> Result<String> {
    if record_chirho.schema_chirho != SOURCE_REGISTRY_RECORD_SCHEMA_V1_CHIRHO {
        bail!("unsupported source registry record schema");
    }
    if record_chirho.registry_id_chirho.is_empty() {
        bail!("source registry record must name its registry");
    }
    if let Some(declaration_chirho) = op_declaration_chirho(&record_chirho.op_chirho) {
        validate_declaration_chirho(declaration_chirho)?;
    }
    serde_json::to_string(record_chirho).context("encode canonical source registry record")
}

pub fn parse_canonical_source_registry_line_chirho(
    line_chirho: &str,
) -> Result<SourceRegistryRecordChirho> {
    #[derive(Deserialize)]
    struct SchemaProbeChirho {
        schema_chirho: String,
    }
    let probe_chirho: SchemaProbeChirho =
        serde_json::from_str(line_chirho).context("probe source registry record schema")?;
    if probe_chirho.schema_chirho != SOURCE_REGISTRY_RECORD_SCHEMA_V1_CHIRHO {
        bail!("unsupported source registry record schema");
    }
    let record_chirho: SourceRegistryRecordChirho =
        serde_json::from_str(line_chirho).context("decode source registry record")?;
    let canonical_chirho = canonical_source_registry_line_chirho(&record_chirho)?;
    if canonical_chirho != line_chirho {
        bail!("source registry record has a byte-canonical mismatch");
    }
    Ok(record_chirho)
}

pub fn source_registry_root_signed_content_chirho(
    record_chirho: &SourceRegistryRecordChirho,
) -> Result<String> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.root_sig_chirho = String::new();
    canonical_source_registry_line_chirho(&unsigned_chirho)
}

struct SourceRegistryChainFamilyChirho<'ports_chirho> {
    registry_id_chirho: &'ports_chirho str,
    root_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
}

impl ChainFamilyChirho for SourceRegistryChainFamilyChirho<'_> {
    type RecordChirho = SourceRegistryRecordChirho;
    type ErrorChirho = anyhow::Error;

    fn parse_line_chirho(
        &self,
        line_chirho: &str,
    ) -> Result<SourceRegistryRecordChirho, anyhow::Error> {
        parse_canonical_source_registry_line_chirho(line_chirho)
    }

    fn seq_chirho(&self, record_chirho: &SourceRegistryRecordChirho) -> u64 {
        record_chirho.seq_chirho
    }

    fn prev_hex_chirho<'record_chirho>(
        &self,
        record_chirho: &'record_chirho SourceRegistryRecordChirho,
    ) -> &'record_chirho str {
        &record_chirho.prev_chirho
    }

    fn verify_record_chirho(
        &self,
        record_chirho: &SourceRegistryRecordChirho,
    ) -> Result<(), anyhow::Error> {
        if record_chirho.registry_id_chirho != self.registry_id_chirho {
            bail!(
                "record names source registry {} — cross-registry replay refused",
                record_chirho.registry_id_chirho
            );
        }
        let signed_content_chirho = source_registry_root_signed_content_chirho(record_chirho)?;
        if !self
            .root_chirho
            .verify_chirho(&signed_content_chirho, &record_chirho.root_sig_chirho)
        {
            bail!(
                "source registry root signature does not verify at seq {}",
                record_chirho.seq_chirho
            );
        }
        Ok(())
    }
}

/// Load and FULLY verify the source registry (torn tail fails closed; the shared chain walk; the
/// op-law fold). Missing object = an empty registry.
pub fn load_verified_source_registry_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_chirho: &dyn LedgerSignerPortChirho,
    path_chirho: &StoragePathChirho,
    registry_id_chirho: &str,
) -> Result<VerifiedSourceRegistryChirho> {
    let anchor_chirho =
        chain_anchor_hex_chirho(SOURCE_REGISTRY_CHAIN_DOMAIN_CHIRHO, registry_id_chirho);
    let Some(bytes_chirho) = storage_chirho
        .read_all_chirho(path_chirho)
        .map_err(|error_chirho| anyhow!("read source registry: {error_chirho}"))?
    else {
        return Ok(VerifiedSourceRegistryChirho {
            records_chirho: Vec::new(),
            tail_digest_hex_chirho: anchor_chirho,
            sources_chirho: BTreeMap::new(),
        });
    };
    if bytes_chirho
        .last()
        .is_some_and(|byte_chirho| *byte_chirho != b'\n')
    {
        bail!(
            "source registry has a torn tail — configuration authority fails closed (operator \
             event, never silent repair)"
        );
    }
    let text_chirho = std::str::from_utf8(&bytes_chirho)
        .map_err(|_| anyhow!("source registry bytes are not UTF-8"))?;
    let family_chirho = SourceRegistryChainFamilyChirho {
        registry_id_chirho,
        root_chirho,
    };
    let (lines_chirho, tail_digest_hex_chirho) =
        walk_verified_chain_chirho(text_chirho, &anchor_chirho, &family_chirho).map_err(
            |error_chirho| match error_chirho {
                ChainWalkErrorChirho::DenseSeqChirho {
                    expected_chirho,
                    found_chirho,
                } => anyhow!("seq {found_chirho} where {expected_chirho} expected (dense law)"),
                ChainWalkErrorChirho::PrevBindingChirho { seq_chirho } => {
                    anyhow!("prev mismatch at seq {seq_chirho}")
                }
                ChainWalkErrorChirho::FamilyChirho { error_chirho } => error_chirho,
            },
        )?;
    let mut sources_chirho: BTreeMap<String, SourceStateChirho> = BTreeMap::new();
    let mut records_chirho = Vec::with_capacity(lines_chirho.len());
    for line_chirho in lines_chirho {
        fold_source_op_chirho(&mut sources_chirho, &line_chirho.record_chirho.op_chirho)?;
        records_chirho.push(line_chirho.record_chirho);
    }
    Ok(VerifiedSourceRegistryChirho {
        records_chirho,
        tail_digest_hex_chirho,
        sources_chirho,
    })
}

/// The op law: first registration wins per family; amends never lower the privacy floor (the
/// downgrade-refusal class); a retired family accepts no further op.
fn fold_source_op_chirho(
    sources_chirho: &mut BTreeMap<String, SourceStateChirho>,
    op_chirho: &SourceRegistryOpChirho,
) -> Result<()> {
    match op_chirho {
        SourceRegistryOpChirho::RegisterSourceChirho { declaration_chirho } => {
            let family_chirho = declaration_chirho.family_id_chirho.clone();
            if sources_chirho.contains_key(&family_chirho) {
                bail!("source {family_chirho} is already registered (first registration wins)");
            }
            sources_chirho.insert(
                family_chirho,
                SourceStateChirho {
                    current_chirho: declaration_chirho.clone(),
                    retired_chirho: false,
                },
            );
        }
        SourceRegistryOpChirho::AmendSourceChirho { declaration_chirho } => {
            let family_chirho = &declaration_chirho.family_id_chirho;
            let Some(state_chirho) = sources_chirho.get_mut(family_chirho) else {
                bail!("amend of unregistered source {family_chirho}");
            };
            if state_chirho.retired_chirho {
                bail!("amend of retired source {family_chirho}");
            }
            if declaration_chirho.privacy_floor_chirho
                < state_chirho.current_chirho.privacy_floor_chirho
            {
                bail!(
                    "amend of source {family_chirho} LOWERS its privacy floor — floors are \
                     monotone (the downgrade-refusal law)"
                );
            }
            if declaration_chirho == &state_chirho.current_chirho {
                bail!("amend of source {family_chirho} names an identical declaration (no-op)");
            }
            state_chirho.current_chirho = declaration_chirho.clone();
        }
        SourceRegistryOpChirho::RetireSourceChirho { family_id_chirho } => {
            let Some(state_chirho) = sources_chirho.get_mut(family_id_chirho) else {
                bail!("retire of unregistered source {family_id_chirho}");
            };
            if state_chirho.retired_chirho {
                bail!("retire of already-retired source {family_id_chirho}");
            }
            state_chirho.retired_chirho = true;
        }
    }
    Ok(())
}

/// Append one op: full verified load, op precondition via the fold, build → root-sign
/// (sign-then-attach) → ONE durable append.
pub fn append_source_registry_op_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_chirho: &dyn LedgerSignerPortChirho,
    path_chirho: &StoragePathChirho,
    registry_id_chirho: &str,
    op_chirho: SourceRegistryOpChirho,
) -> Result<SourceRegistryRecordChirho> {
    let verified_chirho = load_verified_source_registry_chirho(
        storage_chirho,
        root_chirho,
        path_chirho,
        registry_id_chirho,
    )?;
    let mut preview_chirho = verified_chirho.sources_chirho.clone();
    fold_source_op_chirho(&mut preview_chirho, &op_chirho)?;
    let mut record_chirho = SourceRegistryRecordChirho {
        schema_chirho: SOURCE_REGISTRY_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        seq_chirho: verified_chirho.records_chirho.len() as u64,
        prev_chirho: verified_chirho.tail_digest_hex_chirho.clone(),
        registry_id_chirho: registry_id_chirho.to_string(),
        op_chirho,
        root_sig_chirho: String::new(),
    };
    let signed_content_chirho = source_registry_root_signed_content_chirho(&record_chirho)?;
    record_chirho.root_sig_chirho = root_chirho
        .sign_chirho(&signed_content_chirho)
        .map_err(|error_chirho| anyhow!("sign source registry record: {error_chirho}"))?;
    let line_chirho = canonical_source_registry_line_chirho(&record_chirho)?;
    let mut bytes_chirho = line_chirho.into_bytes();
    bytes_chirho.push(b'\n');
    storage_chirho
        .append_durable_chirho(path_chirho, &bytes_chirho)
        .map_err(|error_chirho| anyhow!("append source registry record: {error_chirho}"))?;
    Ok(record_chirho)
}

/// THE RESOLUTION (CF7 notes §2): turn a descriptor's binding set into verified source evidence
/// from the signed registry — per binding IN ORDER, the family must be registered, not retired,
/// and its CURRENT schema ref must EXACTLY equal the binding's (schema drift refuses). The
/// resulting evidence feeds `verify_projection_descriptor_chirho`, whose evidence-digest
/// re-derivation then enforces that the descriptor was registered under exactly these floors.
pub fn resolve_projection_sources_chirho(
    source_registry_chirho: &VerifiedSourceRegistryChirho,
    descriptor_chirho: &ProjectionDescriptorChirho,
) -> Result<Vec<VerifiedProjectionSourceChirho>> {
    let mut resolved_chirho = Vec::with_capacity(descriptor_chirho.source_families_chirho.len());
    for binding_chirho in &descriptor_chirho.source_families_chirho {
        let Some(state_chirho) = source_registry_chirho
            .sources_chirho
            .get(&binding_chirho.family_id_chirho)
        else {
            bail!(
                "descriptor binds UNREGISTERED source family {}",
                binding_chirho.family_id_chirho
            );
        };
        if state_chirho.retired_chirho {
            bail!(
                "descriptor binds RETIRED source family {}",
                binding_chirho.family_id_chirho
            );
        }
        if state_chirho.current_chirho.schema_ref_chirho != binding_chirho.source_schema_ref_chirho
        {
            bail!(
                "descriptor's schema ref for source family {} diverges from the registry's \
                 CURRENT revision (schema drift refuses)",
                binding_chirho.family_id_chirho
            );
        }
        resolved_chirho.push(VerifiedProjectionSourceChirho {
            binding_chirho: binding_chirho.clone(),
            privacy_floor_chirho: state_chirho.current_chirho.privacy_floor_chirho,
            privacy_evidence_ref_chirho: state_chirho
                .current_chirho
                .privacy_evidence_ref_chirho
                .clone(),
        });
    }
    Ok(resolved_chirho)
}

#[cfg(test)]
#[path = "source_registry_chirho/source_registry_tests_chirho.rs"]
mod source_registry_tests_chirho;
