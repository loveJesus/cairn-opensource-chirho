// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The projection registry: WHICH projections are live, at WHICH descriptor revision — a signed
//! append-only chain over the shared chain core (CF4 brick-1b, rulings #4972).
//!
//! Two-concept identity (the R5b pattern): a projection's NAME is its stable identity; the
//! content-addressed descriptor DIGEST is the immutable revision. Register binds a name to its
//! first descriptor; Amend supersedes the CURRENT digest monotonically (an amend off a superseded
//! digest is the downgrade class, refused); Retire ends feeding while history stays readable.
//! Resolution is three-state-plus-retired: Current / Superseded / Retired / Unknown — a NEW feed
//! admits ONLY Current. Configuration authority: torn tail FAILS CLOSED (operator event, never
//! repair); every record carries the registry root's signature verified against the INJECTED trust
//! root (never an embedded key id). Ports are INJECTED (the crate holds no ambient I/O capability).

use crate::descriptor_chirho::{
    parse_canonical_projection_descriptor_chirho, projection_descriptor_bytes_chirho,
    projection_descriptor_digest_chirho, ProjectionDescriptorChirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_chain_core_chirho::{
    chain_anchor_hex_chirho, walk_verified_chain_chirho, ChainFamilyChirho, ChainWalkErrorChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PROJECTION_REGISTRY_RECORD_SCHEMA_V1_CHIRHO: &str =
    "ledger-projection-registry-record-v1-chirho";
/// The chain-core domain for this family — distinct from every other family's domain, so no other
/// log's lines can splice into a projection registry (and vice versa).
pub const PROJECTION_REGISTRY_CHAIN_DOMAIN_CHIRHO: &str = "projection-registry-chain-v1-chirho";

/// One registry operation. The descriptor rides INLINE as the canonical struct (the record's own
/// exact-reserialize law covers its bytes), and its content digest is derived, never caller-stated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ProjectionRegistryOpChirho {
    #[serde(rename = "register-projection-chirho")]
    RegisterProjectionChirho {
        descriptor_chirho: ProjectionDescriptorChirho,
    },
    #[serde(rename = "amend-projection-chirho")]
    AmendProjectionChirho {
        supersedes_digest_chirho: DigestChirho,
        descriptor_chirho: ProjectionDescriptorChirho,
    },
    #[serde(rename = "retire-projection-chirho")]
    RetireProjectionChirho { name_chirho: String },
}

/// One signed registry record — the chain fields plus the op, root-signed (sign-then-attach).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRegistryRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub prev_chirho: String,
    pub registry_id_chirho: String,
    pub op_chirho: ProjectionRegistryOpChirho,
    pub root_sig_chirho: String,
}

/// One projection's folded state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionStateChirho {
    pub current_descriptor_chirho: ProjectionDescriptorChirho,
    pub current_digest_chirho: DigestChirho,
    pub superseded_digests_chirho: BTreeSet<DigestChirho>,
    pub retired_chirho: bool,
}

/// How a descriptor digest resolves against the registry — a NEW feed admits ONLY Current.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectionResolutionChirho {
    CurrentChirho {
        descriptor_chirho: ProjectionDescriptorChirho,
    },
    /// Was a valid revision of this projection, is no longer the current one ("was valid, isn't
    /// current" ≠ "never existed" — the policy-downgrade refusal carries its own name).
    SupersededChirho,
    /// The projection is retired: no revision feeds, however current it once was.
    RetiredChirho,
    UnknownChirho,
}

/// The verified registry: records + tail + the per-projection fold every consumer reads.
#[derive(Debug)]
pub struct VerifiedProjectionRegistryChirho {
    pub records_chirho: Vec<ProjectionRegistryRecordChirho>,
    pub tail_digest_hex_chirho: String,
    pub projections_chirho: BTreeMap<String, ProjectionStateChirho>,
}

impl VerifiedProjectionRegistryChirho {
    /// Resolve a (name, digest) pair for a NEW feed. Retirement dominates supersession: a retired
    /// projection refuses at every digest.
    pub fn resolve_chirho(
        &self,
        name_chirho: &str,
        digest_chirho: &DigestChirho,
    ) -> ProjectionResolutionChirho {
        let Some(state_chirho) = self.projections_chirho.get(name_chirho) else {
            return ProjectionResolutionChirho::UnknownChirho;
        };
        if state_chirho.retired_chirho {
            return ProjectionResolutionChirho::RetiredChirho;
        }
        if state_chirho.current_digest_chirho == *digest_chirho {
            return ProjectionResolutionChirho::CurrentChirho {
                descriptor_chirho: state_chirho.current_descriptor_chirho.clone(),
            };
        }
        if state_chirho
            .superseded_digests_chirho
            .contains(digest_chirho)
        {
            return ProjectionResolutionChirho::SupersededChirho;
        }
        ProjectionResolutionChirho::UnknownChirho
    }
}

/// Canonical line: validate (incl. the nested descriptor) then the ONE serde emission.
pub fn canonical_projection_registry_line_chirho(
    record_chirho: &ProjectionRegistryRecordChirho,
) -> Result<String> {
    if record_chirho.schema_chirho != PROJECTION_REGISTRY_RECORD_SCHEMA_V1_CHIRHO {
        bail!("unsupported projection registry record schema");
    }
    if record_chirho.registry_id_chirho.is_empty() {
        bail!("projection registry record must name its registry");
    }
    if let Some(descriptor_chirho) = op_descriptor_chirho(&record_chirho.op_chirho) {
        // Re-runs the descriptor's own validation so an invalid descriptor can never be emitted.
        projection_descriptor_bytes_chirho(descriptor_chirho)?;
    }
    serde_json::to_string(record_chirho).context("encode canonical projection registry record")
}

/// Strict parse: schema probe, typed decode, descriptor validation, exact reserialize-byte
/// equality — one logical record has exactly one stored form.
pub fn parse_canonical_projection_registry_line_chirho(
    line_chirho: &str,
) -> Result<ProjectionRegistryRecordChirho> {
    #[derive(Deserialize)]
    struct SchemaProbeChirho {
        schema_chirho: String,
    }
    let probe_chirho: SchemaProbeChirho =
        serde_json::from_str(line_chirho).context("probe projection registry record schema")?;
    if probe_chirho.schema_chirho != PROJECTION_REGISTRY_RECORD_SCHEMA_V1_CHIRHO {
        bail!("unsupported projection registry record schema");
    }
    let record_chirho: ProjectionRegistryRecordChirho =
        serde_json::from_str(line_chirho).context("decode projection registry record")?;
    let canonical_chirho = canonical_projection_registry_line_chirho(&record_chirho)?;
    if canonical_chirho != line_chirho {
        bail!("projection registry record has a byte-canonical mismatch");
    }
    Ok(record_chirho)
}

/// The root-signed content: the canonical line with the signature field blanked.
pub fn registry_root_signed_content_chirho(
    record_chirho: &ProjectionRegistryRecordChirho,
) -> Result<String> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.root_sig_chirho = String::new();
    canonical_projection_registry_line_chirho(&unsigned_chirho)
}

fn op_descriptor_chirho(
    op_chirho: &ProjectionRegistryOpChirho,
) -> Option<&ProjectionDescriptorChirho> {
    match op_chirho {
        ProjectionRegistryOpChirho::RegisterProjectionChirho { descriptor_chirho }
        | ProjectionRegistryOpChirho::AmendProjectionChirho {
            descriptor_chirho, ..
        } => Some(descriptor_chirho),
        ProjectionRegistryOpChirho::RetireProjectionChirho { .. } => None,
    }
}

/// The registry's chain-family hooks for the shared walk: strict parse + identity binding + the
/// root signature. Op law runs in the FOLD pass after the walk (same records, same order, same
/// fail-closed refusal — the chain law and the op law stay separately owned).
struct RegistryChainFamilyChirho<'ports_chirho> {
    registry_id_chirho: &'ports_chirho str,
    root_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
}

impl ChainFamilyChirho for RegistryChainFamilyChirho<'_> {
    type RecordChirho = ProjectionRegistryRecordChirho;
    type ErrorChirho = anyhow::Error;

    fn parse_line_chirho(
        &self,
        line_chirho: &str,
    ) -> Result<ProjectionRegistryRecordChirho, anyhow::Error> {
        parse_canonical_projection_registry_line_chirho(line_chirho)
    }

    fn seq_chirho(&self, record_chirho: &ProjectionRegistryRecordChirho) -> u64 {
        record_chirho.seq_chirho
    }

    fn prev_hex_chirho<'record_chirho>(
        &self,
        record_chirho: &'record_chirho ProjectionRegistryRecordChirho,
    ) -> &'record_chirho str {
        &record_chirho.prev_chirho
    }

    fn verify_record_chirho(
        &self,
        record_chirho: &ProjectionRegistryRecordChirho,
    ) -> Result<(), anyhow::Error> {
        if record_chirho.registry_id_chirho != self.registry_id_chirho {
            bail!(
                "record names registry {} — cross-registry replay refused",
                record_chirho.registry_id_chirho
            );
        }
        let signed_content_chirho = registry_root_signed_content_chirho(record_chirho)?;
        if !self
            .root_chirho
            .verify_chirho(&signed_content_chirho, &record_chirho.root_sig_chirho)
        {
            bail!(
                "registry root signature does not verify at seq {}",
                record_chirho.seq_chirho
            );
        }
        Ok(())
    }
}

/// Load and FULLY verify the projection registry: torn tail fails closed; the shared chain walk
/// (dense seq + prev binding + domain-separated anchor + identity + root sig); then the op-law
/// fold. Missing object = an empty registry.
pub fn load_verified_projection_registry_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_chirho: &dyn LedgerSignerPortChirho,
    path_chirho: &StoragePathChirho,
    registry_id_chirho: &str,
) -> Result<VerifiedProjectionRegistryChirho> {
    let anchor_chirho =
        chain_anchor_hex_chirho(PROJECTION_REGISTRY_CHAIN_DOMAIN_CHIRHO, registry_id_chirho);
    let Some(bytes_chirho) = storage_chirho
        .read_all_chirho(path_chirho)
        .map_err(|error_chirho| anyhow!("read projection registry: {error_chirho}"))?
    else {
        return Ok(VerifiedProjectionRegistryChirho {
            records_chirho: Vec::new(),
            tail_digest_hex_chirho: anchor_chirho,
            projections_chirho: BTreeMap::new(),
        });
    };
    if bytes_chirho
        .last()
        .is_some_and(|byte_chirho| *byte_chirho != b'\n')
    {
        bail!(
            "projection registry has a torn tail — configuration authority fails closed \
             (operator event, never silent repair)"
        );
    }
    let text_chirho = std::str::from_utf8(&bytes_chirho)
        .map_err(|_| anyhow!("projection registry bytes are not UTF-8"))?;
    let family_chirho = RegistryChainFamilyChirho {
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
    let mut projections_chirho: BTreeMap<String, ProjectionStateChirho> = BTreeMap::new();
    let mut records_chirho = Vec::with_capacity(lines_chirho.len());
    for line_chirho in lines_chirho {
        fold_op_chirho(
            &mut projections_chirho,
            &line_chirho.record_chirho.op_chirho,
        )?;
        records_chirho.push(line_chirho.record_chirho);
    }
    Ok(VerifiedProjectionRegistryChirho {
        records_chirho,
        tail_digest_hex_chirho,
        projections_chirho,
    })
}

/// The op law, applied in chain order — first registration wins per name; an amend must name the
/// CURRENT digest (monotone — an amend off a superseded digest is the downgrade class); a retired
/// projection accepts NO further op.
fn fold_op_chirho(
    projections_chirho: &mut BTreeMap<String, ProjectionStateChirho>,
    op_chirho: &ProjectionRegistryOpChirho,
) -> Result<()> {
    match op_chirho {
        ProjectionRegistryOpChirho::RegisterProjectionChirho { descriptor_chirho } => {
            let name_chirho = descriptor_chirho.name_chirho.clone();
            if projections_chirho.contains_key(&name_chirho) {
                bail!("projection {name_chirho} is already registered (first registration wins)");
            }
            let digest_chirho = projection_descriptor_digest_chirho(descriptor_chirho)?;
            projections_chirho.insert(
                name_chirho,
                ProjectionStateChirho {
                    current_descriptor_chirho: descriptor_chirho.clone(),
                    current_digest_chirho: digest_chirho,
                    superseded_digests_chirho: BTreeSet::new(),
                    retired_chirho: false,
                },
            );
        }
        ProjectionRegistryOpChirho::AmendProjectionChirho {
            supersedes_digest_chirho,
            descriptor_chirho,
        } => {
            let name_chirho = &descriptor_chirho.name_chirho;
            let Some(state_chirho) = projections_chirho.get_mut(name_chirho) else {
                bail!("amend of unregistered projection {name_chirho}");
            };
            if state_chirho.retired_chirho {
                bail!("amend of retired projection {name_chirho}");
            }
            if *supersedes_digest_chirho != state_chirho.current_digest_chirho {
                bail!(
                    "amend of projection {name_chirho} does not supersede the CURRENT digest \
                     (monotone amend law)"
                );
            }
            let new_digest_chirho = projection_descriptor_digest_chirho(descriptor_chirho)?;
            if new_digest_chirho == state_chirho.current_digest_chirho {
                bail!("amend of projection {name_chirho} names an identical descriptor (no-op)");
            }
            let old_digest_chirho =
                std::mem::replace(&mut state_chirho.current_digest_chirho, new_digest_chirho);
            state_chirho
                .superseded_digests_chirho
                .insert(old_digest_chirho);
            state_chirho.current_descriptor_chirho = descriptor_chirho.clone();
        }
        ProjectionRegistryOpChirho::RetireProjectionChirho { name_chirho } => {
            let Some(state_chirho) = projections_chirho.get_mut(name_chirho) else {
                bail!("retire of unregistered projection {name_chirho}");
            };
            if state_chirho.retired_chirho {
                bail!("retire of already-retired projection {name_chirho}");
            }
            state_chirho.retired_chirho = true;
        }
    }
    Ok(())
}

/// Append one op: full verified load (configuration-rate — O(n) is fine), op precondition via the
/// fold, then build → root-sign (sign-then-attach) → ONE durable append. The descriptor inside a
/// Register/Amend is validated by the canonical emission itself.
pub fn append_projection_registry_op_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_chirho: &dyn LedgerSignerPortChirho,
    path_chirho: &StoragePathChirho,
    registry_id_chirho: &str,
    op_chirho: ProjectionRegistryOpChirho,
) -> Result<ProjectionRegistryRecordChirho> {
    let verified_chirho = load_verified_projection_registry_chirho(
        storage_chirho,
        root_chirho,
        path_chirho,
        registry_id_chirho,
    )?;
    // Precondition: the op must fold cleanly onto the CURRENT projection state.
    let mut preview_chirho = verified_chirho.projections_chirho.clone();
    fold_op_chirho(&mut preview_chirho, &op_chirho)?;
    let mut record_chirho = ProjectionRegistryRecordChirho {
        schema_chirho: PROJECTION_REGISTRY_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        seq_chirho: verified_chirho.records_chirho.len() as u64,
        prev_chirho: verified_chirho.tail_digest_hex_chirho.clone(),
        registry_id_chirho: registry_id_chirho.to_string(),
        op_chirho,
        root_sig_chirho: String::new(),
    };
    let signed_content_chirho = registry_root_signed_content_chirho(&record_chirho)?;
    record_chirho.root_sig_chirho = root_chirho
        .sign_chirho(&signed_content_chirho)
        .map_err(|error_chirho| anyhow!("sign projection registry record: {error_chirho}"))?;
    let line_chirho = canonical_projection_registry_line_chirho(&record_chirho)?;
    let mut bytes_chirho = line_chirho.into_bytes();
    bytes_chirho.push(b'\n');
    storage_chirho
        .append_durable_chirho(path_chirho, &bytes_chirho)
        .map_err(|error_chirho| anyhow!("append projection registry record: {error_chirho}"))?;
    Ok(record_chirho)
}

/// Re-derive and verify a registered descriptor's content digest from its inline bytes — the
/// two-concept binding check consumers use before trusting a (name, digest) pair they carried.
pub fn verify_descriptor_digest_binding_chirho(
    descriptor_chirho: &ProjectionDescriptorChirho,
    claimed_digest_chirho: &DigestChirho,
) -> Result<()> {
    let bytes_chirho = projection_descriptor_bytes_chirho(descriptor_chirho)?;
    let reparsed_chirho = parse_canonical_projection_descriptor_chirho(&bytes_chirho)?;
    let digest_chirho = projection_descriptor_digest_chirho(&reparsed_chirho)?;
    if digest_chirho != *claimed_digest_chirho {
        bail!("descriptor digest binding mismatch");
    }
    Ok(())
}

#[cfg(test)]
#[path = "registry_chirho/registry_tests_chirho.rs"]
mod registry_tests_chirho;
