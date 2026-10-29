// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The registry chain: append (dense seq + prev + two signatures) and the VERIFIED load that every
//! consumer trusts — strict wire parse, chain law, both signatures per record, and the op-level
//! laws (first registration wins; amends chain monotonically off the CURRENT ref). Configuration
//! authority is manifest-postured on a torn tail: FAIL CLOSED, never silent repair — a torn
//! registry is an operator event; unacknowledged money-law config must neither vanish silently nor
//! be trusted. The load also folds the PROJECTION (kind → current policy/ref + superseded refs),
//! so verification and the view are one pass over one authority.

use crate::record_chirho::{
    IdempotencyWindowPolicyChirho, KindPolicyBodyChirho, KindRegistryOpChirho,
    KindRegistryRecordChirho, KIND_REGISTRY_SCHEMA_V1_CHIRHO,
};
use crate::wire_chirho::{
    canonical_registry_line_chirho, chain_anchor_chirho, derive_policy_ref_chirho,
    issuer_signed_content_chirho, parse_canonical_registry_line_chirho,
    registry_signed_content_chirho, RegistryWireErrorChirho,
};
use cairn_chain_core_chirho::{
    walk_verified_chain_chirho, ChainFamilyChirho, ChainWalkErrorChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use std::collections::{BTreeMap, BTreeSet};

/// Verify an ISSUER's signature — the issuer directory is INJECTED (never derived from record
/// bytes); implementations must bind the principal to its key themselves.
pub trait IssuerVerifyViewChirho {
    fn verify_issuer_chirho(
        &self,
        issuer_chirho: &str,
        signed_content_chirho: &str,
        sig_chirho: &str,
    ) -> bool;
}

/// The registry's ports: storage (the LEDGER's own port — the sim drives it already), the registry
/// trust root (sign + verify), and the injected issuer directory.
#[derive(Clone, Copy)]
pub struct KindRegistryPortsChirho<'ports_chirho> {
    pub storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub registry_root_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
    pub issuer_verify_chirho: &'ports_chirho dyn IssuerVerifyViewChirho,
}

/// Why the registry chain refused.
#[derive(Debug)]
pub enum RegistryChainErrorChirho {
    StorageChirho {
        detail_chirho: String,
    },
    WireChirho {
        error_chirho: RegistryWireErrorChirho,
    },
    /// Chain/op law: dense seq, prev binding, identity match, first-registration-wins, monotone
    /// amend chain.
    ChainChirho {
        detail_chirho: String,
    },
    /// The W-law itself: deduplication evidence may never expire before a legitimate retry can
    /// arrive, or a pruned key could admit the retry as a fresh effect.
    InvalidIdempotencyWindowChirho {
        idempotency_horizon_ms_chirho: u64,
        retry_finality_horizon_ms_chirho: u64,
    },
    /// An amendment tried to shorten or remove a previously activated retention window. Policy
    /// amendments are prospective, but they may retain longer and never orphan in-flight work.
    IdempotencyWindowDowngradeChirho {
        detail_chirho: String,
    },
    IssuerSignatureChirho {
        seq_chirho: u64,
    },
    RegistrySignatureChirho {
        seq_chirho: u64,
    },
    /// The registry tail is torn (non-LF-terminated): FAIL CLOSED — operator event, never repair.
    TornTailChirho,
}

impl From<RegistryWireErrorChirho> for RegistryChainErrorChirho {
    fn from(error_chirho: RegistryWireErrorChirho) -> Self {
        RegistryChainErrorChirho::WireChirho { error_chirho }
    }
}

/// One kind's projected state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KindProjectionChirho {
    pub current_policy_chirho: KindPolicyBodyChirho,
    pub current_ref_chirho: AssetKindRefChirho,
    pub superseded_refs_chirho: BTreeSet<AssetKindRefChirho>,
}

/// The verified registry: records + the chain tail + the fold every consumer reads.
#[derive(Debug)]
pub struct VerifiedRegistryChirho {
    pub records_chirho: Vec<KindRegistryRecordChirho>,
    pub tail_digest_chirho: DigestChirho,
    pub kinds_chirho: BTreeMap<AssetKindIdChirho, KindProjectionChirho>,
}

/// Load and FULLY verify the registry log. Missing object = an empty registry (tail = the
/// domain-separated identity anchor). Every line: strict canonical parse, dense seq, prev binding,
/// registry-identity match, BOTH signatures, then the op law folded into the projection.
pub fn load_verified_registry_chirho(
    ports_chirho: KindRegistryPortsChirho<'_>,
    path_chirho: &StoragePathChirho,
    registry_id_chirho: &str,
) -> Result<VerifiedRegistryChirho, RegistryChainErrorChirho> {
    let anchor_chirho = chain_anchor_chirho(registry_id_chirho);
    let Some(bytes_chirho) = ports_chirho
        .storage_chirho
        .read_all_chirho(path_chirho)
        .map_err(|error_chirho| RegistryChainErrorChirho::StorageChirho {
            detail_chirho: error_chirho.to_string(),
        })?
    else {
        return Ok(VerifiedRegistryChirho {
            records_chirho: Vec::new(),
            tail_digest_chirho: anchor_chirho,
            kinds_chirho: BTreeMap::new(),
        });
    };
    if bytes_chirho
        .last()
        .is_some_and(|byte_chirho| *byte_chirho != b'\n')
    {
        return Err(RegistryChainErrorChirho::TornTailChirho);
    }
    let text_chirho =
        std::str::from_utf8(&bytes_chirho).map_err(|_| RegistryChainErrorChirho::ChainChirho {
            detail_chirho: "registry bytes are not UTF-8".to_owned(),
        })?;
    // The chain law rides the SHARED core (the #4972 rule-of-three extraction, re-based here):
    // parse + identity + both signatures live in the family hooks; dense-seq/prev-binding/anchor
    // are the core's one law. Error wording reconstructs the registry's exact pre-re-base strings
    // (law equivalence, byte-for-byte at the goldens).
    let family_chirho = RegistryChainFamilyChirho {
        registry_id_chirho,
        ports_chirho,
    };
    let (lines_chirho, tail_hex_chirho) = walk_verified_chain_chirho(
        text_chirho,
        &anchor_chirho.0,
        &family_chirho,
    )
    .map_err(|error_chirho| match error_chirho {
        ChainWalkErrorChirho::DenseSeqChirho {
            expected_chirho,
            found_chirho,
        } => RegistryChainErrorChirho::ChainChirho {
            detail_chirho: format!("seq {found_chirho} at line {expected_chirho} (dense law)"),
        },
        ChainWalkErrorChirho::PrevBindingChirho { seq_chirho } => {
            RegistryChainErrorChirho::ChainChirho {
                detail_chirho: format!("prev mismatch at seq {seq_chirho}"),
            }
        }
        ChainWalkErrorChirho::FamilyChirho { error_chirho } => error_chirho,
    })?;
    let mut verified_chirho = VerifiedRegistryChirho {
        records_chirho: Vec::with_capacity(lines_chirho.len()),
        tail_digest_chirho: DigestChirho(tail_hex_chirho),
        kinds_chirho: BTreeMap::new(),
    };
    for line_chirho in lines_chirho {
        fold_op_chirho(
            &mut verified_chirho.kinds_chirho,
            &line_chirho.record_chirho.op_chirho,
        )?;
        verified_chirho
            .records_chirho
            .push(line_chirho.record_chirho);
    }
    Ok(verified_chirho)
}

/// The registry's chain-family hooks for the shared walk: strict canonical parse, identity
/// binding, and BOTH signatures (issuer sign-then-registry-attach) — everything family-owned.
struct RegistryChainFamilyChirho<'ports_chirho> {
    registry_id_chirho: &'ports_chirho str,
    ports_chirho: KindRegistryPortsChirho<'ports_chirho>,
}

impl ChainFamilyChirho for RegistryChainFamilyChirho<'_> {
    type RecordChirho = KindRegistryRecordChirho;
    type ErrorChirho = RegistryChainErrorChirho;

    fn parse_line_chirho(
        &self,
        line_chirho: &str,
    ) -> Result<KindRegistryRecordChirho, RegistryChainErrorChirho> {
        Ok(parse_canonical_registry_line_chirho(line_chirho)?)
    }

    fn seq_chirho(&self, record_chirho: &KindRegistryRecordChirho) -> u64 {
        record_chirho.seq_chirho
    }

    fn prev_hex_chirho<'record_chirho>(
        &self,
        record_chirho: &'record_chirho KindRegistryRecordChirho,
    ) -> &'record_chirho str {
        &record_chirho.prev_chirho.0
    }

    fn verify_record_chirho(
        &self,
        record_chirho: &KindRegistryRecordChirho,
    ) -> Result<(), RegistryChainErrorChirho> {
        if record_chirho.registry_id_chirho != self.registry_id_chirho {
            return Err(RegistryChainErrorChirho::ChainChirho {
                detail_chirho: format!(
                    "record names registry {} — cross-registry replay refused",
                    record_chirho.registry_id_chirho
                ),
            });
        }
        let issuer_content_chirho = issuer_signed_content_chirho(record_chirho)?;
        if !self.ports_chirho.issuer_verify_chirho.verify_issuer_chirho(
            &record_chirho.issuer_chirho,
            &issuer_content_chirho,
            &record_chirho.issuer_sig_chirho,
        ) {
            return Err(RegistryChainErrorChirho::IssuerSignatureChirho {
                seq_chirho: record_chirho.seq_chirho,
            });
        }
        let registry_content_chirho = registry_signed_content_chirho(record_chirho)?;
        if !self
            .ports_chirho
            .registry_root_chirho
            .verify_chirho(&registry_content_chirho, &record_chirho.registry_sig_chirho)
        {
            return Err(RegistryChainErrorChirho::RegistrySignatureChirho {
                seq_chirho: record_chirho.seq_chirho,
            });
        }
        Ok(())
    }
}

/// The op law, applied in chain order: first registration wins; an amend must name the kind's
/// CURRENT ref (monotone amend chain — an amend off a superseded ref is the same downgrade class
/// the admission-side refusal closes).
fn fold_op_chirho(
    kinds_chirho: &mut BTreeMap<AssetKindIdChirho, KindProjectionChirho>,
    op_chirho: &KindRegistryOpChirho,
) -> Result<(), RegistryChainErrorChirho> {
    match op_chirho {
        KindRegistryOpChirho::RegisterKindChirho {
            kind_id_chirho,
            policy_chirho,
        } => {
            validate_idempotency_window_chirho(policy_chirho)?;
            if kinds_chirho.contains_key(kind_id_chirho) {
                return Err(RegistryChainErrorChirho::ChainChirho {
                    detail_chirho: format!(
                        "kind {} is already registered (first registration wins)",
                        kind_id_chirho.0
                    ),
                });
            }
            let ref_chirho = derive_policy_ref_chirho(policy_chirho)?;
            kinds_chirho.insert(
                kind_id_chirho.clone(),
                KindProjectionChirho {
                    current_policy_chirho: policy_chirho.clone(),
                    current_ref_chirho: ref_chirho,
                    superseded_refs_chirho: BTreeSet::new(),
                },
            );
        }
        KindRegistryOpChirho::AmendKindPolicyChirho {
            kind_id_chirho,
            supersedes_ref_chirho,
            policy_chirho,
        } => {
            let Some(projection_chirho) = kinds_chirho.get_mut(kind_id_chirho) else {
                return Err(RegistryChainErrorChirho::ChainChirho {
                    detail_chirho: format!("amend of unregistered kind {}", kind_id_chirho.0),
                });
            };
            if *supersedes_ref_chirho != projection_chirho.current_ref_chirho {
                return Err(RegistryChainErrorChirho::ChainChirho {
                    detail_chirho: format!(
                        "amend of kind {} does not supersede the CURRENT ref (monotone amend law)",
                        kind_id_chirho.0
                    ),
                });
            }
            validate_idempotency_window_chirho(policy_chirho)?;
            validate_idempotency_window_amend_chirho(
                projection_chirho
                    .current_policy_chirho
                    .idempotency_window_chirho,
                policy_chirho.idempotency_window_chirho,
            )?;
            let new_ref_chirho = derive_policy_ref_chirho(policy_chirho)?;
            if new_ref_chirho == projection_chirho.current_ref_chirho {
                return Err(RegistryChainErrorChirho::ChainChirho {
                    detail_chirho: format!(
                        "amend of kind {} names an identical policy body (no-op amend refused)",
                        kind_id_chirho.0
                    ),
                });
            }
            let old_ref_chirho =
                std::mem::replace(&mut projection_chirho.current_ref_chirho, new_ref_chirho);
            projection_chirho
                .superseded_refs_chirho
                .insert(old_ref_chirho);
            projection_chirho.current_policy_chirho = policy_chirho.clone();
        }
    }
    Ok(())
}

/// Enforce FLAG-2 at construction and every amendment: the retained idempotency evidence must
/// cover the complete retry/finality interval.
fn validate_idempotency_window_chirho(
    policy_chirho: &KindPolicyBodyChirho,
) -> Result<(), RegistryChainErrorChirho> {
    let Some(window_chirho) = policy_chirho.idempotency_window_chirho else {
        return Ok(());
    };
    if window_chirho.idempotency_horizon_ms_chirho < window_chirho.retry_finality_horizon_ms_chirho
    {
        return Err(RegistryChainErrorChirho::InvalidIdempotencyWindowChirho {
            idempotency_horizon_ms_chirho: window_chirho.idempotency_horizon_ms_chirho,
            retry_finality_horizon_ms_chirho: window_chirho.retry_finality_horizon_ms_chirho,
        });
    }
    Ok(())
}

/// Amendments may activate a finite policy for new work on a legacy-unpruned kind, then may only
/// retain longer. Existing legacy keys remain separately unpruned until CF6 regenesis.
fn validate_idempotency_window_amend_chirho(
    current_chirho: Option<IdempotencyWindowPolicyChirho>,
    proposed_chirho: Option<IdempotencyWindowPolicyChirho>,
) -> Result<(), RegistryChainErrorChirho> {
    let Some(current_chirho) = current_chirho else {
        return Ok(());
    };
    let Some(proposed_chirho) = proposed_chirho else {
        return Err(RegistryChainErrorChirho::IdempotencyWindowDowngradeChirho {
            detail_chirho: "an activated idempotency window cannot be removed".to_owned(),
        });
    };
    if proposed_chirho.idempotency_horizon_ms_chirho < current_chirho.idempotency_horizon_ms_chirho
    {
        return Err(RegistryChainErrorChirho::IdempotencyWindowDowngradeChirho {
            detail_chirho: "idempotency horizon cannot decrease".to_owned(),
        });
    }
    if proposed_chirho.retry_finality_horizon_ms_chirho
        < current_chirho.retry_finality_horizon_ms_chirho
    {
        return Err(RegistryChainErrorChirho::IdempotencyWindowDowngradeChirho {
            detail_chirho: "retry/finality horizon cannot decrease".to_owned(),
        });
    }
    Ok(())
}

/// Append one op: full verified load (configuration-rate — O(n) is fine), op-precondition check via
/// the fold, then build → issuer-sign → registry-sign (sign-then-attach) → ONE durable append.
pub fn append_registry_op_chirho(
    ports_chirho: KindRegistryPortsChirho<'_>,
    issuer_signer_chirho: &dyn LedgerSignerPortChirho,
    path_chirho: &StoragePathChirho,
    registry_id_chirho: &str,
    issuer_chirho: &str,
    op_chirho: KindRegistryOpChirho,
) -> Result<KindRegistryRecordChirho, RegistryChainErrorChirho> {
    let verified_chirho =
        load_verified_registry_chirho(ports_chirho, path_chirho, registry_id_chirho)?;
    // Pre-flight the op law against the CURRENT fold so a refused op never reaches storage.
    let mut preview_chirho = verified_chirho.kinds_chirho.clone();
    fold_op_chirho(&mut preview_chirho, &op_chirho)?;
    let mut record_chirho = KindRegistryRecordChirho {
        schema_chirho: KIND_REGISTRY_SCHEMA_V1_CHIRHO.to_owned(),
        seq_chirho: verified_chirho.records_chirho.len() as u64,
        prev_chirho: verified_chirho.tail_digest_chirho.clone(),
        registry_id_chirho: registry_id_chirho.to_owned(),
        op_chirho,
        issuer_chirho: issuer_chirho.to_owned(),
        issuer_sig_chirho: String::new(),
        registry_sig_chirho: String::new(),
        key_id_chirho: ports_chirho.registry_root_chirho.key_id_chirho(),
    };
    let issuer_content_chirho = issuer_signed_content_chirho(&record_chirho)?;
    record_chirho.issuer_sig_chirho = issuer_signer_chirho
        .sign_chirho(&issuer_content_chirho)
        .map_err(|error_chirho| RegistryChainErrorChirho::StorageChirho {
            detail_chirho: format!("issuer sign failed: {error_chirho}"),
        })?;
    let registry_content_chirho = registry_signed_content_chirho(&record_chirho)?;
    record_chirho.registry_sig_chirho = ports_chirho
        .registry_root_chirho
        .sign_chirho(&registry_content_chirho)
        .map_err(|error_chirho| RegistryChainErrorChirho::StorageChirho {
            detail_chirho: format!("registry sign failed: {error_chirho}"),
        })?;
    let line_chirho = canonical_registry_line_chirho(&record_chirho)?;
    ports_chirho
        .storage_chirho
        .append_durable_chirho(path_chirho, format!("{line_chirho}\n").as_bytes())
        .map_err(|error_chirho| RegistryChainErrorChirho::StorageChirho {
            detail_chirho: error_chirho.to_string(),
        })?;
    Ok(record_chirho)
}
