// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Durable home for the signed tenant-placement records, and the only surface that can answer WHAT IS
//! ALREADY PLACED without an operator telling it.
//!
//! The placement registry derives reserved capacity from placements recorded into it. Measured
//! 2026-08-21, `record_placement_chirho` had **zero production callers**, so every production-loaded
//! registry reported zero reservation for every node and the admission arithmetic ran against a world
//! that looked completely free. That failure arrives NON-VACUOUS — clauses considered, no refusals —
//! so no anti-vacuity guard downstream can catch it. This store is where that is fixed, and the whole
//! design follows from one requirement: **an under-count must be impossible, not unlikely.**
//!
//! **The rule this feed applies to its own history, in the shape its siblings are described in:**
//!
//! ```text
//! capacity    registrar-signed  replay REFUSED at or below the high-water registration seq
//! lifecycle   authority-signed  replay refused by seq AND a stale view refused by from-state
//! usage       NODE-signed       a stale report is RECORDED and FREEZES -- never refused
//! placement   authority-signed  ANY chain defect refuses the WHOLE POPULATION -- never skipped
//! ```
//!
//! **The fourth rule deliberately breaks the sibling precedent and it is worth saying why.**
//! `capacity_attestation_store_chirho` SKIPS a row that no longer verifies, reasoning that one bad row
//! must not deny a node its valid grant. That is right for a per-node query and wrong here: a skipped
//! placement row is a MISSING RESERVATION, and a registry that silently under-counts is the exact
//! false-green this store exists to prevent. A skip there loses one answer; a skip here manufactures
//! free capacity.
//!
//! **Why the record goes in CAS and only a compact ref goes in the log.** The log is a declared
//! surface, so `verify_tenant_self_containment_chirho` scans it for 64-hex tokens and requires each to
//! resolve as a CAS object in this root. `put_object_chirho(root, &v)` stores bytes at
//! `hash_object_chirho(v)`, and the assignment digest is `blake3(serde_json::to_vec(record))` — the
//! same address. So the ref resolves, self-containment passes, and the log stays compact. The equality
//! is CHECKED rather than assumed, because a record whose digest is not its own CAS address would
//! leave a dangling reference in a declared log.
//!
//! **On absent versus unreadable versus tampered — corrected after the missing arm found it.**
//! This file first read objects through `get_object_chirho`, which flattens ALL THREE failures into
//! one error. `cas_chirho`'s own doc says so directly: *"an object that is PRESENT but could not be
//! read gets recorded as ABSENT"*. The refusal was then named `RecordUnresolved` — a name asserting
//! ABSENCE over a value that also meant TAMPERED, which is the defect this codebase has been bitten
//! by repeatedly. Nothing was rescued by a fallback so no permissive branch existed, but an operator
//! reading "unresolved" over a corrupt object is told the wrong thing.
//!
//! It now reads through `read_verified_chirho`, whose four variants must be handled exhaustively, and
//! refuses by three distinct identities. **Absent is the only one for which looking elsewhere could
//! ever be legitimate**, which is exactly why it must be the only one that says so.

use crate::{
    tenant_placement_assignment_digest_chirho, verify_tenant_placement_record_chirho,
    TenantPlacementRecordChirho, VerifiedTenantPlacementChirho,
};
use cairn_core_chirho::cas_chirho::{read_verified_chirho, CasReadOutcomeChirho};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::store_chirho::put_object_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// The declared log surface. Must also appear in `static_surface_manifest_chirho`, or a root carrying
/// this log fails the migration completeness half as an undeclared surface.
pub const TENANT_PLACEMENT_RECORD_LOG_CHIRHO: &str = "tenant-placement-records-chirho.jsonl";

/// One ref is tiny by construction; the whole log is bounded so a hostile file cannot become an
/// unbounded allocation.
pub const TENANT_PLACEMENT_RECORD_LOG_MAX_BYTES_CHIRHO: u64 = 4 * 1024 * 1024;

/// Domain separation for the population digest, so a digest over placement assignments can never be
/// confused with a digest over anything else that happens to hash a sorted list of hex strings.
pub const TENANT_PLACEMENT_POPULATION_DIGEST_DOMAIN_CHIRHO: &str =
    "tenant-placement-population-v1-chirho";

pub const TENANT_PLACEMENT_RECORD_REF_SCHEMA_V1_CHIRHO: &str =
    "tenant-placement-record-ref-v1-chirho";

/// The compact line appended to the log. The canonical record itself lives in CAS at
/// `assignment_digest_chirho`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPlacementRecordRefChirho {
    pub schema_chirho: String,
    pub tenant_id_chirho: String,
    pub revision_chirho: u64,
    pub assignment_digest_chirho: String,
}

/// Why a durable placement-record operation was refused.
///
/// Every variant that can arise during a load refuses the ENTIRE population. None of them is a skip.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlacementRecordStoreRefusalChirho {
    /// The log could not be read or written for an I/O reason.
    StoreUnavailableChirho,
    /// The log path is not one identity-stable single-link bounded regular file.
    StoreIdentityUnstableChirho,
    /// A line in the log is not a decodable ref.
    DecodeChirho { line_chirho: u64 },
    /// A ref carries a schema this store does not speak.
    RefSchemaChirho { line_chirho: u64 },
    /// The canonical record could not be written to CAS, so its digest would not resolve.
    RecordNotStoredChirho,
    /// The record's assignment digest is not the CAS address its bytes actually landed at.
    AssignmentDigestNotItsCasAddressChirho {
        declared_chirho: String,
        stored_at_chirho: String,
    },
    /// Nothing sits at the object path. The ONLY one of these three for which looking elsewhere for
    /// the value could ever be legitimate — which is why it does not share an identity with the rest.
    RecordAbsentChirho { assignment_digest_chirho: String },
    /// Bytes are present at the object path and could not be read. NOT absence.
    RecordUnreadableChirho { assignment_digest_chirho: String },
    /// Bytes are present and do not re-hash to the address that named them: tamper, by definition.
    RecordTamperedChirho { assignment_digest_chirho: String },
    /// A record resolved and then did not re-serialize to the digest its ref named.
    ///
    /// Distinct from tamper: the CAS layer already proved the stored BYTES hash to the address, so this
    /// fires only if the record does not round-trip canonically.
    RecordDigestMismatchChirho {
        declared_chirho: String,
        recomputed_chirho: String,
    },
    /// A resolved record does not verify against the supplied authorities.
    RecordUnverifiableChirho { assignment_digest_chirho: String },
    /// A ref's tenant or revision disagrees with the record it names.
    RefRecordDisagreementChirho { assignment_digest_chirho: String },
    /// Two different records claim the same revision for one tenant.
    ForkedRevisionChirho {
        tenant_id_chirho: String,
        revision_chirho: u64,
    },
    /// The revisions for one tenant are not contiguous from zero.
    SkippedRevisionChirho {
        tenant_id_chirho: String,
        expected_chirho: u64,
        found_chirho: u64,
    },
    /// A revision's declared predecessor is not its actual predecessor's assignment digest.
    BrokenPredecessorChirho {
        tenant_id_chirho: String,
        revision_chirho: u64,
        expected_chirho: String,
        declared_chirho: Option<String>,
    },
    /// The log holds no current placements at all.
    ///
    /// A named refusal rather than an empty success, because a confident empty here becomes a
    /// confident zero reservation one layer up, which is the whole failure this store prevents.
    NoCurrentPlacementsChirho,
    /// The computed population digest is not the one the caller expected: rows were deleted,
    /// truncated, added, or reordered since the expectation was pinned.
    PopulationDigestMismatchChirho {
        expected_chirho: String,
        computed_chirho: String,
    },
}

/// The verified current placement population, plus the identity that proves it is the whole of it.
#[derive(Clone, Debug)]
pub struct VerifiedPlacementPopulationChirho {
    current_chirho: Vec<VerifiedTenantPlacementChirho>,
    population_digest_chirho: String,
}

impl VerifiedPlacementPopulationChirho {
    /// One verified current record per tenant, ordered by tenant id.
    pub fn current_chirho(&self) -> &[VerifiedTenantPlacementChirho] {
        &self.current_chirho
    }

    /// The domain-separated digest over the sorted current assignment digests.
    pub fn population_digest_chirho(&self) -> &str {
        &self.population_digest_chirho
    }
}

fn log_path_chirho(root_chirho: &Path) -> std::path::PathBuf {
    root_chirho.join(TENANT_PLACEMENT_RECORD_LOG_CHIRHO)
}

/// The domain-separated digest over a sorted list of assignment digests.
///
/// Each element is length-terminated by a separator that cannot occur in lower-hex, so no two distinct
/// lists can produce the same pre-image by concatenation.
pub fn tenant_placement_population_digest_chirho(sorted_digests_chirho: &[String]) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(TENANT_PLACEMENT_POPULATION_DIGEST_DOMAIN_CHIRHO.as_bytes());
    hasher_chirho.update(b"\n");
    for digest_chirho in sorted_digests_chirho {
        hasher_chirho.update(digest_chirho.as_bytes());
        hasher_chirho.update(b"\n");
    }
    hasher_chirho.finalize().to_hex().to_string()
}

/// Every ref currently in the log, in append order, decoded but not resolved.
fn read_refs_chirho(
    root_chirho: &Path,
) -> Result<Vec<TenantPlacementRecordRefChirho>, PlacementRecordStoreRefusalChirho> {
    let path_chirho = log_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        TENANT_PLACEMENT_RECORD_LOG_MAX_BYTES_CHIRHO,
    )
    .map_err(|error_chirho| match error_chirho.kind() {
        std::io::ErrorKind::InvalidData => {
            PlacementRecordStoreRefusalChirho::StoreIdentityUnstableChirho
        }
        _ => PlacementRecordStoreRefusalChirho::StoreUnavailableChirho,
    })?;
    let text_chirho = String::from_utf8_lossy(&bytes_chirho);
    let mut refs_chirho = Vec::new();
    for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let line_number_chirho = index_chirho as u64 + 1;
        let ref_chirho: TenantPlacementRecordRefChirho = serde_json::from_str(line_chirho)
            .map_err(
                |_error_chirho| PlacementRecordStoreRefusalChirho::DecodeChirho {
                    line_chirho: line_number_chirho,
                },
            )?;
        if ref_chirho.schema_chirho != TENANT_PLACEMENT_RECORD_REF_SCHEMA_V1_CHIRHO {
            return Err(PlacementRecordStoreRefusalChirho::RefSchemaChirho {
                line_chirho: line_number_chirho,
            });
        }
        refs_chirho.push(ref_chirho);
    }
    Ok(refs_chirho)
}

/// Append one authority-signed placement record, after verifying it.
///
/// Order is the contract: verify first, then store the canonical record in CAS at the address its own
/// digest names, then append the compact ref. The append is last so a failure anywhere earlier leaves
/// the log untouched.
///
/// **Idempotency is exact-bytes only.** Re-appending a record already present at the same tenant and
/// revision AND the same assignment digest is a no-op. A DIFFERENT record at a revision already taken
/// is a conflicting replay and refuses — that is the fork case, caught at append rather than only at
/// load.
pub fn append_verified_placement_record_chirho(
    root_chirho: &Path,
    record_chirho: TenantPlacementRecordChirho,
    expected_placement_key_chirho: &str,
    roster_operator_key_chirho: &str,
    geo_plan_authority_key_chirho: &str,
) -> Result<VerifiedTenantPlacementChirho, PlacementRecordStoreRefusalChirho> {
    let verified_chirho = verify_tenant_placement_record_chirho(
        record_chirho.clone(),
        expected_placement_key_chirho,
        roster_operator_key_chirho,
        geo_plan_authority_key_chirho,
    )
    .map_err(
        |_error_chirho| PlacementRecordStoreRefusalChirho::RecordUnverifiableChirho {
            assignment_digest_chirho: String::new(),
        },
    )?;

    let assignment_digest_chirho = verified_chirho.assignment_digest_chirho().to_string();
    let tenant_id_chirho = verified_chirho.intent_chirho().tenant_id_chirho.clone();
    let revision_chirho = verified_chirho.intent_chirho().revision_chirho;

    for existing_chirho in read_refs_chirho(root_chirho)? {
        if existing_chirho.tenant_id_chirho != tenant_id_chirho
            || existing_chirho.revision_chirho != revision_chirho
        {
            continue;
        }
        if existing_chirho.assignment_digest_chirho == assignment_digest_chirho {
            // Exact duplicate: idempotent, nothing appended.
            return Ok(verified_chirho);
        }
        return Err(PlacementRecordStoreRefusalChirho::ForkedRevisionChirho {
            tenant_id_chirho,
            revision_chirho,
        });
    }

    let stored_chirho = put_object_chirho(root_chirho, &record_chirho)
        .map_err(|_error_chirho| PlacementRecordStoreRefusalChirho::RecordNotStoredChirho)?;
    if stored_chirho.0 != assignment_digest_chirho {
        return Err(
            PlacementRecordStoreRefusalChirho::AssignmentDigestNotItsCasAddressChirho {
                declared_chirho: assignment_digest_chirho,
                stored_at_chirho: stored_chirho.0,
            },
        );
    }

    let ref_chirho = TenantPlacementRecordRefChirho {
        schema_chirho: TENANT_PLACEMENT_RECORD_REF_SCHEMA_V1_CHIRHO.to_string(),
        tenant_id_chirho,
        revision_chirho,
        assignment_digest_chirho,
    };
    let mut line_chirho = serde_json::to_vec(&ref_chirho)
        .map_err(|_error_chirho| PlacementRecordStoreRefusalChirho::StoreUnavailableChirho)?;
    line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(&log_path_chirho(root_chirho), &line_chirho)
        .map_err(|_error_chirho| PlacementRecordStoreRefusalChirho::StoreUnavailableChirho)?;
    Ok(verified_chirho)
}

/// The verified CURRENT placement for every tenant, or a refusal naming what defeated the whole load.
///
/// `expected_population_digest_chirho` is the caller's externally pinned expectation. Without it a
/// deleted or truncated log would simply describe a smaller world and every check downstream would
/// pass over it; with it, removal is a mismatch. **That is the point of the parameter and it should
/// never be made optional.**
pub fn load_verified_placement_population_chirho(
    root_chirho: &Path,
    expected_population_digest_chirho: &str,
    expected_placement_key_chirho: &str,
    roster_operator_key_chirho: &str,
    geo_plan_authority_key_chirho: &str,
) -> Result<VerifiedPlacementPopulationChirho, PlacementRecordStoreRefusalChirho> {
    let population_chirho = reconstruct_population_chirho(
        root_chirho,
        expected_placement_key_chirho,
        roster_operator_key_chirho,
        geo_plan_authority_key_chirho,
    )?;
    if population_chirho.population_digest_chirho != expected_population_digest_chirho {
        return Err(
            PlacementRecordStoreRefusalChirho::PopulationDigestMismatchChirho {
                expected_chirho: expected_population_digest_chirho.to_string(),
                computed_chirho: population_chirho.population_digest_chirho,
            },
        );
    }
    Ok(population_chirho)
}

/// The CANDIDATE population the store currently holds, verified but compared to nothing.
///
/// **This reports; it does not decide, and it grants no admission.** It exists because a digest has to
/// be readable before a human can decide to pin it, and the human pinning it is what makes the
/// expectation external.
///
/// **It must never supply `load_verified_placement_population_chirho`'s expected digest.** A loader
/// computing its own expectation from the log it is about to read has a check that cannot fail — the
/// trust anchor cannot come from the artifact being checked. That is why these are two functions with
/// two names rather than one with an `Option`: an optional expectation is one `None` away from a
/// self-certifying gate, and nothing in the signature would show it.
///
/// Every chain, verification and vacuity refusal still applies: this reports a VERIFIED candidate or
/// it reports nothing.
pub fn report_placement_population_for_review_chirho(
    root_chirho: &Path,
    expected_placement_key_chirho: &str,
    roster_operator_key_chirho: &str,
    geo_plan_authority_key_chirho: &str,
) -> Result<VerifiedPlacementPopulationChirho, PlacementRecordStoreRefusalChirho> {
    reconstruct_population_chirho(
        root_chirho,
        expected_placement_key_chirho,
        roster_operator_key_chirho,
        geo_plan_authority_key_chirho,
    )
}

/// Rebuild every tenant's current placement from the log, refusing the whole population on any defect.
///
/// Private on purpose: the compared load and the review report are the only two ways out of this
/// module, so no later caller can obtain an unexamined population by a third route.
fn reconstruct_population_chirho(
    root_chirho: &Path,
    expected_placement_key_chirho: &str,
    roster_operator_key_chirho: &str,
    geo_plan_authority_key_chirho: &str,
) -> Result<VerifiedPlacementPopulationChirho, PlacementRecordStoreRefusalChirho> {
    let refs_chirho = read_refs_chirho(root_chirho)?;

    // Group by tenant, refusing a fork the moment two records claim one revision.
    let mut by_tenant_chirho: BTreeMap<String, BTreeMap<u64, TenantPlacementRecordRefChirho>> =
        BTreeMap::new();
    for ref_chirho in refs_chirho {
        let tenant_chirho = by_tenant_chirho
            .entry(ref_chirho.tenant_id_chirho.clone())
            .or_default();
        if let Some(existing_chirho) = tenant_chirho.get(&ref_chirho.revision_chirho) {
            if existing_chirho.assignment_digest_chirho != ref_chirho.assignment_digest_chirho {
                return Err(PlacementRecordStoreRefusalChirho::ForkedRevisionChirho {
                    tenant_id_chirho: ref_chirho.tenant_id_chirho,
                    revision_chirho: ref_chirho.revision_chirho,
                });
            }
            continue;
        }
        tenant_chirho.insert(ref_chirho.revision_chirho, ref_chirho);
    }

    let mut current_chirho: Vec<VerifiedTenantPlacementChirho> = Vec::new();
    let mut current_digests_chirho: Vec<String> = Vec::new();

    for (tenant_id_chirho, revisions_chirho) in by_tenant_chirho {
        let mut previous_digest_chirho: Option<String> = None;
        let mut latest_chirho: Option<VerifiedTenantPlacementChirho> = None;

        for (expected_revision_chirho, (revision_chirho, ref_chirho)) in
            revisions_chirho.iter().enumerate()
        {
            let expected_revision_chirho = expected_revision_chirho as u64;
            if *revision_chirho != expected_revision_chirho {
                return Err(PlacementRecordStoreRefusalChirho::SkippedRevisionChirho {
                    tenant_id_chirho,
                    expected_chirho: expected_revision_chirho,
                    found_chirho: *revision_chirho,
                });
            }

            let address_chirho = HashChirho(ref_chirho.assignment_digest_chirho.clone());
            let digest_chirho = ref_chirho.assignment_digest_chirho.clone();
            // Four variants, handled exhaustively, so a later edit cannot quietly fold tamper back
            // into absence.
            let bytes_chirho = match read_verified_chirho(root_chirho, &address_chirho) {
                CasReadOutcomeChirho::VerifiedChirho(bytes_chirho) => bytes_chirho,
                CasReadOutcomeChirho::AbsentChirho(_error_chirho) => {
                    return Err(PlacementRecordStoreRefusalChirho::RecordAbsentChirho {
                        assignment_digest_chirho: digest_chirho,
                    })
                }
                CasReadOutcomeChirho::UnreadableChirho(_error_chirho) => {
                    return Err(PlacementRecordStoreRefusalChirho::RecordUnreadableChirho {
                        assignment_digest_chirho: digest_chirho,
                    })
                }
                CasReadOutcomeChirho::TamperedChirho { .. } => {
                    return Err(PlacementRecordStoreRefusalChirho::RecordTamperedChirho {
                        assignment_digest_chirho: digest_chirho,
                    })
                }
            };
            let record_chirho: TenantPlacementRecordChirho =
                serde_json::from_slice(&bytes_chirho).map_err(|_error_chirho| {
                    PlacementRecordStoreRefusalChirho::DecodeChirho { line_chirho: 0 }
                })?;

            // The bytes already hash to the address. This proves the RECORD re-serializes to those
            // same bytes — a canonical round-trip check, not a tamper check.
            let recomputed_chirho = tenant_placement_assignment_digest_chirho(&record_chirho)
                .map_err(
                    |_error_chirho| PlacementRecordStoreRefusalChirho::DecodeChirho {
                        line_chirho: 0,
                    },
                )?;
            if recomputed_chirho != ref_chirho.assignment_digest_chirho {
                return Err(
                    PlacementRecordStoreRefusalChirho::RecordDigestMismatchChirho {
                        declared_chirho: ref_chirho.assignment_digest_chirho.clone(),
                        recomputed_chirho,
                    },
                );
            }

            let declared_previous_chirho = record_chirho
                .intent_chirho
                .previous_assignment_digest_chirho
                .clone();
            if record_chirho.intent_chirho.tenant_id_chirho != tenant_id_chirho
                || record_chirho.intent_chirho.revision_chirho != *revision_chirho
            {
                return Err(
                    PlacementRecordStoreRefusalChirho::RefRecordDisagreementChirho {
                        assignment_digest_chirho: ref_chirho.assignment_digest_chirho.clone(),
                    },
                );
            }

            let verified_chirho = verify_tenant_placement_record_chirho(
                record_chirho,
                expected_placement_key_chirho,
                roster_operator_key_chirho,
                geo_plan_authority_key_chirho,
            )
            .map_err(|_error_chirho| {
                PlacementRecordStoreRefusalChirho::RecordUnverifiableChirho {
                    assignment_digest_chirho: ref_chirho.assignment_digest_chirho.clone(),
                }
            })?;

            // The chain: revision N's declared predecessor must BE revision N-1's assignment digest.
            if declared_previous_chirho != previous_digest_chirho {
                return Err(PlacementRecordStoreRefusalChirho::BrokenPredecessorChirho {
                    tenant_id_chirho,
                    revision_chirho: *revision_chirho,
                    expected_chirho: previous_digest_chirho.unwrap_or_default(),
                    declared_chirho: declared_previous_chirho,
                });
            }

            previous_digest_chirho = Some(ref_chirho.assignment_digest_chirho.clone());
            latest_chirho = Some(verified_chirho);
        }

        if let Some(latest_chirho) = latest_chirho {
            current_digests_chirho.push(latest_chirho.assignment_digest_chirho().to_string());
            current_chirho.push(latest_chirho);
        }
    }

    if current_chirho.is_empty() {
        return Err(PlacementRecordStoreRefusalChirho::NoCurrentPlacementsChirho);
    }

    current_digests_chirho.sort();
    let population_digest_chirho =
        tenant_placement_population_digest_chirho(&current_digests_chirho);
    Ok(VerifiedPlacementPopulationChirho {
        current_chirho,
        population_digest_chirho,
    })
}

#[cfg(test)]
#[path = "tests_chirho.rs"]
pub(crate) mod tests_chirho;
