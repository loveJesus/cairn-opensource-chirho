// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The A3 canonical wire codec — the J0a byte-law for journal lines (frozen §11.6): strict typed
//! parse, schema-first tag check, then EXACT reserialize-byte equality, so reordered / duplicate
//! keys, whitespace, `null` options, or any parser normalization is structurally unable to fork a
//! line's identity (sig + digest malleability closed, F5). The stored-line digest law and the
//! genesis→record `prev` chain law live here too; signing/verification is B's (the views in
//! `record_chirho` carry the sign-message bytes).

use crate::ids_chirho::DigestChirho;
use crate::record_chirho::{LedgerGenesisRecordChirho, LedgerRecordChirho};
use serde::Serialize;

/// The schema-first wire tag every stored RECORD line must carry (A3).
pub const LEDGER_RECORD_SCHEMA_V1_CHIRHO: &str = "ledger-record-v1-chirho";
/// The schema-first wire tag every stored GENESIS line must carry (A3).
pub const LEDGER_GENESIS_SCHEMA_V1_CHIRHO: &str = "ledger-genesis-v1-chirho";
/// The v1 numeric format version (frozen §11.1).
pub const LEDGER_FORMAT_VERSION_V1_CHIRHO: u32 = 1;

/// Why a wire line (or an emit) was refused — J0a is fail-closed and TYPED, never a bool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireErrorChirho {
    /// Strict typed parse failed (malformed JSON, unknown field, wrong type).
    MalformedChirho { detail_chirho: String },
    /// The line's schema tag is not the expected v1 tag (schema-FIRST law).
    SchemaMismatchChirho { found_chirho: String },
    /// `format_version` is not the v1 constant.
    FormatVersionMismatchChirho { found_chirho: u32 },
    /// Parsed, but reserialization differs byte-wise from the stored line — a non-canonical
    /// encoding (reordered/duplicate keys, whitespace, `null` options, trailing bytes…). REFUSED:
    /// accepting it would let one logical record exist under two digests (identity fork).
    NonCanonicalBytesChirho,
    /// Serialization failed (unreachable for these pure DTOs; kept typed rather than panicking).
    SerializeChirho { detail_chirho: String },
    /// The BOUNDED-IDENTIFIER law refused a record string field (CF4: the PII-free record law at
    /// the type layer — empty/overlong/control/whitespace/email-shaped identifiers are
    /// unrepresentable in the permanent money log).
    UnboundedIdentifierChirho {
        field_chirho: &'static str,
        reason_chirho: &'static str,
    },
}

fn to_canonical_json_chirho<ValueChirho: Serialize>(
    value_chirho: &ValueChirho,
) -> Result<String, WireErrorChirho> {
    serde_json::to_string(value_chirho).map_err(|error_chirho| WireErrorChirho::SerializeChirho {
        detail_chirho: error_chirho.to_string(),
    })
}

/// BLAKE3 hex digest of a stored line's canonical BODY bytes, exactly as stored (§11.4: the body
/// EXCLUDES the JSONL `LF` — the caller hands body bytes; physical extent vs cryptographic message
/// stay separate typed concepts). This digest NAMES the line: genesis digest = journal instance
/// identity; a record's digest = the next record's `prev`.
pub fn stored_line_digest_chirho(line_chirho: &str) -> DigestChirho {
    DigestChirho(blake3::hash(line_chirho.as_bytes()).to_hex().to_string())
}

/// Fail-closed canonical EMIT of a record line: refuses a wrong schema tag or format version BEFORE
/// bytes exist, so a non-canonical line can never be written in the first place.
/// The BOUNDED-IDENTIFIER LAW (CF4 acceptance: "PII-free record law guarded at the type layer").
/// Every free-string field a ledger record can carry must be a BOUNDED, SINGLE-TOKEN,
/// NON-EMAIL-SHAPED label: nonempty, within the byte cap, no control characters, no whitespace
/// (multi-word free text is unrepresentable), and no '@' (email-shaped identifiers are
/// unrepresentable). This guards SHAPE at the type layer — the platform's private-data rule
/// (identifiers are bounded non-identifying labels; PII stays in private blobs, never the money
/// log) remains the composition's semantic duty on top of this structural floor. Enforced at
/// canonical EMIT, and therefore at PARSE too via the exact-reserialize law — one validation
/// site, both directions.
pub const MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO: usize = 128;
/// Idempotency keys (incl. the reserved cf3 namespaces at prefix + 64 hex) get a wider cap.
pub const MAX_LEDGER_IDEMPOTENCY_KEY_BYTES_CHIRHO: usize = 256;

fn validate_bounded_identifier_chirho(
    field_chirho: &'static str,
    value_chirho: &str,
    max_bytes_chirho: usize,
) -> Result<(), WireErrorChirho> {
    if value_chirho.is_empty() {
        return Err(WireErrorChirho::UnboundedIdentifierChirho {
            field_chirho,
            reason_chirho: "empty",
        });
    }
    if value_chirho.len() > max_bytes_chirho {
        return Err(WireErrorChirho::UnboundedIdentifierChirho {
            field_chirho,
            reason_chirho: "over the byte cap",
        });
    }
    for char_chirho in value_chirho.chars() {
        if char_chirho.is_control() {
            return Err(WireErrorChirho::UnboundedIdentifierChirho {
                field_chirho,
                reason_chirho: "control character",
            });
        }
        if char_chirho.is_whitespace() {
            return Err(WireErrorChirho::UnboundedIdentifierChirho {
                field_chirho,
                reason_chirho: "whitespace (free-text shape)",
            });
        }
        if char_chirho == '@' {
            return Err(WireErrorChirho::UnboundedIdentifierChirho {
                field_chirho,
                reason_chirho: "'@' (email shape)",
            });
        }
    }
    Ok(())
}

/// A carried digest payload rides the SAME bounded-token law (the gpt #5241 miss closed):
/// [`DigestChirho`] is a transparent String whose TYPE enforces nothing, so without this walk a
/// canonically emitted, validly signed record could carry `provenance = "john@example.com"` or a
/// policy/evidence digest holding multi-word free text — permanently, since signature verification
/// never removes PII from the log. No lower-hex requirement in this increment: placeholder golden
/// tokens stay byte-stable, and the hex canonical-coordinate migration is its own reviewed cycle.
fn validate_digest_payload_chirho(
    field_chirho: &'static str,
    digest_chirho: &DigestChirho,
) -> Result<(), WireErrorChirho> {
    validate_bounded_identifier_chirho(
        field_chirho,
        &digest_chirho.0,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )
}

fn validate_account_identifier_bounds_chirho(
    field_chirho: &'static str,
    account_chirho: &crate::LogIdChirho,
) -> Result<(), WireErrorChirho> {
    let crate::LogIdChirho {
        owner_chirho,
        kind_id_chirho,
    } = account_chirho;
    validate_bounded_identifier_chirho(
        field_chirho,
        owner_chirho,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )?;
    validate_bounded_identifier_chirho(
        field_chirho,
        &kind_id_chirho.0,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )
}

/// Reapply the ledger wire law before a verified account coordinate crosses into a derived view.
///
/// `AccountIdChirho` remains a wire-compatible plain struct, so its constructor alone cannot prove
/// these bounds. Journal emit/parse already calls the same private validator; projection and
/// reconciliation code use this public boundary instead of duplicating the money-log identifier
/// law.
pub fn validate_ledger_account_identifier_chirho(
    account_chirho: &crate::LogIdChirho,
) -> Result<(), WireErrorChirho> {
    validate_account_identifier_bounds_chirho("account_chirho", account_chirho)
}

/// Apply the money log's own BOUNDED-IDENTIFIER law to a free string on ANOTHER wire object.
///
/// Objects outside the journal (the CF3 effect intent, its minimal warrant, the terminal outcome)
/// carry free `String` fields that end up on disk permanently, and they have their own reviewed byte
/// caps — a detached signature is legitimately longer than an account name. So this door takes the
/// cap and applies THE law rather than letting each object grow a copy of it: one definition of
/// "empty / overlong / control / whitespace (free-text shape) / '@' (email shape)", one place to
/// change it. The caller still owns its cap, and must justify it where it is declared.
pub fn validate_ledger_bounded_label_chirho(
    field_chirho: &'static str,
    value_chirho: &str,
    max_bytes_chirho: usize,
) -> Result<(), WireErrorChirho> {
    validate_bounded_identifier_chirho(field_chirho, value_chirho, max_bytes_chirho)
}

/// The law for an asset-kind id at the standard identifier cap — the coordinate a CF3 intent and its
/// warrant share with `leg.account.kind_id_chirho`, so both sides answer to one definition.
pub fn validate_ledger_asset_kind_id_chirho(
    field_chirho: &'static str,
    kind_id_chirho: &crate::ids_chirho::AssetKindIdChirho,
) -> Result<(), WireErrorChirho> {
    validate_bounded_identifier_chirho(
        field_chirho,
        &kind_id_chirho.0,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )
}

fn validate_record_identifier_bounds_chirho(
    record_chirho: &LedgerRecordChirho,
) -> Result<(), WireErrorChirho> {
    use crate::counterpart_chirho::{CounterpartClaimChirho, FinalBurnRefChirho};
    use crate::record_chirho::{
        AttributionChirho, CrossZoneAnchorChirho, EscrowControlChirho, HlcChirho, LedgerLegChirho,
        LedgerOpChirho, LegDeltaChirho, LegPostStateChirho,
    };
    // EXHAUSTIVE destructure (no `..`), same idiom as `signed_content_chirho`: adding a wire field
    // without classifying it here — validated textual vs discarded numeric — is a COMPILE error,
    // so a future digest-bearing field cannot evade the bounded-token law (gpt #5241).
    let LedgerRecordChirho {
        schema_chirho: _,         // exact-matched against the v1 wire tag before this walk
        format_version_chirho: _, // numeric
        seq_chirho: _,            // numeric
        prev_chirho,
        epoch_chirho: _, // numeric
        hlc_chirho,
        legs_chirho,
        op_chirho,
        idempotency_key_chirho,
        provenance_chirho,
        attribution_chirho,
        anchor_chirho,
        sig_chirho,
        key_id_chirho,
    } = record_chirho;
    let HlcChirho {
        physical_ms_chirho: _,
        logical_chirho: _,
    } = hlc_chirho;
    validate_bounded_identifier_chirho(
        "idempotency_key_chirho",
        idempotency_key_chirho,
        MAX_LEDGER_IDEMPOTENCY_KEY_BYTES_CHIRHO,
    )?;
    validate_digest_payload_chirho("prev_chirho", prev_chirho)?;
    if let Some(provenance_digest_chirho) = provenance_chirho {
        validate_digest_payload_chirho("provenance_chirho", provenance_digest_chirho)?;
    }
    // `key_id` is label-only (never trust-selection) — which is exactly why the walk must bound
    // it: an honest root can validly SIGN a line whose permanent key label is PII, and
    // verification would not remove it from the log. `sig` is deliberately NOT validated here:
    // the sign-message legitimately exists BEFORE the sig does (sign-then-attach, §11.6), so the
    // sig law lives at the STORED-line emit only (`canonical_ledger_record_line_chirho`).
    let _presign_sig_chirho: &String = sig_chirho;
    validate_bounded_identifier_chirho(
        "key_id_chirho",
        key_id_chirho,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )?;
    if let Some(anchor_value_chirho) = anchor_chirho {
        let CrossZoneAnchorChirho {
            inherited_epoch_chirho: _, // numeric
            inherited_seq_chirho: _,   // numeric
            inherited_digest_chirho,
        } = anchor_value_chirho;
        validate_digest_payload_chirho("anchor.inherited_digest_chirho", inherited_digest_chirho)?;
    }
    match op_chirho {
        LedgerOpChirho::TransferChirho
        | LedgerOpChirho::CreditChirho
        | LedgerOpChirho::DebitChirho => {}
        LedgerOpChirho::EscrowHoldChirho { control_chirho }
        | LedgerOpChirho::EscrowFinalizeChirho { control_chirho }
        | LedgerOpChirho::EscrowReleaseChirho { control_chirho } => {
            let EscrowControlChirho {
                saga_id_chirho,
                step_chirho: _, // numeric
            } = control_chirho;
            validate_digest_payload_chirho("op.escrow.saga_id_chirho", saga_id_chirho)?;
        }
        LedgerOpChirho::CompensationChirho { of_chirho } => {
            validate_digest_payload_chirho("op.compensation.of_chirho", of_chirho)?;
        }
        LedgerOpChirho::MintChirho {
            authority_evidence_chirho,
        }
        | LedgerOpChirho::BurnChirho {
            authority_evidence_chirho,
        } => {
            validate_digest_payload_chirho(
                "op.authority_evidence_chirho",
                authority_evidence_chirho,
            )?;
        }
        // The claude #5212 miss stays closed: Timer's purpose is an op-variant free string.
        LedgerOpChirho::TimerChirho {
            fires_at_hlc_chirho,
            purpose_chirho,
        } => {
            let HlcChirho {
                physical_ms_chirho: _,
                logical_chirho: _,
            } = fires_at_hlc_chirho;
            validate_bounded_identifier_chirho(
                "op.timer.purpose_chirho",
                purpose_chirho,
                MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
            )?;
        }
    }
    match attribution_chirho {
        AttributionChirho::CauserChirho { principal_chirho } => {
            validate_bounded_identifier_chirho(
                "attribution.principal_chirho",
                principal_chirho,
                MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
            )?;
        }
        AttributionChirho::PlatformChirho => {}
        AttributionChirho::PolicyChirho { policy_ref_chirho } => {
            validate_digest_payload_chirho("attribution.policy_ref_chirho", policy_ref_chirho)?;
        }
    }
    for leg_chirho in legs_chirho {
        let LedgerLegChirho {
            account_chirho,
            kind_policy_ref_chirho,
            delta_chirho,
            amount_chirho: _, // numeric
            post_chirho,
            counterpart_chirho,
        } = leg_chirho;
        match delta_chirho {
            LegDeltaChirho::CreditChirho
            | LegDeltaChirho::DebitChirho
            | LegDeltaChirho::HoldChirho
            | LegDeltaChirho::ReleaseChirho
            | LegDeltaChirho::FinalizeChirho => {}
        }
        let LegPostStateChirho {
            credits_total_chirho: _,
            debits_total_chirho: _,
            held_chirho: _,
        } = post_chirho;
        validate_account_identifier_bounds_chirho("leg.account.owner_chirho", account_chirho)?;
        validate_digest_payload_chirho("leg.kind_policy_ref_chirho", &kind_policy_ref_chirho.0)?;
        if let Some(claim_chirho) = counterpart_chirho {
            let CounterpartClaimChirho {
                transfer_id_chirho,
                burn_chirho,
                amount_chirho: _, // numeric
                kind_policy_ref_chirho: claim_kind_policy_ref_chirho,
                src_chirho,
                dst_money_group_chirho,
                dst_cluster_chirho,
                dst_chirho,
                channel_chirho,
                nullifier_chirho,
            } = claim_chirho;
            let FinalBurnRefChirho {
                source_money_group_chirho,
                source_cluster_chirho,
                source_epoch_chirho: _, // numeric
                source_seq_chirho: _,   // numeric
                source_record_digest_chirho,
                finality_proof_ref_chirho,
            } = burn_chirho;
            validate_bounded_identifier_chirho(
                "claim.transfer_id_chirho",
                &transfer_id_chirho.0,
                MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
            )?;
            validate_bounded_identifier_chirho(
                "claim.channel_chirho",
                &channel_chirho.0,
                MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
            )?;
            validate_bounded_identifier_chirho(
                "claim.burn.source_money_group_chirho",
                &source_money_group_chirho.0,
                MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
            )?;
            validate_bounded_identifier_chirho(
                "claim.burn.source_cluster_chirho",
                &source_cluster_chirho.0,
                MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
            )?;
            validate_digest_payload_chirho(
                "claim.burn.source_record_digest_chirho",
                source_record_digest_chirho,
            )?;
            validate_digest_payload_chirho(
                "claim.burn.finality_proof_ref_chirho",
                finality_proof_ref_chirho,
            )?;
            validate_digest_payload_chirho(
                "claim.kind_policy_ref_chirho",
                &claim_kind_policy_ref_chirho.0,
            )?;
            validate_digest_payload_chirho("claim.nullifier_chirho", &nullifier_chirho.0)?;
            validate_bounded_identifier_chirho(
                "claim.dst_money_group_chirho",
                &dst_money_group_chirho.0,
                MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
            )?;
            validate_bounded_identifier_chirho(
                "claim.dst_cluster_chirho",
                &dst_cluster_chirho.0,
                MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
            )?;
            validate_account_identifier_bounds_chirho("claim.src_chirho", src_chirho)?;
            validate_account_identifier_bounds_chirho("claim.dst_chirho", dst_chirho)?;
        }
    }
    Ok(())
}

/// The record law shared by the sign-message and the stored line: schema tag, format version, and
/// the bounded-identifier walk over everything EXCEPT `sig` (which does not exist yet at signing).
fn validate_record_sign_message_law_chirho(
    record_chirho: &LedgerRecordChirho,
) -> Result<(), WireErrorChirho> {
    if record_chirho.schema_chirho != LEDGER_RECORD_SCHEMA_V1_CHIRHO {
        return Err(WireErrorChirho::SchemaMismatchChirho {
            found_chirho: record_chirho.schema_chirho.clone(),
        });
    }
    if record_chirho.format_version_chirho != LEDGER_FORMAT_VERSION_V1_CHIRHO {
        return Err(WireErrorChirho::FormatVersionMismatchChirho {
            found_chirho: record_chirho.format_version_chirho,
        });
    }
    validate_record_identifier_bounds_chirho(record_chirho)
}

pub fn canonical_ledger_record_line_chirho(
    record_chirho: &LedgerRecordChirho,
) -> Result<String, WireErrorChirho> {
    validate_record_sign_message_law_chirho(record_chirho)?;
    // The STORED line carries the attached sig, so here it must be a bounded token: the wider cap
    // (a real encoded signature with a scheme prefix outgrows the identifier cap), and the same
    // non-email/non-free-text shape law (gpt #5241 — an honest root could otherwise sign PII into
    // the log forever).
    validate_bounded_identifier_chirho(
        "sig_chirho",
        &record_chirho.sig_chirho,
        MAX_LEDGER_IDEMPOTENCY_KEY_BYTES_CHIRHO,
    )?;
    to_canonical_json_chirho(record_chirho)
}

/// The genesis law shared by the sign-message and the stored line — the same exhaustive-destructure
/// idiom as the record walk (every field classified), with `sig` excluded exactly as there.
fn validate_genesis_sign_message_law_chirho(
    genesis_chirho: &LedgerGenesisRecordChirho,
) -> Result<(), WireErrorChirho> {
    if genesis_chirho.schema_chirho != LEDGER_GENESIS_SCHEMA_V1_CHIRHO {
        return Err(WireErrorChirho::SchemaMismatchChirho {
            found_chirho: genesis_chirho.schema_chirho.clone(),
        });
    }
    if genesis_chirho.format_version_chirho != LEDGER_FORMAT_VERSION_V1_CHIRHO {
        return Err(WireErrorChirho::FormatVersionMismatchChirho {
            found_chirho: genesis_chirho.format_version_chirho,
        });
    }
    let LedgerGenesisRecordChirho {
        schema_chirho: _,         // exact-matched against the v1 wire tag above
        format_version_chirho: _, // numeric
        cluster_id_chirho,
        epoch_chirho: _, // numeric
        hlc_chirho,
        sig_chirho: _, // validated ONLY at the stored-line emit — the sign-message predates it
        key_id_chirho,
    } = genesis_chirho;
    let crate::record_chirho::HlcChirho {
        physical_ms_chirho: _,
        logical_chirho: _,
    } = hlc_chirho;
    validate_bounded_identifier_chirho(
        "genesis.cluster_id_chirho",
        &cluster_id_chirho.0,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )?;
    // The permanent key label rides the law (gpt #5241 — a PII-shaped key label would verify and
    // stay in the log forever).
    validate_bounded_identifier_chirho(
        "genesis.key_id_chirho",
        key_id_chirho,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )
}

/// Fail-closed canonical EMIT of a genesis line (same law as the record emit).
pub fn canonical_ledger_genesis_line_chirho(
    genesis_chirho: &LedgerGenesisRecordChirho,
) -> Result<String, WireErrorChirho> {
    validate_genesis_sign_message_law_chirho(genesis_chirho)?;
    validate_bounded_identifier_chirho(
        "genesis.sig_chirho",
        &genesis_chirho.sig_chirho,
        MAX_LEDGER_IDEMPOTENCY_KEY_BYTES_CHIRHO,
    )?;
    to_canonical_json_chirho(genesis_chirho)
}

/// The record sign-message line (record MINUS `sig`, §11.6 sign-then-attach) — the exact bytes a
/// signature covers. Validates the schema/version/bounds law EXCEPT the sig, which legitimately
/// does not exist yet at signing time (the stored-line emit enforces the sig law after attach).
pub fn ledger_record_signed_content_line_chirho(
    record_chirho: &LedgerRecordChirho,
) -> Result<String, WireErrorChirho> {
    validate_record_sign_message_law_chirho(record_chirho)?;
    to_canonical_json_chirho(&record_chirho.signed_content_chirho())
}

/// The genesis sign-message line (genesis MINUS `sig`) — same sig-excluded law as the record.
pub fn ledger_genesis_signed_content_line_chirho(
    genesis_chirho: &LedgerGenesisRecordChirho,
) -> Result<String, WireErrorChirho> {
    validate_genesis_sign_message_law_chirho(genesis_chirho)?;
    to_canonical_json_chirho(&genesis_chirho.signed_content_chirho())
}

/// One stored journal line, routed (the shape-A decoder law, gpt #4420/#4421/A3-R1). Deliberately
/// carries NO serde derives — the wrapper is a ROUTING result, never itself a wire shape (an
/// untagged/alternate encoding of it cannot exist).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerJournalLineChirho {
    GenesisChirho(LedgerGenesisRecordChirho),
    RecordChirho(LedgerRecordChirho),
}

/// The schema-only probe target: reads `schema_chirho` WITHOUT trusting any other field. No
/// `deny_unknown_fields` (other keys are none of the probe's business), but the derive still
/// refuses a DUPLICATE `schema_chirho` and a non-string tag — the duplicate-safe probe law.
#[derive(serde::Deserialize)]
struct SchemaProbeChirho {
    schema_chirho: String,
}

/// The ONE journal-line router (A3-R1): schema-only duplicate-safe probe → dispatch to the exact
/// concrete J0a parser → non-serde wrapper. B's journal loader uses ONLY this — routing is never
/// positional and never hand-rolled, so a v2/unknown line dies HERE, before either concrete
/// decoder sees it. Physical chain laws (one genesis at line 0, dense seq, prev binding) stay in
/// B's loader — this routes ONE line.
pub fn parse_canonical_ledger_journal_line_chirho(
    line_chirho: &str,
) -> Result<LedgerJournalLineChirho, WireErrorChirho> {
    let probe_chirho: SchemaProbeChirho =
        serde_json::from_str(line_chirho).map_err(|error_chirho| {
            WireErrorChirho::MalformedChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })?;
    match probe_chirho.schema_chirho.as_str() {
        LEDGER_GENESIS_SCHEMA_V1_CHIRHO => Ok(LedgerJournalLineChirho::GenesisChirho(
            parse_canonical_ledger_genesis_chirho(line_chirho)?,
        )),
        LEDGER_RECORD_SCHEMA_V1_CHIRHO => Ok(LedgerJournalLineChirho::RecordChirho(
            parse_canonical_ledger_record_chirho(line_chirho)?,
        )),
        _ => Err(WireErrorChirho::SchemaMismatchChirho {
            found_chirho: probe_chirho.schema_chirho,
        }),
    }
}

/// J0a strict parse of a stored RECORD line: typed deserialize (`deny_unknown_fields`) → schema
/// tag check → format-version check → EXACT reserialize-byte equality against the input. Any
/// deviation is a typed refusal, never a normalization.
pub fn parse_canonical_ledger_record_chirho(
    line_chirho: &str,
) -> Result<LedgerRecordChirho, WireErrorChirho> {
    let record_chirho: LedgerRecordChirho =
        serde_json::from_str(line_chirho).map_err(|error_chirho| {
            WireErrorChirho::MalformedChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })?;
    let canonical_chirho = canonical_ledger_record_line_chirho(&record_chirho)?;
    if canonical_chirho != line_chirho {
        return Err(WireErrorChirho::NonCanonicalBytesChirho);
    }
    Ok(record_chirho)
}

/// J0a strict parse of a stored GENESIS line (same law as the record parse).
pub fn parse_canonical_ledger_genesis_chirho(
    line_chirho: &str,
) -> Result<LedgerGenesisRecordChirho, WireErrorChirho> {
    let genesis_chirho: LedgerGenesisRecordChirho =
        serde_json::from_str(line_chirho).map_err(|error_chirho| {
            WireErrorChirho::MalformedChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })?;
    let canonical_chirho = canonical_ledger_genesis_line_chirho(&genesis_chirho)?;
    if canonical_chirho != line_chirho {
        return Err(WireErrorChirho::NonCanonicalBytesChirho);
    }
    Ok(genesis_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::counterpart_chirho::{
        CounterpartClaimChirho, CounterpartNullifierChirho, FinalBurnRefChirho,
    };
    use crate::ids_chirho::*;
    use crate::record_chirho::*;
    use crate::LogIdChirho;

    /// The golden JOURNAL: genesis + two records, chained by stored-line digests. Literal byte pins
    /// (J0a) — if ANY serialization detail moves (field order, a serde_json upgrade, a rename),
    /// these vectors fail and the change must be an explicitly reviewed wire migration.
    const GOLDEN_GENESIS_LINE_CHIRHO: &str = r#"{"schema_chirho":"ledger-genesis-v1-chirho","format_version_chirho":1,"cluster_id_chirho":"cluster-alpha-chirho","epoch_chirho":1,"hlc_chirho":{"physical_ms_chirho":900,"logical_chirho":0},"sig_chirho":"sig-genesis-golden-chirho","key_id_chirho":"journal-key-1-chirho"}"#;
    const GOLDEN_GENESIS_DIGEST_CHIRHO: &str =
        "53c617517a916c8a36d4f8a898f83a4132a1f9a8367998a9149cafa492afffdf";
    const GOLDEN_RECORD1_LINE_CHIRHO: &str = r#"{"schema_chirho":"ledger-record-v1-chirho","format_version_chirho":1,"seq_chirho":1,"prev_chirho":"53c617517a916c8a36d4f8a898f83a4132a1f9a8367998a9149cafa492afffdf","epoch_chirho":1,"hlc_chirho":{"physical_ms_chirho":1000,"logical_chirho":0},"legs_chirho":[{"account_chirho":{"owner_chirho":"alice-chirho","kind_id_chirho":"money-chirho"},"kind_policy_ref_chirho":"policy-v1-digest-chirho","delta_chirho":"debit","amount_chirho":25,"post_chirho":{"credits_total_chirho":100,"debits_total_chirho":25,"held_chirho":0}},{"account_chirho":{"owner_chirho":"bob-chirho","kind_id_chirho":"money-chirho"},"kind_policy_ref_chirho":"policy-v1-digest-chirho","delta_chirho":"credit","amount_chirho":25,"post_chirho":{"credits_total_chirho":25,"debits_total_chirho":0,"held_chirho":0}}],"op_chirho":"transfer","idempotency_key_chirho":"idem-0001-chirho","attribution_chirho":{"causer":{"principal_chirho":"alice-chirho"}},"sig_chirho":"sig-r1-golden-chirho","key_id_chirho":"journal-key-1-chirho"}"#;
    const GOLDEN_RECORD1_DIGEST_CHIRHO: &str =
        "8f0362353b88909dcb391e86c7e5eee932ab329d669af67aca7e9eb01b8a5ae7";
    const GOLDEN_RECORD2_LINE_CHIRHO: &str = r#"{"schema_chirho":"ledger-record-v1-chirho","format_version_chirho":1,"seq_chirho":2,"prev_chirho":"8f0362353b88909dcb391e86c7e5eee932ab329d669af67aca7e9eb01b8a5ae7","epoch_chirho":2,"hlc_chirho":{"physical_ms_chirho":1100,"logical_chirho":3},"legs_chirho":[{"account_chirho":{"owner_chirho":"bob-chirho","kind_id_chirho":"money-chirho"},"kind_policy_ref_chirho":"policy-v1-digest-chirho","delta_chirho":"credit","amount_chirho":7,"post_chirho":{"credits_total_chirho":32,"debits_total_chirho":0,"held_chirho":5},"counterpart_chirho":{"transfer_id_chirho":"t-77-chirho","burn_chirho":{"source_money_group_chirho":"mg-src-chirho","source_cluster_chirho":"cluster-src-chirho","source_epoch_chirho":4,"source_seq_chirho":19,"source_record_digest_chirho":"srcburndigest-chirho","finality_proof_ref_chirho":"finalityproof-chirho"},"amount_chirho":7,"kind_policy_ref_chirho":"policy-v1-digest-chirho","src_chirho":{"owner_chirho":"carol-chirho","kind_id_chirho":"money-chirho"},"dst_money_group_chirho":"mg-dst-chirho","dst_cluster_chirho":"cluster-alpha-chirho","dst_chirho":{"owner_chirho":"bob-chirho","kind_id_chirho":"money-chirho"},"channel_chirho":"chan-1-chirho","nullifier_chirho":"nullifier-golden-chirho"}}],"op_chirho":"transfer","idempotency_key_chirho":"idem-0002-chirho","provenance_chirho":"provenance-golden-chirho","attribution_chirho":"platform","anchor_chirho":{"inherited_epoch_chirho":1,"inherited_seq_chirho":1,"inherited_digest_chirho":"8f0362353b88909dcb391e86c7e5eee932ab329d669af67aca7e9eb01b8a5ae7"},"sig_chirho":"sig-r2-golden-chirho","key_id_chirho":"journal-key-2-chirho"}"#;
    const GOLDEN_RECORD2_DIGEST_CHIRHO: &str =
        "905197703f3f6ed15ae3213bcf67ab65ec98cab09ca87424b32ae07870640e66";

    fn golden_genesis_chirho() -> LedgerGenesisRecordChirho {
        LedgerGenesisRecordChirho {
            schema_chirho: LEDGER_GENESIS_SCHEMA_V1_CHIRHO.into(),
            format_version_chirho: 1,
            cluster_id_chirho: ClusterIdChirho("cluster-alpha-chirho".into()),
            epoch_chirho: 1,
            hlc_chirho: HlcChirho {
                physical_ms_chirho: 900,
                logical_chirho: 0,
            },
            sig_chirho: "sig-genesis-golden-chirho".into(),
            key_id_chirho: "journal-key-1-chirho".into(),
        }
    }

    fn golden_record1_chirho() -> LedgerRecordChirho {
        let leg_chirho = |owner_chirho: &str, delta_chirho, c_chirho, d_chirho| LedgerLegChirho {
            account_chirho: LogIdChirho::new_chirho(owner_chirho, "money-chirho"),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                "policy-v1-digest-chirho".into(),
            )),
            delta_chirho,
            amount_chirho: 25,
            post_chirho: LegPostStateChirho {
                credits_total_chirho: c_chirho,
                debits_total_chirho: d_chirho,
                held_chirho: 0,
            },
            counterpart_chirho: None,
        };
        LedgerRecordChirho {
            schema_chirho: LEDGER_RECORD_SCHEMA_V1_CHIRHO.into(),
            format_version_chirho: 1,
            seq_chirho: 1,
            prev_chirho: DigestChirho(GOLDEN_GENESIS_DIGEST_CHIRHO.into()),
            epoch_chirho: 1,
            hlc_chirho: HlcChirho {
                physical_ms_chirho: 1000,
                logical_chirho: 0,
            },
            legs_chirho: vec![
                leg_chirho("alice-chirho", LegDeltaChirho::DebitChirho, 100, 25),
                leg_chirho("bob-chirho", LegDeltaChirho::CreditChirho, 25, 0),
            ],
            op_chirho: LedgerOpChirho::TransferChirho,
            idempotency_key_chirho: "idem-0001-chirho".into(),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: "alice-chirho".into(),
            },
            anchor_chirho: None,
            sig_chirho: "sig-r1-golden-chirho".into(),
            key_id_chirho: "journal-key-1-chirho".into(),
        }
    }

    fn golden_record2_chirho() -> LedgerRecordChirho {
        LedgerRecordChirho {
            schema_chirho: LEDGER_RECORD_SCHEMA_V1_CHIRHO.into(),
            format_version_chirho: 1,
            seq_chirho: 2,
            prev_chirho: DigestChirho(GOLDEN_RECORD1_DIGEST_CHIRHO.into()),
            epoch_chirho: 2,
            hlc_chirho: HlcChirho {
                physical_ms_chirho: 1100,
                logical_chirho: 3,
            },
            legs_chirho: vec![LedgerLegChirho {
                account_chirho: LogIdChirho::new_chirho("bob-chirho", "money-chirho"),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                    "policy-v1-digest-chirho".into(),
                )),
                delta_chirho: LegDeltaChirho::CreditChirho,
                amount_chirho: 7,
                post_chirho: LegPostStateChirho {
                    credits_total_chirho: 32,
                    debits_total_chirho: 0,
                    held_chirho: 5,
                },
                counterpart_chirho: Some(CounterpartClaimChirho {
                    transfer_id_chirho: TransferIdChirho("t-77-chirho".into()),
                    burn_chirho: FinalBurnRefChirho {
                        source_money_group_chirho: MoneyGroupIdChirho("mg-src-chirho".into()),
                        source_cluster_chirho: ClusterIdChirho("cluster-src-chirho".into()),
                        source_epoch_chirho: 4,
                        source_seq_chirho: 19,
                        source_record_digest_chirho: DigestChirho("srcburndigest-chirho".into()),
                        finality_proof_ref_chirho: DigestChirho("finalityproof-chirho".into()),
                    },
                    amount_chirho: 7,
                    kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                        "policy-v1-digest-chirho".into(),
                    )),
                    src_chirho: LogIdChirho::new_chirho("carol-chirho", "money-chirho"),
                    dst_money_group_chirho: MoneyGroupIdChirho("mg-dst-chirho".into()),
                    dst_cluster_chirho: ClusterIdChirho("cluster-alpha-chirho".into()),
                    dst_chirho: LogIdChirho::new_chirho("bob-chirho", "money-chirho"),
                    channel_chirho: SettlementChannelIdChirho("chan-1-chirho".into()),
                    nullifier_chirho: CounterpartNullifierChirho(DigestChirho(
                        "nullifier-golden-chirho".into(),
                    )),
                }),
            }],
            op_chirho: LedgerOpChirho::TransferChirho,
            idempotency_key_chirho: "idem-0002-chirho".into(),
            provenance_chirho: Some(DigestChirho("provenance-golden-chirho".into())),
            attribution_chirho: AttributionChirho::PlatformChirho,
            anchor_chirho: Some(CrossZoneAnchorChirho {
                inherited_epoch_chirho: 1,
                inherited_seq_chirho: 1,
                inherited_digest_chirho: DigestChirho(GOLDEN_RECORD1_DIGEST_CHIRHO.into()),
            }),
            sig_chirho: "sig-r2-golden-chirho".into(),
            key_id_chirho: "journal-key-2-chirho".into(),
        }
    }

    /// The documented REGENERATION path (§11.6: a serde upgrade reruns the golden vectors and lands
    /// ONLY if bytes are identical — otherwise the diff is a reviewed wire MIGRATION, never a quiet
    /// re-pin). Run: `cargo nextest run -p cairn-ledger-model-chirho --run-ignored all
    /// print_golden` (or `cargo test -- --ignored --nocapture`), then update the six constants.
    #[test]
    #[ignore = "generator: prints candidate golden lines/digests for a REVIEWED re-pin"]
    fn print_golden_generation_chirho() {
        let genesis_line_chirho =
            canonical_ledger_genesis_line_chirho(&golden_genesis_chirho()).unwrap();
        let genesis_digest_chirho = stored_line_digest_chirho(&genesis_line_chirho);
        let mut record1_chirho = golden_record1_chirho();
        record1_chirho.prev_chirho = genesis_digest_chirho.clone();
        let record1_line_chirho = canonical_ledger_record_line_chirho(&record1_chirho).unwrap();
        let record1_digest_chirho = stored_line_digest_chirho(&record1_line_chirho);
        let mut record2_chirho = golden_record2_chirho();
        record2_chirho.prev_chirho = record1_digest_chirho.clone();
        record2_chirho
            .anchor_chirho
            .as_mut()
            .unwrap()
            .inherited_digest_chirho = record1_digest_chirho.clone();
        let record2_line_chirho = canonical_ledger_record_line_chirho(&record2_chirho).unwrap();
        let record2_digest_chirho = stored_line_digest_chirho(&record2_line_chirho);
        println!("GENESIS LINE:\n{genesis_line_chirho}");
        println!("GENESIS DIGEST: {}", genesis_digest_chirho.0);
        println!("RECORD1 LINE:\n{record1_line_chirho}");
        println!("RECORD1 DIGEST: {}", record1_digest_chirho.0);
        println!("RECORD2 LINE:\n{record2_line_chirho}");
        println!("RECORD2 DIGEST: {}", record2_digest_chirho.0);
    }

    #[test]
    fn golden_vectors_pin_exact_bytes_and_digests_chirho() {
        // Emit → literal byte pins (a serde/field-order/rename drift fails HERE).
        assert_eq!(
            canonical_ledger_genesis_line_chirho(&golden_genesis_chirho()).unwrap(),
            GOLDEN_GENESIS_LINE_CHIRHO
        );
        assert_eq!(
            canonical_ledger_record_line_chirho(&golden_record1_chirho()).unwrap(),
            GOLDEN_RECORD1_LINE_CHIRHO
        );
        assert_eq!(
            canonical_ledger_record_line_chirho(&golden_record2_chirho()).unwrap(),
            GOLDEN_RECORD2_LINE_CHIRHO
        );
        // Digest pins: the stored-line digest law (genesis digest NAMES the journal).
        assert_eq!(
            stored_line_digest_chirho(GOLDEN_GENESIS_LINE_CHIRHO).0,
            GOLDEN_GENESIS_DIGEST_CHIRHO
        );
        assert_eq!(
            stored_line_digest_chirho(GOLDEN_RECORD1_LINE_CHIRHO).0,
            GOLDEN_RECORD1_DIGEST_CHIRHO
        );
        assert_eq!(
            stored_line_digest_chirho(GOLDEN_RECORD2_LINE_CHIRHO).0,
            GOLDEN_RECORD2_DIGEST_CHIRHO
        );
        // Parse round-trip: the canonical line parses to the exact typed value.
        assert_eq!(
            parse_canonical_ledger_genesis_chirho(GOLDEN_GENESIS_LINE_CHIRHO).unwrap(),
            golden_genesis_chirho()
        );
        assert_eq!(
            parse_canonical_ledger_record_chirho(GOLDEN_RECORD1_LINE_CHIRHO).unwrap(),
            golden_record1_chirho()
        );
        assert_eq!(
            parse_canonical_ledger_record_chirho(GOLDEN_RECORD2_LINE_CHIRHO).unwrap(),
            golden_record2_chirho()
        );
    }

    #[test]
    fn chain_law_binds_prev_to_prior_stored_line_chirho() {
        // gen-0 ⟺ no prev (structurally absent on the genesis TYPE); record 1's prev = the genesis
        // stored-line digest; record 2's prev = record 1's stored-line digest.
        let genesis_digest_chirho = stored_line_digest_chirho(GOLDEN_GENESIS_LINE_CHIRHO);
        let record1_chirho =
            parse_canonical_ledger_record_chirho(GOLDEN_RECORD1_LINE_CHIRHO).unwrap();
        assert_eq!(record1_chirho.prev_chirho, genesis_digest_chirho);
        let record1_digest_chirho = stored_line_digest_chirho(GOLDEN_RECORD1_LINE_CHIRHO);
        let record2_chirho =
            parse_canonical_ledger_record_chirho(GOLDEN_RECORD2_LINE_CHIRHO).unwrap();
        assert_eq!(record2_chirho.prev_chirho, record1_digest_chirho);
        // The digest covers the SIGNED line (sig included), so prev binds signatures into the chain:
        // altering ONLY the sig changes the successor's expected prev.
        let tampered_sig_line_chirho =
            GOLDEN_RECORD1_LINE_CHIRHO.replace("sig-r1-golden-chirho", "sig-r1-FORGED-chirho");
        assert_ne!(
            stored_line_digest_chirho(&tampered_sig_line_chirho),
            record1_digest_chirho
        );
    }

    #[test]
    fn signed_content_is_the_stored_line_minus_exactly_the_sig_chirho() {
        // §11.6 sign-then-attach: the sign-message bytes are the stored line with ONLY the sig
        // key-value spliced out (key_id IS signed). Pinned by exact string surgery.
        let expected_record_chirho =
            GOLDEN_RECORD1_LINE_CHIRHO.replace(r#""sig_chirho":"sig-r1-golden-chirho","#, "");
        assert_eq!(
            ledger_record_signed_content_line_chirho(&golden_record1_chirho()).unwrap(),
            expected_record_chirho
        );
        let expected_genesis_chirho =
            GOLDEN_GENESIS_LINE_CHIRHO.replace(r#""sig_chirho":"sig-genesis-golden-chirho","#, "");
        assert_eq!(
            ledger_genesis_signed_content_line_chirho(&golden_genesis_chirho()).unwrap(),
            expected_genesis_chirho
        );
    }

    #[test]
    fn wire_tags_are_pinned_kebab_and_compile_exhaustive_chirho() {
        // The tag map is a MATCH (a new variant fails compilation until classified here), and each
        // serde tag is pinned literal — a rename can never silently fork the wire.
        fn op_tag_json_chirho(op_chirho: &LedgerOpChirho) -> String {
            let d_chirho = || DigestChirho("d-chirho".into());
            match op_chirho {
                LedgerOpChirho::TransferChirho => r#""transfer""#.into(),
                LedgerOpChirho::CreditChirho => r#""credit""#.into(),
                LedgerOpChirho::DebitChirho => r#""debit""#.into(),
                LedgerOpChirho::EscrowHoldChirho { .. } => {
                    r#"{"escrow-hold":{"control_chirho":{"saga_id_chirho":"d-chirho","step_chirho":1}}}"#.into()
                }
                LedgerOpChirho::EscrowFinalizeChirho { .. } => {
                    r#"{"escrow-finalize":{"control_chirho":{"saga_id_chirho":"d-chirho","step_chirho":1}}}"#.into()
                }
                LedgerOpChirho::EscrowReleaseChirho { .. } => {
                    r#"{"escrow-release":{"control_chirho":{"saga_id_chirho":"d-chirho","step_chirho":1}}}"#.into()
                }
                LedgerOpChirho::CompensationChirho { .. } => {
                    format!(
                        r#"{{"compensation":{}}}"#,
                        serde_json::to_string(&serde_json::json!({
                            "of_chirho": d_chirho().0
                        }))
                        .unwrap()
                    )
                }
                LedgerOpChirho::MintChirho { .. } => {
                    r#"{"mint":{"authority_evidence_chirho":"d-chirho"}}"#.into()
                }
                LedgerOpChirho::BurnChirho { .. } => {
                    r#"{"burn":{"authority_evidence_chirho":"d-chirho"}}"#.into()
                }
                LedgerOpChirho::TimerChirho { .. } => {
                    r#"{"timer":{"fires_at_hlc_chirho":{"physical_ms_chirho":5,"logical_chirho":1},"purpose_chirho":"p-chirho"}}"#.into()
                }
            }
        }
        let d_chirho = DigestChirho("d-chirho".into());
        let all_ops_chirho = vec![
            LedgerOpChirho::TransferChirho,
            LedgerOpChirho::CreditChirho,
            LedgerOpChirho::DebitChirho,
            LedgerOpChirho::EscrowHoldChirho {
                control_chirho: EscrowControlChirho {
                    saga_id_chirho: d_chirho.clone(),
                    step_chirho: 1,
                },
            },
            LedgerOpChirho::EscrowFinalizeChirho {
                control_chirho: EscrowControlChirho {
                    saga_id_chirho: d_chirho.clone(),
                    step_chirho: 1,
                },
            },
            LedgerOpChirho::EscrowReleaseChirho {
                control_chirho: EscrowControlChirho {
                    saga_id_chirho: d_chirho.clone(),
                    step_chirho: 1,
                },
            },
            LedgerOpChirho::CompensationChirho {
                of_chirho: d_chirho.clone(),
            },
            LedgerOpChirho::MintChirho {
                authority_evidence_chirho: d_chirho.clone(),
            },
            LedgerOpChirho::BurnChirho {
                authority_evidence_chirho: d_chirho.clone(),
            },
            LedgerOpChirho::TimerChirho {
                fires_at_hlc_chirho: HlcChirho {
                    physical_ms_chirho: 5,
                    logical_chirho: 1,
                },
                purpose_chirho: "p-chirho".into(),
            },
        ];
        for op_chirho in &all_ops_chirho {
            assert_eq!(
                serde_json::to_string(op_chirho).unwrap(),
                op_tag_json_chirho(op_chirho),
                "op wire tag drifted"
            );
        }
        fn delta_tag_chirho(delta_chirho: &LegDeltaChirho) -> &'static str {
            match delta_chirho {
                LegDeltaChirho::CreditChirho => r#""credit""#,
                LegDeltaChirho::DebitChirho => r#""debit""#,
                LegDeltaChirho::HoldChirho => r#""hold""#,
                LegDeltaChirho::ReleaseChirho => r#""release""#,
                LegDeltaChirho::FinalizeChirho => r#""finalize""#,
            }
        }
        for delta_chirho in [
            LegDeltaChirho::CreditChirho,
            LegDeltaChirho::DebitChirho,
            LegDeltaChirho::HoldChirho,
            LegDeltaChirho::ReleaseChirho,
            LegDeltaChirho::FinalizeChirho,
        ] {
            assert_eq!(
                serde_json::to_string(&delta_chirho).unwrap(),
                delta_tag_chirho(&delta_chirho),
                "delta wire tag drifted"
            );
        }
        fn attribution_tag_json_chirho(attribution_chirho: &AttributionChirho) -> &'static str {
            match attribution_chirho {
                AttributionChirho::CauserChirho { .. } => {
                    r#"{"causer":{"principal_chirho":"p-chirho"}}"#
                }
                AttributionChirho::PlatformChirho => r#""platform""#,
                AttributionChirho::PolicyChirho { .. } => {
                    r#"{"policy":{"policy_ref_chirho":"d-chirho"}}"#
                }
            }
        }
        for attribution_chirho in [
            AttributionChirho::CauserChirho {
                principal_chirho: "p-chirho".into(),
            },
            AttributionChirho::PlatformChirho,
            AttributionChirho::PolicyChirho {
                policy_ref_chirho: d_chirho.clone(),
            },
        ] {
            assert_eq!(
                serde_json::to_string(&attribution_chirho).unwrap(),
                attribution_tag_json_chirho(&attribution_chirho),
                "attribution wire tag drifted"
            );
        }
    }

    #[test]
    fn journal_line_router_probes_schema_only_and_dispatches_chirho() {
        // A3-R1 (gpt): the ONE router — schema-only duplicate-safe probe, then the exact concrete
        // parser, wrapped in the non-serde LedgerJournalLineChirho.
        assert_eq!(
            parse_canonical_ledger_journal_line_chirho(GOLDEN_GENESIS_LINE_CHIRHO).unwrap(),
            LedgerJournalLineChirho::GenesisChirho(golden_genesis_chirho())
        );
        assert_eq!(
            parse_canonical_ledger_journal_line_chirho(GOLDEN_RECORD1_LINE_CHIRHO).unwrap(),
            LedgerJournalLineChirho::RecordChirho(golden_record1_chirho())
        );
        // A v2/unknown tag on an otherwise SHAPE-VALID line dies AT THE PROBE (SchemaMismatch),
        // never inside either concrete parser (which would report Malformed/NonCanonical instead).
        let v2_chirho = GOLDEN_GENESIS_LINE_CHIRHO
            .replace("ledger-genesis-v1-chirho", "ledger-genesis-v2-chirho");
        assert_eq!(
            parse_canonical_ledger_journal_line_chirho(&v2_chirho),
            Err(WireErrorChirho::SchemaMismatchChirho {
                found_chirho: "ledger-genesis-v2-chirho".into()
            })
        );
        // A DUPLICATE schema key dies at the probe (the derive tracks known-field duplicates even
        // without deny_unknown_fields).
        let duplicate_chirho = GOLDEN_GENESIS_LINE_CHIRHO.replacen(
            r#"{"schema_chirho":"#,
            r#"{"schema_chirho":"decoy","schema_chirho":"#,
            1,
        );
        assert!(matches!(
            parse_canonical_ledger_journal_line_chirho(&duplicate_chirho),
            Err(WireErrorChirho::MalformedChirho { detail_chirho }) if detail_chirho.contains("duplicate field")
        ));
        // A non-string tag and a MISSING tag die at the probe.
        let nonstring_chirho = GOLDEN_GENESIS_LINE_CHIRHO.replacen(
            r#""schema_chirho":"ledger-genesis-v1-chirho""#,
            r#""schema_chirho":7"#,
            1,
        );
        assert!(matches!(
            parse_canonical_ledger_journal_line_chirho(&nonstring_chirho),
            Err(WireErrorChirho::MalformedChirho { .. })
        ));
        assert!(matches!(
            parse_canonical_ledger_journal_line_chirho(r#"{"seq_chirho":1}"#),
            Err(WireErrorChirho::MalformedChirho { .. })
        ));
        // Dispatch keeps the FULL J0a law: a routed-but-noncanonical line still refuses.
        assert_eq!(
            parse_canonical_ledger_journal_line_chirho(&format!("{GOLDEN_RECORD1_LINE_CHIRHO}\n")),
            Err(WireErrorChirho::NonCanonicalBytesChirho)
        );
    }

    #[test]
    fn j0a_rejects_every_noncanonical_variant_chirho() {
        // Reordered keys (schema/format swapped): parses, but reserialization differs → REFUSED.
        let reordered_chirho = GOLDEN_GENESIS_LINE_CHIRHO.replacen(
            r#"{"schema_chirho":"ledger-genesis-v1-chirho","format_version_chirho":1"#,
            r#"{"format_version_chirho":1,"schema_chirho":"ledger-genesis-v1-chirho""#,
            1,
        );
        assert_eq!(
            parse_canonical_ledger_genesis_chirho(&reordered_chirho),
            Err(WireErrorChirho::NonCanonicalBytesChirho)
        );
        // Duplicate key: the derived strict deserializer refuses it AT PARSE ("duplicate field"),
        // even before the byte-equality backstop would catch it — refusal either way, never a
        // last-wins normalization.
        let duplicate_chirho = GOLDEN_GENESIS_LINE_CHIRHO.replacen(
            r#"{"schema_chirho":"#,
            r#"{"schema_chirho":"decoy","schema_chirho":"#,
            1,
        );
        assert!(matches!(
            parse_canonical_ledger_genesis_chirho(&duplicate_chirho),
            Err(WireErrorChirho::MalformedChirho { detail_chirho }) if detail_chirho.contains("duplicate field")
        ));
        // Incidental whitespace → REFUSED.
        let spaced_chirho = GOLDEN_GENESIS_LINE_CHIRHO.replacen(
            r#""format_version_chirho":1"#,
            r#""format_version_chirho": 1"#,
            1,
        );
        assert_eq!(
            parse_canonical_ledger_genesis_chirho(&spaced_chirho),
            Err(WireErrorChirho::NonCanonicalBytesChirho)
        );
        // Trailing LF: the canonical BODY excludes the JSONL LF (§11.4) → REFUSED.
        assert_eq!(
            parse_canonical_ledger_genesis_chirho(&format!("{GOLDEN_GENESIS_LINE_CHIRHO}\n")),
            Err(WireErrorChirho::NonCanonicalBytesChirho)
        );
        // A `null` Option (provenance): parses to None, reserializes ABSENT → REFUSED.
        let nulled_chirho = GOLDEN_RECORD1_LINE_CHIRHO.replacen(
            r#""attribution_chirho""#,
            r#""provenance_chirho":null,"attribution_chirho""#,
            1,
        );
        assert_eq!(
            parse_canonical_ledger_record_chirho(&nulled_chirho),
            Err(WireErrorChirho::NonCanonicalBytesChirho)
        );
        // Unknown field → deny_unknown_fields refusal at parse.
        let unknown_chirho = GOLDEN_GENESIS_LINE_CHIRHO.replacen(
            r#""key_id_chirho""#,
            r#""smuggled_chirho":1,"key_id_chirho""#,
            1,
        );
        assert!(matches!(
            parse_canonical_ledger_genesis_chirho(&unknown_chirho),
            Err(WireErrorChirho::MalformedChirho { .. })
        ));
        // Wrong schema tag on a shape-valid line → SCHEMA-FIRST refusal.
        let wrong_tag_chirho = GOLDEN_GENESIS_LINE_CHIRHO
            .replace("ledger-genesis-v1-chirho", "ledger-genesis-v9-chirho");
        assert_eq!(
            parse_canonical_ledger_genesis_chirho(&wrong_tag_chirho),
            Err(WireErrorChirho::SchemaMismatchChirho {
                found_chirho: "ledger-genesis-v9-chirho".into()
            })
        );
        // Wrong format version → typed refusal.
        let wrong_version_chirho = GOLDEN_GENESIS_LINE_CHIRHO.replacen(
            r#""format_version_chirho":1"#,
            r#""format_version_chirho":2"#,
            1,
        );
        assert_eq!(
            parse_canonical_ledger_genesis_chirho(&wrong_version_chirho),
            Err(WireErrorChirho::FormatVersionMismatchChirho { found_chirho: 2 })
        );
        // A RECORD line handed to the GENESIS parser (and vice versa): the genesis type has no
        // prev/legs fields, so cross-type smuggling dies at deny_unknown_fields (biconditional:
        // a genesis structurally CANNOT carry prev or legs).
        assert!(matches!(
            parse_canonical_ledger_genesis_chirho(GOLDEN_RECORD1_LINE_CHIRHO),
            Err(WireErrorChirho::MalformedChirho { .. })
        ));
        assert!(matches!(
            parse_canonical_ledger_record_chirho(GOLDEN_GENESIS_LINE_CHIRHO),
            Err(WireErrorChirho::MalformedChirho { .. })
        ));
        // Fail-closed EMIT: a wrong in-memory tag refuses to become bytes at all.
        let mut bad_emit_chirho = golden_genesis_chirho();
        bad_emit_chirho.schema_chirho = "ledger-record-v1-chirho".into();
        assert!(matches!(
            canonical_ledger_genesis_line_chirho(&bad_emit_chirho),
            Err(WireErrorChirho::SchemaMismatchChirho { .. })
        ));
    }

    /// The CF4 bounded-identifier law: PII-shaped and free-text-shaped identifiers are
    /// unrepresentable at EMIT — and therefore at PARSE via the exact-reserialize law.
    #[test]
    fn bounded_identifier_law_refuses_pii_and_free_text_shapes_chirho() {
        let assert_refuses_chirho = |mutate_chirho: &dyn Fn(&mut LedgerRecordChirho)| {
            let mut record_chirho = golden_record1_chirho();
            mutate_chirho(&mut record_chirho);
            assert!(matches!(
                canonical_ledger_record_line_chirho(&record_chirho),
                Err(WireErrorChirho::UnboundedIdentifierChirho { .. })
            ));
        };
        // Email-shaped owner: the classic PII leak into the permanent money log.
        assert_refuses_chirho(&|record_chirho| {
            record_chirho.legs_chirho[0].account_chirho.owner_chirho =
                "alice@example.com".to_string();
        });
        // Free-text (whitespace) principal.
        assert_refuses_chirho(&|record_chirho| {
            record_chirho.attribution_chirho =
                crate::record_chirho::AttributionChirho::CauserChirho {
                    principal_chirho: "John Smith of Kansas".to_string(),
                };
        });
        // Overlong idempotency key.
        assert_refuses_chirho(&|record_chirho| {
            record_chirho.idempotency_key_chirho = "k".repeat(257);
        });
        // Control character in a kind id.
        assert_refuses_chirho(&|record_chirho| {
            record_chirho.legs_chirho[0].account_chirho.kind_id_chirho.0 =
                "money\u{0}-chirho".to_string();
        });
        // Empty owner.
        assert_refuses_chirho(&|record_chirho| {
            record_chirho.legs_chirho[0].account_chirho.owner_chirho = String::new();
        });
        // The #5212 miss closed: a Timer purpose is an op-variant free string under the SAME law —
        // an email-shaped or multi-word purpose is unrepresentable.
        assert_refuses_chirho(&|record_chirho| {
            record_chirho.op_chirho = crate::record_chirho::LedgerOpChirho::TimerChirho {
                fires_at_hlc_chirho: HlcChirho {
                    physical_ms_chirho: 1,
                    logical_chirho: 0,
                },
                purpose_chirho: "call John at john@x.com about his refund".to_string(),
            };
        });
        // The #5241 miss closed: DigestChirho is a TRANSPARENT String — the type enforces nothing,
        // so digest-CARRIED text rides the same law. Email-shaped provenance:
        assert_refuses_chirho(&|record_chirho| {
            record_chirho.provenance_chirho = Some(DigestChirho("john@example.com".to_string()));
        });
        // Free-text policy-attribution digest:
        assert_refuses_chirho(&|record_chirho| {
            record_chirho.attribution_chirho =
                crate::record_chirho::AttributionChirho::PolicyChirho {
                    policy_ref_chirho: DigestChirho("subsidy policy for John Smith".to_string()),
                };
        });
        // Free-text mint authority-evidence digest:
        assert_refuses_chirho(&|record_chirho| {
            record_chirho.op_chirho = crate::record_chirho::LedgerOpChirho::MintChirho {
                authority_evidence_chirho: DigestChirho("approved by Jane over email".to_string()),
            };
        });
        // Email-shaped key label: label-only means verification never trust-selects by it — which is
        // exactly why an honest root could otherwise sign PII permanently into the log.
        assert_refuses_chirho(&|record_chirho| {
            record_chirho.key_id_chirho = "john@example.com".to_string();
        });
        // Free-text sig label (the encoding-shape check).
        assert_refuses_chirho(&|record_chirho| {
            record_chirho.sig_chirho = "signed by John Smith".to_string();
        });
        // The sign-then-attach ASYMMETRY: the sign-message legitimately predates the sig, so the
        // signed-content emit ACCEPTS an empty sig while the STORED-line emit refuses it.
        let mut presign_chirho = golden_record1_chirho();
        presign_chirho.sig_chirho = String::new();
        ledger_record_signed_content_line_chirho(&presign_chirho).unwrap();
        assert!(matches!(
            canonical_ledger_record_line_chirho(&presign_chirho),
            Err(WireErrorChirho::UnboundedIdentifierChirho {
                field_chirho: "sig_chirho",
                ..
            })
        ));
        // And the GENESIS cluster id under the same law.
        let mut genesis_chirho = golden_genesis_chirho();
        genesis_chirho.cluster_id_chirho.0 = "cluster with spaces".to_string();
        assert!(matches!(
            canonical_ledger_genesis_line_chirho(&genesis_chirho),
            Err(WireErrorChirho::UnboundedIdentifierChirho { .. })
        ));
        // The GENESIS permanent key label too.
        let mut genesis_key_chirho = golden_genesis_chirho();
        genesis_key_chirho.key_id_chirho = "john@example.com".to_string();
        assert!(matches!(
            canonical_ledger_genesis_line_chirho(&genesis_key_chirho),
            Err(WireErrorChirho::UnboundedIdentifierChirho { .. })
        ));
        // PARSE inherits the law: a hand-crafted line carrying an email-shaped owner refuses even
        // though it is well-formed JSON (the exact-reserialize route runs the same validation).
        let honest_line_chirho =
            canonical_ledger_record_line_chirho(&golden_record1_chirho()).unwrap();
        let poisoned_line_chirho = honest_line_chirho.replace("alice-chirho", "alice@evil.com");
        assert!(parse_canonical_ledger_record_chirho(&poisoned_line_chirho).is_err());
        // Poisoned-parse twins for the digest law: these lines are VALID JSON that reserializes
        // byte-identically, so before #5241 they PARSED — only the bounds walk refuses them, and
        // the exact variant proves it is the walk (not the byte-compare) doing the refusing.
        let honest_line2_chirho =
            canonical_ledger_record_line_chirho(&golden_record2_chirho()).unwrap();
        let poisoned_provenance_chirho =
            honest_line2_chirho.replace("provenance-golden-chirho", "john@evil.example");
        assert!(matches!(
            parse_canonical_ledger_record_chirho(&poisoned_provenance_chirho),
            Err(WireErrorChirho::UnboundedIdentifierChirho { .. })
        ));
        let poisoned_key_id_chirho =
            honest_line2_chirho.replace("journal-key-2-chirho", "leak@example.com");
        assert!(matches!(
            parse_canonical_ledger_record_chirho(&poisoned_key_id_chirho),
            Err(WireErrorChirho::UnboundedIdentifierChirho { .. })
        ));
        // The reserved CF3 namespaces stay representable (prefix + 64 hex fits the key cap).
        let mut reserved_chirho = golden_record1_chirho();
        reserved_chirho.idempotency_key_chirho =
            format!("cf3-intent-v1-chirho:{}", "ab".repeat(32));
        canonical_ledger_record_line_chirho(&reserved_chirho).unwrap();
    }
}
