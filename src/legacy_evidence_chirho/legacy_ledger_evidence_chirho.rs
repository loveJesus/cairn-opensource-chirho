// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only legacy ledger evidence: load the historical signed double-entry log, and verify it.
//!
//! CF6-D2 brick (a2-0). This is the shared money-integrity core that `verify_ledger_chirho`,
//! `verify_credit_holds_chirho` and the three `verify_billing_*` entry points all reach — money
//! conservation, the signed-message construction, the schema and canonical-v2 decode rules, and the
//! J0a authority-inert gate. It is extracted out of `src/economic_flows_chirho` so that reading and
//! AUTHENTICATING historical ledger evidence survives that directory's deletion.
//!
//! **Why the shared core moved before the three families.** Slicing by family would have either
//! duplicated this code three ways or made whichever family went first drag it along uncredited —
//! and it is where the risk actually lives. The seam that hides risk is the shared one, not the
//! family boundary.
//!
//! **This module must never depend on the spine.** It imports the model crate, the signing crate,
//! `anyhow` and `std` — nothing from `src/economic_flows_chirho`. The spine re-exports back from
//! here during the transition, and that direction dies with the spine. It reaches
//! `cairn_signer_chirho` DIRECTLY rather than through root's `effect_chirho`, whose two
//! verification functions are one-line delegates to exactly these.
//!
//! **What deliberately did NOT come along:** `verified_entries_chirho`, the wrapper that branches
//! through the Gate-1 authority-stream path. That branch is dual-write-era vestige scheduled to die
//! with the spine, so carrying it here would drag gate1 machinery into the module whose whole
//! purpose is to be the clean retained thing. The old road — load, then verify — is gate1-free and
//! is what remains.
//!
//! Pinned by `legacy_ledger_characterization_tests_chirho` (11 arms, mutation-proven 6/6 before the
//! move). Those arms live outside `src/economic_flows_chirho` on purpose: the ledger's own test
//! module is inside the delete scope, so its money pins protect this move and then die.

use crate::economic_model_chirho::{
    AssetChirho, BillingTagsChirho, LedgerEntryChirho, OpBindingChirho, PostingChirho,
    LEDGER_ENTRY_SCHEMA_CHIRHO, LEDGER_ENTRY_SCHEMA_V2_CHIRHO,
};
use crate::legacy_single_road_probe_chirho::refuse_if_gate1_authority_branch_present_chirho;
use anyhow::{bail, Result};
use cairn_signer_chirho::signer_chirho;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(crate) fn ledger_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("ledger-chirho.jsonl")
}

/// The deterministic message signed for an entry (seq + time + memo + each posting).
pub(crate) fn entry_message_chirho(
    seq_chirho: u64,
    memo_chirho: &str,
    postings_chirho: &[PostingChirho],
    at_ms_chirho: u64,
) -> String {
    let mut message_chirho = format!("{seq_chirho}|{at_ms_chirho}|{memo_chirho}");
    for posting_chirho in postings_chirho {
        message_chirho.push_str(&format!(
            "|{}:{:?}:{}",
            posting_chirho.account_chirho,
            posting_chirho.asset_chirho,
            posting_chirho.amount_chirho
        ));
    }
    message_chirho
}

pub(crate) fn entry_signature_message_chirho(
    seq_chirho: u64,
    schema_chirho: &str,
    memo_chirho: &str,
    postings_chirho: &[PostingChirho],
    billing_tags_chirho: &BillingTagsChirho,
    at_ms_chirho: u64,
    op_binding_chirho: Option<&OpBindingChirho>,
) -> Result<Vec<u8>> {
    // Schema-v2: an INJECTIVE, typed signed message. It serializes seq/at_ms/memo/postings as typed
    // JSON fields (memo as an escaped string, postings as a typed array) rather than wrapping the
    // delimiter-concatenated legacy string — otherwise an unframed memo/account could reproduce the
    // same bytes as a different balanced posting set. Distinct from every legacy shape (op_binding
    // present). Returns early so v1 rows keep their exact legacy message bytes below, unchanged.
    if let Some(op_binding_chirho) = op_binding_chirho {
        #[derive(Serialize)]
        struct V2EntryMessageChirho<'a> {
            schema_chirho: &'a str,
            seq_chirho: u64,
            at_ms_chirho: u64,
            memo_chirho: &'a str,
            postings_chirho: &'a [PostingChirho],
            billing_tags_chirho: &'a BillingTagsChirho,
            op_binding_chirho: &'a OpBindingChirho,
        }
        return Ok(serde_json::to_vec(&V2EntryMessageChirho {
            schema_chirho,
            seq_chirho,
            at_ms_chirho,
            memo_chirho,
            postings_chirho,
            billing_tags_chirho,
            op_binding_chirho,
        })?);
    }
    let legacy_message_chirho =
        entry_message_chirho(seq_chirho, memo_chirho, postings_chirho, at_ms_chirho);
    if billing_tags_chirho.is_empty_chirho() {
        if schema_chirho.is_empty() {
            return Ok(legacy_message_chirho.into_bytes());
        }
        #[derive(Serialize)]
        struct SchemaEntryMessageChirho<'a> {
            legacy_message_chirho: String,
            schema_chirho: &'a str,
        }
        return Ok(serde_json::to_vec(&SchemaEntryMessageChirho {
            legacy_message_chirho,
            schema_chirho,
        })?);
    }
    if !schema_chirho.is_empty() {
        #[derive(Serialize)]
        struct SchemaTaggedEntryMessageChirho<'a> {
            legacy_message_chirho: String,
            schema_chirho: &'a str,
            billing_tags_chirho: &'a BillingTagsChirho,
        }
        return Ok(serde_json::to_vec(&SchemaTaggedEntryMessageChirho {
            legacy_message_chirho,
            schema_chirho,
            billing_tags_chirho,
        })?);
    }
    #[derive(Serialize)]
    struct TaggedEntryMessageChirho<'a> {
        legacy_message_chirho: String,
        billing_tags_chirho: &'a BillingTagsChirho,
    }
    Ok(serde_json::to_vec(&TaggedEntryMessageChirho {
        legacy_message_chirho,
        billing_tags_chirho,
    })?)
}

/// Balanced ⇔ for every asset, the signed amounts sum to 0 (debits == credits).
pub(crate) fn assert_balanced_chirho(postings_chirho: &[PostingChirho]) -> Result<()> {
    if postings_chirho.is_empty() {
        bail!("a ledger entry needs at least one posting");
    }
    // Accumulate per asset in i128 so conservation is EXACT and ORDER-INDEPENDENT for any sequence
    // of i64 postings: a legitimately balanced entry never false-rejects even when a partial i64 sum
    // would overflow mid-fold (e.g. [i64::MAX, 1, -i64::MAX, -1]), while a crafted same-sign set
    // whose true sum is 2^64 stays nonzero instead of wrapping to a false zero and minting value.
    let mut sums_chirho: BTreeMap<AssetChirho, i128> = BTreeMap::new();
    for posting_chirho in postings_chirho {
        let sum_chirho = sums_chirho.entry(posting_chirho.asset_chirho).or_insert(0);
        match sum_chirho.checked_add(posting_chirho.amount_chirho as i128) {
            Some(next_chirho) => *sum_chirho = next_chirho,
            None => bail!(
                "ledger entry {:?} posting sum overflows i128 (rejecting malformed entry)",
                posting_chirho.asset_chirho
            ),
        }
    }
    for (asset_chirho, sum_chirho) in &sums_chirho {
        if *sum_chirho != 0 {
            bail!("unbalanced entry: {asset_chirho:?} sums to {sum_chirho} (debits must equal credits)");
        }
    }
    Ok(())
}

pub(crate) fn verify_ledger_entry_schema_chirho(schema_chirho: &str) -> Result<()> {
    // v1 (or the legacy empty label) and v2 are the KNOWN schemas; anything else is unsupported.
    // v2 being known does not make it accepted — the authority-inert gate below rejects it.
    if !schema_chirho.is_empty()
        && schema_chirho != LEDGER_ENTRY_SCHEMA_CHIRHO
        && schema_chirho != LEDGER_ENTRY_SCHEMA_V2_CHIRHO
    {
        bail!("unsupported ledger entry schema '{schema_chirho}'");
    }
    Ok(())
}

/// The canonical v2 decode rule: a schema-v2 ledger line MUST be byte-canonical — exactly
/// `serde_json::to_string(entry_chirho)`. This single v2-only check rejects, at EVERY depth, any
/// unknown field (including inside the legacy-permissive `BillingTagsChirho`/`PostingChirho` shapes),
/// any missing defaulted key, duplicate-key last-wins ambiguity, alternate key order, and
/// noncanonical whitespace/spelling — so a v2 row can never parse-and-drop. v1/legacy rows stay
/// exempt (permissive, byte-preserving), so this changes no legacy semantics.
pub(crate) fn require_canonical_v2_line_chirho(
    entry_chirho: &LedgerEntryChirho,
    line_chirho: &str,
) -> Result<()> {
    let is_v2_chirho = entry_chirho.schema_chirho == LEDGER_ENTRY_SCHEMA_V2_CHIRHO
        || entry_chirho.op_binding_chirho.is_some();
    if !is_v2_chirho {
        return Ok(());
    }
    let canonical_chirho = serde_json::to_string(entry_chirho)?;
    if line_chirho != canonical_chirho {
        bail!(
            "schema-v2 ledger line {} is not byte-canonical (canonical v2 decode rejects parse-and-drop, reorder, or noncanonical bytes)",
            entry_chirho.seq_chirho
        );
    }
    Ok(())
}

/// The J0a schema-v2 authority gate, enforced on every authoritative read of a ledger entry.
///
/// It enforces the schema/op_binding BICONDITIONAL in both directions (schema-v2 ⟺ `op_binding`
/// present; v1/legacy ⟺ absent), shape-validates any v2 binding, and then FAILS CLOSED on v2:
/// schema-v2 money authority is INACTIVE in this build (J0a is authority-inert; J0b activates it).
/// A root-signed, shape-valid v2 row therefore moves zero money.
///
/// Part of the W3 brick-1 money protocol (`spec-chirho/workflows-chirho/perf-chirho/
/// w3-financials-brick1-design-chirho.md`, job J0a).
pub(crate) fn validate_ledger_entry_v2_gate_chirho(entry_chirho: &LedgerEntryChirho) -> Result<()> {
    let is_v2_schema_chirho = entry_chirho.schema_chirho == LEDGER_ENTRY_SCHEMA_V2_CHIRHO;
    if is_v2_schema_chirho != entry_chirho.op_binding_chirho.is_some() {
        bail!(
            "ledger entry {} violates the schema/op_binding biconditional (schema-v2 ⟺ op_binding present)",
            entry_chirho.seq_chirho
        );
    }
    if let Some(op_binding_chirho) = &entry_chirho.op_binding_chirho {
        op_binding_chirho
            .validate_shape_chirho()
            .map_err(|error_chirho| {
                anyhow::anyhow!(
                    "ledger entry {} has an invalid schema-v2 op binding: {error_chirho:?}",
                    entry_chirho.seq_chirho
                )
            })?;
        bail!(
            "ledger entry {} is schema-v2; v2 money authority is INACTIVE in this build (J0a authority-inert)",
            entry_chirho.seq_chirho
        );
    }
    Ok(())
}

pub fn load_entries_chirho(root_chirho: &Path) -> Result<Vec<LedgerEntryChirho>> {
    let path_chirho = ledger_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)?;
    let mut out_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let entry_chirho: LedgerEntryChirho = serde_json::from_str(line_chirho)
            .map_err(|e_chirho| anyhow::anyhow!("bad ledger line: {e_chirho}"))?;
        verify_ledger_entry_schema_chirho(&entry_chirho.schema_chirho)?;
        require_canonical_v2_line_chirho(&entry_chirho, line_chirho)?;
        validate_ledger_entry_v2_gate_chirho(&entry_chirho)?;
        out_chirho.push(entry_chirho);
    }
    Ok(out_chirho)
}

pub(crate) fn verify_entries_chirho(
    root_chirho: &Path,
    entries_chirho: &[LedgerEntryChirho],
) -> Result<()> {
    if entries_chirho.is_empty() {
        return Ok(());
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (i_chirho, entry_chirho) in entries_chirho.iter().enumerate() {
        if entry_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "seq gap at index {i_chirho}: entry seq is {}",
                entry_chirho.seq_chirho
            );
        }
        // J0a authority-inert gate: enforce the schema/op_binding biconditional and reject any v2
        // row before it can influence a money decision (this covers the Gate-1 authority-stream
        // path, whose entries never pass through `load_entries_chirho`).
        validate_ledger_entry_v2_gate_chirho(entry_chirho)?;
        assert_balanced_chirho(&entry_chirho.postings_chirho)?;
        let message_chirho = entry_signature_message_chirho(
            entry_chirho.seq_chirho,
            &entry_chirho.schema_chirho,
            &entry_chirho.memo_chirho,
            &entry_chirho.postings_chirho,
            &entry_chirho.billing_tags_chirho,
            entry_chirho.at_ms_chirho,
            entry_chirho.op_binding_chirho.as_ref(),
        )?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &entry_chirho.sig_chirho,
        )? {
            bail!(
                "entry {} signature invalid (tampered?)",
                entry_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

pub(crate) fn verified_entries_old_road_chirho(
    root_chirho: &Path,
) -> Result<Vec<LedgerEntryChirho>> {
    let entries_chirho = load_entries_chirho(root_chirho)?;
    verify_entries_chirho(root_chirho, &entries_chirho)?;
    Ok(entries_chirho)
}

/// The verified ledger read for consumers that must outlive the spine: probe, then the old road.
///
/// Named `single_road` because that is its ASSUMPTION, and
/// [`refuse_if_gate1_authority_branch_present_chirho`] is what enforces it rather than leaving it
/// hoped-for.
pub fn verified_entries_single_road_chirho(root_chirho: &Path) -> Result<Vec<LedgerEntryChirho>> {
    refuse_if_gate1_authority_branch_present_chirho(root_chirho)?;
    verified_entries_old_road_chirho(root_chirho)
}

/// Verify the whole ledger and report how many entries were authenticated.
///
/// Reached by the CLI, `ops_restore_drill_chirho`, and `data_rights_chirho` -- the SUBJECT EXPORT
/// path. It returns a COUNT rather than a unit so a caller can distinguish "verified nothing" from
/// "verified something"; an `is_ok()` check would treat an empty root as success.
pub fn verify_ledger_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(verified_entries_single_road_chirho(root_chirho)?.len())
}

/// Balances folded from AUTHENTICATED entries.
///
/// Distinct from [`balances_chirho`] in GUARANTEE, not in shape: this refuses evidence whose
/// signatures do not check out, and that one does not look at signatures at all.
pub fn verified_balances_chirho(
    root_chirho: &Path,
) -> Result<BTreeMap<(String, AssetChirho), i64>> {
    balances_from_entries_chirho(&verified_entries_single_road_chirho(root_chirho)?)
}

/// One account's token balance, read through the VERIFIED fold.
pub fn verified_gas_balance_chirho(root_chirho: &Path, account_chirho: &str) -> Result<i64> {
    Ok(verified_balances_chirho(root_chirho)?
        .get(&(account_chirho.to_string(), AssetChirho::TokenChirho))
        .copied()
        .unwrap_or(0))
}

/// Balances folded from LOADED entries, with NO signature check and NO gate-1 probe.
///
/// **The missing probe is deliberate and must stay missing.** This family carries a different
/// guarantee -- it authenticates nothing -- so letting it inherit the probe would blur which
/// promise each family makes rather than strengthen this one. A caller that needs authenticated
/// evidence calls [`verified_balances_chirho`]; a caller that needs a cheap unverified view calls
/// this and is on notice by its name.
///
/// Noted because it is easy to misread as an oversight: this pair ALREADY bypassed the gate-1
/// dispatcher before brick (a2-1), so on a flipped root it has always answered from the JSONL while
/// the verified family answered from the stream. That divergence is older than this brick and is
/// latent only because the pair has no production consumer outside the deleting spine.
pub fn balances_chirho(root_chirho: &Path) -> Result<BTreeMap<(String, AssetChirho), i64>> {
    balances_from_entries_chirho(&load_entries_chirho(root_chirho)?)
}

/// One account's token balance, read through the UNVERIFIED fold. See [`balances_chirho`].
pub fn gas_balance_chirho(root_chirho: &Path, account_chirho: &str) -> Result<i64> {
    Ok(balances_chirho(root_chirho)?
        .get(&(account_chirho.to_string(), AssetChirho::TokenChirho))
        .copied()
        .unwrap_or(0))
}

/// Fold entries into per-(account, asset) balances, REFUSING rather than wrapping on overflow.
///
/// Accumulates in i128 and converts back on exit, exactly like [`assert_balanced_chirho`] — which is
/// the point. That function guards each entry's per-asset sums with checked i128 arithmetic so a
/// crafted posting set cannot wrap to a false zero and mint value; this one folds the SAME money
/// ACROSS entries and used plain `+=` on i64, so two individually-clean entries could push one pair
/// past `i64::MAX`. Under dev that panicked the evidence read; under release, where this workspace
/// sets no `overflow-checks`, it wrapped SILENTLY and misreported a balance to [`balances_chirho`],
/// [`verified_balances_chirho`], [`gas_balance_chirho`], and `assert_balance_requirements_chirho` —
/// the min-balance spend guard.
///
/// Found by the second seat's independently-selected review arm, not by the mover's own pins.
/// Reaching it needs root-SIGNED entries, so this is robustness parity rather than privilege
/// escalation; the fold should still refuse like its sibling instead of panicking or wrapping.
pub(crate) fn balances_from_entries_chirho(
    entries_chirho: &[LedgerEntryChirho],
) -> Result<BTreeMap<(String, AssetChirho), i64>> {
    let mut wide_chirho: BTreeMap<(String, AssetChirho), i128> = BTreeMap::new();
    for entry_chirho in entries_chirho {
        for posting_chirho in &entry_chirho.postings_chirho {
            let key_chirho = (
                posting_chirho.account_chirho.clone(),
                posting_chirho.asset_chirho,
            );
            let running_chirho = wide_chirho.entry(key_chirho).or_insert(0);
            match running_chirho.checked_add(posting_chirho.amount_chirho as i128) {
                Some(next_chirho) => *running_chirho = next_chirho,
                None => bail!(
                    "balance fold for '{}' {:?} overflows i128 (rejecting malformed history)",
                    posting_chirho.account_chirho,
                    posting_chirho.asset_chirho
                ),
            }
        }
    }
    let mut balances_chirho: BTreeMap<(String, AssetChirho), i64> = BTreeMap::new();
    for (key_chirho, wide_total_chirho) in wide_chirho {
        let total_chirho = i64::try_from(wide_total_chirho).map_err(|_| {
            anyhow::anyhow!(
                "balance for '{}' {:?} leaves i64 range at {wide_total_chirho} (refusing rather \
                 than wrapping: a wrapped balance would misreport money and could satisfy a \
                 min-balance spend guard it should fail)",
                key_chirho.0,
                key_chirho.1
            )
        })?;
        balances_chirho.insert(key_chirho, total_chirho);
    }
    Ok(balances_chirho)
}
