// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Verifies credit-hold evidence: authenticates each signed record and binds it to the ledger
//! entries it names, independently of which authority road wrote it.
//!
//! **CF6-D2 brick (a2-2): the RETAINED half of the credit-hold verifier.** Reading and
//! AUTHENTICATING historical hold evidence has to outlive `src/economic_flows_chirho`, because kept
//! consumers -- subject exports and compliance source snapshots -- disclose hold state from roots
//! written before the deletion. What stayed behind is the two-road dispatcher
//! (`verified_credit_hold_states_chirho`, `verify_credit_holds_chirho`), which is gate-1 aware and
//! dies with the spine; everything here takes records and ledger entries as PARAMETERS and is
//! therefore road-agnostic by construction. Brick (a2-0) made the identical cut for the ledger.
//!
//! Pinned by `legacy_holds_characterization_tests_chirho`, whose eleven arms had to stay green
//! through this move WITHOUT being edited -- that, rather than the diff, is what makes it a
//! relocation.
//!
//! **Reaches `cairn_signer_chirho` directly, not root's `effect_chirho`** (2026-07-26), matching
//! [`legacy_ledger_evidence_chirho`], whose header already stated the reason: those verification and
//! signing functions are one-line delegates to exactly these. Going through the delegate made this
//! module depend on `src/execution_runtime_chirho` for crypto that does not live there -- an accident
//! of where a re-export sits, not a real dependency. Removing it took the whole production
//! legacy_evidence -> execution_runtime edge to zero, which is what breaks that pillar cycle.

use crate::economic_model_chirho::{
    AssetChirho, BillingTagsChirho, CreditHoldRecordChirho, CreditHoldStatusChirho,
    LedgerEntryChirho,
};
use cairn_signer_chirho::signer_chirho;
// Brick (a1) put the schema check in the other retained module; both are retained, so this is a
// retained -> retained edge and does not reintroduce a dependency on the deleting spine.
use crate::legacy_evidence_readers_chirho::validate_hold_record_schema_chirho;
use anyhow::{anyhow, bail, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// The write-side reserve input. It lives here rather than with the writer because
/// `validate_hold_record_chirho` reconstructs one from a stored record to reuse the SAME field
/// validation on read that the writer applied -- so the type is part of the evidence contract, and
/// the spine re-exports it so every write-side call site is unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditHoldInputChirho {
    pub hold_id_chirho: String,
    pub app_chirho: String,
    pub effect_chirho: String,
    pub caller_chirho: String,
    pub payer_chirho: String,
    pub authorized_token_chirho: i64,
    pub billing_tags_chirho: BillingTagsChirho,
}

pub(crate) fn validate_hold_input_chirho(input_chirho: &CreditHoldInputChirho) -> Result<()> {
    if input_chirho.hold_id_chirho.trim().is_empty() {
        bail!("hold_id_chirho is required");
    }
    if input_chirho.app_chirho.trim().is_empty() {
        bail!("app_chirho is required");
    }
    if input_chirho.effect_chirho.trim().is_empty() {
        bail!("effect_chirho is required");
    }
    if input_chirho.caller_chirho.trim().is_empty() {
        bail!("caller_chirho is required");
    }
    if input_chirho.payer_chirho.trim().is_empty() {
        bail!("payer_chirho is required");
    }
    if input_chirho.authorized_token_chirho <= 0 {
        bail!("authorized_token_chirho must be positive");
    }
    input_chirho.billing_tags_chirho.validate_chirho()?;
    Ok(())
}

/// The verified-state shape every hold consumer reads: how many records were verified, and the
/// open/terminal record pair for each hold id.
pub type VerifiedCreditHoldStatesChirho = (
    usize,
    BTreeMap<String, (CreditHoldRecordChirho, Option<CreditHoldRecordChirho>)>,
);

pub(crate) fn verified_credit_hold_states_from_records_chirho(
    root_chirho: &Path,
    records_chirho: &[CreditHoldRecordChirho],
    ledger_entries_chirho: &[LedgerEntryChirho],
) -> Result<VerifiedCreditHoldStatesChirho> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut by_hold_chirho: BTreeMap<String, Vec<&CreditHoldRecordChirho>> = BTreeMap::new();
    // THE VERIFY SIDE of the deliberate asymmetry documented on `load_credit_holds_chirho`:
    // sequence continuity is asserted HERE and must NOT migrate into the loader, because an export
    // has to be able to read a damaged log in order to disclose it.
    //
    // Check order is load-bearing and measured: seq -> per-record validation (money conservation)
    // -> signature -> cross-record pairing. Conservation therefore refuses BEFORE authenticity.
    //
    // ** OPEN QUESTION, RAISED 2026-07-25, NOT RULED ON. ** This order INTERPRETS BEFORE IT
    // AUTHENTICATES: record contents -- amounts, conservation, terminal state -- are evaluated on
    // bytes not yet proven authentic. The usual rule is the reverse, because every validation path
    // run on unauthenticated input is attack surface the signature check was meant to make
    // unreachable.
    //
    // THIS IS A CONSISTENCY QUESTION AGAINST CAIRN'S OWN RULE, not generic security advice (second
    // seat's framing, and it is the right one). M142 established that runtime code verifies
    // content-addressed reads across the CAS, typed store, WASM DAG loads, and portable store/audit
    // adapters BEFORE IT TRUSTS RETURNED BYTES OR RECORDS. The same principle applied here wants
    // signature-first -- and the function departing from it is the one whose job IS verification.
    // So whoever rules is being asked for consistency with an existing decision rather than for a
    // new judgment.
    //
    // NOT asserted to be a vulnerability. All checks must pass, so the final VERDICT is unaffected,
    // and failing fast on cheap checks before expensive crypto is a normal deliberate design. The
    // problem is that NOBODY HAS DECIDED IT: two seats both believed signature-first until the order
    // was measured, so the current order was assumed rather than chosen.
    //
    // MEASURED CONTEXT for whoever rules:
    //   - Reachability: NOT reachable from any served route. Callers are the CLI, compliance
    //     `source_snapshots_chirho`, and `data_rights_chirho` (SUBJECT EXPORT). So a forged record
    //     requires local write access to the root's log, not a remote request.
    //     BUT DO NOT LET "LOCAL ONLY" CLOSE THIS. The artifact at the end of the pipeline is a
    //     document produced FOR a data subject and possibly relied on by them or a regulator, and
    //     these records are signed PRECISELY SO ITS INTEGRITY DOES NOT REST ON HOST SECURITY.
    //     Requiring local write access is therefore a weaker mitigation here than it would be for an
    //     internal tool: defending against exactly that is what the signatures are for.
    //   - Error text: the conservation refusal NAMES THE AMOUNTS from an unverified record, and that
    //     text reaches evidence surfaces. Given cairn's scrubbing discipline elsewhere, unverified
    //     attacker-supplied numbers in error text deserve a look.
    //   - Oracle: distinct refusals for "bad maths" and "bad signature" tell a local attacker which
    //     forgeries would have been conservation-valid. Small, and bounded by the reachability above.
    //
    // Deliberately NOT resolved here by inventing a rationale: a money-path ordering wants a stated
    // reason from someone with the authority to give one, and "it has always been this way" is not
    // one. Pinned meanwhile by the characterization tests, which record the behaviour without
    // blessing it.
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "credit hold seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_hold_record_chirho(record_chirho)?;
        let message_chirho = hold_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "credit hold record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        by_hold_chirho
            .entry(record_chirho.hold_id_chirho.clone())
            .or_default()
            .push(record_chirho);
    }
    let mut states_chirho = BTreeMap::new();
    for (hold_id_chirho, records_for_hold_chirho) in by_hold_chirho {
        let open_records_chirho: Vec<_> = records_for_hold_chirho
            .iter()
            .copied()
            .filter(|record_chirho| {
                record_chirho.status_chirho == CreditHoldStatusChirho::OpenChirho
            })
            .collect();
        if open_records_chirho.len() != 1 {
            bail!(
                "credit hold '{hold_id_chirho}' must have exactly one open record, found {}",
                open_records_chirho.len()
            );
        }
        let open_chirho = open_records_chirho[0];
        verify_reserve_entry_chirho(open_chirho, ledger_entries_chirho)?;
        let terminal_records_chirho: Vec<_> = records_for_hold_chirho
            .iter()
            .copied()
            .filter(|record_chirho| {
                record_chirho.status_chirho != CreditHoldStatusChirho::OpenChirho
            })
            .collect();
        if terminal_records_chirho.len() > 1 {
            bail!(
                "credit hold '{hold_id_chirho}' has {} terminal records",
                terminal_records_chirho.len()
            );
        }
        let terminal_chirho = terminal_records_chirho.first().copied();
        if let Some(terminal_chirho) = terminal_chirho {
            verify_terminal_matches_open_chirho(open_chirho, terminal_chirho)?;
            if terminal_chirho.status_chirho == CreditHoldStatusChirho::SettledChirho {
                verify_settlement_entry_chirho(terminal_chirho, ledger_entries_chirho)?;
            } else {
                verify_release_entry_chirho(terminal_chirho, ledger_entries_chirho)?;
            }
        }
        states_chirho.insert(
            hold_id_chirho,
            (open_chirho.clone(), terminal_chirho.cloned()),
        );
    }
    assert_terminal_hold_accounts_drained_chirho(&states_chirho, ledger_entries_chirho)?;
    Ok((records_chirho.len(), states_chirho))
}

/// Every TERMINAL hold's account must reconcile to zero across the whole ledger.
///
/// # Why this exists, and why it is stated about MONEY rather than about postings
///
/// The three binders above ask whether an entry CONTAINS a posting of the right amount --
/// `require_posting_chirho` matches a component with `.any()` and never computes an account's net,
/// while `assert_balanced_chirho` keys conservation on ASSET ONLY, so two postings for one account
/// in one entry are conservation-legal. A settlement that drains the hold account and immediately
/// credits it back therefore satisfies every earlier check: balanced, signed, and containing the
/// required drain -- while the hold account never actually empties. The money is then stranded in a
/// TERMINAL hold's account, which nothing will ever release. Found by claude_chirho from an
/// independent read and executed as
/// `a_settlement_entry_that_cancels_its_own_drain_verifies_clean_chirho`.
///
/// Fixing it inside `require_posting_chirho` would have replaced one encoding-shaped rule with
/// another. This asks the question the binding actually means: is the account EMPTY.
///
/// # Scope, and why each bound is where it is
///
/// - **Terminal holds only.** An OPEN hold's account legitimately carries `+authorized` between
///   reserve and settlement, so a blanket rule would refuse every open hold.
/// - **The WHOLE ledger, not just the entries the hold names.** The account name is
///   `platform/credit-hold/<hold_id>` and is therefore derivable, so an entry the hold does not name
///   could credit it. Netting only the named entries would state a property about bookkeeping;
///   netting the ledger states one about money.
/// - **Every asset, not only tokens.** The hold flow is token-only, so a non-token residue on a hold
///   account is precisely the kind of thing no other check is looking for.
/// - **`i128` accumulation.** Same reason `balances_from_entries_chirho` was hardened: an `i64` fold
///   over adversarial postings can wrap to a false zero, and a false zero here reads as "drained".
///
/// # Cost
///
/// One pass over the entries, accumulating only for the terminal hold accounts, so it is
/// O(entries x postings) with O(terminal holds) memory -- never O(holds x entries). The pass is
/// dominated by the caller's own work: producing this slice verifies a signature per entry, which is
/// orders of magnitude more expensive than the arithmetic here. No serve-path caller reaches this
/// function; its callers are the CLI, compliance source snapshots, and subject export.
fn assert_terminal_hold_accounts_drained_chirho(
    states_chirho: &BTreeMap<String, (CreditHoldRecordChirho, Option<CreditHoldRecordChirho>)>,
    ledger_entries_chirho: &[LedgerEntryChirho],
) -> Result<()> {
    let mut watched_chirho: BTreeMap<&str, &str> = BTreeMap::new();
    for (hold_id_chirho, (open_chirho, terminal_chirho)) in states_chirho {
        if terminal_chirho.is_some() {
            watched_chirho.insert(open_chirho.hold_account_chirho.as_str(), hold_id_chirho);
        }
    }
    if watched_chirho.is_empty() {
        return Ok(());
    }
    let mut nets_chirho: BTreeMap<(&str, AssetChirho), i128> = BTreeMap::new();
    for entry_chirho in ledger_entries_chirho {
        for posting_chirho in &entry_chirho.postings_chirho {
            let Some((account_chirho, _)) = watched_chirho
                .get_key_value(posting_chirho.account_chirho.as_str())
                .map(|(account_chirho, hold_chirho)| (*account_chirho, *hold_chirho))
            else {
                continue;
            };
            let net_chirho = nets_chirho
                .entry((account_chirho, posting_chirho.asset_chirho))
                .or_insert(0);
            match net_chirho.checked_add(posting_chirho.amount_chirho as i128) {
                Some(next_chirho) => *net_chirho = next_chirho,
                None => bail!(
                    "credit hold account net overflows i128 (rejecting malformed ledger evidence)"
                ),
            }
        }
    }
    for ((account_chirho, asset_chirho), net_chirho) in &nets_chirho {
        if *net_chirho != 0 {
            // NOTE: this refusal names an amount taken from records not yet proven authentic, and
            // that text reaches evidence surfaces. That is not a new exposure -- it is a NEW
            // INSTANCE of the open question already recorded on the check order above, and it is
            // recorded here rather than treated as settled.
            let hold_id_chirho = watched_chirho
                .get(account_chirho)
                .copied()
                .unwrap_or("unknown");
            bail!(
                "terminal credit hold '{hold_id_chirho}' does not reconcile to zero: account \
                 '{account_chirho}' still holds {net_chirho} {asset_chirho:?} after settlement"
            );
        }
    }
    Ok(())
}

fn verify_terminal_matches_open_chirho(
    open_chirho: &CreditHoldRecordChirho,
    terminal_chirho: &CreditHoldRecordChirho,
) -> Result<()> {
    if open_chirho.hold_account_chirho != terminal_chirho.hold_account_chirho
        || open_chirho.app_chirho != terminal_chirho.app_chirho
        || open_chirho.effect_chirho != terminal_chirho.effect_chirho
        || open_chirho.caller_chirho != terminal_chirho.caller_chirho
        || open_chirho.payer_chirho != terminal_chirho.payer_chirho
        || open_chirho.authorized_token_chirho != terminal_chirho.authorized_token_chirho
        || open_chirho.reserve_ledger_seq_chirho != terminal_chirho.reserve_ledger_seq_chirho
        || open_chirho.billing_tags_chirho != terminal_chirho.billing_tags_chirho
    {
        bail!(
            "credit hold '{}' terminal record does not match its open record",
            open_chirho.hold_id_chirho
        );
    }
    Ok(())
}

pub(crate) fn validate_terminal_amounts_chirho(
    authorized_token_chirho: i64,
    settled_token_chirho: i64,
    released_token_chirho: i64,
) -> Result<()> {
    if settled_token_chirho < 0 || released_token_chirho < 0 {
        bail!("credit hold terminal amounts must be non-negative");
    }
    let total_chirho = settled_token_chirho
        .checked_add(released_token_chirho)
        .ok_or_else(|| anyhow!("credit hold terminal amount overflow"))?;
    if authorized_token_chirho != total_chirho {
        bail!(
            "credit hold terminal amounts settle/release {total_chirho}, not authorized {authorized_token_chirho}"
        );
    }
    Ok(())
}

pub(crate) fn validate_hold_record_chirho(record_chirho: &CreditHoldRecordChirho) -> Result<()> {
    validate_hold_record_schema_chirho(record_chirho)?;
    validate_hold_input_chirho(&CreditHoldInputChirho {
        hold_id_chirho: record_chirho.hold_id_chirho.clone(),
        app_chirho: record_chirho.app_chirho.clone(),
        effect_chirho: record_chirho.effect_chirho.clone(),
        caller_chirho: record_chirho.caller_chirho.clone(),
        payer_chirho: record_chirho.payer_chirho.clone(),
        authorized_token_chirho: record_chirho.authorized_token_chirho,
        billing_tags_chirho: record_chirho.billing_tags_chirho.clone(),
    })?;
    match record_chirho.status_chirho {
        CreditHoldStatusChirho::OpenChirho => {
            if record_chirho.settled_token_chirho != 0
                || record_chirho.released_token_chirho != 0
                || record_chirho.settlement_ledger_seq_chirho.is_some()
                || record_chirho.release_ledger_seq_chirho.is_some()
            {
                bail!(
                    "open credit hold '{}' carries terminal fields",
                    record_chirho.hold_id_chirho
                );
            }
        }
        CreditHoldStatusChirho::SettledChirho => {
            validate_terminal_amounts_chirho(
                record_chirho.authorized_token_chirho,
                record_chirho.settled_token_chirho,
                record_chirho.released_token_chirho,
            )?;
            if record_chirho.settlement_ledger_seq_chirho.is_none()
                || record_chirho.release_ledger_seq_chirho.is_some()
            {
                bail!(
                    "settled credit hold '{}' has invalid ledger refs",
                    record_chirho.hold_id_chirho
                );
            }
        }
        CreditHoldStatusChirho::ReleasedChirho => {
            validate_terminal_amounts_chirho(
                record_chirho.authorized_token_chirho,
                record_chirho.settled_token_chirho,
                record_chirho.released_token_chirho,
            )?;
            if record_chirho.settled_token_chirho != 0
                || record_chirho.release_ledger_seq_chirho.is_none()
                || record_chirho.settlement_ledger_seq_chirho.is_some()
            {
                bail!(
                    "released credit hold '{}' has invalid ledger refs",
                    record_chirho.hold_id_chirho
                );
            }
        }
    }
    Ok(())
}

fn verify_reserve_entry_chirho(
    record_chirho: &CreditHoldRecordChirho,
    ledger_entries_chirho: &[LedgerEntryChirho],
) -> Result<()> {
    let entry_chirho = ledger_entries_chirho
        .get(record_chirho.reserve_ledger_seq_chirho as usize)
        .ok_or_else(|| {
            anyhow!(
                "credit hold '{}' points at missing reserve ledger entry {}",
                record_chirho.hold_id_chirho,
                record_chirho.reserve_ledger_seq_chirho
            )
        })?;
    if entry_chirho.billing_tags_chirho != record_chirho.billing_tags_chirho {
        bail!(
            "credit hold '{}' reserve ledger tags mismatch",
            record_chirho.hold_id_chirho
        );
    }
    require_posting_chirho(
        entry_chirho,
        &record_chirho.payer_chirho,
        -record_chirho.authorized_token_chirho,
    )?;
    require_posting_chirho(
        entry_chirho,
        &record_chirho.hold_account_chirho,
        record_chirho.authorized_token_chirho,
    )?;
    Ok(())
}

fn verify_settlement_entry_chirho(
    record_chirho: &CreditHoldRecordChirho,
    ledger_entries_chirho: &[LedgerEntryChirho],
) -> Result<()> {
    let seq_chirho = record_chirho.settlement_ledger_seq_chirho.ok_or_else(|| {
        anyhow!(
            "settled credit hold '{}' missing settlement ledger seq",
            record_chirho.hold_id_chirho
        )
    })?;
    let entry_chirho = ledger_entries_chirho
        .get(seq_chirho as usize)
        .ok_or_else(|| {
            anyhow!(
                "credit hold '{}' points at missing settlement ledger entry {}",
                record_chirho.hold_id_chirho,
                seq_chirho
            )
        })?;
    if entry_chirho.billing_tags_chirho != record_chirho.billing_tags_chirho {
        bail!(
            "credit hold '{}' settlement ledger tags mismatch",
            record_chirho.hold_id_chirho
        );
    }
    require_posting_chirho(
        entry_chirho,
        &record_chirho.hold_account_chirho,
        -record_chirho.authorized_token_chirho,
    )?;
    if record_chirho.released_token_chirho > 0 {
        require_posting_chirho(
            entry_chirho,
            &record_chirho.payer_chirho,
            record_chirho.released_token_chirho,
        )?;
    }
    Ok(())
}

fn verify_release_entry_chirho(
    record_chirho: &CreditHoldRecordChirho,
    ledger_entries_chirho: &[LedgerEntryChirho],
) -> Result<()> {
    let seq_chirho = record_chirho.release_ledger_seq_chirho.ok_or_else(|| {
        anyhow!(
            "released credit hold '{}' missing release ledger seq",
            record_chirho.hold_id_chirho
        )
    })?;
    let entry_chirho = ledger_entries_chirho
        .get(seq_chirho as usize)
        .ok_or_else(|| {
            anyhow!(
                "credit hold '{}' points at missing release ledger entry {}",
                record_chirho.hold_id_chirho,
                seq_chirho
            )
        })?;
    if entry_chirho.billing_tags_chirho != record_chirho.billing_tags_chirho {
        bail!(
            "credit hold '{}' release ledger tags mismatch",
            record_chirho.hold_id_chirho
        );
    }
    require_posting_chirho(
        entry_chirho,
        &record_chirho.hold_account_chirho,
        -record_chirho.released_token_chirho,
    )?;
    require_posting_chirho(
        entry_chirho,
        &record_chirho.payer_chirho,
        record_chirho.released_token_chirho,
    )?;
    Ok(())
}

fn require_posting_chirho(
    entry_chirho: &LedgerEntryChirho,
    account_chirho: &str,
    amount_chirho: i64,
) -> Result<()> {
    if !entry_chirho.postings_chirho.iter().any(|posting_chirho| {
        posting_chirho.account_chirho == account_chirho
            && posting_chirho.asset_chirho == AssetChirho::TokenChirho
            && posting_chirho.amount_chirho == amount_chirho
    }) {
        bail!(
            "ledger entry {} missing token posting {} {}",
            entry_chirho.seq_chirho,
            account_chirho,
            amount_chirho
        );
    }
    Ok(())
}

pub(crate) fn hold_record_message_chirho(
    record_chirho: &CreditHoldRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct HoldRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        hold_id_chirho: &'a str,
        hold_account_chirho: &'a str,
        app_chirho: &'a str,
        effect_chirho: &'a str,
        caller_chirho: &'a str,
        payer_chirho: &'a str,
        authorized_token_chirho: i64,
        settled_token_chirho: i64,
        released_token_chirho: i64,
        reserve_ledger_seq_chirho: u64,
        settlement_ledger_seq_chirho: &'a Option<u64>,
        release_ledger_seq_chirho: &'a Option<u64>,
        status_chirho: &'a CreditHoldStatusChirho,
        billing_tags_chirho: &'a BillingTagsChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&HoldRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: (!record_chirho.schema_chirho.is_empty())
            .then_some(record_chirho.schema_chirho.as_str()),
        hold_id_chirho: &record_chirho.hold_id_chirho,
        hold_account_chirho: &record_chirho.hold_account_chirho,
        app_chirho: &record_chirho.app_chirho,
        effect_chirho: &record_chirho.effect_chirho,
        caller_chirho: &record_chirho.caller_chirho,
        payer_chirho: &record_chirho.payer_chirho,
        authorized_token_chirho: record_chirho.authorized_token_chirho,
        settled_token_chirho: record_chirho.settled_token_chirho,
        released_token_chirho: record_chirho.released_token_chirho,
        reserve_ledger_seq_chirho: record_chirho.reserve_ledger_seq_chirho,
        settlement_ledger_seq_chirho: &record_chirho.settlement_ledger_seq_chirho,
        release_ledger_seq_chirho: &record_chirho.release_ledger_seq_chirho,
        status_chirho: &record_chirho.status_chirho,
        billing_tags_chirho: &record_chirho.billing_tags_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

/// The OLD-ROAD credit-hold states: load the records, verify the ledger they bind to, then fold.
///
/// Lifted out of the two-road dispatcher by the holds rebase. Every piece it needs was already
/// retained — the reader by brick (a1), the ledger verify by (a2-0), the fold by (a2-2) — so this is
/// the last three lines rather than a new extraction. No probe: this is the road-specific half, and
/// the gate belongs on the entry point below.
pub(crate) fn verified_credit_hold_states_old_road_chirho(
    root_chirho: &Path,
) -> Result<VerifiedCreditHoldStatesChirho> {
    let records_chirho =
        crate::legacy_evidence_readers_chirho::load_credit_holds_chirho(root_chirho)?;
    let ledger_entries_chirho =
        crate::legacy_ledger_evidence_chirho::verified_entries_old_road_chirho(root_chirho)?;
    verified_credit_hold_states_from_records_chirho(
        root_chirho,
        &records_chirho,
        &ledger_entries_chirho,
    )
}

/// Verify every credit hold for consumers that must outlive the spine: probe, then the old road.
///
/// The STILL-OPEN check is part of the contract, not a detail: a hold that never reached a terminal
/// state is money reserved and never resolved, so the count this returns is only meaningful once
/// every hold has settled or released. Pinned by
/// `legacy_holds_characterization_tests_chirho` (11 arms, mutation-proven before the (a2-2) move).
pub fn verify_credit_holds_single_road_chirho(root_chirho: &Path) -> Result<usize> {
    crate::legacy_single_road_probe_chirho::refuse_if_gate1_authority_branch_present_chirho(
        root_chirho,
    )?;
    let states_chirho = verified_credit_hold_states_old_road_chirho(root_chirho)?;
    for (hold_id_chirho, (_, terminal_chirho)) in &states_chirho.1 {
        if terminal_chirho.is_none() {
            bail!("credit hold '{hold_id_chirho}' is still open");
        }
    }
    Ok(states_chirho.0)
}
