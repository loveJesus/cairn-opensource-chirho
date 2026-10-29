// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The ONE verified cut/census evidence object for the credits-demo LocalPhaseB smoke: it reuses
//! the monitor's proven canonical journal walk (no second parser, no raw re-read), verifies the H3
//! regenesis packet-claim scalars against the retained SIGNED pre-L2 published receipt on the FULL
//! coordinate set (name, descriptor revision, seq, HLC, prefix digest, view digest), exact-selects
//! the claimed account's net from the canonical-parsed VERIFIED view (never copied from the claim),
//! binds both cuts to the live chain by ancestry, and derives the exact escrow/mint op census from
//! the retained records. The evidence type has PRIVATE fields and a SOLE verifying constructor, so
//! no code path can mint a `Verified` value carrying copied-not-verified coordinates.
//!
//! Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/credits-demo-localphaseb-smoke-chirho.md`.

use crate::account_net_chirho::parse_canonical_account_net_projection_view_chirho;
use crate::feeder_chirho::{
    view_bytes_digest_hex_chirho, MaterializedProjectionChirho, ProjectionSourceChirho,
};
use crate::publication_chirho::load_published_projection_chirho;
use anyhow::{bail, Context, Result};
use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_log_chirho::recompose_chirho::read_recomposed_journal_lines_chirho;
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, AssetKindIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{
    HlcChirho, LedgerOpChirho, LedgerRecordChirho, LegDeltaChirho,
};
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};

/// The verified O(n) canonical record walk over a source journal, bound to the live verified chain
/// by genesis/prev/tail digests and the count==tail_seq law. `records_chirho` retains each record
/// with its stored-line digest so interior ancestry and the op census are exact — the journal's own
/// replay proves state but does not retain records, so this bound walk is the census authority.
pub struct VerifiedJournalWalkChirho {
    pub genesis_digest_chirho: DigestChirho,
    pub tail_seq_chirho: u64,
    pub tail_line_digest_chirho: DigestChirho,
    pub records_chirho: Vec<(LedgerRecordChirho, DigestChirho)>,
}

/// Verified-open + chain-bound recomposed walk (the same law `conservation_check_chirho` consumes).
/// Genesis at index 0 must equal the verified instance digest; every record's prev must bind the
/// prior line; the tail digest and record count must equal the verified journal — TOCTOU/torn/forged
/// re-reads all REFUSE. No raw deserialize: every line goes through the canonical parser.
pub fn verified_journal_walk_chirho(
    source_chirho: ProjectionSourceChirho<'_>,
) -> Result<VerifiedJournalWalkChirho> {
    let journal_chirho = LedgerJournalChirho::open_read_only_full_chirho(
        source_chirho.journal_ports_chirho,
        source_chirho.journal_path_chirho.clone(),
        source_chirho.cluster_chirho,
    )
    .map_err(|error_chirho| anyhow::anyhow!("verified source open failed: {error_chirho:?}"))?;
    let lines_chirho = read_recomposed_journal_lines_chirho(
        source_chirho.journal_ports_chirho,
        source_chirho.journal_path_chirho,
        source_chirho.cluster_chirho,
    )
    .map_err(|error_chirho| anyhow::anyhow!("recomposed re-read failed: {error_chirho:?}"))?;

    let mut records_chirho: Vec<(LedgerRecordChirho, DigestChirho)> = Vec::new();
    let mut prev_digest_chirho: Option<DigestChirho> = None;
    for (index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
        let parsed_chirho =
            parse_canonical_ledger_journal_line_chirho(line_chirho).map_err(|error_chirho| {
                anyhow::anyhow!("re-read parse at line {index_chirho}: {error_chirho:?}")
            })?;
        let line_digest_chirho = stored_line_digest_chirho(line_chirho);
        match parsed_chirho {
            LedgerJournalLineChirho::GenesisChirho(_) => {
                if index_chirho != 0 {
                    bail!("genesis line at nonzero index {index_chirho}");
                }
                if &line_digest_chirho != journal_chirho.genesis_digest_chirho() {
                    bail!("re-read genesis does not bind the verified instance identity");
                }
            }
            LedgerJournalLineChirho::RecordChirho(record_chirho) => {
                let prev_bound_chirho = prev_digest_chirho
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("record before genesis in re-read"))?;
                if &record_chirho.prev_chirho != prev_bound_chirho {
                    bail!(
                        "re-read prev-binding breaks at seq {} — bytes diverge from the verified \
                         chain",
                        record_chirho.seq_chirho
                    );
                }
                // Explicit density: record seq must be exactly index+1, so seq-indexed lookups
                // over the retained records are self-contained rather than inherited from the
                // verified open's internal law across a crate boundary (#6051 rider).
                let expected_seq_chirho = u64::try_from(records_chirho.len())
                    .ok()
                    .and_then(|len_chirho| len_chirho.checked_add(1))
                    .ok_or_else(|| anyhow::anyhow!("re-read record count overflow"))?;
                if record_chirho.seq_chirho != expected_seq_chirho {
                    bail!(
                        "re-read record seq {} at dense index {expected_seq_chirho} — seq/index \
                         density broken",
                        record_chirho.seq_chirho
                    );
                }
                records_chirho.push((record_chirho, line_digest_chirho.clone()));
            }
        }
        prev_digest_chirho = Some(line_digest_chirho);
    }
    let tail_digest_chirho =
        prev_digest_chirho.ok_or_else(|| anyhow::anyhow!("source journal re-read is empty"))?;
    if &tail_digest_chirho != journal_chirho.tail_line_digest_chirho() {
        bail!("re-read tail digest does not bind the verified chain (TOCTOU or torn re-read)");
    }
    let record_count_chirho = u64::try_from(records_chirho.len())
        .map_err(|_error_chirho| anyhow::anyhow!("re-read record count overflow"))?;
    if record_count_chirho != journal_chirho.tail_seq_chirho() {
        bail!("re-read record count diverges from the verified tail seq");
    }
    Ok(VerifiedJournalWalkChirho {
        genesis_digest_chirho: journal_chirho.genesis_digest_chirho().clone(),
        tail_seq_chirho: journal_chirho.tail_seq_chirho(),
        tail_line_digest_chirho: tail_digest_chirho,
        records_chirho,
    })
}

/// The walked stored-line digest at `seq_chirho` — seq 0 = the genesis instance digest, else the
/// digest of the record at that seq. A cut claiming a seq beyond the verified tail REFUSES.
pub fn walk_line_digest_at_seq_chirho(
    walk_chirho: &VerifiedJournalWalkChirho,
    seq_chirho: u64,
) -> Result<&DigestChirho> {
    if seq_chirho == 0 {
        return Ok(&walk_chirho.genesis_digest_chirho);
    }
    if seq_chirho > walk_chirho.tail_seq_chirho {
        bail!(
            "cut seq {seq_chirho} is beyond the verified tail {}",
            walk_chirho.tail_seq_chirho
        );
    }
    let index_chirho = seq_chirho
        .checked_sub(1)
        .and_then(|index_chirho| usize::try_from(index_chirho).ok())
        .ok_or_else(|| anyhow::anyhow!("cut seq index overflow"))?;
    walk_chirho
        .records_chirho
        .get(index_chirho)
        .map(|(_record_chirho, digest_chirho)| digest_chirho)
        .ok_or_else(|| anyhow::anyhow!("cut seq {seq_chirho} has no retained record"))
}

/// The lent verified-ports bundle for the LocalPhaseB evidence read: the serve-runtime lending
/// seam hands exactly ONE of these to its closure — the caller cannot obtain, outlive, or
/// substitute individual components (in particular the FINAL head path is host-resolved inside
/// the seam) — and the packet-evidence parent passes it through whole to the low verifier.
pub struct LocalPhaseBEvidencePortsChirho<'ports_chirho> {
    pub source_chirho: ProjectionSourceChirho<'ports_chirho>,
    pub storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub feeder_root_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
    pub final_head_path_chirho: &'ports_chirho StoragePathChirho,
}

/// The H3 regenesis cut-claim scalars — UNVERIFIED by definition. Every coordinate is
/// verified-or-refused against SIGNED artifacts by
/// [`VerifiedLocalPhaseBEvidenceChirho::verify_and_bind_chirho`]; none is copied into the verified
/// evidence. What this LOW layer cannot know is whether the claim equals the CANONICAL H3 packet's
/// selection — that packet-provenance seam is sealed by the regenesis-crate parent
/// (`verified_localphaseb_evidence_from_packet_chirho`), the SOLE production entry, which parses
/// the canonical packet bytes, re-digests them against the regenesis receipt, exact-selects the
/// one balance projection row, and forms this claim internally (#6050 HOLD A).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H3RegenesisCutPacketClaimChirho {
    pub projection_name_chirho: String,
    pub descriptor_digest_chirho: DigestChirho,
    pub source_seq_chirho: u64,
    pub source_hlc_chirho: HlcChirho,
    pub signed_prefix_digest_chirho: DigestChirho,
    pub view_digest_hex_chirho: String,
    pub account_owner_chirho: String,
    pub account_kind_chirho: String,
    pub account_net_chirho: u64,
}

/// One escrow transition's TYPED per-record evidence (not an aggregate count): which op, on which
/// control saga+step, moving how much on which account, plus the settlement CREDIT leg where present
/// (the payer->settlement meter, distinct from the genesis mint which is a separate Mint record). The
/// wire binds EXACT intervals by control saga from this — so a Release/Finalize bound to a different
/// Hold, a reordering, or a wrong amount cannot pass with equal aggregate totals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowRecordEvidenceChirho {
    pub seq_chirho: u64,
    pub op_kind_chirho: EscrowOpKindChirho,
    pub control_saga_chirho: DigestChirho,
    pub control_step_chirho: u32,
    pub escrow_account_owner_chirho: String,
    pub escrow_account_kind_chirho: String,
    pub escrow_amount_chirho: u64,
    /// (owner, kind, amount) of the settlement CREDIT leg on this record, where present (Finalize).
    pub settlement_credit_leg_chirho: Option<(String, String, u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscrowOpKindChirho {
    HoldChirho,
    FinalizeChirho,
    ReleaseChirho,
}

/// The verified per-record census: every escrow transition in seq order (typed), plus the count of
/// genesis-scope mint records (which the settlement meter EXCLUDES by construction — mints are not
/// escrow records and carry no settlement credit leg here).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalPhaseBOpCensusChirho {
    pub escrow_records_chirho: Vec<EscrowRecordEvidenceChirho>,
    pub mint_count_chirho: u64,
    /// The summed Mint-record credit-leg amounts — an INDEPENDENT source for the initial-minted
    /// coordinate (#6073: census amount, digest-bound plan, and regenesis-cut net must cross-equal).
    pub mint_total_amount_chirho: u64,
}

fn op_census_from_records_chirho(
    records_chirho: &[(LedgerRecordChirho, DigestChirho)],
) -> Result<LocalPhaseBOpCensusChirho> {
    let mut census_chirho = LocalPhaseBOpCensusChirho::default();
    for (record_chirho, _digest_chirho) in records_chirho {
        let (op_kind_chirho, control_chirho) = match &record_chirho.op_chirho {
            LedgerOpChirho::EscrowHoldChirho { control_chirho } => {
                (EscrowOpKindChirho::HoldChirho, control_chirho)
            }
            LedgerOpChirho::EscrowFinalizeChirho { control_chirho } => {
                (EscrowOpKindChirho::FinalizeChirho, control_chirho)
            }
            LedgerOpChirho::EscrowReleaseChirho { control_chirho } => {
                (EscrowOpKindChirho::ReleaseChirho, control_chirho)
            }
            LedgerOpChirho::MintChirho { .. } => {
                census_chirho.mint_count_chirho = census_chirho
                    .mint_count_chirho
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("mint count overflow"))?;
                let leg_chirho = record_chirho.legs_chirho.first().ok_or_else(|| {
                    anyhow::anyhow!("mint record at seq {} has no leg", record_chirho.seq_chirho)
                })?;
                census_chirho.mint_total_amount_chirho = census_chirho
                    .mint_total_amount_chirho
                    .checked_add(leg_chirho.amount_chirho)
                    .ok_or_else(|| anyhow::anyhow!("mint total amount overflow"))?;
                continue;
            }
            _ => continue,
        };
        // The escrow leg (Hold/Release/Finalize delta) names the escrowing account + amount; the
        // Credit leg, where present, is the settlement meter. A malformed escrow record with no
        // escrow leg REFUSES (never a fabricated zero).
        let mut escrow_leg_chirho: Option<(String, String, u64)> = None;
        let mut settlement_credit_leg_chirho: Option<(String, String, u64)> = None;
        for leg_chirho in &record_chirho.legs_chirho {
            let coord_chirho = (
                leg_chirho.account_chirho.owner_chirho.clone(),
                leg_chirho.account_chirho.kind_id_chirho.0.clone(),
                leg_chirho.amount_chirho,
            );
            match leg_chirho.delta_chirho {
                LegDeltaChirho::HoldChirho
                | LegDeltaChirho::ReleaseChirho
                | LegDeltaChirho::FinalizeChirho => escrow_leg_chirho = Some(coord_chirho),
                LegDeltaChirho::CreditChirho => settlement_credit_leg_chirho = Some(coord_chirho),
                LegDeltaChirho::DebitChirho => {}
            }
        }
        let (owner_chirho, kind_chirho, amount_chirho) = escrow_leg_chirho.ok_or_else(|| {
            anyhow::anyhow!(
                "escrow record at seq {} has no escrow leg",
                record_chirho.seq_chirho
            )
        })?;
        census_chirho
            .escrow_records_chirho
            .push(EscrowRecordEvidenceChirho {
                seq_chirho: record_chirho.seq_chirho,
                op_kind_chirho,
                control_saga_chirho: control_chirho.saga_id_chirho.clone(),
                control_step_chirho: control_chirho.step_chirho,
                escrow_account_owner_chirho: owner_chirho,
                escrow_account_kind_chirho: kind_chirho,
                escrow_amount_chirho: amount_chirho,
                settlement_credit_leg_chirho,
            });
    }
    Ok(census_chirho)
}

/// Verify one published cut against the packet-claimed projection identity and the live walk, then
/// exact-select the claimed account's net from the canonical-parsed VERIFIED view bytes. Shared by
/// the pre-L2 (regenesis) and final cuts — same law, different coordinate expectations.
fn verify_cut_against_walk_chirho(
    label_chirho: &str,
    cut_chirho: &MaterializedProjectionChirho,
    claim_chirho: &H3RegenesisCutPacketClaimChirho,
    walk_chirho: &VerifiedJournalWalkChirho,
    source_cluster_chirho: &str,
    account_chirho: &AccountIdChirho,
) -> Result<u64> {
    let receipt_chirho = &cut_chirho.receipt_chirho;
    if receipt_chirho.projection_name_chirho != claim_chirho.projection_name_chirho {
        bail!(
            "{label_chirho} receipt projection '{}' does not match the packet claim projection \
             '{}' (cross-projection join)",
            receipt_chirho.projection_name_chirho,
            claim_chirho.projection_name_chirho
        );
    }
    if receipt_chirho.descriptor_digest_chirho != claim_chirho.descriptor_digest_chirho {
        bail!(
            "{label_chirho} receipt descriptor revision does not match the packet claim descriptor \
             (cross-revision join)"
        );
    }
    if receipt_chirho.source_genesis_digest_chirho != walk_chirho.genesis_digest_chirho {
        bail!("{label_chirho} receipt binds a different journal instance than the verified chain");
    }
    if receipt_chirho.source_cluster_chirho != source_cluster_chirho {
        bail!("{label_chirho} receipt binds a different source cluster");
    }
    // INTERIOR ANCESTRY, re-derived from OUR walk — the receipt's bound tail-line digest must be
    // the walked digest at its seq; and for a record cut, the receipt's HLC must equal the CHAIN
    // record's HLC at that seq (receipt==chain, not merely packet==receipt).
    let ancestor_chirho =
        walk_line_digest_at_seq_chirho(walk_chirho, receipt_chirho.source_tail_seq_chirho)?;
    if ancestor_chirho != &receipt_chirho.source_tail_line_digest_chirho {
        bail!(
            "{label_chirho} receipt's bound line digest is NOT an ancestor of the live chain \
             (interior rewrite or forged/same-seq-fork cut)"
        );
    }
    if receipt_chirho.source_tail_seq_chirho >= 1 {
        let record_index_chirho = receipt_chirho
            .source_tail_seq_chirho
            .checked_sub(1)
            .and_then(|index_chirho| usize::try_from(index_chirho).ok())
            .ok_or_else(|| anyhow::anyhow!("{label_chirho} receipt seq index overflow"))?;
        let record_chirho = &walk_chirho
            .records_chirho
            .get(record_index_chirho)
            .ok_or_else(|| anyhow::anyhow!("{label_chirho} receipt seq has no retained record"))?
            .0;
        if record_chirho.hlc_chirho != receipt_chirho.source_tail_hlc_chirho {
            bail!(
                "{label_chirho} receipt's source HLC does not equal the chain record HLC at its seq"
            );
        }
    }
    if view_bytes_digest_hex_chirho(&cut_chirho.view_bytes_chirho)
        != receipt_chirho.view_digest_hex_chirho
    {
        bail!("{label_chirho} view bytes do not re-hash to the receipt binding");
    }
    // CANONICAL EXACT-SELECT (the anti-verified-by-copy heart): the claimed account's net comes
    // from the canonical-parsed VERIFIED view — a missing row REFUSES, never a fabricated zero.
    let view_chirho =
        parse_canonical_account_net_projection_view_chirho(&cut_chirho.view_bytes_chirho)
            .with_context(|| {
                format!("{label_chirho} verified view is not a canonical account-net view")
            })?;
    let row_net_chirho = view_chirho
        .rows_chirho
        .iter()
        .find(|row_chirho| &row_chirho.account_chirho == account_chirho)
        .map(|row_chirho| row_chirho.account_net_chirho)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{label_chirho} verified view has no row for the packet-claimed account"
            )
        })?;
    Ok(row_net_chirho)
}

/// The one verify-and-bound LocalPhaseB evidence object. Both the smoke's wire and its verifier
/// consume this — no second census law, no fabricated constants, no raw walk. Fields are PRIVATE
/// and the SOLE producer is [`Self::verify_and_bind_chirho`]: no struct literal, no field
/// mutation, no copied-not-verified coordinate can exist behind this type (the #6041/#6042/#6043
/// by-construction invariant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLocalPhaseBEvidenceChirho {
    projection_name_chirho: String,
    descriptor_digest_chirho: DigestChirho,
    genesis_digest_chirho: DigestChirho,
    tail_seq_chirho: u64,
    tail_line_digest_chirho: DigestChirho,
    regenesis_source_seq_chirho: u64,
    regenesis_source_hlc_chirho: HlcChirho,
    regenesis_signed_prefix_digest_chirho: DigestChirho,
    regenesis_view_digest_hex_chirho: String,
    regenesis_account_owner_chirho: String,
    regenesis_account_kind_chirho: String,
    regenesis_account_net_chirho: u64,
    final_source_seq_chirho: u64,
    final_source_hlc_chirho: HlcChirho,
    final_view_digest_hex_chirho: String,
    final_account_net_chirho: u64,
    /// The verified chain's stored-line digest column (index i = seq i+1), retained so mid-arc
    /// phase snapshots can be ANCESTOR-VERIFIED cuts of this one walk (#6050 HOLD B (iii)).
    seq_line_digests_chirho: Vec<DigestChirho>,
    op_census_chirho: LocalPhaseBOpCensusChirho,
}

impl VerifiedLocalPhaseBEvidenceChirho {
    /// Build the verified LocalPhaseB evidence — the SOLE constructor. Law order:
    /// (1) the bound canonical walk; (2) load the RETAINED pre-L2 (regenesis-cut) published head
    /// through the signed-receipt loader — the signature makes the retention path untrusted-safe:
    /// a tampered copy fails signature verification, a replayed different genuine receipt fails
    /// the equality set below; (3) FULL packet==receipt equality on {projection name, descriptor
    /// revision, seq, HLC physical+logical, signed-prefix/tail-line digest, view digest} — any
    /// partial coordinate set would readmit same-name/other-revision or same-seq/other-cut joins;
    /// (4) receipt==chain binds: genesis + cluster from the VERIFIED receipt must equal the walk's,
    /// the ancestor digest at the cut seq is re-derived from OUR walk, and the receipt HLC must
    /// equal the chain record HLC; (5) canonical-parse the verified view and EXACT-SELECT the
    /// claimed account's net — cross-checked to the packet claim, never copied from it; (6) the
    /// final published head must bind the SAME projection name AND descriptor revision at exactly
    /// the walk tail, with its own exact-select; (7) the per-record op census.
    pub fn verify_and_bind_chirho(
        ports_chirho: LocalPhaseBEvidencePortsChirho<'_>,
        packet_claim_chirho: &H3RegenesisCutPacketClaimChirho,
        regenesis_head_path_chirho: &StoragePathChirho,
    ) -> Result<Self> {
        let LocalPhaseBEvidencePortsChirho {
            source_chirho,
            storage_chirho,
            feeder_root_chirho,
            final_head_path_chirho,
        } = ports_chirho;
        let source_cluster_chirho = source_chirho.cluster_chirho.0.clone();
        let walk_chirho = verified_journal_walk_chirho(source_chirho)?;
        let account_chirho = AccountIdChirho {
            owner_chirho: packet_claim_chirho.account_owner_chirho.clone(),
            kind_id_chirho: AssetKindIdChirho(packet_claim_chirho.account_kind_chirho.clone()),
        };

        // (2)-(5) the pre-L2 regenesis cut.
        let regenesis_chirho = load_published_projection_chirho(
            storage_chirho,
            regenesis_head_path_chirho,
            feeder_root_chirho,
        )
        .context("retained pre-L2 regenesis-cut head")?;
        let regenesis_receipt_chirho = &regenesis_chirho.receipt_chirho;
        if regenesis_receipt_chirho.source_tail_seq_chirho != packet_claim_chirho.source_seq_chirho
        {
            bail!("pre-L2 receipt seq does not equal the packet-claimed regenesis cut seq");
        }
        if regenesis_receipt_chirho.source_tail_hlc_chirho != packet_claim_chirho.source_hlc_chirho
        {
            bail!("pre-L2 receipt HLC does not equal the packet-claimed regenesis cut HLC");
        }
        if regenesis_receipt_chirho.source_tail_line_digest_chirho
            != packet_claim_chirho.signed_prefix_digest_chirho
        {
            bail!(
                "pre-L2 receipt tail-line digest does not equal the packet-claimed signed prefix"
            );
        }
        if regenesis_receipt_chirho.view_digest_hex_chirho
            != packet_claim_chirho.view_digest_hex_chirho
        {
            bail!("pre-L2 receipt view digest does not equal the packet-claimed view digest");
        }
        let regenesis_net_chirho = verify_cut_against_walk_chirho(
            "pre-L2 regenesis",
            &regenesis_chirho,
            packet_claim_chirho,
            &walk_chirho,
            &source_cluster_chirho,
            &account_chirho,
        )?;
        if regenesis_net_chirho != packet_claim_chirho.account_net_chirho {
            bail!(
                "packet-claimed regenesis account net {} does not equal the VERIFIED view's \
                 exact-selected net {regenesis_net_chirho}",
                packet_claim_chirho.account_net_chirho
            );
        }

        // (6) the final cut: same projection name AND descriptor revision, at exactly the walk tail.
        let final_chirho = load_published_projection_chirho(
            storage_chirho,
            final_head_path_chirho,
            feeder_root_chirho,
        )
        .context("final published head")?;
        let final_receipt_chirho = &final_chirho.receipt_chirho;
        if final_receipt_chirho.source_tail_seq_chirho != walk_chirho.tail_seq_chirho {
            bail!("final published receipt tail seq does not equal the verified tail seq");
        }
        if final_receipt_chirho.source_tail_line_digest_chirho
            != walk_chirho.tail_line_digest_chirho
        {
            bail!(
                "final published receipt tail-line digest does not equal the verified tail digest"
            );
        }
        let final_account_net_chirho = verify_cut_against_walk_chirho(
            "final",
            &final_chirho,
            packet_claim_chirho,
            &walk_chirho,
            &source_cluster_chirho,
            &account_chirho,
        )?;

        // (7) the census from the same walk, plus the retained digest column for ancestor checks.
        let op_census_chirho = op_census_from_records_chirho(&walk_chirho.records_chirho)?;
        let seq_line_digests_chirho: Vec<DigestChirho> = walk_chirho
            .records_chirho
            .iter()
            .map(|(_record_chirho, digest_chirho)| digest_chirho.clone())
            .collect();

        Ok(Self {
            projection_name_chirho: regenesis_receipt_chirho.projection_name_chirho.clone(),
            descriptor_digest_chirho: regenesis_receipt_chirho.descriptor_digest_chirho.clone(),
            genesis_digest_chirho: walk_chirho.genesis_digest_chirho.clone(),
            tail_seq_chirho: walk_chirho.tail_seq_chirho,
            tail_line_digest_chirho: walk_chirho.tail_line_digest_chirho.clone(),
            regenesis_source_seq_chirho: regenesis_receipt_chirho.source_tail_seq_chirho,
            regenesis_source_hlc_chirho: regenesis_receipt_chirho.source_tail_hlc_chirho.clone(),
            regenesis_signed_prefix_digest_chirho: regenesis_receipt_chirho
                .source_tail_line_digest_chirho
                .clone(),
            regenesis_view_digest_hex_chirho: regenesis_receipt_chirho
                .view_digest_hex_chirho
                .clone(),
            regenesis_account_owner_chirho: account_chirho.owner_chirho.clone(),
            regenesis_account_kind_chirho: account_chirho.kind_id_chirho.0.clone(),
            regenesis_account_net_chirho: regenesis_net_chirho,
            final_source_seq_chirho: final_receipt_chirho.source_tail_seq_chirho,
            final_source_hlc_chirho: final_receipt_chirho.source_tail_hlc_chirho.clone(),
            final_view_digest_hex_chirho: final_receipt_chirho.view_digest_hex_chirho.clone(),
            final_account_net_chirho,
            seq_line_digests_chirho,
            op_census_chirho,
        })
    }

    /// The verified stored-line digest at `seq_chirho` (0 = the genesis instance digest) — for
    /// binding a mid-arc phase snapshot (seq + tail-line digest) as an ANCESTOR-VERIFIED cut of
    /// this evidence's one verified walk. A seq beyond the verified tail REFUSES.
    pub fn ancestor_line_digest_at_seq_chirho(&self, seq_chirho: u64) -> Result<&DigestChirho> {
        if seq_chirho == 0 {
            return Ok(&self.genesis_digest_chirho);
        }
        if seq_chirho > self.tail_seq_chirho {
            bail!(
                "snapshot seq {seq_chirho} is beyond the verified tail {}",
                self.tail_seq_chirho
            );
        }
        let index_chirho = seq_chirho
            .checked_sub(1)
            .and_then(|index_chirho| usize::try_from(index_chirho).ok())
            .ok_or_else(|| anyhow::anyhow!("snapshot seq index overflow"))?;
        self.seq_line_digests_chirho
            .get(index_chirho)
            .ok_or_else(|| anyhow::anyhow!("snapshot seq {seq_chirho} has no retained digest"))
    }

    pub fn projection_name_chirho(&self) -> &str {
        &self.projection_name_chirho
    }
    pub fn descriptor_digest_chirho(&self) -> &DigestChirho {
        &self.descriptor_digest_chirho
    }
    pub fn genesis_digest_chirho(&self) -> &DigestChirho {
        &self.genesis_digest_chirho
    }
    pub fn tail_seq_chirho(&self) -> u64 {
        self.tail_seq_chirho
    }
    pub fn tail_line_digest_chirho(&self) -> &DigestChirho {
        &self.tail_line_digest_chirho
    }
    pub fn regenesis_source_seq_chirho(&self) -> u64 {
        self.regenesis_source_seq_chirho
    }
    pub fn regenesis_source_hlc_chirho(&self) -> &HlcChirho {
        &self.regenesis_source_hlc_chirho
    }
    pub fn regenesis_signed_prefix_digest_chirho(&self) -> &DigestChirho {
        &self.regenesis_signed_prefix_digest_chirho
    }
    pub fn regenesis_view_digest_hex_chirho(&self) -> &str {
        &self.regenesis_view_digest_hex_chirho
    }
    pub fn regenesis_account_owner_chirho(&self) -> &str {
        &self.regenesis_account_owner_chirho
    }
    pub fn regenesis_account_kind_chirho(&self) -> &str {
        &self.regenesis_account_kind_chirho
    }
    pub fn regenesis_account_net_chirho(&self) -> u64 {
        self.regenesis_account_net_chirho
    }
    pub fn final_source_seq_chirho(&self) -> u64 {
        self.final_source_seq_chirho
    }
    pub fn final_source_hlc_chirho(&self) -> &HlcChirho {
        &self.final_source_hlc_chirho
    }
    pub fn final_view_digest_hex_chirho(&self) -> &str {
        &self.final_view_digest_hex_chirho
    }
    pub fn final_account_net_chirho(&self) -> u64 {
        self.final_account_net_chirho
    }
    pub fn op_census_chirho(&self) -> &LocalPhaseBOpCensusChirho {
        &self.op_census_chirho
    }
}

#[cfg(test)]
#[path = "localphaseb_evidence_chirho/localphaseb_tests_chirho.rs"]
mod localphaseb_tests_chirho;
