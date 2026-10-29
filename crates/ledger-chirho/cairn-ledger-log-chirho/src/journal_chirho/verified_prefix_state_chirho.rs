// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Opaque verified state at one historical prefix of a read-only journal.
//!
//! The ordinary full read-only open proves the whole physical journal. The existing recomposition
//! path then rereads the same sealed-history plus active-prefix bytes without repair authority.
//! This module binds that second walk back to the verified genesis, dense sequence, predecessor
//! chain, and tail before exposing the account heads at one exact interior cut. It carries no GD7
//! identity or adoption authority; callers must bind the returned cuts to their own protocol.

use crate::journal_chirho::{JournalErrorChirho, JournalPortsChirho, LedgerJournalChirho};
use crate::ports_chirho::StoragePathChirho;
use crate::recompose_chirho::read_recomposed_journal_lines_chirho;
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, ClusterIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{HlcChirho, LegPostStateChirho};
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};
use cairn_ledger_model_chirho::ShardEpochChirho;
use std::collections::BTreeMap;

/// Caller-selected prefix coordinate. This is a request, not verified evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerPrefixCutChirho {
    epoch_chirho: ShardEpochChirho,
    seq_chirho: u64,
    record_digest_chirho: DigestChirho,
}

impl LedgerPrefixCutChirho {
    pub fn new_chirho(
        epoch_chirho: ShardEpochChirho,
        seq_chirho: u64,
        record_digest_chirho: DigestChirho,
    ) -> Self {
        Self {
            epoch_chirho,
            seq_chirho,
            record_digest_chirho,
        }
    }

    pub fn epoch_chirho(&self) -> ShardEpochChirho {
        self.epoch_chirho
    }

    pub fn seq_chirho(&self) -> u64 {
        self.seq_chirho
    }

    pub fn record_digest_chirho(&self) -> &DigestChirho {
        &self.record_digest_chirho
    }
}

/// One cut established by the full-open-bound second walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLedgerReadCutChirho {
    epoch_chirho: ShardEpochChirho,
    seq_chirho: u64,
    record_digest_chirho: DigestChirho,
    hlc_chirho: HlcChirho,
}

impl VerifiedLedgerReadCutChirho {
    pub fn epoch_chirho(&self) -> ShardEpochChirho {
        self.epoch_chirho
    }

    pub fn seq_chirho(&self) -> u64 {
        self.seq_chirho
    }

    pub fn record_digest_chirho(&self) -> &DigestChirho {
        &self.record_digest_chirho
    }

    pub fn hlc_chirho(&self) -> &HlcChirho {
        &self.hlc_chirho
    }
}

/// Full-verify one read-only journal and return its exact tail as opaque evidence.
///
/// This is intentionally not a read-and-wrap helper. [`LedgerJournalChirho::open_read_only_full_chirho`]
/// verifies canonical framing, signatures, the dense predecessor chain, balance folds, and the
/// tail before this module can construct the cut. Corrupt or truncated history returns a journal
/// refusal and never yields evidence.
pub fn open_read_only_verified_tail_cut_chirho(
    ports_chirho: JournalPortsChirho<'_>,
    path_chirho: &StoragePathChirho,
    expected_cluster_chirho: &ClusterIdChirho,
) -> Result<VerifiedLedgerReadCutChirho, JournalErrorChirho> {
    let verified_journal_chirho = LedgerJournalChirho::open_read_only_full_chirho(
        ports_chirho,
        path_chirho.clone(),
        expected_cluster_chirho,
    )?;
    Ok(VerifiedLedgerReadCutChirho {
        epoch_chirho: verified_journal_chirho.last_recorded_epoch_chirho,
        seq_chirho: verified_journal_chirho.tail_seq_chirho(),
        record_digest_chirho: verified_journal_chirho.tail_line_digest_chirho().clone(),
        // This HLC is carried by the verified genesis/record bytes. It is not sampled at read time.
        hlc_chirho: verified_journal_chirho.tail_hlc_chirho().clone(),
    })
}

/// Opaque account-head state at one exact verified prefix.
///
/// This is sufficient for state-derived account-net reads. It deliberately does not claim to be a
/// complete journal checkpoint: supply, active holds, consumed nullifiers, idempotency state, and
/// effect receipt windows are not exposed.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedLedgerPrefixStateChirho {
    genesis_digest_chirho: DigestChirho,
    prefix_cut_chirho: VerifiedLedgerReadCutChirho,
    source_tail_cut_chirho: VerifiedLedgerReadCutChirho,
    head_states_chirho: BTreeMap<AccountIdChirho, LegPostStateChirho>,
}

impl VerifiedLedgerPrefixStateChirho {
    pub fn genesis_digest_chirho(&self) -> &DigestChirho {
        &self.genesis_digest_chirho
    }

    pub fn prefix_cut_chirho(&self) -> &VerifiedLedgerReadCutChirho {
        &self.prefix_cut_chirho
    }

    pub fn source_tail_cut_chirho(&self) -> &VerifiedLedgerReadCutChirho {
        &self.source_tail_cut_chirho
    }

    pub fn head_states_chirho(&self) -> &BTreeMap<AccountIdChirho, LegPostStateChirho> {
        &self.head_states_chirho
    }
}

/// Full-verify one journal, bind a second read-only recomposed walk to it, and expose the account
/// heads at `requested_cut_chirho`.
///
/// Work is O(full journal history) and belongs on rebuild/evidence paths, never a hot served read.
/// No storage method capable of mutation is called.
pub fn open_read_only_verified_prefix_state_chirho(
    ports_chirho: JournalPortsChirho<'_>,
    path_chirho: &StoragePathChirho,
    expected_cluster_chirho: &ClusterIdChirho,
    requested_cut_chirho: &LedgerPrefixCutChirho,
) -> Result<VerifiedLedgerPrefixStateChirho, JournalErrorChirho> {
    let verified_journal_chirho = LedgerJournalChirho::open_read_only_full_chirho(
        ports_chirho,
        path_chirho.clone(),
        expected_cluster_chirho,
    )?;
    let lines_chirho =
        read_recomposed_journal_lines_chirho(ports_chirho, path_chirho, expected_cluster_chirho)?;

    let mut previous_digest_chirho = None;
    let mut observed_record_count_chirho = 0_u64;
    let mut prefix_cut_chirho = None;
    let mut source_tail_cut_chirho = None;
    let mut head_states_chirho = BTreeMap::new();

    for (line_index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
        let line_digest_chirho = stored_line_digest_chirho(line_chirho);
        match parse_canonical_ledger_journal_line_chirho(line_chirho)? {
            LedgerJournalLineChirho::GenesisChirho(genesis_chirho) => {
                if line_index_chirho != 0
                    || line_digest_chirho != *verified_journal_chirho.genesis_digest_chirho()
                {
                    return Err(chain_refusal_chirho(
                        "recomposed genesis does not bind the verified journal",
                    ));
                }
                let genesis_cut_chirho = VerifiedLedgerReadCutChirho {
                    epoch_chirho: genesis_chirho.epoch_chirho,
                    seq_chirho: 0,
                    record_digest_chirho: line_digest_chirho.clone(),
                    hlc_chirho: genesis_chirho.hlc_chirho,
                };
                if requested_cut_chirho.seq_chirho == 0 {
                    require_requested_cut_chirho(requested_cut_chirho, &genesis_cut_chirho)?;
                    prefix_cut_chirho = Some(genesis_cut_chirho.clone());
                }
                source_tail_cut_chirho = Some(genesis_cut_chirho);
            }
            LedgerJournalLineChirho::RecordChirho(record_chirho) => {
                let expected_seq_chirho = observed_record_count_chirho
                    .checked_add(1)
                    .ok_or_else(|| chain_refusal_chirho("recomposed record count overflowed"))?;
                if record_chirho.seq_chirho != expected_seq_chirho
                    || previous_digest_chirho.as_ref() != Some(&record_chirho.prev_chirho)
                {
                    return Err(chain_refusal_chirho(
                        "recomposed record sequence or predecessor diverges from the verified journal",
                    ));
                }
                let record_cut_chirho = VerifiedLedgerReadCutChirho {
                    epoch_chirho: record_chirho.epoch_chirho,
                    seq_chirho: record_chirho.seq_chirho,
                    record_digest_chirho: line_digest_chirho.clone(),
                    hlc_chirho: record_chirho.hlc_chirho.clone(),
                };
                if record_chirho.seq_chirho <= requested_cut_chirho.seq_chirho {
                    for leg_chirho in &record_chirho.legs_chirho {
                        head_states_chirho.insert(
                            leg_chirho.account_chirho.clone(),
                            leg_chirho.post_chirho.clone(),
                        );
                    }
                }
                if record_chirho.seq_chirho == requested_cut_chirho.seq_chirho {
                    require_requested_cut_chirho(requested_cut_chirho, &record_cut_chirho)?;
                    prefix_cut_chirho = Some(record_cut_chirho.clone());
                }
                observed_record_count_chirho = expected_seq_chirho;
                source_tail_cut_chirho = Some(record_cut_chirho);
            }
        }
        previous_digest_chirho = Some(line_digest_chirho);
    }

    let source_tail_cut_chirho =
        source_tail_cut_chirho.ok_or_else(|| chain_refusal_chirho("journal reread is empty"))?;
    if observed_record_count_chirho != verified_journal_chirho.tail_seq_chirho()
        || source_tail_cut_chirho.seq_chirho != verified_journal_chirho.tail_seq_chirho()
        || source_tail_cut_chirho.hlc_chirho != *verified_journal_chirho.tail_hlc_chirho()
        || source_tail_cut_chirho.record_digest_chirho
            != *verified_journal_chirho.tail_line_digest_chirho()
        || previous_digest_chirho.as_ref()
            != Some(verified_journal_chirho.tail_line_digest_chirho())
    {
        return Err(chain_refusal_chirho(
            "recomposed tail does not bind the full verified journal",
        ));
    }
    let prefix_cut_chirho = prefix_cut_chirho
        .ok_or_else(|| chain_refusal_chirho("requested prefix cut is absent from the journal"))?;
    Ok(VerifiedLedgerPrefixStateChirho {
        genesis_digest_chirho: verified_journal_chirho.genesis_digest_chirho().clone(),
        prefix_cut_chirho,
        source_tail_cut_chirho,
        head_states_chirho,
    })
}

fn require_requested_cut_chirho(
    requested_cut_chirho: &LedgerPrefixCutChirho,
    observed_cut_chirho: &VerifiedLedgerReadCutChirho,
) -> Result<(), JournalErrorChirho> {
    if requested_cut_chirho.epoch_chirho != observed_cut_chirho.epoch_chirho
        || requested_cut_chirho.seq_chirho != observed_cut_chirho.seq_chirho
        || requested_cut_chirho.record_digest_chirho != observed_cut_chirho.record_digest_chirho
    {
        return Err(chain_refusal_chirho(
            "requested prefix cut does not bind the recomposed journal",
        ));
    }
    Ok(())
}

fn chain_refusal_chirho(detail_chirho: &str) -> JournalErrorChirho {
    JournalErrorChirho::ChainChirho {
        detail_chirho: detail_chirho.to_owned(),
    }
}
