// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Hot-account sharded credit-only sub-accounts (CF2, ruled #5030): ORDINARY accounts named by a
//! parent-owner-SIGNED shard-set declaration — zero new admission surface. C1: routing and the
//! logical view consult ONLY the verified declaration chain (prefix/name matching is a DEFECT).
//! C2: same-journal shards relieve head-row dependency chains (the structural bench), NOT
//! single-writer log throughput; cross-journal consolidate-home is F3-GATED and stays refused.
//! C3: "credit-only" is ROUTER discipline — a direct shard debit violates no money law, and
//! admission must never learn shard semantics.
//!
//! THE DECLARATION COMPOSITION INVARIANT (second-seat #5042 — the shard analog of the coordinator
//! invariant): verify_record binds the LOG identity and the root signature, but a record's OWNER
//! string is not bound to the signing root — so one declaration log's injected root speaks for
//! EVERY owner named inside that log. Compose ONE declaration log per owner-root authority (the
//! shard_log_id names whose root it is); a shared-root multi-owner log is only sound where that
//! root legitimately holds routing authority for all owners it names. ENFR candidate: an
//! expected-owner binding parameter at load/verify for the multi-tenant era.

use anyhow::{anyhow, bail, Context, Result};
use cairn_chain_core_chirho::{
    chain_anchor_hex_chirho, walk_verified_chain_chirho, ChainFamilyChirho, ChainWalkErrorChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The shard-set family's schema tag (shard-set ≠ saga ≠ journal ≠ registry).
pub const SHARD_SET_SCHEMA_V1_CHIRHO: &str = "ledger-shard-set-record-v1-chirho";
/// The shard-set family's chain-core domain.
pub const SHARD_SET_CHAIN_DOMAIN_CHIRHO: &str = "ledger-shard-set-chain-v1-chirho";

/// One shard-set operation: Declare binds (owner, kind) to its FIRST shard set (first
/// declaration wins); Amend replaces the CURRENT set (chain order is the monotonicity).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ShardSetOpChirho {
    #[serde(rename = "declare-chirho")]
    DeclareChirho { shards_chirho: Vec<String> },
    #[serde(rename = "amend-chirho")]
    AmendChirho { shards_chirho: Vec<String> },
}

/// One owner-signed shard-set record. The OWNER's signature is what makes a shard a shard —
/// C1's law: an account whose NAME merely looks shard-like is an ordinary unrelated account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardSetRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub prev_chirho: String,
    /// The declaration log's identity (the chain anchor's instance id).
    pub shard_log_id_chirho: String,
    pub owner_chirho: String,
    pub kind_chirho: String,
    pub op_chirho: ShardSetOpChirho,
    pub owner_sig_chirho: String,
}

/// The verified per-(owner, kind) shard sets a consumer may route/aggregate by.
#[derive(Debug)]
pub struct VerifiedShardSetsChirho {
    pub records_chirho: Vec<ShardSetRecordChirho>,
    pub tail_digest_hex_chirho: String,
    pub sets_chirho: BTreeMap<(String, String), Vec<String>>,
}

impl VerifiedShardSetsChirho {
    /// The declared shard list for (owner, kind) — `None` when nothing was ever declared.
    /// THE ONLY sanctioned source of shard-ness (C1).
    pub fn shards_chirho(&self, owner_chirho: &str, kind_chirho: &str) -> Option<&[String]> {
        self.sets_chirho
            .get(&(owner_chirho.to_owned(), kind_chirho.to_owned()))
            .map(Vec::as_slice)
    }
}

pub fn canonical_shard_set_line_chirho(record_chirho: &ShardSetRecordChirho) -> Result<String> {
    if record_chirho.schema_chirho != SHARD_SET_SCHEMA_V1_CHIRHO {
        bail!("unsupported shard-set record schema");
    }
    if record_chirho.shard_log_id_chirho.is_empty() {
        bail!("shard-set record must name its log");
    }
    let (ShardSetOpChirho::DeclareChirho { shards_chirho }
    | ShardSetOpChirho::AmendChirho { shards_chirho }) = &record_chirho.op_chirho;
    if shards_chirho.is_empty() {
        bail!("a shard set declares at least one shard");
    }
    let mut sorted_chirho = shards_chirho.clone();
    sorted_chirho.sort();
    sorted_chirho.dedup();
    if sorted_chirho.len() != shards_chirho.len() || sorted_chirho != *shards_chirho {
        bail!("shard sets are canonical: sorted, duplicate-free");
    }
    if shards_chirho
        .iter()
        .any(|shard_chirho| shard_chirho == &record_chirho.owner_chirho)
    {
        bail!("the parent account is not its own shard");
    }
    serde_json::to_string(record_chirho).context("encode canonical shard-set record")
}

pub fn parse_canonical_shard_set_line_chirho(line_chirho: &str) -> Result<ShardSetRecordChirho> {
    #[derive(Deserialize)]
    struct SchemaProbeChirho {
        schema_chirho: String,
    }
    let probe_chirho: SchemaProbeChirho =
        serde_json::from_str(line_chirho).context("probe shard-set record schema")?;
    if probe_chirho.schema_chirho != SHARD_SET_SCHEMA_V1_CHIRHO {
        bail!("unsupported shard-set record schema");
    }
    let record_chirho: ShardSetRecordChirho =
        serde_json::from_str(line_chirho).context("decode shard-set record")?;
    let canonical_chirho = canonical_shard_set_line_chirho(&record_chirho)?;
    if canonical_chirho != line_chirho {
        bail!("shard-set record has a byte-canonical mismatch");
    }
    Ok(record_chirho)
}

pub fn shard_set_signed_content_chirho(record_chirho: &ShardSetRecordChirho) -> Result<String> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.owner_sig_chirho = String::new();
    canonical_shard_set_line_chirho(&unsigned_chirho)
}

struct ShardSetChainFamilyChirho<'ports_chirho> {
    shard_log_id_chirho: &'ports_chirho str,
    owner_root_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
}

impl ChainFamilyChirho for ShardSetChainFamilyChirho<'_> {
    type RecordChirho = ShardSetRecordChirho;
    type ErrorChirho = anyhow::Error;

    fn parse_line_chirho(&self, line_chirho: &str) -> Result<ShardSetRecordChirho, anyhow::Error> {
        parse_canonical_shard_set_line_chirho(line_chirho)
    }

    fn seq_chirho(&self, record_chirho: &ShardSetRecordChirho) -> u64 {
        record_chirho.seq_chirho
    }

    fn prev_hex_chirho<'record_chirho>(
        &self,
        record_chirho: &'record_chirho ShardSetRecordChirho,
    ) -> &'record_chirho str {
        &record_chirho.prev_chirho
    }

    fn verify_record_chirho(
        &self,
        record_chirho: &ShardSetRecordChirho,
    ) -> Result<(), anyhow::Error> {
        if record_chirho.shard_log_id_chirho != self.shard_log_id_chirho {
            bail!(
                "record names shard log {} — cross-log replay refused",
                record_chirho.shard_log_id_chirho
            );
        }
        let signed_content_chirho = shard_set_signed_content_chirho(record_chirho)?;
        if !self
            .owner_root_chirho
            .verify_chirho(&signed_content_chirho, &record_chirho.owner_sig_chirho)
        {
            bail!(
                "shard-set owner signature does not verify at seq {}",
                record_chirho.seq_chirho
            );
        }
        Ok(())
    }
}

/// Load + verify the shard-set declaration chain (config authority: torn tail FAILS CLOSED —
/// declarations gate routing, so a torn declaration file is an operator event, never a repair).
pub fn load_shard_sets_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    owner_root_chirho: &dyn LedgerSignerPortChirho,
    path_chirho: &StoragePathChirho,
    shard_log_id_chirho: &str,
) -> Result<VerifiedShardSetsChirho> {
    let anchor_chirho = chain_anchor_hex_chirho(SHARD_SET_CHAIN_DOMAIN_CHIRHO, shard_log_id_chirho);
    let Some(bytes_chirho) = storage_chirho
        .read_all_chirho(path_chirho)
        .map_err(|error_chirho| anyhow!("read shard-set log: {error_chirho}"))?
    else {
        return Ok(VerifiedShardSetsChirho {
            records_chirho: Vec::new(),
            tail_digest_hex_chirho: anchor_chirho,
            sets_chirho: BTreeMap::new(),
        });
    };
    if bytes_chirho
        .last()
        .is_some_and(|byte_chirho| *byte_chirho != b'\n')
    {
        bail!("shard-set log has a torn tail — configuration authority fails closed");
    }
    let text_chirho = std::str::from_utf8(&bytes_chirho)
        .map_err(|_| anyhow!("shard-set log bytes are not UTF-8"))?;
    let family_chirho = ShardSetChainFamilyChirho {
        shard_log_id_chirho,
        owner_root_chirho,
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
    let mut sets_chirho: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    let mut records_chirho = Vec::with_capacity(lines_chirho.len());
    for line_chirho in lines_chirho {
        let record_chirho = line_chirho.record_chirho;
        let key_chirho = (
            record_chirho.owner_chirho.clone(),
            record_chirho.kind_chirho.clone(),
        );
        match &record_chirho.op_chirho {
            ShardSetOpChirho::DeclareChirho { shards_chirho } => {
                if sets_chirho.contains_key(&key_chirho) {
                    bail!(
                        "shard set for {}/{} already declared (first declaration wins)",
                        key_chirho.0,
                        key_chirho.1
                    );
                }
                sets_chirho.insert(key_chirho, shards_chirho.clone());
            }
            ShardSetOpChirho::AmendChirho { shards_chirho } => {
                let Some(current_chirho) = sets_chirho.get_mut(&key_chirho) else {
                    bail!(
                        "amend of undeclared shard set {}/{}",
                        key_chirho.0,
                        key_chirho.1
                    );
                };
                *current_chirho = shards_chirho.clone();
            }
        }
        records_chirho.push(record_chirho);
    }
    Ok(VerifiedShardSetsChirho {
        records_chirho,
        tail_digest_hex_chirho,
        sets_chirho,
    })
}

/// Append one owner-signed shard-set op (verified load first; the fold precondition previews).
pub fn append_shard_set_op_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    owner_root_chirho: &dyn LedgerSignerPortChirho,
    path_chirho: &StoragePathChirho,
    shard_log_id_chirho: &str,
    owner_chirho: &str,
    kind_chirho: &str,
    op_chirho: ShardSetOpChirho,
) -> Result<ShardSetRecordChirho> {
    let verified_chirho = load_shard_sets_chirho(
        storage_chirho,
        owner_root_chirho,
        path_chirho,
        shard_log_id_chirho,
    )?;
    let key_declared_chirho = verified_chirho
        .sets_chirho
        .contains_key(&(owner_chirho.to_owned(), kind_chirho.to_owned()));
    match &op_chirho {
        ShardSetOpChirho::DeclareChirho { .. } if key_declared_chirho => {
            bail!("shard set for {owner_chirho}/{kind_chirho} already declared");
        }
        ShardSetOpChirho::AmendChirho { .. } if !key_declared_chirho => {
            bail!("amend of undeclared shard set {owner_chirho}/{kind_chirho}");
        }
        _ => {}
    }
    let mut record_chirho = ShardSetRecordChirho {
        schema_chirho: SHARD_SET_SCHEMA_V1_CHIRHO.to_string(),
        seq_chirho: verified_chirho.records_chirho.len() as u64,
        prev_chirho: verified_chirho.tail_digest_hex_chirho.clone(),
        shard_log_id_chirho: shard_log_id_chirho.to_string(),
        owner_chirho: owner_chirho.to_string(),
        kind_chirho: kind_chirho.to_string(),
        op_chirho,
        owner_sig_chirho: String::new(),
    };
    let signed_content_chirho = shard_set_signed_content_chirho(&record_chirho)?;
    record_chirho.owner_sig_chirho = owner_root_chirho
        .sign_chirho(&signed_content_chirho)
        .map_err(|error_chirho| anyhow!("sign shard-set record: {error_chirho}"))?;
    let line_chirho = canonical_shard_set_line_chirho(&record_chirho)?;
    let mut bytes_chirho = line_chirho.into_bytes();
    bytes_chirho.push(b'\n');
    storage_chirho
        .append_durable_chirho(path_chirho, &bytes_chirho)
        .map_err(|error_chirho| anyhow!("append shard-set record: {error_chirho}"))?;
    Ok(record_chirho)
}

/// C3 router discipline: pick the shard for the NEXT credit by rotation over the DECLARED set.
/// Pure: same (declaration, counter) → same shard; the counter is the caller's fan-out sequence.
pub fn route_credit_shard_chirho<'sets_chirho>(
    sets_chirho: &'sets_chirho VerifiedShardSetsChirho,
    owner_chirho: &str,
    kind_chirho: &str,
    counter_chirho: u64,
) -> Result<&'sets_chirho str> {
    let shards_chirho = sets_chirho
        .shards_chirho(owner_chirho, kind_chirho)
        .ok_or_else(|| anyhow!("no declared shard set for {owner_chirho}/{kind_chirho}"))?;
    let index_chirho = (counter_chirho % shards_chirho.len() as u64) as usize;
    Ok(&shards_chirho[index_chirho])
}

/// The LOGICAL aggregate (parent + DECLARED shards only — C1: an undeclared look-alike name is
/// invisible no matter what it is called). Pure over the journal's verified head states.
pub fn logical_net_chirho(
    sets_chirho: &VerifiedShardSetsChirho,
    head_states_chirho: &BTreeMap<
        cairn_ledger_model_chirho::ids_chirho::AccountIdChirho,
        cairn_ledger_model_chirho::record_chirho::LegPostStateChirho,
    >,
    owner_chirho: &str,
    kind_chirho: &str,
) -> i128 {
    let net_of_chirho = |name_chirho: &str| -> i128 {
        head_states_chirho
            .iter()
            .filter(|(account_chirho, _)| {
                account_chirho.owner_chirho == name_chirho
                    && account_chirho.kind_id_chirho.0 == kind_chirho
            })
            .map(|(_, post_chirho)| {
                i128::from(post_chirho.credits_total_chirho)
                    - i128::from(post_chirho.debits_total_chirho)
            })
            .sum()
    };
    let mut total_chirho = net_of_chirho(owner_chirho);
    if let Some(shards_chirho) = sets_chirho.shards_chirho(owner_chirho, kind_chirho) {
        for shard_chirho in shards_chirho {
            total_chirho += net_of_chirho(shard_chirho);
        }
    }
    total_chirho
}
