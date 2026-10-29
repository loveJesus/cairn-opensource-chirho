// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Phase 1 of the batch-first Subscribe workflow:
//! `spec-chirho/workflows-chirho/subscribe-primitive-chirho/subscribe-primitive-design-chirho.md`.
//!
//! This crate is an in-memory, read-only dispatch skeleton. It reads one verified source tail per
//! tick and fans opaque invalidations through one index pass. It does not provide a daemon,
//! transport, durable cursor, authorization surface, or authority mutation.

#[cfg(test)]
mod tests_chirho;

use anyhow::{bail, Result};
use cairn_core_chirho::{cas_chirho, model_chirho::HashChirho};
use cairn_gate1_authority_log_chirho::authority_log_chirho::verified_gate1_authority_records_chirho;
use cairn_model_gate1_chirho::{
    Gate1AuthorityLogRecordChirho, GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO,
    GATE1_BILLING_POLICIES_FAMILY_CHIRHO, GATE1_BILLING_USAGE_FAMILY_CHIRHO,
    GATE1_CREDIT_HOLDS_FAMILY_CHIRHO, GATE1_LEDGER_FAMILY_CHIRHO,
    GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO, GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO,
    GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const GATE1_DEPENDENCY_KEY_PREFIX_CHIRHO: &str = "gate1-group-dependency-v1-chirho:";
const GATE1_LEDGER_GROUP_CHIRHO: &str = "ledger-chirho";
const GATE1_HOLDS_GROUP_CHIRHO: &str = "holds-chirho";
const GATE1_RESOURCES_GROUP_CHIRHO: &str = "resources-chirho";
const GATE1_BILLING_GROUP_CHIRHO: &str = "billing-chirho";

/// Opaque invalidation identity shared by subscription, render-input, and cache-invalidation views.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueDependencyKeyChirho(HashChirho);

impl OpaqueDependencyKeyChirho {
    pub fn as_hash_chirho(&self) -> &HashChirho {
        &self.0
    }
}

/// One owned dependency set. All three role accessors borrow this same field without cloning.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewDependencySetChirho {
    keys_chirho: BTreeSet<OpaqueDependencyKeyChirho>,
}

impl ViewDependencySetChirho {
    pub fn gate1_group_chirho(family_chirho: &str) -> Result<Self> {
        Ok(Self {
            keys_chirho: BTreeSet::from([gate1_dependency_key_chirho(family_chirho)?]),
        })
    }

    pub fn subscription_dependencies_chirho(&self) -> &BTreeSet<OpaqueDependencyKeyChirho> {
        &self.keys_chirho
    }

    pub fn render_dag_inputs_chirho(&self) -> &BTreeSet<OpaqueDependencyKeyChirho> {
        &self.keys_chirho
    }

    pub fn cache_invalidation_keys_chirho(&self) -> &BTreeSet<OpaqueDependencyKeyChirho> {
        &self.keys_chirho
    }
}

/// Root-local Gate 1 cursor. The value is the next authority sequence to observe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gate1AuthorityCursorChirho {
    pub next_authority_seq_chirho: u64,
}

/// Server-minted subscription identity. Its inner value cannot be supplied by a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionIdChirho(u64);

impl SubscriptionIdChirho {
    pub fn value_chirho(self) -> u64 {
        self.0
    }
}

/// Deterministic, monotonic subscription-id issuer for one in-memory dispatcher lifecycle.
#[derive(Clone, Debug, Default)]
pub struct SubscriptionIdIssuerChirho {
    next_id_chirho: u64,
}

impl SubscriptionIdIssuerChirho {
    pub fn mint_chirho(&mut self) -> Result<SubscriptionIdChirho> {
        let id_chirho = SubscriptionIdChirho(self.next_id_chirho);
        self.next_id_chirho = self
            .next_id_chirho
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("subscription id space exhausted"))?;
        Ok(id_chirho)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceTailEventChirho {
    pub dependency_key_chirho: OpaqueDependencyKeyChirho,
    pub authority_seq_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceTailBatchChirho {
    pub events_chirho: Vec<SourceTailEventChirho>,
    pub next_cursor_chirho: Gate1AuthorityCursorChirho,
}

/// A source adapter performs one root-local tail read for one dispatcher tick.
pub trait SourceTailReaderChirho {
    fn read_after_chirho(
        &mut self,
        cursor_chirho: Gate1AuthorityCursorChirho,
    ) -> Result<SourceTailBatchChirho>;
}

/// Verified Gate 1 source adapter. It never parses or trusts raw authority-log records.
#[derive(Clone, Debug)]
pub struct Gate1AuthorityTailReaderChirho {
    root_chirho: PathBuf,
}

impl Gate1AuthorityTailReaderChirho {
    pub fn new_chirho(root_chirho: &Path) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
        }
    }
}

impl SourceTailReaderChirho for Gate1AuthorityTailReaderChirho {
    fn read_after_chirho(
        &mut self,
        cursor_chirho: Gate1AuthorityCursorChirho,
    ) -> Result<SourceTailBatchChirho> {
        let verified_records_chirho = verified_gate1_authority_records_chirho(&self.root_chirho)?;
        gate1_tail_batch_from_records_chirho(
            verified_records_chirho.records_chirho(),
            cursor_chirho,
        )
    }
}

/// In-memory dependency-key index. Registration accepts reviewed dependency sets, not topic text.
#[derive(Clone, Debug, Default)]
pub struct DispatchIndexChirho {
    subscriptions_by_key_chirho:
        BTreeMap<OpaqueDependencyKeyChirho, BTreeSet<SubscriptionIdChirho>>,
    cursors_by_subscription_chirho: BTreeMap<SubscriptionIdChirho, Gate1AuthorityCursorChirho>,
}

impl DispatchIndexChirho {
    pub fn register_chirho(
        &mut self,
        subscription_id_chirho: SubscriptionIdChirho,
        dependency_set_chirho: &ViewDependencySetChirho,
    ) {
        self.register_at_cursor_chirho(
            subscription_id_chirho,
            dependency_set_chirho,
            Gate1AuthorityCursorChirho::default(),
        );
    }

    pub fn register_at_cursor_chirho(
        &mut self,
        subscription_id_chirho: SubscriptionIdChirho,
        dependency_set_chirho: &ViewDependencySetChirho,
        cursor_chirho: Gate1AuthorityCursorChirho,
    ) {
        self.cursors_by_subscription_chirho
            .insert(subscription_id_chirho, cursor_chirho);
        for dependency_key_chirho in dependency_set_chirho.subscription_dependencies_chirho() {
            self.subscriptions_by_key_chirho
                .entry(dependency_key_chirho.clone())
                .or_default()
                .insert(subscription_id_chirho);
        }
    }

    pub fn cursor_chirho(
        &self,
        subscription_id_chirho: SubscriptionIdChirho,
    ) -> Option<Gate1AuthorityCursorChirho> {
        self.cursors_by_subscription_chirho
            .get(&subscription_id_chirho)
            .copied()
    }
}

/// Private-safe tick result: opaque keys, server ids, counts, and cursor only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchTickChirho {
    pub source_reads_chirho: u64,
    pub dispatch_passes_chirho: u64,
    pub matched_keys_chirho: BTreeSet<OpaqueDependencyKeyChirho>,
    pub invalidated_subscriptions_chirho: BTreeSet<SubscriptionIdChirho>,
    pub next_cursor_chirho: Gate1AuthorityCursorChirho,
}

/// Private-safe heterogeneous tick result over server-side in-memory cursors only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeterogeneousDispatchTickChirho {
    pub source_reads_chirho: u64,
    pub dispatch_passes_chirho: u64,
    pub matched_keys_chirho: BTreeSet<OpaqueDependencyKeyChirho>,
    pub invalidated_subscriptions_chirho: BTreeSet<SubscriptionIdChirho>,
    pub next_cursors_by_subscription_chirho:
        BTreeMap<SubscriptionIdChirho, Gate1AuthorityCursorChirho>,
    pub resnapshot_required_subscriptions_chirho: BTreeSet<SubscriptionIdChirho>,
}

#[derive(Clone, Debug, Default)]
pub struct SubscriptionDispatcherChirho;

impl SubscriptionDispatcherChirho {
    pub fn tick_chirho<RChirho: SourceTailReaderChirho>(
        &self,
        reader_chirho: &mut RChirho,
        index_chirho: &DispatchIndexChirho,
        cursor_chirho: Gate1AuthorityCursorChirho,
    ) -> Result<DispatchTickChirho> {
        let batch_chirho = reader_chirho.read_after_chirho(cursor_chirho)?;
        let mut matched_keys_chirho = BTreeSet::new();
        let mut invalidated_subscriptions_chirho = BTreeSet::new();
        for event_chirho in batch_chirho.events_chirho {
            if let Some(subscription_ids_chirho) = index_chirho
                .subscriptions_by_key_chirho
                .get(&event_chirho.dependency_key_chirho)
            {
                matched_keys_chirho.insert(event_chirho.dependency_key_chirho);
                invalidated_subscriptions_chirho.extend(subscription_ids_chirho);
            }
        }
        Ok(DispatchTickChirho {
            source_reads_chirho: 1,
            dispatch_passes_chirho: 1,
            matched_keys_chirho,
            invalidated_subscriptions_chirho,
            next_cursor_chirho: batch_chirho.next_cursor_chirho,
        })
    }

    /// One shared verified read and one dispatch pass for server-side heterogeneous cursors.
    pub fn tick_heterogeneous_chirho<RChirho: SourceTailReaderChirho>(
        &self,
        reader_chirho: &mut RChirho,
        index_chirho: &mut DispatchIndexChirho,
    ) -> Result<HeterogeneousDispatchTickChirho> {
        let minimum_cursor_chirho = index_chirho
            .cursors_by_subscription_chirho
            .values()
            .copied()
            .min_by_key(|cursor_chirho| cursor_chirho.next_authority_seq_chirho)
            .unwrap_or_default();
        let batch_chirho = reader_chirho.read_after_chirho(minimum_cursor_chirho)?;
        let verified_cut_chirho = batch_chirho.next_cursor_chirho;
        let mut next_cursors_by_subscription_chirho = BTreeMap::new();
        let mut resnapshot_required_subscriptions_chirho = BTreeSet::new();
        for (subscription_id_chirho, cursor_chirho) in &index_chirho.cursors_by_subscription_chirho
        {
            if cursor_chirho.next_authority_seq_chirho
                > verified_cut_chirho.next_authority_seq_chirho
            {
                resnapshot_required_subscriptions_chirho.insert(*subscription_id_chirho);
            } else {
                next_cursors_by_subscription_chirho
                    .insert(*subscription_id_chirho, verified_cut_chirho);
            }
        }

        let mut matched_keys_chirho = BTreeSet::new();
        let mut invalidated_subscriptions_chirho = BTreeSet::new();
        for event_chirho in batch_chirho.events_chirho {
            let Some(subscription_ids_chirho) = index_chirho
                .subscriptions_by_key_chirho
                .get(&event_chirho.dependency_key_chirho)
            else {
                continue;
            };
            let mut matched_chirho = false;
            for subscription_id_chirho in subscription_ids_chirho {
                if resnapshot_required_subscriptions_chirho.contains(subscription_id_chirho) {
                    continue;
                }
                let Some(cursor_chirho) = index_chirho
                    .cursors_by_subscription_chirho
                    .get(subscription_id_chirho)
                else {
                    continue;
                };
                if event_chirho.authority_seq_chirho >= cursor_chirho.next_authority_seq_chirho {
                    invalidated_subscriptions_chirho.insert(*subscription_id_chirho);
                    matched_chirho = true;
                }
            }
            if matched_chirho {
                matched_keys_chirho.insert(event_chirho.dependency_key_chirho);
            }
        }

        for (subscription_id_chirho, cursor_chirho) in &next_cursors_by_subscription_chirho {
            index_chirho
                .cursors_by_subscription_chirho
                .insert(*subscription_id_chirho, *cursor_chirho);
        }

        Ok(HeterogeneousDispatchTickChirho {
            source_reads_chirho: 1,
            dispatch_passes_chirho: 1,
            matched_keys_chirho,
            invalidated_subscriptions_chirho,
            next_cursors_by_subscription_chirho,
            resnapshot_required_subscriptions_chirho,
        })
    }
}

fn gate1_group_label_chirho(family_chirho: &str) -> Result<&'static str> {
    match family_chirho {
        GATE1_LEDGER_FAMILY_CHIRHO => Ok(GATE1_LEDGER_GROUP_CHIRHO),
        GATE1_CREDIT_HOLDS_FAMILY_CHIRHO => Ok(GATE1_HOLDS_GROUP_CHIRHO),
        GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO
        | GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO
        | GATE1_RESOURCE_USAGE_FAMILY_CHIRHO => Ok(GATE1_RESOURCES_GROUP_CHIRHO),
        GATE1_BILLING_POLICIES_FAMILY_CHIRHO
        | GATE1_BILLING_USAGE_FAMILY_CHIRHO
        | GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO => Ok(GATE1_BILLING_GROUP_CHIRHO),
        _ => bail!("unknown Gate 1 family for subscription dependency"),
    }
}

/// The hash input is a bounded public semantic-group label only. Record lines never reach it.
fn gate1_dependency_key_chirho(family_chirho: &str) -> Result<OpaqueDependencyKeyChirho> {
    let group_chirho = gate1_group_label_chirho(family_chirho)?;
    Ok(OpaqueDependencyKeyChirho(cas_chirho::hash_chirho(
        format!("{GATE1_DEPENDENCY_KEY_PREFIX_CHIRHO}{group_chirho}").as_bytes(),
    )))
}

fn gate1_tail_batch_from_records_chirho(
    records_chirho: &[Gate1AuthorityLogRecordChirho],
    cursor_chirho: Gate1AuthorityCursorChirho,
) -> Result<SourceTailBatchChirho> {
    let record_count_chirho = u64::try_from(records_chirho.len())?;
    if cursor_chirho.next_authority_seq_chirho > record_count_chirho {
        bail!(
            "Gate 1 subscription cursor {} exceeds verified authority length {}",
            cursor_chirho.next_authority_seq_chirho,
            record_count_chirho
        );
    }
    let start_chirho = usize::try_from(cursor_chirho.next_authority_seq_chirho)?;
    let mut events_chirho = Vec::with_capacity(records_chirho.len() - start_chirho);
    for (offset_chirho, record_chirho) in records_chirho[start_chirho..].iter().enumerate() {
        let expected_seq_chirho =
            cursor_chirho.next_authority_seq_chirho + u64::try_from(offset_chirho)?;
        if record_chirho.authority_seq_chirho != expected_seq_chirho {
            bail!(
                "non-dense verified Gate 1 authority sequence: expected {}, found {}",
                expected_seq_chirho,
                record_chirho.authority_seq_chirho
            );
        }
        events_chirho.push(SourceTailEventChirho {
            dependency_key_chirho: gate1_dependency_key_chirho(&record_chirho.family_chirho)?,
            authority_seq_chirho: record_chirho.authority_seq_chirho,
        });
    }
    Ok(SourceTailBatchChirho {
        events_chirho,
        next_cursor_chirho: Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: record_count_chirho,
        },
    })
}
