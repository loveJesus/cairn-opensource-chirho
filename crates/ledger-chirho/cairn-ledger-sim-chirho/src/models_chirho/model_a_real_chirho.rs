// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Model A-REAL — the epoch fence model-checked OVER THE REAL ENGINE (the 2.1 re-point off the
//! toy): the state is nothing but the DURABLE JOURNAL BYTES (+ the lease authority's grant), and
//! every transition drives `LedgerJournalChirho` itself — open (so REAL recovery runs on every
//! step), advance, append, snapshot. The checked transition function IS the production code, not
//! an abstract mirror of it.
//!
//! Properties across every interleaving (small-N exhaustive):
//! - **AR1 (detection, always)** — an unpoisoned journal always OPENS verified; after a stale-writer
//!   tail-replay splice (the simplest split-brain write: a superseded writer's line landing on a
//!   moved journal) the open always FAILS TYPED. Fail-closed: corruption can never be read as money.
//! - **AR2 (no forged-future epoch, always)** — no recorded epoch ever exceeds the authority's
//!   grant (the engine can only advance through the granted lease).
//! - **AR3 (monotone recorded epochs, always)** — enforced by re-verifying the REAL chain on every
//!   state (open performs the §11.5 anchor/monotonicity law).
//! - **AR-live (sometimes)** — a run reaches the op bound across multiple grants (the fences are
//!   not vacuously safe by refusing everything).
//!
//! The two-live-writers FORK interleave (two engines diverging from one snapshot) explores as two
//! branches here (each internally lawful); the cross-branch splice detection is exactly AR1. The
//! richer concurrent-fork model composes with A6's election (CF8), not with CF1's single-writer
//! lock.

use crate::fault_chirho::FaultPlanChirho;
use crate::storage_chirho::SimStorageChirho;
use anyhow::Result;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
    MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerSignerPortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use stateright::{Model, Property};
use std::collections::BTreeMap;

const MONEY_KIND_CHIRHO: &str = "money-chirho";
const MONEY_POLICY_REF_CHIRHO: &str = "policy-money-v1-chirho";
const MINT_EVIDENCE_CHIRHO: &str = "evidence-good-mint-chirho";

struct FixedClockChirho {
    now_ms_chirho: u64,
}

impl LedgerClockPortChirho for FixedClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.now_ms_chirho
    }
}

struct FakeSignerChirho;

impl LedgerSignerPortChirho for FakeSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(format!(
            "fake-sig-{}",
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        "model-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

struct AllMembersChirho;

impl MembershipViewChirho for AllMembersChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::MemberChirho
    }
}

struct MoneyRegistryChirho;

impl KindRegistryViewChirho for MoneyRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        (policy_ref_chirho.0 .0 == MONEY_POLICY_REF_CHIRHO)
            .then(|| KindPolicyViewChirho {
                kind_id_chirho: MONEY_KIND_CHIRHO.into(),
                mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                    max_supply_chirho: None,
                },
                rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
                settlement_owner_chirho: None,
                idempotency_window_chirho: None,
            })
            .map_or(
                KindResolutionChirho::UnknownChirho,
                KindResolutionChirho::CurrentChirho,
            )
    }
}

struct OpenAuthorityChirho;

impl AuthorityVerifierViewChirho for OpenAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        if evidence_chirho.0 == MINT_EVIDENCE_CHIRHO {
            AuthorityVerdictChirho::VerifiedChirho
        } else {
            AuthorityVerdictChirho::UnverifiedChirho
        }
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }
}

fn path_chirho() -> StoragePathChirho {
    StoragePathChirho::new_chirho("journals/model-a-real-chirho.jsonl")
}

fn cluster_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-model-chirho".into())
}

/// Run `operate` on a REAL engine reconstructed from `bytes` (a fresh open = real recovery), then
/// return the resulting durable bytes. `None` if open or the operation refused.
fn with_real_engine_chirho(
    bytes_chirho: &[u8],
    ops_so_far_chirho: u64,
    operate_chirho: impl FnOnce(&mut LedgerJournalChirho<'_>) -> bool,
) -> Option<Vec<u8>> {
    let mut snapshot_chirho = BTreeMap::new();
    snapshot_chirho.insert(path_chirho().0, bytes_chirho.to_vec());
    let storage_chirho =
        SimStorageChirho::restore_chirho(snapshot_chirho, FaultPlanChirho::none_chirho());
    // Deterministic per-state clock: strictly ahead of every recorded HLC (ops are 100ms apart).
    let clock_chirho = FixedClockChirho {
        now_ms_chirho: 1_000 + (ops_so_far_chirho + 1) * 100,
    };
    let signer_chirho = FakeSignerChirho;
    let membership_chirho = AllMembersChirho;
    let registry_chirho = MoneyRegistryChirho;
    let authority_chirho = OpenAuthorityChirho;
    let ports_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let mut engine_chirho =
        LedgerJournalChirho::open_chirho(ports_chirho, path_chirho(), &cluster_chirho()).ok()?;
    if !operate_chirho(&mut engine_chirho) {
        return None;
    }
    drop(engine_chirho);
    storage_chirho.snapshot_chirho().remove(&path_chirho().0)
}

/// Does the journal OPEN verified? (The AR1 detection predicate — real open, real chain law.)
fn opens_verified_chirho(bytes_chirho: &[u8]) -> bool {
    let mut snapshot_chirho = BTreeMap::new();
    snapshot_chirho.insert(path_chirho().0, bytes_chirho.to_vec());
    let storage_chirho =
        SimStorageChirho::restore_chirho(snapshot_chirho, FaultPlanChirho::none_chirho());
    let clock_chirho = FixedClockChirho { now_ms_chirho: 0 };
    let signer_chirho = FakeSignerChirho;
    let membership_chirho = AllMembersChirho;
    let registry_chirho = MoneyRegistryChirho;
    let authority_chirho = OpenAuthorityChirho;
    let ports_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &registry_chirho,
        authority_chirho: &authority_chirho,
    };
    LedgerJournalChirho::open_chirho(ports_chirho, path_chirho(), &cluster_chirho()).is_ok()
}

/// The max recorded epoch in the journal bytes (0 if none) — read via the REAL parser-verified
/// open; `None` when the journal does not verify.
fn max_recorded_epoch_chirho(bytes_chirho: &[u8]) -> Option<ShardEpochChirho> {
    let mut snapshot_chirho = BTreeMap::new();
    snapshot_chirho.insert(path_chirho().0, bytes_chirho.to_vec());
    let storage_chirho =
        SimStorageChirho::restore_chirho(snapshot_chirho, FaultPlanChirho::none_chirho());
    let clock_chirho = FixedClockChirho { now_ms_chirho: 0 };
    let signer_chirho = FakeSignerChirho;
    let membership_chirho = AllMembersChirho;
    let registry_chirho = MoneyRegistryChirho;
    let authority_chirho = OpenAuthorityChirho;
    let ports_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &registry_chirho,
        authority_chirho: &authority_chirho,
    };
    LedgerJournalChirho::open_chirho(ports_chirho, path_chirho(), &cluster_chirho())
        .ok()
        .map(|engine_chirho| engine_chirho.current_epoch_chirho())
}

/// The model state: the DURABLE journal bytes + the lease authority's grant + bookkeeping. A
/// poisoned state remembers that a stale splice landed (AR1 requires its open to FAIL).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateARealChirho {
    pub journal_bytes_chirho: Vec<u8>,
    pub granted_epoch_chirho: ShardEpochChirho,
    pub ops_chirho: u64,
    pub poisoned_chirho: bool,
}

/// The transitions: the authority grants; the (single) writer appends under the granted lease
/// (advancing first when the grant moved); a superseded writer's tail-replay lands on the journal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ActionARealChirho {
    GrantChirho,
    AppendUnderGrantChirho,
    StaleTailReplayChirho,
}

/// Bounded model config (small-N exhaustive; every transition runs the REAL engine).
pub struct ModelARealChirho {
    pub max_epoch_chirho: ShardEpochChirho,
    pub max_ops_chirho: u64,
}

impl ModelARealChirho {
    fn genesis_bytes_chirho() -> Vec<u8> {
        let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        let clock_chirho = FixedClockChirho {
            now_ms_chirho: 1_000,
        };
        let signer_chirho = FakeSignerChirho;
        let membership_chirho = AllMembersChirho;
        let registry_chirho = MoneyRegistryChirho;
        let authority_chirho = OpenAuthorityChirho;
        let ports_chirho = JournalPortsChirho {
            storage_chirho: &storage_chirho,
            signer_chirho: &signer_chirho,
            clock_chirho: &clock_chirho,
            membership_chirho: &membership_chirho,
            kind_registry_chirho: &registry_chirho,
            authority_chirho: &authority_chirho,
        };
        LedgerJournalChirho::create_chirho(ports_chirho, path_chirho(), cluster_chirho(), 1)
            .expect("genesis creation");
        storage_chirho
            .snapshot_chirho()
            .remove(&path_chirho().0)
            .expect("genesis bytes")
    }
}

fn unit_mint_chirho(ops_chirho: u64) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho(MINT_EVIDENCE_CHIRHO.into()),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: LogIdChirho::new_chirho("issuer-chirho", MONEY_KIND_CHIRHO),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                MONEY_POLICY_REF_CHIRHO.into(),
            )),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho: 1,
            counterpart_chirho: None,
        }],
        idempotency_key_chirho: format!("idem-model-{ops_chirho}-chirho"),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

impl Model for ModelARealChirho {
    type State = StateARealChirho;
    type Action = ActionARealChirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateARealChirho {
            journal_bytes_chirho: Self::genesis_bytes_chirho(),
            granted_epoch_chirho: 1,
            ops_chirho: 0,
            poisoned_chirho: false,
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        if state.poisoned_chirho {
            // A poisoned journal is terminal in the model: AR1 asserts its open FAILS; there is no
            // lawful continuation to explore past detected corruption.
            return;
        }
        if state.granted_epoch_chirho < self.max_epoch_chirho {
            actions.push(ActionARealChirho::GrantChirho);
        }
        if state.ops_chirho < self.max_ops_chirho {
            actions.push(ActionARealChirho::AppendUnderGrantChirho);
        }
        // The stale replay needs at least one RECORD line to replay (genesis + 1).
        if state.ops_chirho > 0 {
            actions.push(ActionARealChirho::StaleTailReplayChirho);
        }
    }

    fn next_state(&self, state: &Self::State, action: Self::Action) -> Option<Self::State> {
        match action {
            ActionARealChirho::GrantChirho => Some(StateARealChirho {
                granted_epoch_chirho: state.granted_epoch_chirho + 1,
                ..state.clone()
            }),
            ActionARealChirho::AppendUnderGrantChirho => {
                let granted_chirho = state.granted_epoch_chirho;
                let ops_chirho = state.ops_chirho;
                let new_bytes_chirho = with_real_engine_chirho(
                    &state.journal_bytes_chirho,
                    ops_chirho,
                    |engine_chirho| {
                        if engine_chirho.current_epoch_chirho() < granted_chirho
                            && engine_chirho.advance_epoch_chirho(granted_chirho).is_err()
                        {
                            return false;
                        }
                        engine_chirho
                            .append_chirho(unit_mint_chirho(ops_chirho))
                            .is_ok()
                    },
                )?;
                Some(StateARealChirho {
                    journal_bytes_chirho: new_bytes_chirho,
                    granted_epoch_chirho: state.granted_epoch_chirho,
                    ops_chirho: state.ops_chirho + 1,
                    poisoned_chirho: false,
                })
            }
            ActionARealChirho::StaleTailReplayChirho => {
                // The simplest superseded-writer write: the journal's own last record line lands
                // AGAIN (a writer that saw the pre-append tail re-sends its append). The engine's
                // dense-seq/prev chain law must make the result UNREADABLE (AR1), never silently
                // fold it twice (that would be double-minted money).
                let text_chirho = String::from_utf8(state.journal_bytes_chirho.clone()).ok()?;
                let last_line_chirho = text_chirho.lines().last()?.to_owned();
                let mut spliced_chirho = state.journal_bytes_chirho.clone();
                spliced_chirho.extend_from_slice(last_line_chirho.as_bytes());
                spliced_chirho.push(b'\n');
                Some(StateARealChirho {
                    journal_bytes_chirho: spliced_chirho,
                    granted_epoch_chirho: state.granted_epoch_chirho,
                    ops_chirho: state.ops_chirho,
                    poisoned_chirho: true,
                })
            }
        }
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always("ar1-detection-chirho", |_, state| {
                // Unpoisoned ⇒ the REAL open verifies; poisoned ⇒ the REAL open FAILS (fail-closed:
                // a stale-writer splice can never be read as money).
                opens_verified_chirho(&state.journal_bytes_chirho) != state.poisoned_chirho
            }),
            Property::<Self>::always("ar2-no-forged-future-epoch-chirho", |_, state| {
                if state.poisoned_chirho {
                    return true;
                }
                match max_recorded_epoch_chirho(&state.journal_bytes_chirho) {
                    Some(recorded_chirho) => recorded_chirho <= state.granted_epoch_chirho,
                    None => false,
                }
            }),
            Property::<Self>::sometimes("ar-live-full-run-chirho", |model_chirho: &Self, state| {
                state.ops_chirho == model_chirho.max_ops_chirho
                    && state.granted_epoch_chirho == model_chirho.max_epoch_chirho
            }),
            Property::<Self>::sometimes("ar-live-poisoned-reached-chirho", |_, state| {
                // The attack IS exercised (AR1 is not vacuous).
                state.poisoned_chirho
            }),
        ]
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use stateright::Checker;

    #[test]
    fn model_a_real_epoch_fence_holds_over_the_real_engine_chirho() {
        // Small-N exhaustive: 3 grants, 3 ops — every interleaving of grant/append/stale-replay
        // runs the REAL engine (open = real recovery on every transition).
        let checker_chirho = ModelARealChirho {
            max_epoch_chirho: 3,
            max_ops_chirho: 3,
        }
        .checker()
        .spawn_bfs()
        .join();
        checker_chirho.assert_properties();
    }
}
