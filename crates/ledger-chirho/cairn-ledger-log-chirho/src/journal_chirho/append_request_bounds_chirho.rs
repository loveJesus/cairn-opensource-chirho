// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Request-sized-allocation-free, fixed-work admission bounds for borrowed append requests.
//!
//! These limits govern new engine requests only. They do not narrow the accepted language of
//! already-persisted `ledger-record-v1-chirho` bytes.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-a6-money-election-design-chirho.md`.

use super::{AppendLegRequestChirho, AppendRequestChirho, JournalErrorChirho};
use cairn_ledger_model_chirho::counterpart_chirho::{CounterpartClaimChirho, FinalBurnRefChirho};
use cairn_ledger_model_chirho::ids_chirho::AccountIdChirho;
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, EscrowControlChirho, HlcChirho, LedgerOpChirho, LegDeltaChirho,
};
use std::io::Write;

/// Maximum legs accepted in one new append request.
pub const MAX_APPEND_REQUEST_LEGS_CHIRHO: usize = 256;
/// Maximum JSON bytes inspected before any caller field is cloned.
pub const MAX_APPEND_REQUEST_BYTES_CHIRHO: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendRequestBoundDimensionChirho {
    LegsChirho,
    EncodedBytesChirho,
}

struct AppendRequestByteCounterChirho {
    written_chirho: usize,
    exceeded_chirho: bool,
}

impl AppendRequestByteCounterChirho {
    fn new_chirho() -> Self {
        Self {
            written_chirho: 0,
            exceeded_chirho: false,
        }
    }
}

impl Write for AppendRequestByteCounterChirho {
    fn write(&mut self, bytes_chirho: &[u8]) -> std::io::Result<usize> {
        let remaining_chirho = MAX_APPEND_REQUEST_BYTES_CHIRHO.saturating_sub(self.written_chirho);
        if bytes_chirho.len() > remaining_chirho {
            self.exceeded_chirho = true;
            return Err(std::io::Error::other(
                "AppendRequestEncodedBytesBoundsChirho",
            ));
        }
        self.written_chirho += bytes_chirho.len();
        Ok(bytes_chirho.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn append_request_byte_bound_error_chirho() -> JournalErrorChirho {
    JournalErrorChirho::AppendRequestBoundsChirho {
        dimension_chirho: AppendRequestBoundDimensionChirho::EncodedBytesChirho,
        observed_at_least_chirho: MAX_APPEND_REQUEST_BYTES_CHIRHO + 1,
        maximum_chirho: MAX_APPEND_REQUEST_BYTES_CHIRHO,
    }
}

fn add_append_request_string_bytes_chirho(
    total_chirho: &mut usize,
    value_chirho: &str,
) -> Result<(), JournalErrorChirho> {
    *total_chirho = total_chirho.saturating_add(value_chirho.len());
    if *total_chirho > MAX_APPEND_REQUEST_BYTES_CHIRHO {
        return Err(append_request_byte_bound_error_chirho());
    }
    Ok(())
}

fn add_append_request_account_bytes_chirho(
    total_chirho: &mut usize,
    account_chirho: &AccountIdChirho,
) -> Result<(), JournalErrorChirho> {
    let cairn_ledger_model_chirho::LogIdChirho {
        owner_chirho,
        kind_id_chirho,
    } = account_chirho;
    add_append_request_string_bytes_chirho(total_chirho, owner_chirho)?;
    add_append_request_string_bytes_chirho(total_chirho, &kind_id_chirho.0)
}

fn add_append_request_counterpart_bytes_chirho(
    total_chirho: &mut usize,
    counterpart_chirho: &CounterpartClaimChirho,
) -> Result<(), JournalErrorChirho> {
    let CounterpartClaimChirho {
        transfer_id_chirho,
        burn_chirho,
        amount_chirho: _,
        kind_policy_ref_chirho,
        src_chirho,
        dst_money_group_chirho,
        dst_cluster_chirho,
        dst_chirho,
        channel_chirho,
        nullifier_chirho,
    } = counterpart_chirho;
    let FinalBurnRefChirho {
        source_money_group_chirho,
        source_cluster_chirho,
        source_epoch_chirho: _,
        source_seq_chirho: _,
        source_record_digest_chirho,
        finality_proof_ref_chirho,
    } = burn_chirho;
    add_append_request_string_bytes_chirho(total_chirho, &transfer_id_chirho.0)?;
    add_append_request_string_bytes_chirho(total_chirho, &source_money_group_chirho.0)?;
    add_append_request_string_bytes_chirho(total_chirho, &source_cluster_chirho.0)?;
    add_append_request_string_bytes_chirho(total_chirho, &source_record_digest_chirho.0)?;
    add_append_request_string_bytes_chirho(total_chirho, &finality_proof_ref_chirho.0)?;
    add_append_request_string_bytes_chirho(total_chirho, &kind_policy_ref_chirho.0 .0)?;
    add_append_request_account_bytes_chirho(total_chirho, src_chirho)?;
    add_append_request_string_bytes_chirho(total_chirho, &dst_money_group_chirho.0)?;
    add_append_request_string_bytes_chirho(total_chirho, &dst_cluster_chirho.0)?;
    add_append_request_account_bytes_chirho(total_chirho, dst_chirho)?;
    add_append_request_string_bytes_chirho(total_chirho, &channel_chirho.0)?;
    add_append_request_string_bytes_chirho(total_chirho, &nullifier_chirho.0 .0)
}

fn validate_append_request_raw_string_bytes_chirho(
    request_chirho: &AppendRequestChirho,
) -> Result<(), JournalErrorChirho> {
    let AppendRequestChirho {
        op_chirho,
        legs_chirho,
        idempotency_key_chirho,
        provenance_chirho,
        attribution_chirho,
    } = request_chirho;
    let mut total_chirho = 0usize;
    add_append_request_string_bytes_chirho(&mut total_chirho, idempotency_key_chirho)?;
    if let Some(provenance_chirho) = provenance_chirho {
        add_append_request_string_bytes_chirho(&mut total_chirho, &provenance_chirho.0)?;
    }
    match attribution_chirho {
        AttributionChirho::CauserChirho { principal_chirho } => {
            add_append_request_string_bytes_chirho(&mut total_chirho, principal_chirho)?;
        }
        AttributionChirho::PlatformChirho => {}
        AttributionChirho::PolicyChirho { policy_ref_chirho } => {
            add_append_request_string_bytes_chirho(&mut total_chirho, &policy_ref_chirho.0)?;
        }
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
                step_chirho: _,
            } = control_chirho;
            add_append_request_string_bytes_chirho(&mut total_chirho, &saga_id_chirho.0)?;
        }
        LedgerOpChirho::CompensationChirho { of_chirho } => {
            add_append_request_string_bytes_chirho(&mut total_chirho, &of_chirho.0)?;
        }
        LedgerOpChirho::MintChirho {
            authority_evidence_chirho,
        }
        | LedgerOpChirho::BurnChirho {
            authority_evidence_chirho,
        } => {
            add_append_request_string_bytes_chirho(
                &mut total_chirho,
                &authority_evidence_chirho.0,
            )?;
        }
        LedgerOpChirho::TimerChirho {
            fires_at_hlc_chirho,
            purpose_chirho,
        } => {
            let HlcChirho {
                physical_ms_chirho: _,
                logical_chirho: _,
            } = fires_at_hlc_chirho;
            add_append_request_string_bytes_chirho(&mut total_chirho, purpose_chirho)?;
        }
    }
    for leg_chirho in legs_chirho {
        let AppendLegRequestChirho {
            account_chirho,
            kind_policy_ref_chirho,
            delta_chirho,
            amount_chirho: _,
            counterpart_chirho,
        } = leg_chirho;
        match delta_chirho {
            LegDeltaChirho::CreditChirho
            | LegDeltaChirho::DebitChirho
            | LegDeltaChirho::HoldChirho
            | LegDeltaChirho::ReleaseChirho
            | LegDeltaChirho::FinalizeChirho => {}
        }
        add_append_request_account_bytes_chirho(&mut total_chirho, account_chirho)?;
        add_append_request_string_bytes_chirho(&mut total_chirho, &kind_policy_ref_chirho.0 .0)?;
        if let Some(counterpart_chirho) = counterpart_chirho {
            add_append_request_counterpart_bytes_chirho(&mut total_chirho, counterpart_chirho)?;
        }
    }
    Ok(())
}

pub(super) fn validate_append_request_bounds_chirho(
    request_chirho: &AppendRequestChirho,
) -> Result<(), JournalErrorChirho> {
    if request_chirho.legs_chirho.len() > MAX_APPEND_REQUEST_LEGS_CHIRHO {
        return Err(JournalErrorChirho::AppendRequestBoundsChirho {
            dimension_chirho: AppendRequestBoundDimensionChirho::LegsChirho,
            observed_at_least_chirho: request_chirho.legs_chirho.len(),
            maximum_chirho: MAX_APPEND_REQUEST_LEGS_CHIRHO,
        });
    }
    // `serde_json` may scan a complete string before the writer sees a chunk. Count every borrowed
    // string by O(1) `str::len` first, exhaustively over the request shape, so serialization never
    // processes or allocates request-sized caller text before the streaming cap can fire.
    validate_append_request_raw_string_bytes_chirho(request_chirho)?;
    let mut counter_chirho = AppendRequestByteCounterChirho::new_chirho();
    match serde_json::to_writer(&mut counter_chirho, request_chirho) {
        Ok(()) => Ok(()),
        Err(_error_chirho) if counter_chirho.exceeded_chirho => {
            Err(append_request_byte_bound_error_chirho())
        }
        Err(error_chirho) => Err(JournalErrorChirho::AppendRequestPreflightChirho {
            detail_chirho: error_chirho.to_string(),
        }),
    }
}
