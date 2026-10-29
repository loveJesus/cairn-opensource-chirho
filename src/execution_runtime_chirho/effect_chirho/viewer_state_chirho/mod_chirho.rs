// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Host-derived viewer state over the reviewed ReadStore/WriteStore effect doors.
//!
//! Workflow: `spec-chirho/workflows-chirho/viewer-state-authority-chirho/README-chirho.md`.

use super::{
    run_intent_chirho::current_run_intent_effect_invocation_chirho, ViewerStateActionChirho,
    ViewerStateConflictChirho, ViewerStateMutationReceiptChirho, ViewerStateRequestChirho,
    ViewerStateResponseChirho, ViewerStateVersionChirho,
};
use crate::model_chirho::{HashChirho, RequestContextChirho};
use crate::{app_chirho, seqlog_chirho, store_seal_chirho};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use cairn_signer_chirho::signer_chirho;
use cairn_store_redb_chirho::viewer_state_chirho::{
    ViewerStateEntryChirho, ViewerStateHeadChirho, ViewerStateHeadTransitionChirho,
    ViewerStateStoreChirho,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const VIEWER_STATE_REQUEST_SCHEMA_CHIRHO: &str = "viewer-state-request-v1-chirho";
pub const VIEWER_STATE_RESPONSE_SCHEMA_CHIRHO: &str = "viewer-state-response-v2-chirho";
pub const VIEWER_STATE_CONFLICT_SCHEMA_CHIRHO: &str = "viewer-state-conflict-v1-chirho";
pub const VIEWER_STATE_MUTATION_RECEIPT_SCHEMA_CHIRHO: &str =
    "viewer-state-mutation-receipt-v2-chirho";
pub const VIEWER_STATE_STORED_ROW_SCHEMA_CHIRHO: &str = "viewer-state-stored-row-v2-chirho";
pub const VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO: &str = "viewer-state-chirho/";
pub const VIEWER_STATE_HISTORY_LIMIT_CHIRHO: u64 = 16;
pub const VIEWER_STATE_MAX_KEYS_PER_VIEWER_CHIRHO: usize = 64;
pub const VIEWER_STATE_MAX_VALUE_BYTES_CHIRHO: usize = 16 * 1024;

const VIEWER_STATE_ACTOR_DIGEST_CONTEXT_CHIRHO: &str = "cairn-viewer-state-actor-v1-chirho";
const VIEWER_STATE_GENESIS_DIGEST_CONTEXT_CHIRHO: &str =
    "cairn-viewer-state-genesis-receipt-v1-chirho";
const VIEWER_STATE_KEY_DIGEST_CONTEXT_CHIRHO: &str = "cairn-viewer-state-key-v1-chirho";
const VIEWER_STATE_RECEIPT_DIGEST_CONTEXT_CHIRHO: &str = "cairn-viewer-state-receipt-v1-chirho";
const VIEWER_STATE_LOCK_CHIRHO: &str = "viewer-state-effect-chirho";
const VIEWER_STATE_MAX_LOGICAL_KEY_BYTES_CHIRHO: usize = 128;

pub(crate) fn viewer_state_capability_prefix_chirho() -> &'static str {
    VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO
}

/// The logical-key grammar, for a route opening's declared resources: the very check a request's key passes.
pub(crate) fn validate_viewer_state_logical_key_chirho(key_chirho: &str) -> Result<()> {
    validate_logical_key_chirho(key_chirho)
}

/// A limited key's request may touch only the logical keys its matched grant consented to, and never restores, since
/// restoration stays a human browser action. A request without a key limit (a browser session or a legacy key) is
/// unchanged. Checked after the request's shape and context, before any read or write.
/// Workflow: limited-key authority (K1),
/// `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.
fn enforce_key_limit_chirho(
    context_chirho: &RequestContextChirho,
    request_chirho: &ViewerStateRequestChirho,
) -> Result<()> {
    let Some(limit_chirho) = &context_chirho.key_limit_chirho else {
        return Ok(());
    };
    if request_chirho.action_chirho == ViewerStateActionChirho::RestoreChirho {
        bail!("a limited key may not restore a viewer-state version");
    }
    if !limit_chirho
        .resources_chirho
        .iter()
        .any(|resource_chirho| resource_chirho == &request_chirho.key_chirho)
    {
        bail!("a limited key's grant does not cover this viewer-state key");
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewerStateStoredRowChirho {
    schema_chirho: String,
    sealed_chirho: store_seal_chirho::SealedStoreValueChirho,
    receipt_chirho: ViewerStateMutationReceiptChirho,
}

#[derive(Debug)]
pub(super) struct ViewerStateEffectOutputChirho {
    pub response_chirho: Vec<u8>,
    pub private_subject_chirho: String,
}

pub(super) fn decode_request_chirho(
    request_bytes_chirho: &[u8],
) -> Result<Option<ViewerStateRequestChirho>> {
    let Ok(value_chirho) = serde_json::from_slice::<serde_json::Value>(request_bytes_chirho) else {
        return Ok(None);
    };
    let Some(schema_chirho) = value_chirho
        .get("schema_chirho")
        .and_then(|schema_chirho| schema_chirho.as_str())
    else {
        return Ok(None);
    };
    if schema_chirho != VIEWER_STATE_REQUEST_SCHEMA_CHIRHO {
        return Ok(None);
    }
    serde_json::from_value(value_chirho)
        .map(Some)
        .context("decode ViewerStateRequestChirho")
}

pub(super) fn reserved_capability_prefix_chirho(prefix_chirho: &str) -> bool {
    prefix_chirho.starts_with(VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO)
}

pub(super) fn response_subject_chirho(
    request_chirho: &ViewerStateRequestChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<String> {
    let context_chirho = require_context_chirho(request_context_chirho)?;
    validate_request_shape_chirho(request_chirho)?;
    let physical_key_chirho = physical_key_chirho(context_chirho, &request_chirho.key_chirho)?;
    store_seal_chirho::store_seal_subject_chirho(
        Some(&context_chirho.app_chirho),
        &physical_key_chirho,
    )
}

pub(super) fn run_read_chirho(
    root_chirho: &Path,
    capability_prefix_chirho: &str,
    request_chirho: &ViewerStateRequestChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<ViewerStateEffectOutputChirho> {
    require_exact_capability_prefix_chirho(capability_prefix_chirho)?;
    if request_chirho.action_chirho != ViewerStateActionChirho::ReadChirho {
        bail!("ReadStoreChirho viewer-state request must use read-chirho action");
    }
    validate_request_shape_chirho(request_chirho)?;
    let context_chirho = require_context_chirho(request_context_chirho)?;
    enforce_key_limit_chirho(context_chirho, request_chirho)?;
    let physical_key_chirho = physical_key_chirho(context_chirho, &request_chirho.key_chirho)?;
    let private_subject_chirho = store_seal_chirho::store_seal_subject_chirho(
        Some(&context_chirho.app_chirho),
        &physical_key_chirho,
    )?;
    let response_chirho =
        seqlog_chirho::with_named_lock_chirho(root_chirho, VIEWER_STATE_LOCK_CHIRHO, || {
            response_for_key_chirho(root_chirho, context_chirho, request_chirho, None)
        })?;
    Ok(ViewerStateEffectOutputChirho {
        response_chirho: serde_json::to_vec(&response_chirho)?,
        private_subject_chirho,
    })
}

pub(super) fn run_write_chirho(
    root_chirho: &Path,
    capability_prefix_chirho: &str,
    request_chirho: &ViewerStateRequestChirho,
    request_bytes_chirho: &[u8],
    idempotency_chirho: &HashChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<ViewerStateEffectOutputChirho> {
    require_exact_capability_prefix_chirho(capability_prefix_chirho)?;
    if !matches!(
        request_chirho.action_chirho,
        ViewerStateActionChirho::WriteChirho | ViewerStateActionChirho::RestoreChirho
    ) {
        bail!(
            "WriteStoreChirho viewer-state request must use write-chirho or restore-chirho action"
        );
    }
    validate_request_shape_chirho(request_chirho)?;
    let context_chirho = require_context_chirho(request_context_chirho)?;
    enforce_key_limit_chirho(context_chirho, request_chirho)?;
    let physical_key_chirho = physical_key_chirho(context_chirho, &request_chirho.key_chirho)?;
    let private_subject_chirho = store_seal_chirho::store_seal_subject_chirho(
        Some(&context_chirho.app_chirho),
        &physical_key_chirho,
    )?;
    let request_digest_chirho = HashChirho(blake3::hash(request_bytes_chirho).to_hex().to_string());
    let outcome_chirho =
        seqlog_chirho::with_named_lock_chirho(root_chirho, VIEWER_STATE_LOCK_CHIRHO, || {
            mutate_chirho(
                root_chirho,
                context_chirho,
                request_chirho,
                &physical_key_chirho,
                idempotency_chirho,
                &request_digest_chirho,
            )
        })?;
    let response_chirho = match outcome_chirho {
        ViewerStateMutationOutcomeChirho::AppliedChirho(response_chirho) => {
            serde_json::to_vec(&response_chirho)?
        }
        ViewerStateMutationOutcomeChirho::ConflictChirho(conflict_chirho) => {
            serde_json::to_vec(&conflict_chirho)?
        }
    };
    Ok(ViewerStateEffectOutputChirho {
        response_chirho,
        private_subject_chirho,
    })
}

/// What one mutation request came to: an appended version with its receipt, or a typed
/// conflict with the verified head and nothing appended. Only a stale
/// `expected_current_version_chirho` takes the second road; every other refusal is an `Err`.
enum ViewerStateMutationOutcomeChirho {
    AppliedChirho(ViewerStateResponseChirho),
    ConflictChirho(ViewerStateConflictChirho),
}

fn mutate_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    request_chirho: &ViewerStateRequestChirho,
    physical_key_chirho: &str,
    idempotency_chirho: &HashChirho,
    request_digest_chirho: &HashChirho,
) -> Result<ViewerStateMutationOutcomeChirho> {
    let store_chirho = open_store_chirho(root_chirho)?;
    let history_chirho = verified_history_chirho(
        root_chirho,
        context_chirho,
        physical_key_chirho,
        &store_chirho,
    )?;
    if let Some(existing_receipt_chirho) = history_chirho
        .iter()
        .find(|version_chirho| {
            version_chirho.receipt_chirho.idempotency_chirho == *idempotency_chirho
        })
        .map(|version_chirho| version_chirho.receipt_chirho.clone())
    {
        if existing_receipt_chirho.request_digest_chirho != *request_digest_chirho {
            bail!("viewer-state idempotency key was reused with different request bytes");
        }
        return Ok(ViewerStateMutationOutcomeChirho::AppliedChirho(
            response_for_verified_history_chirho(
                request_chirho,
                history_chirho,
                Some(existing_receipt_chirho),
            )?,
        ));
    }

    let current_version_chirho = history_chirho
        .first()
        .map(|version_chirho| version_chirho.version_chirho);
    if current_version_chirho != request_chirho.expected_current_version_chirho {
        // A stale optimistic version is the one refusal that is an ANSWER rather than an error:
        // the caller learns the head it did not know about and keeps what it tried to write.
        // Nothing is appended and no receipt is signed. Like any optimistic answer it can be
        // superseded before the caller reads it; the atomicity that matters lives on the APPLY
        // path below, where the store compares-and-appends against the very head this function
        // read. The attempted value is echoed only for a write; a restore carries none, and the
        // field is absent rather than empty. This check must stay BELOW the idempotency replay
        // above: a retry of a request that already applied moved the head, so it would otherwise
        // be told a write that happened did not (pinned by
        // `idempotent_retry_after_apply_returns_the_original_receipt_not_a_conflict`).
        // Workflow: `spec-chirho/workflows-chirho/viewer-state-authority-chirho/README-chirho.md`.
        let attempted_value_base64_chirho = match request_chirho.action_chirho {
            ViewerStateActionChirho::WriteChirho => request_chirho.value_base64_chirho.clone(),
            ViewerStateActionChirho::RestoreChirho | ViewerStateActionChirho::ReadChirho => None,
        };
        let current_chirho =
            response_for_verified_history_chirho(request_chirho, history_chirho, None)?;
        return Ok(ViewerStateMutationOutcomeChirho::ConflictChirho(
            ViewerStateConflictChirho {
                schema_chirho: VIEWER_STATE_CONFLICT_SCHEMA_CHIRHO.to_string(),
                key_chirho: request_chirho.key_chirho.clone(),
                action_chirho: request_chirho.action_chirho,
                expected_current_version_chirho: request_chirho.expected_current_version_chirho,
                current_version_chirho,
                current_chirho,
                attempted_value_base64_chirho,
                attempted_restore_from_version_chirho: request_chirho.restore_from_version_chirho,
            },
        ));
    }
    let viewer_scope_chirho = viewer_prefix_chirho(context_chirho);
    if current_version_chirho.is_none()
        && store_chirho.key_count_for_viewer_chirho(&viewer_scope_chirho)?
            >= VIEWER_STATE_MAX_KEYS_PER_VIEWER_CHIRHO as u64
    {
        bail!("viewer-state key limit of {VIEWER_STATE_MAX_KEYS_PER_VIEWER_CHIRHO} reached");
    }
    let after_version_chirho = current_version_chirho
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("viewer-state version exhausted"))?;
    let (sealed_chirho, restored_from_version_chirho) = match request_chirho.action_chirho {
        ViewerStateActionChirho::WriteChirho => {
            let value_chirho = decode_write_value_chirho(request_chirho)?;
            if value_chirho.len() > VIEWER_STATE_MAX_VALUE_BYTES_CHIRHO {
                bail!("viewer-state value exceeds {VIEWER_STATE_MAX_VALUE_BYTES_CHIRHO} bytes");
            }
            (
                // Viewer state is the signed-in user's own data: its key joins the user's account.
                store_seal_chirho::seal_store_value_chirho(
                    root_chirho,
                    &crate::privacy_chirho::PrivateBlobAttributionChirho::account_owned_chirho(
                        &context_chirho.user_principal_chirho,
                    )?,
                    Some(&context_chirho.app_chirho),
                    physical_key_chirho,
                    &value_chirho,
                )?,
                None,
            )
        }
        ViewerStateActionChirho::RestoreChirho => {
            let restore_version_chirho =
                request_chirho.restore_from_version_chirho.ok_or_else(|| {
                    anyhow::anyhow!("viewer-state restore requires restore_from_version_chirho")
                })?;
            if Some(restore_version_chirho) == current_version_chirho {
                bail!("viewer-state restore target must be an earlier retained version");
            }
            let target_chirho = history_chirho
                .iter()
                .find(|version_chirho| version_chirho.version_chirho == restore_version_chirho)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "viewer-state restore target {restore_version_chirho} is not retained"
                    )
                })?;
            let target_row_chirho = decode_stored_row_chirho(
                root_chirho,
                context_chirho,
                physical_key_chirho,
                &ViewerStateEntryChirho {
                    version_chirho: target_chirho.version_chirho,
                    value_chirho: store_chirho
                        .exact_chirho(physical_key_chirho, restore_version_chirho)?
                        .ok_or_else(|| anyhow::anyhow!("viewer-state restore row disappeared"))?
                        .value_chirho,
                },
            )?;
            (
                target_row_chirho.sealed_chirho,
                Some(restore_version_chirho),
            )
        }
        ViewerStateActionChirho::ReadChirho => unreachable!("read rejected before mutation"),
    };
    let sealed_value_digest_chirho = sealed_value_digest_chirho(&sealed_chirho)?;
    let predecessor_receipt_digest_chirho = match history_chirho.first() {
        Some(version_chirho) => receipt_digest_chirho(&version_chirho.receipt_chirho)?,
        None => genesis_receipt_digest_chirho(context_chirho, physical_key_chirho)?,
    };

    let mut receipt_chirho = ViewerStateMutationReceiptChirho {
        schema_chirho: VIEWER_STATE_MUTATION_RECEIPT_SCHEMA_CHIRHO.to_string(),
        actor_principal_digest_chirho: actor_digest_chirho(context_chirho),
        app_chirho: context_chirho.app_chirho.clone(),
        action_chirho: request_chirho.action_chirho,
        key_digest_chirho: key_digest_chirho(context_chirho, &request_chirho.key_chirho),
        before_version_chirho: current_version_chirho,
        predecessor_receipt_digest_chirho: predecessor_receipt_digest_chirho.clone(),
        after_version_chirho,
        restored_from_version_chirho,
        run_chirho: current_run_intent_effect_invocation_chirho()
            .map(|invocation_chirho| invocation_chirho.run_chirho),
        idempotency_chirho: idempotency_chirho.clone(),
        request_digest_chirho: request_digest_chirho.clone(),
        sealed_value_digest_chirho,
        at_ms_chirho: now_ms_chirho(),
        sig_chirho: String::new(),
    };
    receipt_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(root_chirho, &receipt_message_chirho(&receipt_chirho)?)?;
    let stored_row_chirho = ViewerStateStoredRowChirho {
        schema_chirho: VIEWER_STATE_STORED_ROW_SCHEMA_CHIRHO.to_string(),
        sealed_chirho,
        receipt_chirho: receipt_chirho.clone(),
    };
    let receipt_digest_chirho = receipt_digest_chirho(&receipt_chirho)?;
    let stored_bytes_chirho = serde_json::to_vec(&stored_row_chirho)?;
    let expected_head_chirho = current_version_chirho.map(|version_chirho| ViewerStateHeadChirho {
        version_chirho,
        receipt_digest_chirho: predecessor_receipt_digest_chirho,
    });
    let head_transition_chirho = ViewerStateHeadTransitionChirho {
        expected_chirho: expected_head_chirho,
        next_chirho: ViewerStateHeadChirho {
            version_chirho: after_version_chirho,
            receipt_digest_chirho,
        },
    };
    // The door owns "is the CALLER stale" (the check above); the store owns "is the DOOR stale":
    // `expected_head_chirho` is the head THIS function read, so a writer that commits between that
    // read and this append fails the store's compare-and-append and nothing lands. Together the two
    // cover both races without the store needing the caller's version — which is why the store
    // API has exactly one production caller, pinned by `append_bounded_has_exactly_one_production_caller`.
    let appended_version_chirho = store_chirho.append_bounded_chirho(
        &viewer_scope_chirho,
        physical_key_chirho,
        &head_transition_chirho,
        &stored_bytes_chirho,
        VIEWER_STATE_HISTORY_LIMIT_CHIRHO,
        VIEWER_STATE_MAX_KEYS_PER_VIEWER_CHIRHO as u64,
    )?;
    if appended_version_chirho != after_version_chirho {
        bail!("viewer-state appended version disagrees with signed receipt");
    }
    drop(store_chirho);
    Ok(ViewerStateMutationOutcomeChirho::AppliedChirho(
        response_for_key_chirho(
            root_chirho,
            context_chirho,
            request_chirho,
            Some(receipt_chirho),
        )?,
    ))
}

/// The verified head of one of the signed-in viewer's keys together with its value bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ViewerStateHeadValueChirho {
    pub head_chirho: ViewerStateHeadChirho,
    pub value_chirho: Vec<u8>,
}

/// The verified head of one of the signed-in viewer's keys — version, receipt digest, AND its
/// value bytes — handed to `act_chirho` while the viewer-state lock is still held, so nothing this
/// viewer saves can land between the head the caller binds and the act performed on that head's
/// bytes. Verification is the same as a read's: the retained history must chain and the
/// authoritative head must bind it; a key with no versions is `None`. This is self-service publication's linearization point:
/// the declassifying CAS write and the intent append run inside `act_chirho`, and a concurrent
/// save waits for them. The value bytes cross into the caller on purpose: they are the document
/// the viewer approved, and the caller is the one door allowed to make them public.
/// Part of `spec-chirho/workflows-chirho/publication-chirho/self-service-publication-chirho.md`.
pub(crate) fn with_verified_head_value_for_key_chirho<T>(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    logical_key_chirho: &str,
    act_chirho: impl FnOnce(Option<ViewerStateHeadValueChirho>) -> Result<T>,
) -> Result<T> {
    let physical_key_chirho = physical_key_chirho(context_chirho, logical_key_chirho)?;
    seqlog_chirho::with_named_lock_chirho(root_chirho, VIEWER_STATE_LOCK_CHIRHO, || {
        let store_chirho = open_store_chirho(root_chirho)?;
        let history_chirho = verified_history_chirho(
            root_chirho,
            context_chirho,
            &physical_key_chirho,
            &store_chirho,
        )?;
        let head_chirho = match history_chirho.first() {
            Some(version_chirho) => Some(ViewerStateHeadValueChirho {
                head_chirho: ViewerStateHeadChirho {
                    version_chirho: version_chirho.version_chirho,
                    receipt_digest_chirho: receipt_digest_chirho(&version_chirho.receipt_chirho)?,
                },
                value_chirho: BASE64_CHIRHO
                    .decode(&version_chirho.value_base64_chirho)
                    .context("decode the verified head value")?,
            }),
            None => None,
        };
        act_chirho(head_chirho)
    })
}

fn response_for_key_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    request_chirho: &ViewerStateRequestChirho,
    mutation_receipt_chirho: Option<ViewerStateMutationReceiptChirho>,
) -> Result<ViewerStateResponseChirho> {
    let physical_key_chirho = physical_key_chirho(context_chirho, &request_chirho.key_chirho)?;
    let store_chirho = open_store_chirho(root_chirho)?;
    let history_chirho = verified_history_chirho(
        root_chirho,
        context_chirho,
        &physical_key_chirho,
        &store_chirho,
    )?;
    response_for_verified_history_chirho(request_chirho, history_chirho, mutation_receipt_chirho)
}

fn response_for_verified_history_chirho(
    request_chirho: &ViewerStateRequestChirho,
    history_chirho: Vec<ViewerStateVersionChirho>,
    mutation_receipt_chirho: Option<ViewerStateMutationReceiptChirho>,
) -> Result<ViewerStateResponseChirho> {
    Ok(ViewerStateResponseChirho {
        schema_chirho: VIEWER_STATE_RESPONSE_SCHEMA_CHIRHO.to_string(),
        key_chirho: request_chirho.key_chirho.clone(),
        current_chirho: history_chirho.first().cloned(),
        history_chirho,
        mutation_receipt_chirho,
    })
}

fn verified_history_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    physical_key_chirho: &str,
    store_chirho: &ViewerStateStoreChirho,
) -> Result<Vec<ViewerStateVersionChirho>> {
    let history_chirho = store_chirho
        .history_chirho(
            physical_key_chirho,
            usize::try_from(VIEWER_STATE_HISTORY_LIMIT_CHIRHO).unwrap_or(16),
        )?
        .iter()
        .map(|entry_chirho| {
            let row_chirho = decode_stored_row_chirho(
                root_chirho,
                context_chirho,
                physical_key_chirho,
                entry_chirho,
            )?;
            let value_chirho = store_seal_chirho::unseal_store_value_chirho(
                root_chirho,
                &row_chirho.sealed_chirho,
            )?;
            Ok(ViewerStateVersionChirho {
                version_chirho: entry_chirho.version_chirho,
                value_base64_chirho: BASE64_CHIRHO.encode(value_chirho),
                receipt_chirho: row_chirho.receipt_chirho,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_head_chirho = match history_chirho.first() {
        Some(version_chirho) => Some(ViewerStateHeadChirho {
            version_chirho: version_chirho.version_chirho,
            receipt_digest_chirho: receipt_digest_chirho(&version_chirho.receipt_chirho)?,
        }),
        None => None,
    };
    let recorded_head_chirho = store_chirho.head_chirho(physical_key_chirho)?;
    if recorded_head_chirho != expected_head_chirho {
        bail!(
            "viewer-state authoritative head does not bind the verified latest receipt: expected {:?}, received {:?}",
            expected_head_chirho,
            recorded_head_chirho
        );
    }
    for adjacent_chirho in history_chirho.windows(2) {
        let newer_chirho = &adjacent_chirho[0];
        let older_chirho = &adjacent_chirho[1];
        if newer_chirho.receipt_chirho.before_version_chirho != Some(older_chirho.version_chirho)
            || newer_chirho
                .receipt_chirho
                .predecessor_receipt_digest_chirho
                != receipt_digest_chirho(&older_chirho.receipt_chirho)?
        {
            bail!("viewer-state retained receipt chain is not contiguous");
        }
    }
    Ok(history_chirho)
}

fn decode_stored_row_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    physical_key_chirho: &str,
    entry_chirho: &ViewerStateEntryChirho,
) -> Result<ViewerStateStoredRowChirho> {
    let row_chirho: ViewerStateStoredRowChirho =
        serde_json::from_slice(&entry_chirho.value_chirho).context("decode viewer-state row")?;
    if row_chirho.schema_chirho != VIEWER_STATE_STORED_ROW_SCHEMA_CHIRHO {
        bail!("unsupported viewer-state stored-row schema");
    }
    store_seal_chirho::ensure_store_seal_subject_binds_key_chirho(
        &row_chirho.sealed_chirho.subject_chirho,
        physical_key_chirho,
    )?;
    verify_receipt_chirho(
        root_chirho,
        context_chirho,
        physical_key_chirho,
        entry_chirho.version_chirho,
        &row_chirho.sealed_chirho,
        &row_chirho.receipt_chirho,
    )?;
    Ok(row_chirho)
}

fn verify_receipt_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    physical_key_chirho: &str,
    version_chirho: u64,
    sealed_chirho: &store_seal_chirho::SealedStoreValueChirho,
    receipt_chirho: &ViewerStateMutationReceiptChirho,
) -> Result<()> {
    if receipt_chirho.schema_chirho != VIEWER_STATE_MUTATION_RECEIPT_SCHEMA_CHIRHO
        || receipt_chirho.app_chirho != context_chirho.app_chirho
        || receipt_chirho.actor_principal_digest_chirho != actor_digest_chirho(context_chirho)
        || receipt_chirho.key_digest_chirho
            != key_digest_for_physical_chirho(context_chirho, physical_key_chirho)
        || receipt_chirho.after_version_chirho != version_chirho
        || receipt_chirho.sealed_value_digest_chirho != sealed_value_digest_chirho(sealed_chirho)?
    {
        bail!("viewer-state receipt binding invalid");
    }
    let expected_after_version_chirho = receipt_chirho
        .before_version_chirho
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("viewer-state receipt version exhausted"))?;
    if receipt_chirho.after_version_chirho != expected_after_version_chirho {
        bail!("viewer-state receipt version transition invalid");
    }
    let genesis_digest_chirho = genesis_receipt_digest_chirho(context_chirho, physical_key_chirho)?;
    if version_chirho == 1 {
        if receipt_chirho.before_version_chirho.is_some()
            || receipt_chirho.predecessor_receipt_digest_chirho != genesis_digest_chirho
        {
            bail!("viewer-state genesis receipt binding invalid");
        }
    } else if receipt_chirho.before_version_chirho != version_chirho.checked_sub(1)
        || receipt_chirho.predecessor_receipt_digest_chirho == genesis_digest_chirho
    {
        bail!("viewer-state predecessor receipt binding invalid");
    }
    match receipt_chirho.action_chirho {
        ViewerStateActionChirho::WriteChirho => {
            if receipt_chirho.restored_from_version_chirho.is_some() {
                bail!("viewer-state write receipt carries a restore target");
            }
        }
        ViewerStateActionChirho::RestoreChirho => {
            let before_version_chirho = receipt_chirho.before_version_chirho.ok_or_else(|| {
                anyhow::anyhow!("viewer-state restore receipt has no prior state")
            })?;
            let restored_from_version_chirho =
                receipt_chirho.restored_from_version_chirho.ok_or_else(|| {
                    anyhow::anyhow!("viewer-state restore receipt has no restore target")
                })?;
            if restored_from_version_chirho >= before_version_chirho {
                bail!("viewer-state restore receipt target is not an earlier version");
            }
        }
        ViewerStateActionChirho::ReadChirho => {
            bail!("viewer-state mutation receipt cannot describe a read");
        }
    }
    if !signer_chirho::verify_with_root_pubkey_chirho(
        root_chirho,
        &receipt_message_chirho(receipt_chirho)?,
        &receipt_chirho.sig_chirho,
    )? {
        bail!("viewer-state receipt signature invalid");
    }
    Ok(())
}

fn receipt_message_chirho(receipt_chirho: &ViewerStateMutationReceiptChirho) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct ReceiptMessageChirho<'a> {
        schema_chirho: &'a str,
        actor_principal_digest_chirho: &'a HashChirho,
        app_chirho: &'a str,
        action_chirho: ViewerStateActionChirho,
        key_digest_chirho: &'a HashChirho,
        before_version_chirho: Option<u64>,
        predecessor_receipt_digest_chirho: &'a HashChirho,
        after_version_chirho: u64,
        restored_from_version_chirho: Option<u64>,
        run_chirho: &'a Option<HashChirho>,
        idempotency_chirho: &'a HashChirho,
        request_digest_chirho: &'a HashChirho,
        sealed_value_digest_chirho: &'a HashChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&ReceiptMessageChirho {
        schema_chirho: &receipt_chirho.schema_chirho,
        actor_principal_digest_chirho: &receipt_chirho.actor_principal_digest_chirho,
        app_chirho: &receipt_chirho.app_chirho,
        action_chirho: receipt_chirho.action_chirho,
        key_digest_chirho: &receipt_chirho.key_digest_chirho,
        before_version_chirho: receipt_chirho.before_version_chirho,
        predecessor_receipt_digest_chirho: &receipt_chirho.predecessor_receipt_digest_chirho,
        after_version_chirho: receipt_chirho.after_version_chirho,
        restored_from_version_chirho: receipt_chirho.restored_from_version_chirho,
        run_chirho: &receipt_chirho.run_chirho,
        idempotency_chirho: &receipt_chirho.idempotency_chirho,
        request_digest_chirho: &receipt_chirho.request_digest_chirho,
        sealed_value_digest_chirho: &receipt_chirho.sealed_value_digest_chirho,
        at_ms_chirho: receipt_chirho.at_ms_chirho,
    })?)
}

fn sealed_value_digest_chirho(
    sealed_chirho: &store_seal_chirho::SealedStoreValueChirho,
) -> Result<HashChirho> {
    Ok(HashChirho(
        blake3::hash(&serde_json::to_vec(sealed_chirho)?)
            .to_hex()
            .to_string(),
    ))
}

fn receipt_digest_chirho(receipt_chirho: &ViewerStateMutationReceiptChirho) -> Result<HashChirho> {
    Ok(digest_chirho(
        VIEWER_STATE_RECEIPT_DIGEST_CONTEXT_CHIRHO,
        &serde_json::to_vec(receipt_chirho)?,
    ))
}

fn genesis_receipt_digest_chirho(
    context_chirho: &RequestContextChirho,
    physical_key_chirho: &str,
) -> Result<HashChirho> {
    #[derive(Serialize)]
    struct ViewerStateGenesisCoordinateChirho<'a> {
        schema_chirho: &'a str,
        actor_principal_digest_chirho: HashChirho,
        app_chirho: &'a str,
        key_digest_chirho: HashChirho,
    }
    Ok(digest_chirho(
        VIEWER_STATE_GENESIS_DIGEST_CONTEXT_CHIRHO,
        &serde_json::to_vec(&ViewerStateGenesisCoordinateChirho {
            schema_chirho: "viewer-state-genesis-receipt-v1-chirho",
            actor_principal_digest_chirho: actor_digest_chirho(context_chirho),
            app_chirho: &context_chirho.app_chirho,
            key_digest_chirho: key_digest_for_physical_chirho(context_chirho, physical_key_chirho),
        })?,
    ))
}

fn validate_request_shape_chirho(request_chirho: &ViewerStateRequestChirho) -> Result<()> {
    if request_chirho.schema_chirho != VIEWER_STATE_REQUEST_SCHEMA_CHIRHO {
        bail!("unsupported viewer-state request schema");
    }
    validate_logical_key_chirho(&request_chirho.key_chirho)?;
    match request_chirho.action_chirho {
        ViewerStateActionChirho::ReadChirho => {
            if request_chirho.expected_current_version_chirho.is_some()
                || request_chirho.value_base64_chirho.is_some()
                || request_chirho.restore_from_version_chirho.is_some()
            {
                bail!("viewer-state read request carries mutation fields");
            }
        }
        ViewerStateActionChirho::WriteChirho => {
            if request_chirho.value_base64_chirho.is_none()
                || request_chirho.restore_from_version_chirho.is_some()
            {
                bail!("viewer-state write request shape invalid");
            }
        }
        ViewerStateActionChirho::RestoreChirho => {
            if request_chirho.expected_current_version_chirho.is_none()
                || request_chirho.value_base64_chirho.is_some()
                || request_chirho.restore_from_version_chirho.is_none()
            {
                bail!("viewer-state restore request shape invalid");
            }
        }
    }
    Ok(())
}

fn validate_logical_key_chirho(key_chirho: &str) -> Result<()> {
    if key_chirho.is_empty()
        || key_chirho.len() > VIEWER_STATE_MAX_LOGICAL_KEY_BYTES_CHIRHO
        || key_chirho.starts_with('/')
        || key_chirho.ends_with('/')
        || key_chirho.split('/').any(|segment_chirho| {
            segment_chirho.is_empty()
                || segment_chirho == "."
                || segment_chirho == ".."
                || !segment_chirho.bytes().all(|byte_chirho| {
                    byte_chirho.is_ascii_lowercase()
                        || byte_chirho.is_ascii_digit()
                        || matches!(byte_chirho, b'-' | b'_')
                })
        })
    {
        bail!(
            "viewer-state key must be a bounded lowercase slug path without empty or dot segments"
        );
    }
    Ok(())
}

fn require_context_chirho(
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<&RequestContextChirho> {
    let context_chirho = request_context_chirho
        .ok_or_else(|| anyhow::anyhow!("viewer-state effect requires an authenticated request"))?;
    if context_chirho.user_principal_chirho.trim().is_empty()
        || context_chirho.app_chirho.trim().is_empty()
    {
        bail!("viewer-state effect requires host-derived principal and app context");
    }
    app_chirho::validate_app_name_chirho(&context_chirho.app_chirho)
        .context("validate host-derived viewer-state app")?;
    Ok(context_chirho)
}

fn require_exact_capability_prefix_chirho(prefix_chirho: &str) -> Result<()> {
    if prefix_chirho != VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO {
        bail!(
            "viewer-state request requires exact store capability prefix '{VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO}'"
        );
    }
    Ok(())
}

fn decode_write_value_chirho(request_chirho: &ViewerStateRequestChirho) -> Result<Vec<u8>> {
    BASE64_CHIRHO
        .decode(
            request_chirho
                .value_base64_chirho
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        )
        .context("decode viewer-state value_base64_chirho")
}

fn viewer_state_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("viewer-state-chirho.redb")
}

fn open_store_chirho(root_chirho: &Path) -> Result<ViewerStateStoreChirho> {
    ViewerStateStoreChirho::open_chirho(&viewer_state_path_chirho(root_chirho))
}

fn viewer_prefix_chirho(context_chirho: &RequestContextChirho) -> String {
    format!(
        "{VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO}{}/{}/",
        context_chirho.app_chirho,
        actor_digest_chirho(context_chirho).0
    )
}

fn physical_key_chirho(
    context_chirho: &RequestContextChirho,
    logical_key_chirho: &str,
) -> Result<String> {
    validate_logical_key_chirho(logical_key_chirho)?;
    Ok(format!(
        "{}{logical_key_chirho}",
        viewer_prefix_chirho(context_chirho)
    ))
}

fn actor_digest_chirho(context_chirho: &RequestContextChirho) -> HashChirho {
    digest_chirho(
        VIEWER_STATE_ACTOR_DIGEST_CONTEXT_CHIRHO,
        context_chirho.user_principal_chirho.as_bytes(),
    )
}

fn key_digest_chirho(
    context_chirho: &RequestContextChirho,
    logical_key_chirho: &str,
) -> HashChirho {
    let mut bytes_chirho = context_chirho.app_chirho.as_bytes().to_vec();
    bytes_chirho.push(0);
    bytes_chirho.extend_from_slice(logical_key_chirho.as_bytes());
    digest_chirho(VIEWER_STATE_KEY_DIGEST_CONTEXT_CHIRHO, &bytes_chirho)
}

fn key_digest_for_physical_chirho(
    context_chirho: &RequestContextChirho,
    physical_key_chirho: &str,
) -> HashChirho {
    let logical_key_chirho = physical_key_chirho
        .strip_prefix(&viewer_prefix_chirho(context_chirho))
        .unwrap_or(physical_key_chirho);
    key_digest_chirho(context_chirho, logical_key_chirho)
}

fn digest_chirho(context_chirho: &str, bytes_chirho: &[u8]) -> HashChirho {
    let mut hasher_chirho = blake3::Hasher::new_derive_key(context_chirho);
    hasher_chirho.update(bytes_chirho);
    HashChirho(hasher_chirho.finalize().to_hex().to_string())
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;

#[cfg(test)]
#[path = "conflict_tests_chirho.rs"]
mod conflict_tests_chirho;
