// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Stores content-addressed, owner-gated app price books with signed history.

pub use crate::economic_model_chirho::{
    PriceBookChirho, PriceBookRecordChirho, PriceSourceChirho, ResolvedPriceChirho,
    PRICE_BOOK_RECORD_SCHEMA_CHIRHO, PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO,
};
use crate::model_chirho::HashChirho;
use crate::{app_chirho, refs_chirho, seqlog_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_economic_governance_chirho::pricebook_policy_chirho;
use cairn_signer_chirho::signer_chirho;
use cairn_writer_head_chirho::{
    head_transition_chirho::{
        self as head_transition_chirho, HeadTransitionIdentityInputChirho,
        HeadTransitionRecoveryOutcomeChirho, PreparedHeadTransitionChirho,
        HEAD_TRANSITION_ID_PREFIX_CHIRHO,
    },
    writer_head_chirho::{self as writer_head_chirho, WriterFenceTokenChirho},
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PRICE_BOOK_RECORDS_LOG_CHIRHO: &str = "pricebook-records-chirho.jsonl";
const PRICE_BOOK_HEAD_REASON_CHIRHO: &str = "price-book";

#[path = "effect_pricing_chirho/price_book_evidence_chirho.rs"]
mod price_book_evidence_chirho;

use cairn_writer_head_chirho::head_transition_authority_chirho::{
    dispatch_head_transition_chirho, HeadTransitionAuthorityPortChirho,
};
const PRICE_BOOK_TRANSITION_OPERATION_SCHEMA_CHIRHO: &str =
    "price-book-transition-operation-v1-chirho";

const REGISTERED_EFFECT_PRICES_CHIRHO: &[(&str, i64, &str)] = &[
    ("echo_paid_chirho", 5, "provider/echo"),
    ("query_chirho", 1, "platform/query"),
    ("llm_chirho", 100, "provider/llm"),
    ("media_chirho", 250, "provider/media"),
    ("email_provider_chirho", 2, "provider/email"),
    ("card_charge_chirho", 17, "provider/card"),
    ("card_refund_chirho", 1, "provider/card"),
    ("package_dispatch_chirho", 30, "provider/package"),
];

/// Fixed review-time fallback catalog retained outside the legacy money executor. Runtime
/// Descriptor-D pricing still resolves through the signed app price book and injected policy.
pub fn registered_effect_prices_chirho() -> &'static [(&'static str, i64, &'static str)] {
    REGISTERED_EFFECT_PRICES_CHIRHO
}

pub fn registered_effect_price_chirho(name_chirho: &str) -> Option<(i64, &'static str)> {
    registered_effect_prices_chirho()
        .iter()
        .find(|(candidate_chirho, _, _)| *candidate_chirho == name_chirho)
        .map(|(_, price_chirho, provider_chirho)| (*price_chirho, *provider_chirho))
}

fn price_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(PRICE_BOOK_RECORDS_LOG_CHIRHO)
}

fn pricebook_ref_chirho(app_chirho: &str) -> String {
    format!("pricebook/{app_chirho}")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn set_price_book_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    price_per_request_chirho: Option<i64>,
    effect_prices_chirho: BTreeMap<String, i64>,
    external_markup_bps_chirho: i64,
) -> Result<(HashChirho, PriceBookChirho, PriceBookRecordChirho)> {
    pricebook_policy_chirho::validate_app_name_chirho(app_chirho)?;
    // Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/
    // cairn-engine-definition-of-done-chirho.md
    set_price_book_with_authority_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        price_per_request_chirho,
        effect_prices_chirho,
        external_markup_bps_chirho,
        None,
    )
}

/// The price door with an explicit elected authority port — the elected-path entry the S3 arms drive.
#[allow(clippy::too_many_arguments)]
pub fn set_price_book_with_head_transition_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    price_per_request_chirho: Option<i64>,
    effect_prices_chirho: BTreeMap<String, i64>,
    external_markup_bps_chirho: i64,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<(HashChirho, PriceBookChirho, PriceBookRecordChirho)> {
    pricebook_policy_chirho::validate_app_name_chirho(app_chirho)?;
    set_price_book_with_authority_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        price_per_request_chirho,
        effect_prices_chirho,
        external_markup_bps_chirho,
        Some(authority_chirho),
    )
}

/// Dispatch by the persisted one-way authority era, exactly as S1's app Deploy does.
///
/// A never-latched root runs `set_price_book_local_unlocked_chirho` under the same
/// `with_head_transition_scope_chirho` it always took — byte-identically, which is the property the
/// never-latched arm pins. A geo-latched root PREPAREs Class-A evidence and COMMITs under the affine
/// scope. **The era predicate is not re-spelled here**: `dispatch_head_transition_chirho` reads it
/// through `writer_authority_era_chirho` (`writer_head_chirho.rs:277`), which is also the predicate
/// my S1-review arm pins for agreement with the local fence's refusal. No seventh spelling is added.
#[allow(clippy::too_many_arguments)]
fn set_price_book_with_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    price_per_request_chirho: Option<i64>,
    effect_prices_chirho: BTreeMap<String, i64>,
    external_markup_bps_chirho: i64,
    authority_chirho: Option<&dyn HeadTransitionAuthorityPortChirho>,
) -> Result<(HashChirho, PriceBookChirho, PriceBookRecordChirho)> {
    // Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/
    // cairn-engine-definition-of-done-chirho.md
    let local_effect_prices_chirho = effect_prices_chirho.clone();
    dispatch_head_transition_chirho(
        root_chirho,
        authority_chirho,
        |fence_chirho| {
            set_price_book_local_unlocked_chirho(
                root_chirho,
                app_chirho,
                owner_principal_chirho,
                price_per_request_chirho,
                local_effect_prices_chirho,
                external_markup_bps_chirho,
                fence_chirho,
            )
        },
        || {
            price_book_evidence_chirho::prepare_elected_price_book_chirho(
                root_chirho,
                app_chirho,
                owner_principal_chirho,
                price_per_request_chirho,
                effect_prices_chirho,
                external_markup_bps_chirho,
            )
        },
        |prepared_chirho, scope_chirho| {
            price_book_evidence_chirho::commit_elected_price_book_chirho(
                root_chirho,
                prepared_chirho,
                scope_chirho,
            )
        },
    )
}

/// The pre-S3 price-book write body, extracted verbatim so the never-latched path can stay
/// byte-identical once S3's era dispatcher lands in front of it.
///
/// **Nothing here changed in the extraction** — same order, same calls, same refusals. The only
/// edits are the ones extraction forces: the closure's captured parameters became this function's
/// parameters. S1 did exactly this for app Deploy and pinned the result with
/// `never_latched_deploy_stays_on_the_existing_local_path_chirho`; the S3 twin arm pins this one.
#[allow(clippy::too_many_arguments)]
fn set_price_book_local_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    price_per_request_chirho: Option<i64>,
    effect_prices_chirho: BTreeMap<String, i64>,
    external_markup_bps_chirho: i64,
    fence_chirho: &writer_head_chirho::WriterFenceTokenChirho,
) -> Result<(HashChirho, PriceBookChirho, PriceBookRecordChirho)> {
    {
        app_chirho::ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
        recover_price_book_head_unlocked_chirho(root_chirho, app_chirho, fence_chirho)?;
        let previous_chirho = current_price_book_hash_chirho(root_chirho, app_chirho)?;
        let book_chirho = pricebook_policy_chirho::propose_price_book_chirho(
            app_chirho,
            owner_principal_chirho,
            price_per_request_chirho,
            effect_prices_chirho,
            external_markup_bps_chirho,
            previous_chirho.clone(),
            now_ms_chirho(),
        )?;
        let hash_chirho = store_chirho::put_object_chirho(root_chirho, &book_chirho)?;
        let record_chirho = append_price_record_unlocked_chirho(
            root_chirho,
            app_chirho,
            owner_principal_chirho,
            hash_chirho.clone(),
            previous_chirho.clone(),
            fence_chirho,
        )?;
        let verified_records_chirho = verified_price_book_records_chirho(root_chirho)?;
        let verified_index_chirho = usize::try_from(record_chirho.seq_chirho)
            .context("new price book sequence does not fit usize")?;
        let verified_record_chirho = verified_records_chirho
            .get(verified_index_chirho)
            .filter(|verified_chirho| *verified_chirho == &record_chirho)
            .ok_or_else(|| {
                anyhow!("new price book record did not verify at its signed sequence")
            })?;
        let prepared_chirho =
            prepared_from_verified_price_book_record_chirho(root_chirho, verified_record_chirho)?;
        head_transition_chirho::complete_head_transition_unlocked_chirho(
            root_chirho,
            &prepared_chirho,
            fence_chirho,
        )?;
        Ok((hash_chirho, book_chirho, record_chirho))
    }
}

/// Recover one fully verified v2 pricebook transition, if an unsettled row exists for `app_chirho`.
pub fn recover_price_book_head_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    pricebook_policy_chirho::validate_app_name_chirho(app_chirho)?;
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        recover_price_book_head_unlocked_chirho(root_chirho, app_chirho, fence_chirho)
    })
}

fn recover_price_book_head_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    seqlog_chirho::recover_jsonl_len_unlocked_chirho(&price_records_path_chirho(root_chirho))?;
    let verified_records_chirho = verified_price_book_records_chirho(root_chirho)?;
    let prepared_chirho = verified_records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.schema_chirho == PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO
        })
        .map(|record_chirho| {
            prepared_from_verified_price_book_record_chirho(root_chirho, record_chirho)
        })
        .collect::<Result<Vec<_>>>()?;
    let current_head_chirho = price_book_ref_head_chirho(root_chirho, app_chirho)?;
    let Some(pending_index_chirho) =
        head_transition_chirho::pending_head_transition_index_unlocked_chirho(
            root_chirho,
            &current_head_chirho,
            &prepared_chirho,
        )?
    else {
        return Ok(None);
    };
    Ok(Some(
        head_transition_chirho::complete_head_transition_unlocked_chirho(
            root_chirho,
            &prepared_chirho[pending_index_chirho],
            applier_fence_chirho,
        )?,
    ))
}

fn prepared_from_verified_price_book_record_chirho(
    root_chirho: &Path,
    record_chirho: &PriceBookRecordChirho,
) -> Result<PreparedHeadTransitionChirho> {
    if record_chirho.schema_chirho != PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO {
        bail!("only verified price book v2 rows can become prepared head transitions");
    }
    let prepared_epoch_chirho = record_chirho
        .prepared_writer_fence_epoch_chirho
        .ok_or_else(|| anyhow!("verified price book v2 row is missing its prepared fence epoch"))?;
    let prepared_fence_chirho = WriterFenceTokenChirho {
        group_chirho: writer_head_chirho::consistency_group_for_root_chirho(root_chirho)?,
        epoch_chirho: prepared_epoch_chirho,
        issued_at_ms_chirho: 0,
    };
    let operation_bytes_chirho = price_book_transition_operation_bytes_chirho(record_chirho)?;
    let branch_chirho = pricebook_ref_chirho(&record_chirho.app_chirho);
    let identity_chirho = HeadTransitionIdentityInputChirho {
        family_log_chirho: PRICE_BOOK_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho: &record_chirho.price_book_chirho,
        reason_chirho: PRICE_BOOK_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &prepared_fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    head_transition_chirho::bind_caller_verified_head_transition_chirho(
        &identity_chirho,
        &record_chirho.transition_id_chirho,
        &serde_json::to_vec(record_chirho)?,
    )
}

fn price_book_transition_operation_bytes_chirho(
    record_chirho: &PriceBookRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct PriceBookTransitionOperationChirho<'a> {
        schema_chirho: &'static str,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
    }
    Ok(serde_json::to_vec(&PriceBookTransitionOperationChirho {
        schema_chirho: PRICE_BOOK_TRANSITION_OPERATION_SCHEMA_CHIRHO,
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
    })?)
}

fn price_book_ref_head_chirho(root_chirho: &Path, app_chirho: &str) -> Result<Option<HashChirho>> {
    Ok(refs_chirho::load_refs_chirho(root_chirho)?
        .branches_chirho
        .get(&pricebook_ref_chirho(app_chirho))
        .cloned())
}

fn selected_verified_price_book_record_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<PriceBookRecordChirho>> {
    let records_chirho = verified_price_book_records_chirho(root_chirho)?;
    let Some(selected_hash_chirho) = price_book_ref_head_chirho(root_chirho, app_chirho)? else {
        return Ok(None);
    };
    let selected_chirho = records_chirho
        .iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.price_book_chirho == selected_hash_chirho
        })
        .cloned()
        .ok_or_else(|| {
            anyhow!("price book ref for app '{app_chirho}' does not select verified signed history")
        })?;
    if selected_chirho.schema_chirho == PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO {
        let prepared_chirho =
            prepared_from_verified_price_book_record_chirho(root_chirho, &selected_chirho)?;
        if !head_transition_chirho::verified_head_transition_receipt_chirho(
            root_chirho,
            &prepared_chirho,
        )? {
            bail!("selected price book v2 record has no valid Applied receipt");
        }
    }
    Ok(Some(selected_chirho))
}

pub fn current_price_book_hash_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<HashChirho>> {
    pricebook_policy_chirho::validate_app_name_chirho(app_chirho)?;
    Ok(
        selected_verified_price_book_record_chirho(root_chirho, app_chirho)?
            .map(|record_chirho| record_chirho.price_book_chirho),
    )
}

pub fn current_price_book_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<(HashChirho, PriceBookChirho)>> {
    let Some(hash_chirho) = current_price_book_hash_chirho(root_chirho, app_chirho)? else {
        return Ok(None);
    };
    let book_chirho: PriceBookChirho = store_chirho::get_object_chirho(root_chirho, &hash_chirho)?;
    pricebook_policy_chirho::validate_price_book_chirho(&book_chirho)?;
    if book_chirho.app_chirho != app_chirho {
        bail!(
            "price book ref for app '{app_chirho}' points at price book for '{}'",
            book_chirho.app_chirho
        );
    }
    Ok(Some((hash_chirho, book_chirho)))
}

pub fn resolve_price_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    effect_chirho: &str,
) -> Result<ResolvedPriceChirho> {
    let (hash_chirho, book_chirho) = current_price_book_chirho(root_chirho, app_chirho)?
        .ok_or_else(|| anyhow!("no current price book for app '{app_chirho}'"))?;
    pricebook_policy_chirho::resolve_price_from_book_chirho(
        hash_chirho,
        &book_chirho,
        effect_chirho,
    )
}

pub fn price_book_history_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Vec<PriceBookRecordChirho>> {
    pricebook_policy_chirho::validate_app_name_chirho(app_chirho)?;
    Ok(load_price_book_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| record_chirho.app_chirho == app_chirho)
        .collect())
}

pub fn load_price_book_records_chirho(root_chirho: &Path) -> Result<Vec<PriceBookRecordChirho>> {
    let path_chirho = price_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: PriceBookRecordChirho = serde_json::from_str(line_chirho)?;
        verify_price_record_schema_chirho(&record_chirho.schema_chirho)?;
        verify_price_record_transition_shape_chirho(&record_chirho)?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

pub fn verified_price_book_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<PriceBookRecordChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_price_book_records_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "price book seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        pricebook_policy_chirho::validate_app_name_chirho(&record_chirho.app_chirho)?;
        app_chirho::ensure_app_owner_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        let book_chirho: PriceBookChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.price_book_chirho)?;
        pricebook_policy_chirho::validate_price_book_chirho(&book_chirho)?;
        if book_chirho.app_chirho != record_chirho.app_chirho {
            bail!(
                "price book record {} app mismatch",
                record_chirho.seq_chirho
            );
        }
        if book_chirho.owner_principal_chirho != record_chirho.owner_principal_chirho {
            bail!(
                "price book record {} owner mismatch",
                record_chirho.seq_chirho
            );
        }
        if book_chirho.previous_chirho != record_chirho.previous_chirho {
            bail!(
                "price book record {} previous hash mismatch",
                record_chirho.seq_chirho
            );
        }
        let message_chirho = price_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "price book record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho)
}

pub fn verify_price_books_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(verified_price_book_records_chirho(root_chirho)?.len())
}

fn append_price_record_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    price_book_chirho: HashChirho,
    previous_chirho: Option<HashChirho>,
    prepared_fence_chirho: &WriterFenceTokenChirho,
) -> Result<PriceBookRecordChirho> {
    let path_chirho = price_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
        let mut record_chirho = PriceBookRecordChirho {
            seq_chirho,
            schema_chirho: PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            price_book_chirho,
            previous_chirho,
            at_ms_chirho: now_ms_chirho(),
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: Some(prepared_fence_chirho.epoch_chirho),
            sig_chirho: String::new(),
        };
        let operation_bytes_chirho = price_book_transition_operation_bytes_chirho(&record_chirho)?;
        let branch_chirho = pricebook_ref_chirho(&record_chirho.app_chirho);
        let identity_chirho = HeadTransitionIdentityInputChirho {
            family_log_chirho: PRICE_BOOK_RECORDS_LOG_CHIRHO,
            family_seq_chirho: record_chirho.seq_chirho,
            branch_chirho: &branch_chirho,
            previous_chirho: &record_chirho.previous_chirho,
            next_chirho: &record_chirho.price_book_chirho,
            reason_chirho: PRICE_BOOK_HEAD_REASON_CHIRHO,
            operation_bytes_chirho: &operation_bytes_chirho,
            prepared_fence_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        };
        record_chirho.transition_id_chirho =
            head_transition_chirho::derive_head_transition_id_chirho(&identity_chirho)?;
        let message_chirho = price_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn nonempty_schema_chirho(schema_chirho: &str) -> Option<&str> {
    (!schema_chirho.is_empty()).then_some(schema_chirho)
}

fn verify_price_record_schema_chirho(schema_chirho: &str) -> Result<()> {
    if !schema_chirho.is_empty()
        && schema_chirho != PRICE_BOOK_RECORD_SCHEMA_CHIRHO
        && schema_chirho != PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO
    {
        bail!("unsupported price book record schema '{schema_chirho}'");
    }
    Ok(())
}

fn verify_price_record_transition_shape_chirho(
    record_chirho: &PriceBookRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho == PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO {
        if !record_chirho
            .transition_id_chirho
            .starts_with(HEAD_TRANSITION_ID_PREFIX_CHIRHO)
            || record_chirho.prepared_writer_fence_epoch_chirho == Some(0)
            || record_chirho.prepared_writer_fence_epoch_chirho.is_none()
        {
            bail!("price book v2 record has incomplete head transition evidence");
        }
    } else if !record_chirho.transition_id_chirho.is_empty()
        || record_chirho.prepared_writer_fence_epoch_chirho.is_some()
    {
        bail!("legacy price book record must not carry head transition evidence");
    }
    Ok(())
}

fn price_record_message_chirho(record_chirho: &PriceBookRecordChirho) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct PriceRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
        price_book_chirho: &'a HashChirho,
        previous_chirho: &'a Option<HashChirho>,
        at_ms_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        transition_id_chirho: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prepared_writer_fence_epoch_chirho: Option<u64>,
    }
    Ok(serde_json::to_vec(&PriceRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        price_book_chirho: &record_chirho.price_book_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
        transition_id_chirho: nonempty_schema_chirho(&record_chirho.transition_id_chirho),
        prepared_writer_fence_epoch_chirho: record_chirho.prepared_writer_fence_epoch_chirho,
    })?)
}

#[cfg(test)]
#[path = "effect_pricing_chirho/tests_chirho.rs"]
mod tests_chirho;

#[cfg(test)]
#[path = "effect_pricing_chirho/elected_price_book_tests_chirho.rs"]
mod elected_price_book_tests_chirho;
