// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Stores owner-authored onboarding guides as versioned data and renders the default guide kit.

#[path = "onboarding_chirho/elected_chirho.rs"]
mod elected_chirho;
pub use elected_chirho::{
    recover_onboarding_head_with_head_transition_authority_chirho,
    set_onboarding_guide_with_head_transition_authority_chirho,
};

#[cfg(test)]
#[path = "onboarding_chirho/elected_tests_chirho.rs"]
mod elected_tests_chirho;

#[cfg(test)]
use crate::app_model_chirho::onboarding_chirho::ONBOARDING_RECORD_SCHEMA_CHIRHO;
use crate::app_model_chirho::onboarding_chirho::{
    onboarding_record_message_chirho, onboarding_transition_operation_bytes_chirho,
    validate_app_name_chirho, validate_onboarding_guide_chirho,
    validate_onboarding_record_schema_chirho, ONBOARDING_RECORD_V2_SCHEMA_CHIRHO,
};
pub use crate::app_model_chirho::onboarding_chirho::{
    parse_onboarding_step_spec_chirho, OnboardingGuideChirho, OnboardingRecordChirho,
    OnboardingStepChirho,
};
use crate::model_chirho::HashChirho;
use crate::{app_chirho, refs_chirho, seqlog_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
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
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const ONBOARDING_RECORDS_LOG_CHIRHO: &str = "onboarding-records-chirho.jsonl";
const ONBOARDING_HEAD_REASON_CHIRHO: &str = "onboarding-guide";

fn onboarding_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(ONBOARDING_RECORDS_LOG_CHIRHO)
}

fn onboarding_ref_chirho(app_chirho: &str) -> String {
    format!("onboarding/{app_chirho}")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn set_onboarding_guide_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    title_chirho: &str,
    steps_chirho: Vec<OnboardingStepChirho>,
) -> Result<(HashChirho, OnboardingGuideChirho, OnboardingRecordChirho)> {
    validate_app_name_chirho(app_chirho)?;
    // Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/
    // cairn-engine-definition-of-done-chirho.md
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        set_onboarding_guide_unlocked_chirho(
            root_chirho,
            app_chirho,
            owner_principal_chirho,
            title_chirho,
            steps_chirho,
            fence_chirho,
        )
    })
}

fn set_onboarding_guide_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    title_chirho: &str,
    steps_chirho: Vec<OnboardingStepChirho>,
    fence_chirho: &WriterFenceTokenChirho,
) -> Result<(HashChirho, OnboardingGuideChirho, OnboardingRecordChirho)> {
    app_chirho::ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    recover_onboarding_head_unlocked_chirho(root_chirho, app_chirho, fence_chirho)?;
    let previous_chirho = current_onboarding_hash_chirho(root_chirho, app_chirho)?;
    let guide_chirho = OnboardingGuideChirho {
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: owner_principal_chirho.to_string(),
        title_chirho: title_chirho.trim().to_string(),
        steps_chirho,
        previous_chirho: previous_chirho.clone(),
        at_ms_chirho: now_ms_chirho(),
    };
    validate_onboarding_guide_chirho(&guide_chirho)?;
    let hash_chirho = store_chirho::put_object_chirho(root_chirho, &guide_chirho)?;
    let record_chirho = append_onboarding_record_unlocked_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        hash_chirho.clone(),
        previous_chirho.clone(),
        fence_chirho,
    )?;
    let verified_records_chirho = verified_onboarding_records_chirho(root_chirho)?;
    let verified_index_chirho = usize::try_from(record_chirho.seq_chirho)
        .context("new onboarding sequence does not fit usize")?;
    let verified_record_chirho = verified_records_chirho
        .get(verified_index_chirho)
        .filter(|verified_chirho| *verified_chirho == &record_chirho)
        .ok_or_else(|| anyhow!("new onboarding record did not verify at its signed sequence"))?;
    let prepared_chirho =
        prepared_from_verified_onboarding_record_chirho(root_chirho, verified_record_chirho)?;
    head_transition_chirho::complete_head_transition_unlocked_chirho(
        root_chirho,
        &prepared_chirho,
        fence_chirho,
    )?;
    Ok((hash_chirho, guide_chirho, record_chirho))
}

/// Recover one fully verified v2 onboarding transition, if one is unsettled for `app_chirho`.
pub fn recover_onboarding_head_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    validate_app_name_chirho(app_chirho)?;
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        recover_onboarding_head_unlocked_chirho(root_chirho, app_chirho, fence_chirho)
    })
}

fn recover_onboarding_head_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    seqlog_chirho::recover_jsonl_len_unlocked_chirho(&onboarding_records_path_chirho(root_chirho))?;
    let verified_records_chirho = verified_onboarding_records_chirho(root_chirho)?;
    let prepared_chirho = verified_records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.schema_chirho == ONBOARDING_RECORD_V2_SCHEMA_CHIRHO
        })
        .map(|record_chirho| {
            prepared_from_verified_onboarding_record_chirho(root_chirho, record_chirho)
        })
        .collect::<Result<Vec<_>>>()?;
    let current_head_chirho = onboarding_ref_head_chirho(root_chirho, app_chirho)?;
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

fn prepared_from_verified_onboarding_record_chirho(
    root_chirho: &Path,
    record_chirho: &OnboardingRecordChirho,
) -> Result<PreparedHeadTransitionChirho> {
    if record_chirho.schema_chirho != ONBOARDING_RECORD_V2_SCHEMA_CHIRHO {
        bail!("only verified onboarding v2 rows can become prepared head transitions");
    }
    let prepared_epoch_chirho = record_chirho
        .prepared_writer_fence_epoch_chirho
        .ok_or_else(|| anyhow!("verified onboarding v2 row is missing its prepared fence epoch"))?;
    let prepared_fence_chirho = WriterFenceTokenChirho {
        group_chirho: writer_head_chirho::consistency_group_for_root_chirho(root_chirho)?,
        epoch_chirho: prepared_epoch_chirho,
        issued_at_ms_chirho: 0,
    };
    let operation_bytes_chirho = onboarding_transition_operation_bytes_chirho(record_chirho)?;
    let branch_chirho = onboarding_ref_chirho(&record_chirho.app_chirho);
    let identity_chirho = HeadTransitionIdentityInputChirho {
        family_log_chirho: ONBOARDING_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho: &record_chirho.guide_chirho,
        reason_chirho: ONBOARDING_HEAD_REASON_CHIRHO,
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

fn onboarding_ref_head_chirho(root_chirho: &Path, app_chirho: &str) -> Result<Option<HashChirho>> {
    Ok(refs_chirho::load_refs_chirho(root_chirho)?
        .branches_chirho
        .get(&onboarding_ref_chirho(app_chirho))
        .cloned())
}

fn selected_verified_onboarding_record_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<OnboardingRecordChirho>> {
    let records_chirho = verified_onboarding_records_chirho(root_chirho)?;
    let Some(selected_hash_chirho) = onboarding_ref_head_chirho(root_chirho, app_chirho)? else {
        return Ok(None);
    };
    let selected_chirho = records_chirho
        .iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.guide_chirho == selected_hash_chirho
        })
        .cloned()
        .ok_or_else(|| {
            anyhow!("onboarding ref for app '{app_chirho}' does not select verified signed history")
        })?;
    if selected_chirho.schema_chirho == ONBOARDING_RECORD_V2_SCHEMA_CHIRHO {
        let prepared_chirho =
            prepared_from_verified_onboarding_record_chirho(root_chirho, &selected_chirho)?;
        if !head_transition_chirho::verified_head_transition_receipt_chirho(
            root_chirho,
            &prepared_chirho,
        )? {
            bail!("selected onboarding v2 record has no valid Applied receipt");
        }
    }
    Ok(Some(selected_chirho))
}

pub fn current_onboarding_hash_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<HashChirho>> {
    validate_app_name_chirho(app_chirho)?;
    Ok(
        selected_verified_onboarding_record_chirho(root_chirho, app_chirho)?
            .map(|record_chirho| record_chirho.guide_chirho),
    )
}

pub fn current_onboarding_guide_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<(HashChirho, OnboardingGuideChirho)>> {
    let Some(hash_chirho) = current_onboarding_hash_chirho(root_chirho, app_chirho)? else {
        return Ok(None);
    };
    let guide_chirho: OnboardingGuideChirho =
        store_chirho::get_object_chirho(root_chirho, &hash_chirho)?;
    validate_onboarding_guide_chirho(&guide_chirho)?;
    if guide_chirho.app_chirho != app_chirho {
        bail!(
            "onboarding ref for app '{app_chirho}' points at guide for '{}'",
            guide_chirho.app_chirho
        );
    }
    Ok(Some((hash_chirho, guide_chirho)))
}

pub fn onboarding_history_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Vec<OnboardingRecordChirho>> {
    validate_app_name_chirho(app_chirho)?;
    Ok(load_onboarding_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| record_chirho.app_chirho == app_chirho)
        .collect())
}

pub fn load_onboarding_records_chirho(root_chirho: &Path) -> Result<Vec<OnboardingRecordChirho>> {
    let path_chirho = onboarding_records_path_chirho(root_chirho);
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
        let record_chirho: OnboardingRecordChirho = serde_json::from_str(line_chirho)?;
        validate_onboarding_record_schema_chirho(&record_chirho)?;
        validate_onboarding_record_transition_shape_chirho(&record_chirho)?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

pub fn verified_onboarding_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<OnboardingRecordChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_onboarding_records_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "onboarding record seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_app_name_chirho(&record_chirho.app_chirho)?;
        app_chirho::ensure_app_owner_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        let guide_chirho: OnboardingGuideChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.guide_chirho)?;
        validate_onboarding_guide_chirho(&guide_chirho)?;
        if guide_chirho.app_chirho != record_chirho.app_chirho {
            bail!(
                "onboarding record {} app mismatch",
                record_chirho.seq_chirho
            );
        }
        if guide_chirho.owner_principal_chirho != record_chirho.owner_principal_chirho {
            bail!(
                "onboarding record {} owner mismatch",
                record_chirho.seq_chirho
            );
        }
        if guide_chirho.previous_chirho != record_chirho.previous_chirho {
            bail!(
                "onboarding record {} previous hash mismatch",
                record_chirho.seq_chirho
            );
        }
        let message_chirho = onboarding_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "onboarding record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho)
}

pub fn verify_onboarding_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(verified_onboarding_records_chirho(root_chirho)?.len())
}

pub fn onboarding_kit_html_chirho(root_chirho: &Path, app_chirho: &str) -> String {
    match current_onboarding_guide_chirho(root_chirho, app_chirho) {
        Ok(Some((hash_chirho, guide_chirho))) => {
            match render_onboarding_kit_chirho(&hash_chirho, &guide_chirho) {
                Ok(html_chirho) => html_chirho,
                Err(e_chirho) => format!(
                    "<!-- onboarding-chirho render error: {} -->",
                    escape_html_chirho(&e_chirho.to_string())
                ),
            }
        }
        Ok(None) => String::new(),
        Err(e_chirho) => format!(
            "<!-- onboarding-chirho load error: {} -->",
            escape_html_chirho(&e_chirho.to_string())
        ),
    }
}

fn append_onboarding_record_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    guide_chirho: HashChirho,
    previous_chirho: Option<HashChirho>,
    prepared_fence_chirho: &WriterFenceTokenChirho,
) -> Result<OnboardingRecordChirho> {
    let path_chirho = onboarding_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
        let mut record_chirho = OnboardingRecordChirho {
            seq_chirho,
            schema_chirho: ONBOARDING_RECORD_V2_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            guide_chirho,
            previous_chirho,
            at_ms_chirho: now_ms_chirho(),
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: Some(prepared_fence_chirho.epoch_chirho),
            sig_chirho: String::new(),
        };
        let operation_bytes_chirho = onboarding_transition_operation_bytes_chirho(&record_chirho)?;
        let branch_chirho = onboarding_ref_chirho(&record_chirho.app_chirho);
        let identity_chirho = HeadTransitionIdentityInputChirho {
            family_log_chirho: ONBOARDING_RECORDS_LOG_CHIRHO,
            family_seq_chirho: record_chirho.seq_chirho,
            branch_chirho: &branch_chirho,
            previous_chirho: &record_chirho.previous_chirho,
            next_chirho: &record_chirho.guide_chirho,
            reason_chirho: ONBOARDING_HEAD_REASON_CHIRHO,
            operation_bytes_chirho: &operation_bytes_chirho,
            prepared_fence_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        };
        record_chirho.transition_id_chirho =
            head_transition_chirho::derive_head_transition_id_chirho(&identity_chirho)?;
        let message_chirho = onboarding_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn validate_onboarding_record_transition_shape_chirho(
    record_chirho: &OnboardingRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho == ONBOARDING_RECORD_V2_SCHEMA_CHIRHO {
        if !record_chirho
            .transition_id_chirho
            .starts_with(HEAD_TRANSITION_ID_PREFIX_CHIRHO)
            || record_chirho.prepared_writer_fence_epoch_chirho == Some(0)
            || record_chirho.prepared_writer_fence_epoch_chirho.is_none()
        {
            bail!("onboarding v2 record has incomplete head transition evidence");
        }
    } else if !record_chirho.transition_id_chirho.is_empty()
        || record_chirho.prepared_writer_fence_epoch_chirho.is_some()
    {
        bail!("legacy onboarding record must not carry head transition evidence");
    }
    Ok(())
}

fn render_onboarding_kit_chirho(
    hash_chirho: &HashChirho,
    guide_chirho: &OnboardingGuideChirho,
) -> Result<String> {
    #[derive(Serialize)]
    struct GuideViewChirho<'a> {
        app_chirho: &'a str,
        guide_chirho: &'a str,
        title_chirho: &'a str,
        steps_chirho: &'a [OnboardingStepChirho],
    }

    let guide_json_chirho = serde_json::to_string(&GuideViewChirho {
        app_chirho: &guide_chirho.app_chirho,
        guide_chirho: &hash_chirho.0,
        title_chirho: &guide_chirho.title_chirho,
        steps_chirho: &guide_chirho.steps_chirho,
    })?
    .replace('<', "\\u003c")
    .replace('>', "\\u003e")
    .replace('&', "\\u0026")
    .replace('\u{2028}', "\\u2028")
    .replace('\u{2029}', "\\u2029");

    Ok(format!(
        r#"<style>
#cairn-onboarding-toggle-chirho{{position:fixed;left:1rem;bottom:1rem;z-index:2147483646;border:1px solid #0d3b3e;background:#0d3b3e;color:#fff;border-radius:6px;padding:.55rem .7rem;font:14px system-ui,sans-serif;cursor:pointer}}
#cairn-onboarding-panel-chirho{{position:fixed;left:1rem;bottom:3.8rem;z-index:2147483646;width:min(24rem,calc(100vw - 2rem));display:none;background:#fff;color:#111;border:1px solid #c9c9c9;border-radius:8px;box-shadow:0 10px 30px #0002;padding:.85rem;font:14px system-ui,sans-serif}}
#cairn-onboarding-panel-chirho h2{{margin:.1rem 0 .45rem;font-size:16px;line-height:1.25;letter-spacing:0}}
#cairn-onboarding-panel-chirho h3{{margin:.25rem 0 .35rem;font-size:14px;line-height:1.3;letter-spacing:0}}
#cairn-onboarding-panel-chirho p{{margin:.25rem 0 .65rem;line-height:1.45;white-space:pre-wrap}}
#cairn-onboarding-actions-chirho{{display:flex;align-items:center;gap:.45rem;flex-wrap:wrap}}
#cairn-onboarding-actions-chirho button{{border:1px solid #111;background:#111;color:#fff;border-radius:6px;padding:.42rem .62rem;font:14px system-ui,sans-serif;cursor:pointer}}
#cairn-onboarding-count-chirho{{margin-left:auto;color:#555;font-size:12px}}
.cairn-onboarding-highlight-chirho{{outline:3px solid #2f7d32!important;outline-offset:4px!important;scroll-margin:4rem}}
@media (prefers-color-scheme:dark){{#cairn-onboarding-panel-chirho{{background:#161616;color:#f5f5f5;border-color:#555}}#cairn-onboarding-count-chirho{{color:#bbb}}}}
</style>
<button id="cairn-onboarding-toggle-chirho" type="button">Guide</button>
<section id="cairn-onboarding-panel-chirho" aria-label="Onboarding">
  <h2 id="cairn-onboarding-title-chirho"></h2>
  <h3 id="cairn-onboarding-step-title-chirho"></h3>
  <p id="cairn-onboarding-body-chirho"></p>
  <div id="cairn-onboarding-actions-chirho">
    <button id="cairn-onboarding-prev-chirho" type="button">Back</button>
    <button id="cairn-onboarding-next-chirho" type="button">Next</button>
    <button id="cairn-onboarding-done-chirho" type="button">Done</button>
    <span id="cairn-onboarding-count-chirho"></span>
  </div>
</section>
<script>
(() => {{
  const guideChirho = {guide_json_chirho};
  const storageKeyChirho = "cairn-onboarding-chirho:" + guideChirho.app_chirho + ":" + guideChirho.guide_chirho;
  const toggleChirho = document.getElementById("cairn-onboarding-toggle-chirho");
  const panelChirho = document.getElementById("cairn-onboarding-panel-chirho");
  const titleChirho = document.getElementById("cairn-onboarding-title-chirho");
  const stepTitleChirho = document.getElementById("cairn-onboarding-step-title-chirho");
  const bodyChirho = document.getElementById("cairn-onboarding-body-chirho");
  const prevChirho = document.getElementById("cairn-onboarding-prev-chirho");
  const nextChirho = document.getElementById("cairn-onboarding-next-chirho");
  const doneChirho = document.getElementById("cairn-onboarding-done-chirho");
  const countChirho = document.getElementById("cairn-onboarding-count-chirho");
  let indexChirho = 0;
  let highlightedChirho = null;

  const highlightChirho = (selectorChirho) => {{
    if (highlightedChirho) {{
      highlightedChirho.classList.remove("cairn-onboarding-highlight-chirho");
      highlightedChirho = null;
    }}
    if (!selectorChirho) return;
    try {{
      const targetChirho = document.querySelector(selectorChirho);
      if (targetChirho) {{
        highlightedChirho = targetChirho;
        highlightedChirho.classList.add("cairn-onboarding-highlight-chirho");
        highlightedChirho.scrollIntoView({{ block: "center", inline: "nearest", behavior: "smooth" }});
      }}
    }} catch (_) {{}}
  }};

  const renderChirho = () => {{
    const stepChirho = guideChirho.steps_chirho[indexChirho];
    titleChirho.textContent = guideChirho.title_chirho;
    stepTitleChirho.textContent = stepChirho.title_chirho;
    bodyChirho.textContent = stepChirho.body_chirho;
    countChirho.textContent = String(indexChirho + 1) + " / " + String(guideChirho.steps_chirho.length);
    prevChirho.disabled = indexChirho === 0;
    nextChirho.style.display = indexChirho + 1 === guideChirho.steps_chirho.length ? "none" : "";
    doneChirho.style.display = indexChirho + 1 === guideChirho.steps_chirho.length ? "" : "none";
    highlightChirho(stepChirho.target_chirho);
  }};

  const openChirho = () => {{
    panelChirho.style.display = "block";
    renderChirho();
  }};
  const closeChirho = () => {{
    panelChirho.style.display = "none";
    highlightChirho(null);
  }};
  toggleChirho.addEventListener("click", () => {{
    if (panelChirho.style.display === "block") closeChirho(); else openChirho();
  }});
  prevChirho.addEventListener("click", () => {{
    if (indexChirho > 0) {{
      indexChirho -= 1;
      renderChirho();
    }}
  }});
  nextChirho.addEventListener("click", () => {{
    if (indexChirho + 1 < guideChirho.steps_chirho.length) {{
      indexChirho += 1;
      renderChirho();
    }}
  }});
  doneChirho.addEventListener("click", () => {{
    try {{ window.localStorage.setItem(storageKeyChirho, "done"); }} catch (_) {{}}
    closeChirho();
  }});
  try {{
    if (window.localStorage.getItem(storageKeyChirho) !== "done") openChirho();
  }} catch (_) {{
    openChirho();
  }}
}})();
</script>"#
    ))
}

fn escape_html_chirho(value_chirho: &str) -> String {
    value_chirho
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
#[path = "onboarding_chirho/tests_chirho.rs"]
mod tests_chirho;
