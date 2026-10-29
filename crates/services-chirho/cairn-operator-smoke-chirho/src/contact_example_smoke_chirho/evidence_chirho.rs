// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Evidence and PII-safety helpers for the contact example smoke.

use anyhow::{bail, Result};
use cairn_chirho::model_chirho::EffectChirho;
use cairn_chirho::{
    cas_chirho, dag_private_value_chirho, effect_chirho, query_chirho, versioned_chirho,
};
use std::path::{Path, PathBuf};

use super::types_chirho::{
    ContactExampleWireEvidenceChirho, HttpSmokeResponseChirho,
    CONTACT_EXAMPLE_WIRE_EVIDENCE_SCHEMA_CHIRHO,
};
pub(super) fn wire_evidence_chirho(
    method_chirho: &str,
    path_chirho: &str,
    response_chirho: &HttpSmokeResponseChirho,
    pii_needles_chirho: &[&str],
) -> Result<ContactExampleWireEvidenceChirho> {
    assert_no_contact_pii_chirho(
        path_chirho,
        &response_chirho.body_chirho,
        pii_needles_chirho,
    )?;
    Ok(ContactExampleWireEvidenceChirho {
        schema_chirho: CONTACT_EXAMPLE_WIRE_EVIDENCE_SCHEMA_CHIRHO,
        method_chirho: method_chirho.to_string(),
        path_chirho: path_chirho.to_string(),
        status_chirho: response_chirho.status_chirho,
        content_type_chirho: response_chirho.headers_chirho.get("content-type").cloned(),
        body_bytes_chirho: response_chirho.body_chirho.len(),
        body_chirho: cas_chirho::hash_chirho(&response_chirho.body_chirho),
        pii_needles_absent_chirho: true,
    })
}

pub(super) fn versioned_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("versioned-chirho.redb")
}

pub(super) fn persistent_effect_record_count_chirho(root_chirho: &Path) -> Result<usize> {
    let effects_dir_chirho = root_chirho.join("effects-chirho");
    if !effects_dir_chirho.exists() {
        return Ok(0);
    }
    Ok(std::fs::read_dir(effects_dir_chirho)?.count())
}

pub(super) fn assert_contact_safe_surfaces_no_pii_chirho(
    root_chirho: &Path,
    pii_needles_chirho: &[&str],
) -> Result<usize> {
    let mut surfaces_chirho = 0usize;
    for path_chirho in [
        root_chirho.join("privacy-blob-records-chirho.jsonl"),
        root_chirho.join("privacy-access-records-chirho.jsonl"),
        root_chirho.join("volatile-effects-chirho.jsonl"),
    ] {
        if path_chirho.exists() {
            let bytes_chirho = std::fs::read(&path_chirho)?;
            assert_no_contact_pii_chirho(
                &path_chirho.display().to_string(),
                &bytes_chirho,
                pii_needles_chirho,
            )?;
            surfaces_chirho += 1;
        }
    }
    let effects_dir_chirho = root_chirho.join("effects-chirho");
    if effects_dir_chirho.exists() {
        for entry_chirho in std::fs::read_dir(&effects_dir_chirho)? {
            let path_chirho = entry_chirho?.path();
            let bytes_chirho = std::fs::read(&path_chirho)?;
            assert_no_contact_pii_chirho(
                &path_chirho.display().to_string(),
                &bytes_chirho,
                pii_needles_chirho,
            )?;
            let effect_chirho: EffectChirho = serde_json::from_slice(&bytes_chirho)?;
            effect_chirho::verify_effect_chirho(root_chirho, &effect_chirho)?;
            assert_effect_cas_objects_no_contact_pii_chirho(
                root_chirho,
                &effect_chirho,
                pii_needles_chirho,
            )?;
            surfaces_chirho += 1;
        }
    }
    for row_chirho in query_chirho::query_prefix_chirho(root_chirho, "contacts-chirho", 50)? {
        assert_no_contact_pii_chirho(
            &format!("read model key {}", row_chirho.key_chirho),
            row_chirho.key_chirho.as_bytes(),
            pii_needles_chirho,
        )?;
        assert_no_contact_pii_chirho(
            &format!("read model value {}", row_chirho.key_chirho),
            row_chirho.value_chirho.as_bytes(),
            pii_needles_chirho,
        )?;
        surfaces_chirho += 1;
    }
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))?;
    for (key_chirho, value_chirho) in store_chirho.current_entries_chirho()? {
        if contact_store_key_chirho(&key_chirho) {
            assert_no_contact_pii_chirho(
                &format!("current versioned key {key_chirho}"),
                key_chirho.as_bytes(),
                pii_needles_chirho,
            )?;
            assert_no_contact_pii_chirho(
                &format!("current versioned value {key_chirho}"),
                &value_chirho,
                pii_needles_chirho,
            )?;
            surfaces_chirho += 1;
        }
    }
    Ok(surfaces_chirho)
}

fn assert_effect_cas_objects_no_contact_pii_chirho(
    root_chirho: &Path,
    effect_chirho: &EffectChirho,
    pii_needles_chirho: &[&str],
) -> Result<()> {
    let request_chirho = cas_chirho::get_chirho(root_chirho, &effect_chirho.request_chirho)?;
    assert_no_contact_pii_chirho("effect request object", &request_chirho, pii_needles_chirho)?;
    if let Some(response_chirho) = &effect_chirho.response_chirho {
        // A sealed write's response rests as a private DAG value, so public CAS need not answer at
        // all — absence IS the evidence. When it does answer (a shape whose request shares the
        // response address), those bytes still get the needle check.
        //
        // ABSENCE, though, means NotFound and nothing else, and the private record must VERIFY.
        // Catching every read error alike let a TAMPERED public object — bytes that are present
        // and do not re-hash — skip the needle check entirely, and a bare existence check let one
        // appended line stand in for the sealing evidence. Both would make this operator evidence
        // report "no PII on the persisted surfaces" without having looked.
        match cas_chirho::read_verified_chirho(root_chirho, response_chirho) {
            cas_chirho::CasReadOutcomeChirho::VerifiedChirho(response_bytes_chirho) => {
                assert_no_contact_pii_chirho(
                    "effect response object",
                    &response_bytes_chirho,
                    pii_needles_chirho,
                )?
            }
            cas_chirho::CasReadOutcomeChirho::AbsentChirho(_absent_chirho) => {
                if dag_private_value_chirho::verified_private_dag_value_record_chirho(
                    root_chirho,
                    response_chirho,
                )?
                .is_none()
                {
                    bail!(
                        "effect response object is neither in public CAS nor a verified private DAG value"
                    );
                }
            }
            cas_chirho::CasReadOutcomeChirho::TamperedChirho { actual_chirho, .. } => bail!(
                "effect response object {} is present in public CAS and re-hashes to {}",
                response_chirho.0,
                actual_chirho.0
            ),
            cas_chirho::CasReadOutcomeChirho::UnreadableChirho(error_chirho) => bail!(
                "effect response object {} is present but could not be read: {error_chirho}",
                response_chirho.0
            ),
        }
    }
    Ok(())
}

fn contact_store_key_chirho(key_chirho: &str) -> bool {
    key_chirho == "contacts-chirho" || key_chirho.starts_with("contacts-chirho/")
}

pub(super) fn assert_no_contact_pii_chirho(
    surface_chirho: &str,
    bytes_chirho: &[u8],
    pii_needles_chirho: &[&str],
) -> Result<()> {
    let text_chirho = String::from_utf8_lossy(bytes_chirho);
    for needle_chirho in pii_needles_chirho {
        if text_chirho.contains(needle_chirho) {
            bail!("{surface_chirho} leaked contact PII needle '{needle_chirho}'");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "evidence_fail_closed_tests_chirho.rs"]
mod evidence_fail_closed_tests_chirho;
