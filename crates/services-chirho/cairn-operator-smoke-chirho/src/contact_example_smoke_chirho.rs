// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Runs the checked-in contact source manifest through the local HTTP lifecycle and emits safe evidence.

mod evidence_chirho;
mod http_smoke_chirho;
mod types_chirho;
mod wire_smoke_chirho;

use anyhow::{bail, Context, Result};
use cairn_chirho::model_chirho::CapabilityChirho;
use cairn_chirho::{
    app_chirho, app_source_manifest_chirho, cas_chirho, effect_chirho, identity_chirho,
    operator_evidence_chirho, privacy_chirho, query_chirho, tenant_chirho, verify_chirho,
    versioned_chirho,
};
use std::path::{Path, PathBuf};

use crate::cas_absence_evidence_chirho::raw_body_absent_from_public_cas_chirho;
use evidence_chirho::{
    assert_contact_safe_surfaces_no_pii_chirho, assert_no_contact_pii_chirho,
    persistent_effect_record_count_chirho, versioned_path_chirho,
};
pub use types_chirho::{
    ContactExamplePersistedEvidenceChirho, ContactExamplePrivateBodyEvidenceChirho,
    ContactExampleReadEvidenceChirho, ContactExampleRevealEvidenceChirho,
    ContactExampleSmokeReportChirho, ContactExampleWireEvidenceChirho,
    CONTACT_EXAMPLE_OPERATOR_READ_POSTURE_CHIRHO, CONTACT_EXAMPLE_SERVED_READ_POSTURE_CHIRHO,
    CONTACT_EXAMPLE_SMOKE_REPORT_SCHEMA_CHIRHO,
};
use types_chirho::{
    CONTACT_EXAMPLE_PERSISTED_EVIDENCE_SCHEMA_CHIRHO,
    CONTACT_EXAMPLE_PRIVATE_BODY_EVIDENCE_SCHEMA_CHIRHO,
};
use wire_smoke_chirho::run_contact_example_wire_smoke_chirho;

const CONTACT_EXAMPLE_SMOKE_TENANT_CHIRHO: &str = "contact-example-smoke-chirho";
pub fn default_contact_example_manifest_path_chirho() -> PathBuf {
    crate::workspace_root_for_operator_smoke_chirho()
        .join("examples-chirho")
        .join("contact-persisting-source-manifest-chirho.example.json")
}

pub fn contact_example_smoke_runtime_root_chirho(root_chirho: &Path) -> Result<PathBuf> {
    match tenant_chirho::tenant_id_for_root_chirho(root_chirho)? {
        tenant_chirho::TenantIdChirho::TenantChirho(_) => Ok(root_chirho.to_path_buf()),
        tenant_chirho::TenantIdChirho::PlatformRootChirho => {
            tenant_chirho::prepare_tenant_root_chirho(
                root_chirho,
                CONTACT_EXAMPLE_SMOKE_TENANT_CHIRHO,
            )
        }
    }
}

pub fn run_contact_example_smoke_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
) -> Result<ContactExampleSmokeReportChirho> {
    let runtime_root_chirho = contact_example_smoke_runtime_root_chirho(root_chirho)?;
    let root_chirho = runtime_root_chirho.as_path();
    let manifest_bytes_chirho = std::fs::read(manifest_path_chirho)
        .with_context(|| format!("read {}", manifest_path_chirho.display()))?;
    let manifest_hash_chirho = cas_chirho::hash_chirho(&manifest_bytes_chirho);
    let (_manifest_base_chirho, manifest_chirho) =
        app_source_manifest_chirho::load_app_source_manifest_from_path_chirho(
            manifest_path_chirho,
        )?;
    let manifest_template_owner_chirho = manifest_chirho.owner_chirho.clone();

    let owner_registration_chirho = identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )?;
    let owner_chirho = owner_registration_chirho.principal_chirho;
    let owner_login_chirho = identity_chirho::login_identity_chirho(root_chirho, &owner_chirho)?;

    let deploy_chirho =
        app_source_manifest_chirho::deploy_app_source_manifest_from_path_for_owner_chirho(
            root_chirho,
            manifest_path_chirho,
            &owner_chirho,
        )?;
    if deploy_chirho.schema_chirho
        != app_source_manifest_chirho::APP_SOURCE_DEPLOY_REPORT_SCHEMA_CHIRHO
    {
        bail!("source deploy report was not schema-tagged");
    }
    let status_chirho = app_chirho::app_status_chirho(root_chirho, "contact")?;
    if status_chirho
        .routes_chirho
        .get("contact-list")
        .is_none_or(|route_chirho| {
            deploy_chirho
                .modules_chirho
                .get(1)
                .is_none_or(|module_chirho| route_chirho != &module_chirho.dag_chirho)
        })
    {
        bail!("contact-list route did not resolve to the source-manifest route DAG");
    }

    let raw_body_chirho =
        b"name_chirho=Alice+Example&email_chirho=alice%40example.com&message_chirho=Apartment+above+the+bakery";
    let pii_needles_chirho = ["Alice", "alice@example.com", "bakery"];
    let raw_hash_chirho = cas_chirho::hash_chirho(raw_body_chirho);
    let owner_bearer_chirho = format!("Bearer {}", owner_login_chirho.token_chirho);
    let wire_chirho = run_contact_example_wire_smoke_chirho(
        root_chirho,
        &owner_chirho,
        &owner_bearer_chirho,
        raw_body_chirho,
        &pii_needles_chirho,
    )?;

    // ABSENT means NotFound and nothing else. The `is_err()` this replaced also swallowed
    // UNREADABLE — a mode-000 object file or shard directory — and recorded "the raw body is absent
    // from public CAS" over a body that may be sitting there intact. That sentence does not stay
    // local: it ships in this report and feeds the launch-readiness AND-chain.
    let raw_body_absent_from_cas_chirho = raw_body_absent_from_public_cas_chirho(
        root_chirho,
        &raw_hash_chirho,
        "contact example raw body",
    )?;
    if !raw_body_absent_from_cas_chirho {
        bail!("raw contact body was present in CAS");
    }
    let blob_records_chirho = privacy_chirho::load_privacy_blob_records_chirho(root_chirho)?;
    let _contact_blob_record_chirho = blob_records_chirho
        .iter()
        .find(|record_chirho| {
            privacy_chirho::load_private_blob_chirho(root_chirho, &record_chirho.blob_chirho)
                .is_ok_and(|body_chirho| body_chirho == raw_body_chirho)
        })
        .ok_or_else(|| anyhow::anyhow!("private contact body was not found in blob records"))?;
    let private_blob_roundtrip_verified_chirho = true;
    if !private_blob_roundtrip_verified_chirho {
        bail!("private contact body did not round-trip through the private blob store");
    }

    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))?;
    let versioned_view_chirho = store_chirho.current_view_chirho()?;
    let stored_contact_chirho = store_chirho
        .get_chirho(&wire_chirho.contact_key_chirho)?
        .ok_or_else(|| anyhow::anyhow!("missing contact row {}", wire_chirho.contact_key_chirho))?;
    assert_no_contact_pii_chirho(
        "versioned contact row",
        &stored_contact_chirho,
        &pii_needles_chirho,
    )?;
    drop(store_chirho);

    let surfaces_scanned_chirho =
        assert_contact_safe_surfaces_no_pii_chirho(root_chirho, &pii_needles_chirho)?;
    let persistent_effect_records_chirho = persistent_effect_record_count_chirho(root_chirho)?;
    let volatile_report_chirho = verify_chirho::verify_volatile_effect_records_chirho(root_chirho)?;
    let volatile_rows_chirho = effect_chirho::load_volatile_effect_records_chirho(root_chirho)?;
    if volatile_rows_chirho.iter().any(|record_chirho| {
        !matches!(
            record_chirho.effect_chirho.capability_chirho,
            CapabilityChirho::QueryChirho { .. }
        )
    }) {
        bail!("contact example smoke observed a non-query volatile effect");
    }

    let access_records_chirho = privacy_chirho::load_privacy_access_records_chirho(root_chirho)?;
    if access_records_chirho.len() != 1 {
        bail!(
            "expected one privacy access record, found {}",
            access_records_chirho.len()
        );
    }
    let owner_contact_reveal_seen_chirho = access_records_chirho.iter().any(|record_chirho| {
        record_chirho.accessed_by_chirho == owner_chirho
            && record_chirho.app_chirho == "contact"
            && record_chirho.row_key_chirho == wire_chirho.contact_key_chirho
            && record_chirho.purpose_chirho == "owner-contact-reveal-chirho"
    });
    if !owner_contact_reveal_seen_chirho {
        bail!("privacy access record did not bind the owner reveal to the contact row");
    }

    let privacy_verify_chirho = privacy_chirho::verify_privacy_logs_chirho(root_chirho)?;
    let privacy_scan_chirho = privacy_chirho::scan_privacy_surfaces_chirho(root_chirho)?;
    if !privacy_scan_chirho.findings_chirho.is_empty() {
        bail!(
            "contact example smoke privacy scan findings: {:?}",
            privacy_scan_chirho.findings_chirho
        );
    }

    Ok(ContactExampleSmokeReportChirho {
        schema_chirho: CONTACT_EXAMPLE_SMOKE_REPORT_SCHEMA_CHIRHO,
        manifest_source_chirho: operator_evidence_chirho::redacted_manifest_source_chirho(
            manifest_path_chirho,
        ),
        manifest_hash_chirho,
        manifest_template_owner_chirho,
        root_scope_chirho: operator_evidence_chirho::redacted_local_root_scope_chirho(root_chirho),
        app_chirho: deploy_chirho.app_chirho.clone(),
        owner_chirho,
        server_chirho: wire_chirho.server_chirho,
        deploy_chirho,
        page_chirho: wire_chirho.page_chirho,
        submit_chirho: wire_chirho.submit_chirho,
        list_refresh_chirho: wire_chirho.list_refresh_chirho,
        read_evidence_chirho: wire_chirho.read_evidence_chirho,
        missing_owner_session_chirho: wire_chirho.missing_owner_session_chirho,
        app_state_chirho: wire_chirho.app_state_chirho,
        reveal_chirho: wire_chirho.reveal_chirho,
        private_body_chirho: ContactExamplePrivateBodyEvidenceChirho {
            schema_chirho: CONTACT_EXAMPLE_PRIVATE_BODY_EVIDENCE_SCHEMA_CHIRHO,
            request_bytes_chirho: raw_body_chirho.len(),
            request_chirho: raw_hash_chirho,
            raw_body_absent_from_cas_chirho,
            private_blob_records_chirho: blob_records_chirho.len(),
            private_blob_roundtrip_verified_chirho,
        },
        persisted_chirho: ContactExamplePersistedEvidenceChirho {
            schema_chirho: CONTACT_EXAMPLE_PERSISTED_EVIDENCE_SCHEMA_CHIRHO,
            contact_key_chirho: wire_chirho.contact_key_chirho,
            versioned_view_chirho,
            query_rows_chirho: query_chirho::query_prefix_chirho(
                root_chirho,
                "contacts-chirho",
                50,
            )?
            .len(),
            persistent_effect_records_chirho,
            volatile_effect_records_chirho: volatile_report_chirho.records_chirho,
            volatile_effect_objects_chirho: volatile_report_chirho.objects_chirho,
            contact_safe_surfaces_scanned_chirho: surfaces_scanned_chirho,
            contact_safe_surfaces_pii_free_chirho: true,
        },
        privacy_verify_chirho,
        privacy_scan_chirho,
    })
}

#[cfg(test)]
#[path = "contact_example_smoke_chirho/tests_chirho.rs"]
mod tests_chirho;
