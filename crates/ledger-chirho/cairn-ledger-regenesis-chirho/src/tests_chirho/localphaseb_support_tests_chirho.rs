// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Packet-provenance parent refusal pins (#6050/#6051/#6052): every mutation fires BEFORE the
//! lent ports are used, so the ports here are deliberate panic stubs — a stub panic would itself
//! be a test failure proving the refusal order broke.

use super::*;
use crate::completion_chirho::LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO;
use crate::localphaseb_support_chirho::verified_localphaseb_evidence_from_packet_chirho;
use crate::run_ledger_regenesis_chirho;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindRegistryViewChirho,
    KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::ShardEpochChirho;
use cairn_ledger_read_model_chirho::feeder_chirho::ProjectionSourceChirho;
use cairn_ledger_read_model_chirho::localphaseb_evidence_chirho::LocalPhaseBEvidencePortsChirho;

struct PanicStorageChirho;
impl LedgerStoragePortChirho for PanicStorageChirho {
    fn create_durable_chirho(
        &self,
        _path_chirho: &StoragePathChirho,
        _bytes_chirho: &[u8],
    ) -> anyhow::Result<cairn_ledger_log_chirho::ports_chirho::CreateDurableOutcomeChirho> {
        unimplemented!("parent refusal must fire before storage use")
    }
    fn append_durable_chirho(&self, _p: &StoragePathChirho, _b: &[u8]) -> anyhow::Result<()> {
        unimplemented!("parent refusal must fire before storage use")
    }
    fn read_all_chirho(&self, _p: &StoragePathChirho) -> anyhow::Result<Option<Vec<u8>>> {
        unimplemented!("parent refusal must fire before storage use")
    }
    fn object_len_chirho(&self, _p: &StoragePathChirho) -> anyhow::Result<Option<u64>> {
        unimplemented!("parent refusal must fire before storage use")
    }
    fn read_exact_range_chirho(
        &self,
        _p: &StoragePathChirho,
        _o: u64,
        _l: u64,
    ) -> anyhow::Result<Vec<u8>> {
        unimplemented!("parent refusal must fire before storage use")
    }
    fn atomic_write_chirho(&self, _p: &StoragePathChirho, _b: &[u8]) -> anyhow::Result<()> {
        unimplemented!("parent refusal must fire before storage use")
    }
    fn truncate_durable_chirho(&self, _p: &StoragePathChirho, _l: u64) -> anyhow::Result<()> {
        unimplemented!("parent refusal must fire before storage use")
    }
    fn rename_chirho(&self, _f: &StoragePathChirho, _t: &StoragePathChirho) -> anyhow::Result<()> {
        unimplemented!("parent refusal must fire before storage use")
    }
    fn remove_chirho(&self, _p: &StoragePathChirho) -> anyhow::Result<()> {
        unimplemented!("parent refusal must fire before storage use")
    }
    fn list_chirho(&self, _p: &StoragePathChirho) -> anyhow::Result<Vec<StoragePathChirho>> {
        unimplemented!("parent refusal must fire before storage use")
    }
    fn exists_chirho(&self, _p: &StoragePathChirho) -> anyhow::Result<bool> {
        unimplemented!("parent refusal must fire before storage use")
    }
}

struct PanicSignerChirho;
impl LedgerSignerPortChirho for PanicSignerChirho {
    fn sign_chirho(&self, _l: &str) -> anyhow::Result<String> {
        unimplemented!("parent refusal must fire before signer use")
    }
    fn key_id_chirho(&self) -> String {
        unimplemented!("parent refusal must fire before signer use")
    }
    fn verify_chirho(&self, _l: &str, _s: &str) -> bool {
        unimplemented!("parent refusal must fire before signer use")
    }
}

struct PanicClockChirho;
impl LedgerClockPortChirho for PanicClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        unimplemented!("parent refusal must fire before clock use")
    }
}

struct PanicMembershipChirho;
impl MembershipViewChirho for PanicMembershipChirho {
    fn status_chirho(&self, _a: &AccountIdChirho, _e: ShardEpochChirho) -> MembershipStatusChirho {
        unimplemented!("parent refusal must fire before membership use")
    }
}

struct PanicRegistryChirho;
impl KindRegistryViewChirho for PanicRegistryChirho {
    fn resolve_chirho(&self, _r: &AssetKindRefChirho) -> KindResolutionChirho {
        unimplemented!("parent refusal must fire before registry use")
    }
}

struct PanicAuthorityChirho;
impl AuthorityVerifierViewChirho for PanicAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        _e: &DigestChirho,
        _k: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        unimplemented!("parent refusal must fire before authority use")
    }
    fn verify_burn_chirho(
        &self,
        _e: &DigestChirho,
        _k: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        unimplemented!("parent refusal must fire before authority use")
    }
}

struct ParentFixtureChirho {
    _fixture_chirho: RegenesisFixtureChirho,
    packet_bytes_chirho: Vec<u8>,
    packet_digest_chirho: String,
    cluster_chirho: ClusterIdChirho,
    journal_path_chirho: StoragePathChirho,
    projection_name_chirho: String,
}

fn published_parent_fixture_chirho() -> ParentFixtureChirho {
    let fixture_chirho = fixture_chirho();
    let published_chirho = run_ledger_regenesis_chirho(request_chirho(&fixture_chirho)).unwrap();
    let packet_path_chirho = fixture_chirho
        .root_chirho
        .join(&fixture_chirho.plan_chirho.monitor_evidence_namespace_chirho)
        .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO);
    let packet_bytes_chirho = fs::read(packet_path_chirho).unwrap();
    let projection_name_chirho = fixture_chirho
        .plan_chirho
        .projection_routes_chirho
        .first()
        .unwrap()
        .projection_name_chirho
        .clone();
    ParentFixtureChirho {
        cluster_chirho: ClusterIdChirho(fixture_chirho.plan_chirho.cluster_id_chirho.clone()),
        journal_path_chirho: StoragePathChirho(
            fixture_chirho.plan_chirho.journal_path_chirho.clone(),
        ),
        projection_name_chirho,
        packet_bytes_chirho,
        packet_digest_chirho: published_chirho.packet_digest_chirho,
        _fixture_chirho: fixture_chirho,
    }
}

fn run_parent_chirho(
    fixture_chirho: &ParentFixtureChirho,
    packet_bytes_chirho: &[u8],
    expected_digest_chirho: &str,
) -> anyhow::Error {
    let storage_chirho = PanicStorageChirho;
    let signer_chirho = PanicSignerChirho;
    let clock_chirho = PanicClockChirho;
    let membership_chirho = PanicMembershipChirho;
    let registry_chirho = PanicRegistryChirho;
    let authority_chirho = PanicAuthorityChirho;
    let retained_chirho = StoragePathChirho("published/retained-chirho.json".to_string());
    let final_chirho = StoragePathChirho("published/final-chirho.json".to_string());
    verified_localphaseb_evidence_from_packet_chirho(
        packet_bytes_chirho,
        expected_digest_chirho,
        &fixture_chirho.projection_name_chirho,
        LocalPhaseBEvidencePortsChirho {
            source_chirho: ProjectionSourceChirho {
                journal_ports_chirho: JournalPortsChirho {
                    storage_chirho: &storage_chirho,
                    signer_chirho: &signer_chirho,
                    clock_chirho: &clock_chirho,
                    membership_chirho: &membership_chirho,
                    kind_registry_chirho: &registry_chirho,
                    authority_chirho: &authority_chirho,
                },
                journal_path_chirho: &fixture_chirho.journal_path_chirho,
                cluster_chirho: &fixture_chirho.cluster_chirho,
            },
            storage_chirho: &storage_chirho,
            feeder_root_chirho: &signer_chirho,
            final_head_path_chirho: &final_chirho,
        },
        &retained_chirho,
    )
    .err()
    .expect("parent must refuse the mutated packet")
}

#[test]
fn parent_refuses_wrong_expected_digest_chirho() {
    let fixture_chirho = published_parent_fixture_chirho();
    let error_chirho = run_parent_chirho(
        &fixture_chirho,
        &fixture_chirho.packet_bytes_chirho,
        &"0".repeat(64),
    );
    assert!(error_chirho
        .to_string()
        .contains("does not equal the regenesis receipt packet digest"));
}

#[test]
fn parent_refuses_truncated_packet_bytes_chirho() {
    let fixture_chirho = published_parent_fixture_chirho();
    let truncated_chirho =
        &fixture_chirho.packet_bytes_chirho[..fixture_chirho.packet_bytes_chirho.len() - 2];
    let digest_chirho =
        crate::completion_chirho::ledger_regenesis_evidence_packet_digest_chirho(truncated_chirho);
    // The mutation genuinely moved the digest coordinate away from the published receipt's.
    assert_ne!(digest_chirho, fixture_chirho.packet_digest_chirho);
    let error_chirho = run_parent_chirho(&fixture_chirho, truncated_chirho, &digest_chirho);
    assert!(error_chirho.to_string().contains("canonical parse refused"));
}

#[test]
fn parent_refuses_duplicate_balance_projection_rows_chirho() {
    let fixture_chirho = published_parent_fixture_chirho();
    let mut value_chirho: serde_json::Value =
        serde_json::from_slice(&fixture_chirho.packet_bytes_chirho).unwrap();
    let projections_chirho = value_chirho
        .get_mut("projections_chirho")
        .and_then(|value_chirho| value_chirho.as_array_mut())
        .unwrap();
    let balance_chirho = projections_chirho
        .iter()
        .find(|row_chirho| {
            row_chirho["projection_name_chirho"] == fixture_chirho.projection_name_chirho.as_str()
        })
        .cloned()
        .unwrap();
    projections_chirho.push(balance_chirho);
    let mutated_chirho = serde_json::to_vec(&value_chirho).unwrap();
    let digest_chirho =
        crate::completion_chirho::ledger_regenesis_evidence_packet_digest_chirho(&mutated_chirho);
    let error_chirho = run_parent_chirho(&fixture_chirho, &mutated_chirho, &digest_chirho);
    let message_chirho = error_chirho.to_string();
    assert!(
        message_chirho.contains("duplicate projection evidence")
            || message_chirho.contains("canonical parse refused"),
        "unexpected refusal: {message_chirho}"
    );
}

#[test]
fn parent_refuses_forged_source_family_chirho() {
    let fixture_chirho = published_parent_fixture_chirho();
    let text_chirho = String::from_utf8(fixture_chirho.packet_bytes_chirho.clone()).unwrap();
    let forged_chirho = text_chirho.replace(
        &format!("ledger-journal-{}", fixture_chirho.cluster_chirho.0),
        "ledger-journal-forged-cluster-chirho",
    );
    assert_ne!(forged_chirho, text_chirho);
    let mutated_chirho = forged_chirho.into_bytes();
    let digest_chirho =
        crate::completion_chirho::ledger_regenesis_evidence_packet_digest_chirho(&mutated_chirho);
    let error_chirho = run_parent_chirho(&fixture_chirho, &mutated_chirho, &digest_chirho);
    let message_chirho = error_chirho.to_string();
    assert!(
        message_chirho.contains("journal source family derived from the")
            || message_chirho.contains("canonical parse refused"),
        "unexpected refusal: {message_chirho}"
    );
}
