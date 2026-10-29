// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Real signed destination-enrollment fixtures for dependent crate tests.
//!
//! This module is feature-gated test support, but it does not construct the private verified type.
//! It authors a signed roster and head, authors an enrollment through the production road, writes
//! the exact returned bytes, and obtains the typed value only through the production reader.

use crate::{
    author_destination_authority_enrollment_chirho, read_destination_authority_enrollment_chirho,
    DestinationAuthorityEnrollmentAuthorRequestChirho,
    VerifiedDestinationAuthorityEnrollmentChirho,
};
use cairn_replication_chirho::membership_chirho::{
    roster_prefix_digest_chirho, unsigned_membership_roster_head_message_chirho,
    unsigned_membership_roster_message_chirho, MembershipActionChirho, MembershipRosterHeadChirho,
    MembershipRosterRecordChirho, MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO,
    MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO,
};
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEST_ENROLLMENT_CHIRHO: AtomicU64 = AtomicU64::new(1);

pub struct DestinationAuthorityEnrollmentTestFixtureChirho {
    pub root_chirho: PathBuf,
    pub destination_authority_signing_root_chirho: PathBuf,
    pub enrollment_path_chirho: PathBuf,
    pub enrollment_digest_chirho: String,
    pub cluster_genesis_roster_path_chirho: PathBuf,
    pub cluster_genesis_roster_head_path_chirho: PathBuf,
    pub cluster_genesis_roster_operator_pubkey_hex_chirho: String,
    pub verified_chirho: VerifiedDestinationAuthorityEnrollmentChirho,
}

impl Drop for DestinationAuthorityEnrollmentTestFixtureChirho {
    fn drop(&mut self) {
        let _removed_chirho = fs::remove_dir_all(&self.root_chirho);
    }
}

pub fn create_destination_authority_enrollment_test_fixture_chirho(
    label_chirho: &str,
) -> DestinationAuthorityEnrollmentTestFixtureChirho {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-enrollment-test-{label_chirho}-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock follows the epoch")
            .as_nanos(),
        NEXT_TEST_ENROLLMENT_CHIRHO.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir(&root_chirho).expect("create the enrollment fixture root");
    let destination_authority_signing_root_chirho =
        root_chirho.join("destination-authority-key-chirho");
    install_existing_keypair_chirho(&destination_authority_signing_root_chirho, 41);
    let genesis_root_chirho = root_chirho.join("cluster-genesis-chirho");
    fs::create_dir(&genesis_root_chirho).expect("create the genesis fixture root");
    let (
        cluster_genesis_roster_path_chirho,
        cluster_genesis_roster_head_path_chirho,
        cluster_genesis_roster_operator_pubkey_hex_chirho,
    ) = author_genesis_bundle_chirho(&genesis_root_chirho);
    let authored_chirho = author_destination_authority_enrollment_chirho(
        DestinationAuthorityEnrollmentAuthorRequestChirho {
            destination_authority_signing_root_chirho: &destination_authority_signing_root_chirho,
            cluster_genesis_roster_path_chirho: &cluster_genesis_roster_path_chirho,
            cluster_genesis_roster_head_path_chirho: &cluster_genesis_roster_head_path_chirho,
            cluster_genesis_roster_operator_pubkey_hex_chirho:
                &cluster_genesis_roster_operator_pubkey_hex_chirho,
        },
    )
    .expect("author the real destination enrollment fixture");
    let enrollment_path_chirho = root_chirho.join("destination-authority-enrollment-chirho.json");
    write_private_chirho(
        &enrollment_path_chirho,
        &authored_chirho.canonical_record_bytes_chirho,
    );
    let verified_chirho = read_destination_authority_enrollment_chirho(
        &enrollment_path_chirho,
        &cluster_genesis_roster_path_chirho,
        &cluster_genesis_roster_head_path_chirho,
        &cluster_genesis_roster_operator_pubkey_hex_chirho,
    )
    .expect("read the fixture only through production enrollment verification");
    DestinationAuthorityEnrollmentTestFixtureChirho {
        root_chirho,
        destination_authority_signing_root_chirho,
        enrollment_path_chirho,
        enrollment_digest_chirho: authored_chirho.enrollment_digest_chirho,
        cluster_genesis_roster_path_chirho,
        cluster_genesis_roster_head_path_chirho,
        cluster_genesis_roster_operator_pubkey_hex_chirho,
        verified_chirho,
    }
}

fn author_genesis_bundle_chirho(parent_chirho: &Path) -> (PathBuf, PathBuf, String) {
    let operator_key_chirho = SigningKey::from_bytes(&[31_u8; 32]);
    let operator_pubkey_hex_chirho = hex_chirho(operator_key_chirho.verifying_key().as_bytes());
    let node_key_chirho = SigningKey::from_bytes(&[51_u8; 32]);
    let mut record_chirho = MembershipRosterRecordChirho {
        schema_chirho: MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO.to_owned(),
        seq_chirho: 0,
        action_chirho: MembershipActionChirho::AddNodeChirho,
        node_pubkey_hex_chirho: hex_chirho(node_key_chirho.verifying_key().as_bytes()),
        region_label_chirho: "cluster-genesis-region-chirho".to_owned(),
        at_ms_chirho: 1,
        operator_key_id_chirho: operator_pubkey_hex_chirho.clone(),
        sig_chirho: String::new(),
    };
    let record_message_chirho = unsigned_membership_roster_message_chirho(&record_chirho)
        .expect("encode the fixture roster record");
    record_chirho.sig_chirho =
        hex_chirho(&operator_key_chirho.sign(&record_message_chirho).to_bytes());
    let record_bytes_chirho = serde_json::to_vec(&record_chirho).expect("encode the roster record");
    let roster_path_chirho = parent_chirho.join("membership-roster-chirho.jsonl");
    let mut roster_bytes_chirho = record_bytes_chirho.clone();
    roster_bytes_chirho.push(b'\n');
    write_private_chirho(&roster_path_chirho, &roster_bytes_chirho);

    let mut head_chirho = MembershipRosterHeadChirho {
        schema_chirho: MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO.to_owned(),
        roster_record_count_chirho: 1,
        roster_prefix_digest_chirho: roster_prefix_digest_chirho(&[record_bytes_chirho]),
        at_ms_chirho: 1,
        operator_key_id_chirho: operator_pubkey_hex_chirho.clone(),
        sig_chirho: String::new(),
    };
    let head_message_chirho = unsigned_membership_roster_head_message_chirho(&head_chirho)
        .expect("encode the fixture roster head");
    head_chirho.sig_chirho = hex_chirho(&operator_key_chirho.sign(&head_message_chirho).to_bytes());
    let head_path_chirho = parent_chirho.join("membership-roster-head-chirho.json");
    write_private_chirho(
        &head_path_chirho,
        &serde_json::to_vec(&head_chirho).expect("encode the roster head"),
    );
    (
        roster_path_chirho,
        head_path_chirho,
        operator_pubkey_hex_chirho,
    )
}

fn install_existing_keypair_chirho(root_chirho: &Path, seed_chirho: u8) {
    fs::create_dir(root_chirho).expect("create the external destination-key root");
    let signing_key_chirho = SigningKey::from_bytes(&[seed_chirho; 32]);
    write_private_chirho(
        &root_chirho.join("signing-key-chirho.bin"),
        &signing_key_chirho.to_bytes(),
    );
    write_private_chirho(
        &root_chirho.join("pubkey-chirho.hex"),
        hex_chirho(signing_key_chirho.verifying_key().as_bytes()).as_bytes(),
    );
}

fn write_private_chirho(path_chirho: &Path, bytes_chirho: &[u8]) {
    let mut options_chirho = fs::OpenOptions::new();
    options_chirho.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options_chirho.mode(0o600);
    }
    let mut file_chirho = options_chirho
        .open(path_chirho)
        .expect("create the private fixture file");
    file_chirho
        .write_all(bytes_chirho)
        .expect("write the private fixture file");
    file_chirho
        .sync_all()
        .expect("sync the private fixture file");
}

fn hex_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}
