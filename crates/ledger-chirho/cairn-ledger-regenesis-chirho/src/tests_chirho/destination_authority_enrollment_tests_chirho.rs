// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::destination_authority_enrollment_chirho::{
    author_destination_authority_enrollment_chirho, bind_destination_authority_possession_chirho,
    destination_authority_enrollment_digest_chirho,
    destination_authority_enrollment_unsigned_message_chirho,
    read_destination_authority_enrollment_chirho,
    read_digest_bound_destination_authority_enrollment_chirho,
    DestinationAuthorityEnrollmentAuthorRequestChirho,
    DestinationAuthorityEnrollmentRecordV1Chirho,
};
use crate::error_chirho::LedgerRegenesisRefusalChirho;
use cairn_replication_chirho::membership_chirho::{
    roster_prefix_digest_chirho, unsigned_membership_roster_head_message_chirho,
    unsigned_membership_roster_message_chirho, MembershipActionChirho, MembershipRosterHeadChirho,
    MembershipRosterRecordChirho, MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO,
    MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho;
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_FIXTURE_CHIRHO: AtomicU64 = AtomicU64::new(1);

struct GenesisBundleChirho {
    roster_path_chirho: PathBuf,
    roster_head_path_chirho: PathBuf,
    operator_pubkey_hex_chirho: String,
}

struct EnrollmentFixtureChirho {
    root_chirho: PathBuf,
    destination_key_root_chirho: PathBuf,
    enrollment_path_chirho: PathBuf,
    genesis_chirho: GenesisBundleChirho,
    destination_pubkey_hex_chirho: String,
}

impl Drop for EnrollmentFixtureChirho {
    fn drop(&mut self) {
        let _removed_chirho = fs::remove_dir_all(&self.root_chirho);
    }
}

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cairn-destination-enrollment-{label_chirho}-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock follows the epoch")
            .as_nanos(),
        NEXT_FIXTURE_CHIRHO.fetch_add(1, Ordering::Relaxed),
    ))
}

fn hex_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

fn write_private_chirho(path_chirho: &Path, bytes_chirho: &[u8]) {
    let mut options_chirho = fs::OpenOptions::new();
    options_chirho.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options_chirho.mode(0o600);
    }
    let mut file_chirho = options_chirho
        .open(path_chirho)
        .expect("open the private fixture file");
    file_chirho
        .write_all(bytes_chirho)
        .expect("write the private fixture file");
    file_chirho.sync_all().expect("sync the fixture file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path_chirho, fs::Permissions::from_mode(0o600))
            .expect("fix the private fixture mode");
    }
}

fn install_existing_keypair_chirho(root_chirho: &Path, seed_byte_chirho: u8) -> String {
    fs::create_dir_all(root_chirho).expect("create the external signing root");
    let signing_key_chirho = SigningKey::from_bytes(&[seed_byte_chirho; 32]);
    let pubkey_hex_chirho = hex_chirho(signing_key_chirho.verifying_key().as_bytes());
    write_private_chirho(
        &root_chirho.join("signing-key-chirho.bin"),
        &signing_key_chirho.to_bytes(),
    );
    write_private_chirho(
        &root_chirho.join("pubkey-chirho.hex"),
        pubkey_hex_chirho.as_bytes(),
    );
    pubkey_hex_chirho
}

fn author_genesis_bundle_chirho(
    parent_chirho: &Path,
    operator_seed_byte_chirho: u8,
    node_seed_byte_chirho: u8,
) -> GenesisBundleChirho {
    fs::create_dir_all(parent_chirho).expect("create the genesis bundle parent");
    let operator_key_chirho = SigningKey::from_bytes(&[operator_seed_byte_chirho; 32]);
    let operator_pubkey_hex_chirho = hex_chirho(operator_key_chirho.verifying_key().as_bytes());
    let node_key_chirho = SigningKey::from_bytes(&[node_seed_byte_chirho; 32]);
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
        .expect("encode the unsigned roster record");
    record_chirho.sig_chirho =
        hex_chirho(&operator_key_chirho.sign(&record_message_chirho).to_bytes());
    let record_bytes_chirho =
        serde_json::to_vec(&record_chirho).expect("encode the signed roster record");
    let roster_path_chirho = parent_chirho.join("membership-roster-chirho.jsonl");
    let mut roster_file_bytes_chirho = record_bytes_chirho.clone();
    roster_file_bytes_chirho.push(b'\n');
    write_private_chirho(&roster_path_chirho, &roster_file_bytes_chirho);

    let mut head_chirho = MembershipRosterHeadChirho {
        schema_chirho: MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO.to_owned(),
        roster_record_count_chirho: 1,
        roster_prefix_digest_chirho: roster_prefix_digest_chirho(&[record_bytes_chirho]),
        at_ms_chirho: 1,
        operator_key_id_chirho: operator_pubkey_hex_chirho.clone(),
        sig_chirho: String::new(),
    };
    let head_message_chirho = unsigned_membership_roster_head_message_chirho(&head_chirho)
        .expect("encode the unsigned roster head");
    head_chirho.sig_chirho = hex_chirho(&operator_key_chirho.sign(&head_message_chirho).to_bytes());
    let roster_head_path_chirho = parent_chirho.join("membership-roster-head-chirho.json");
    write_private_chirho(
        &roster_head_path_chirho,
        &serde_json::to_vec(&head_chirho).expect("encode the signed roster head"),
    );
    GenesisBundleChirho {
        roster_path_chirho,
        roster_head_path_chirho,
        operator_pubkey_hex_chirho,
    }
}

fn fixture_with_seeds_chirho(
    label_chirho: &str,
    operator_seed_byte_chirho: u8,
    destination_seed_byte_chirho: u8,
    node_seed_byte_chirho: u8,
) -> EnrollmentFixtureChirho {
    let root_chirho = temp_root_chirho(label_chirho);
    fs::create_dir(&root_chirho).expect("create the enrollment fixture root");
    let genesis_chirho = author_genesis_bundle_chirho(
        &root_chirho.join("genesis-chirho"),
        operator_seed_byte_chirho,
        node_seed_byte_chirho,
    );
    let destination_key_root_chirho = root_chirho.join("destination-key-chirho");
    let destination_pubkey_hex_chirho =
        install_existing_keypair_chirho(&destination_key_root_chirho, destination_seed_byte_chirho);
    let authored_chirho = author_destination_authority_enrollment_chirho(
        DestinationAuthorityEnrollmentAuthorRequestChirho {
            destination_authority_signing_root_chirho: &destination_key_root_chirho,
            cluster_genesis_roster_path_chirho: &genesis_chirho.roster_path_chirho,
            cluster_genesis_roster_head_path_chirho: &genesis_chirho.roster_head_path_chirho,
            cluster_genesis_roster_operator_pubkey_hex_chirho: &genesis_chirho
                .operator_pubkey_hex_chirho,
        },
    )
    .expect("author the self-verified enrollment fixture");
    let enrollment_path_chirho = root_chirho.join("destination-enrollment-chirho.json");
    write_private_chirho(
        &enrollment_path_chirho,
        &authored_chirho.canonical_record_bytes_chirho,
    );
    EnrollmentFixtureChirho {
        root_chirho,
        destination_key_root_chirho,
        enrollment_path_chirho,
        genesis_chirho,
        destination_pubkey_hex_chirho,
    }
}

fn fixture_chirho(label_chirho: &str) -> EnrollmentFixtureChirho {
    fixture_with_seeds_chirho(label_chirho, 31, 41, 51)
}

fn read_fixture_chirho(
    fixture_chirho: &EnrollmentFixtureChirho,
) -> Result<
    crate::destination_authority_enrollment_chirho::VerifiedDestinationAuthorityEnrollmentChirho,
    LedgerRegenesisRefusalChirho,
> {
    read_destination_authority_enrollment_chirho(
        &fixture_chirho.enrollment_path_chirho,
        &fixture_chirho.genesis_chirho.roster_path_chirho,
        &fixture_chirho.genesis_chirho.roster_head_path_chirho,
        &fixture_chirho.genesis_chirho.operator_pubkey_hex_chirho,
    )
}

#[test]
fn a_self_signed_enrollment_proves_possession_and_genesis_binding_not_legitimacy_chirho() {
    let fixture_chirho = fixture_chirho("valid-chirho");
    let verified_chirho = read_fixture_chirho(&fixture_chirho).expect("verify the enrollment");
    let config_chirho = verified_chirho.destination_authority_config_chirho();
    assert_eq!(
        config_chirho.key_id_chirho,
        fixture_chirho.destination_pubkey_hex_chirho
    );
    assert_eq!(
        config_chirho.verifying_key_hex_chirho,
        fixture_chirho.destination_pubkey_hex_chirho
    );
    assert_eq!(verified_chirho.verified_roster_record_count_chirho(), 1);
    assert_eq!(verified_chirho.verified_active_member_count_chirho(), 1);
    assert_eq!(
        verified_chirho.enrollment_digest_chirho(),
        destination_authority_enrollment_digest_chirho(
            &fs::read(&fixture_chirho.enrollment_path_chirho).unwrap()
        )
    );
}

#[test]
fn the_genesis_coordinate_hashes_the_original_verified_head_bytes_chirho() {
    let fixture_chirho = fixture_chirho("raw-head-bytes-chirho");
    let mut head_bytes_chirho =
        fs::read(&fixture_chirho.genesis_chirho.roster_head_path_chirho).unwrap();
    head_bytes_chirho.push(b'\n');
    write_private_chirho(
        &fixture_chirho.genesis_chirho.roster_head_path_chirho,
        &head_bytes_chirho,
    );
    let authored_chirho = author_destination_authority_enrollment_chirho(
        DestinationAuthorityEnrollmentAuthorRequestChirho {
            destination_authority_signing_root_chirho: &fixture_chirho.destination_key_root_chirho,
            cluster_genesis_roster_path_chirho: &fixture_chirho.genesis_chirho.roster_path_chirho,
            cluster_genesis_roster_head_path_chirho: &fixture_chirho
                .genesis_chirho
                .roster_head_path_chirho,
            cluster_genesis_roster_operator_pubkey_hex_chirho: &fixture_chirho
                .genesis_chirho
                .operator_pubkey_hex_chirho,
        },
    )
    .expect("JSON trailing whitespace does not invalidate the signed parsed head");
    assert_eq!(
        authored_chirho.cluster_genesis_roster_head_blake3_chirho,
        blake3::hash(&head_bytes_chirho).to_hex().to_string()
    );
}

#[test]
fn a_wrong_expected_digest_refuses_before_parse_or_genesis_access_chirho() {
    let root_chirho = temp_root_chirho("digest-order-chirho");
    fs::create_dir(&root_chirho).unwrap();
    let enrollment_path_chirho = root_chirho.join("malformed-enrollment-chirho.json");
    write_private_chirho(&enrollment_path_chirho, b"not-json-chirho");
    let missing_chirho = root_chirho.join("missing-genesis-chirho");
    let refusal_chirho = read_digest_bound_destination_authority_enrollment_chirho(
        &enrollment_path_chirho,
        &"11".repeat(32),
        &missing_chirho,
        &missing_chirho,
        &"22".repeat(32),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentDigestMismatchChirho
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn an_invalid_expected_digest_refuses_before_the_enrollment_is_read_chirho() {
    let missing_chirho = temp_root_chirho("missing-enrollment-chirho");
    let refusal_chirho = read_digest_bound_destination_authority_enrollment_chirho(
        &missing_chirho,
        "not-a-digest-chirho",
        &missing_chirho,
        &missing_chirho,
        &"22".repeat(32),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentDigestInvalidChirho
    );
}

#[test]
fn a_valid_enrollment_cannot_be_transplanted_to_another_verified_genesis_chirho() {
    let first_chirho = fixture_with_seeds_chirho("first-genesis-chirho", 31, 41, 51);
    let second_chirho = fixture_with_seeds_chirho("second-genesis-chirho", 32, 42, 52);
    let refusal_chirho = read_destination_authority_enrollment_chirho(
        &first_chirho.enrollment_path_chirho,
        &second_chirho.genesis_chirho.roster_path_chirho,
        &second_chirho.genesis_chirho.roster_head_path_chirho,
        &second_chirho.genesis_chirho.operator_pubkey_hex_chirho,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentGenesisBindingRefusedChirho
    );
}

#[test]
fn a_roster_file_cannot_masquerade_as_its_signed_head_chirho() {
    let fixture_chirho = fixture_chirho("wrong-sibling-chirho");
    let refusal_chirho = read_destination_authority_enrollment_chirho(
        &fixture_chirho.enrollment_path_chirho,
        &fixture_chirho.genesis_chirho.roster_path_chirho,
        &fixture_chirho.genesis_chirho.roster_path_chirho,
        &fixture_chirho.genesis_chirho.operator_pubkey_hex_chirho,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ClusterGenesisRosterVerificationRefusedChirho
    );
}

#[test]
fn a_free_choice_key_label_cannot_name_a_different_destination_key_chirho() {
    let fixture_chirho = fixture_chirho("key-label-chirho");
    let mut record_chirho: DestinationAuthorityEnrollmentRecordV1Chirho =
        serde_json::from_slice(&fs::read(&fixture_chirho.enrollment_path_chirho).unwrap()).unwrap();
    record_chirho.authority_key_id_chirho = hex_chirho(
        SigningKey::from_bytes(&[77_u8; 32])
            .verifying_key()
            .as_bytes(),
    );
    write_private_chirho(
        &fixture_chirho.enrollment_path_chirho,
        &serde_json::to_vec(&record_chirho).unwrap(),
    );
    assert_eq!(
        read_fixture_chirho(&fixture_chirho).unwrap_err(),
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentAuthorityBindingRefusedChirho
    );
}

#[test]
fn every_enrollment_schema_coordinate_is_pinned_before_signature_credit_chirho() {
    let fixture_chirho = fixture_chirho("schema-chirho");
    let original_chirho: DestinationAuthorityEnrollmentRecordV1Chirho =
        serde_json::from_slice(&fs::read(&fixture_chirho.enrollment_path_chirho).unwrap()).unwrap();
    let mut record_schema_chirho = original_chirho.clone();
    record_schema_chirho.schema_chirho = "wrong-record-schema-chirho".to_owned();
    let mut intent_schema_chirho = original_chirho.clone();
    intent_schema_chirho.intent_chirho.schema_chirho = "wrong-intent-schema-chirho".to_owned();
    let mut signature_domain_chirho = original_chirho;
    signature_domain_chirho.signature_domain_chirho = "wrong-signature-domain-chirho".to_owned();

    for refused_record_chirho in [
        record_schema_chirho,
        intent_schema_chirho,
        signature_domain_chirho,
    ] {
        write_private_chirho(
            &fixture_chirho.enrollment_path_chirho,
            &serde_json::to_vec(&refused_record_chirho).unwrap(),
        );
        assert_eq!(
            read_fixture_chirho(&fixture_chirho).unwrap_err(),
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentSchemaRefusedChirho
        );
    }
}

#[test]
fn an_invalid_reviewed_roster_operator_key_refuses_before_genesis_verification_chirho() {
    let fixture_chirho = fixture_chirho("operator-key-shape-chirho");
    assert_eq!(
        read_destination_authority_enrollment_chirho(
            &fixture_chirho.enrollment_path_chirho,
            &fixture_chirho.genesis_chirho.roster_path_chirho,
            &fixture_chirho.genesis_chirho.roster_head_path_chirho,
            "not-an-ed25519-public-key-chirho",
        )
        .unwrap_err(),
        LedgerRegenesisRefusalChirho::ClusterGenesisRosterOperatorKeyInvalidChirho
    );
}

#[test]
fn a_stored_intent_digest_must_describe_the_carried_intent_chirho() {
    let fixture_chirho = fixture_chirho("intent-digest-chirho");
    let mut record_chirho: DestinationAuthorityEnrollmentRecordV1Chirho =
        serde_json::from_slice(&fs::read(&fixture_chirho.enrollment_path_chirho).unwrap()).unwrap();
    let wrong_digest_chirho = "00".repeat(32);
    assert_ne!(record_chirho.intent_digest_chirho, wrong_digest_chirho);
    record_chirho.intent_digest_chirho = wrong_digest_chirho;
    write_private_chirho(
        &fixture_chirho.enrollment_path_chirho,
        &serde_json::to_vec(&record_chirho).unwrap(),
    );
    assert_eq!(
        read_fixture_chirho(&fixture_chirho).unwrap_err(),
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentIntentDigestMismatchChirho
    );
}

#[test]
fn possession_from_a_swapped_key_cannot_sign_the_advertised_authority_chirho() {
    let fixture_chirho = fixture_chirho("possession-key-identity-chirho");
    let mut record_chirho: DestinationAuthorityEnrollmentRecordV1Chirho =
        serde_json::from_slice(&fs::read(&fixture_chirho.enrollment_path_chirho).unwrap()).unwrap();
    let original_signature_chirho = record_chirho.sig_chirho.clone();
    let swapped_key_root_chirho = fixture_chirho.root_chirho.join("swapped-key-chirho");
    let swapped_key_chirho = install_existing_keypair_chirho(&swapped_key_root_chirho, 77);
    assert_ne!(swapped_key_chirho, record_chirho.authority_key_id_chirho);
    let message_chirho = destination_authority_enrollment_unsigned_message_chirho(&record_chirho);
    let possession_chirho = sign_with_existing_key_possession_chirho(
        &swapped_key_root_chirho,
        message_chirho.as_bytes(),
    )
    .unwrap();

    assert_eq!(
        bind_destination_authority_possession_chirho(&mut record_chirho, possession_chirho)
            .unwrap_err(),
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentSigningKeyRefusedChirho
    );
    assert_eq!(record_chirho.sig_chirho, original_signature_chirho);
}

#[test]
fn a_tampered_enrollment_signature_has_its_own_refusal_chirho() {
    let fixture_chirho = fixture_chirho("signature-chirho");
    let mut record_chirho: DestinationAuthorityEnrollmentRecordV1Chirho =
        serde_json::from_slice(&fs::read(&fixture_chirho.enrollment_path_chirho).unwrap()).unwrap();
    record_chirho.sig_chirho = "00".repeat(64);
    write_private_chirho(
        &fixture_chirho.enrollment_path_chirho,
        &serde_json::to_vec(&record_chirho).unwrap(),
    );
    assert_eq!(
        read_fixture_chirho(&fixture_chirho).unwrap_err(),
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentSignatureRefusedChirho
    );
}

#[test]
fn a_noncanonical_enrollment_refuses_before_its_signature_is_credited_chirho() {
    let fixture_chirho = fixture_chirho("noncanonical-chirho");
    let mut bytes_chirho = fs::read(&fixture_chirho.enrollment_path_chirho).unwrap();
    bytes_chirho.push(b'\n');
    write_private_chirho(&fixture_chirho.enrollment_path_chirho, &bytes_chirho);
    assert_eq!(
        read_fixture_chirho(&fixture_chirho).unwrap_err(),
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentNonCanonicalChirho
    );
}

#[test]
fn authoring_verifies_genesis_before_opening_destination_private_custody_chirho() {
    let root_chirho = temp_root_chirho("genesis-before-key-chirho");
    fs::create_dir(&root_chirho).unwrap();
    let genesis_chirho = author_genesis_bundle_chirho(&root_chirho.join("genesis-chirho"), 61, 62);
    let refusal_chirho = author_destination_authority_enrollment_chirho(
        DestinationAuthorityEnrollmentAuthorRequestChirho {
            destination_authority_signing_root_chirho: &root_chirho.join("missing-key-chirho"),
            cluster_genesis_roster_path_chirho: &genesis_chirho.roster_path_chirho,
            cluster_genesis_roster_head_path_chirho: &genesis_chirho.roster_path_chirho,
            cluster_genesis_roster_operator_pubkey_hex_chirho: &genesis_chirho
                .operator_pubkey_hex_chirho,
        },
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ClusterGenesisRosterVerificationRefusedChirho
    );
    fs::remove_dir_all(root_chirho).unwrap();
}
