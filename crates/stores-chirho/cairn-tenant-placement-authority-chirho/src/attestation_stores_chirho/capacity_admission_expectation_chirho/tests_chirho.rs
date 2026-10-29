// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use std::path::{Path, PathBuf};

struct FixtureChirho {
    _temp_chirho: tempfile::TempDir,
    evidence_root_chirho: PathBuf,
    record_path_chirho: PathBuf,
    placement_sign_root_chirho: PathBuf,
    topology_sign_root_chirho: PathBuf,
    record_chirho: TenantMigrationCapacityExpectationChirho,
}

impl FixtureChirho {
    fn context_chirho(&self) -> TenantMigrationCapacityExpectationContextChirho<'_> {
        TenantMigrationCapacityExpectationContextChirho {
            expectation_revision_chirho: self.record_chirho.expectation_revision_chirho,
            cluster_config_blake3_chirho: &self.record_chirho.cluster_config_blake3_chirho,
            tenant_id_chirho: &self.record_chirho.tenant_id_chirho,
            placement_revision_chirho: self.record_chirho.placement_revision_chirho,
            current_assignment_digest_chirho: &self.record_chirho.current_assignment_digest_chirho,
            placement_key_id_chirho: &self.record_chirho.placement_key_id_chirho,
            topology_grant_key_id_chirho: &self.record_chirho.topology_grant_key_id_chirho,
        }
    }
}

fn fixture_chirho() -> FixtureChirho {
    let temp_chirho = tempfile::tempdir().expect("fixture root");
    let evidence_root_chirho = temp_chirho.path().join("evidence-root-chirho");
    std::fs::create_dir(&evidence_root_chirho).expect("evidence root");
    let placement_sign_root_chirho = temp_chirho.path().join("placement-sign-root-chirho");
    let topology_sign_root_chirho = temp_chirho.path().join("topology-sign-root-chirho");
    let placement_key_chirho =
        pubkey_hex_chirho(&placement_sign_root_chirho).expect("placement key");
    let topology_key_chirho = pubkey_hex_chirho(&topology_sign_root_chirho).expect("topology key");
    let mut record_chirho = TenantMigrationCapacityExpectationChirho {
        schema_chirho: TENANT_MIGRATION_CAPACITY_EXPECTATION_SCHEMA_V1_CHIRHO.to_string(),
        placement_signature_domain_chirho:
            TENANT_MIGRATION_CAPACITY_EXPECTATION_PLACEMENT_DOMAIN_V1_CHIRHO.to_string(),
        topology_grant_signature_domain_chirho:
            TENANT_MIGRATION_CAPACITY_EXPECTATION_TOPOLOGY_GRANT_DOMAIN_V1_CHIRHO.to_string(),
        expectation_revision_chirho: 7,
        cluster_config_blake3_chirho: "1".repeat(64),
        tenant_id_chirho: "capacity-expectation-test-chirho".to_string(),
        placement_revision_chirho: 4,
        current_assignment_digest_chirho: "2".repeat(64),
        expected_placement_population_digest_chirho: "3".repeat(64),
        expected_capacity_load_snapshot_digest_chirho: "4".repeat(64),
        placement_key_id_chirho: placement_key_chirho,
        topology_grant_key_id_chirho: topology_key_chirho,
        placement_sig_chirho: String::new(),
        topology_grant_sig_chirho: String::new(),
    };
    let placement_message_chirho =
        unsigned_placement_capacity_expectation_message_chirho(&record_chirho)
            .expect("placement message");
    let topology_message_chirho =
        unsigned_topology_grant_capacity_expectation_message_chirho(&record_chirho)
            .expect("topology message");
    record_chirho.placement_sig_chirho =
        sign_message_chirho(&placement_sign_root_chirho, &placement_message_chirho)
            .expect("placement signature");
    record_chirho.topology_grant_sig_chirho =
        sign_message_chirho(&topology_sign_root_chirho, &topology_message_chirho)
            .expect("topology signature");
    let record_path_chirho = temp_chirho.path().join("capacity-expectation-chirho.json");
    write_record_chirho(&record_path_chirho, &record_chirho);
    FixtureChirho {
        _temp_chirho: temp_chirho,
        evidence_root_chirho,
        record_path_chirho,
        placement_sign_root_chirho,
        topology_sign_root_chirho,
        record_chirho,
    }
}

fn write_record_chirho(
    path_chirho: &Path,
    record_chirho: &TenantMigrationCapacityExpectationChirho,
) {
    let mut bytes_chirho = serde_json::to_vec_pretty(record_chirho).expect("encode record");
    bytes_chirho.push(b'\n');
    cairn_durable_chirho::write_file_durable_with_mode_chirho(path_chirho, &bytes_chirho, 0o600)
        .expect("write record");
}

#[test]
fn both_distinct_authorities_must_sign_the_same_material_chirho() {
    let fixture_chirho = fixture_chirho();
    verify_tenant_migration_capacity_expectation_chirho(
        fixture_chirho.record_chirho.clone(),
        fixture_chirho.context_chirho(),
    )
    .expect("both signatures admit the exact reviewed material");

    let canonical_chirho = canonical_tenant_migration_capacity_expectation_payload_chirho(
        &fixture_chirho.record_chirho,
    )
    .expect("canonical payload");
    let mut reverse_order_chirho = fixture_chirho.record_chirho.clone();
    reverse_order_chirho.placement_sig_chirho.clear();
    reverse_order_chirho.topology_grant_sig_chirho.clear();
    reverse_order_chirho.topology_grant_sig_chirho = sign_message_chirho(
        &fixture_chirho.topology_sign_root_chirho,
        &unsigned_topology_grant_capacity_expectation_message_chirho(&reverse_order_chirho)
            .expect("topology message before placement signature"),
    )
    .expect("topology signature first");
    assert_eq!(
        canonical_tenant_migration_capacity_expectation_payload_chirho(&reverse_order_chirho)
            .expect("payload after topology signature"),
        canonical_chirho,
        "the first signature must not enter the second authority's canonical payload"
    );
    reverse_order_chirho.placement_sig_chirho = sign_message_chirho(
        &fixture_chirho.placement_sign_root_chirho,
        &unsigned_placement_capacity_expectation_message_chirho(&reverse_order_chirho)
            .expect("placement message after topology signature"),
    )
    .expect("placement signature second");
    assert_eq!(
        reverse_order_chirho, fixture_chirho.record_chirho,
        "deterministic signatures over one canonical payload make signing order irrelevant"
    );

    let mut forged_topology_chirho = fixture_chirho.record_chirho.clone();
    forged_topology_chirho.topology_grant_sig_chirho = sign_message_chirho(
        &fixture_chirho.topology_sign_root_chirho,
        b"different-material-chirho",
    )
    .expect("forge a real signature over the wrong material");
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            forged_topology_chirho,
            fixture_chirho.context_chirho(),
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::TopologyGrantSignatureChirho)
    );

    let placement_key_chirho = fixture_chirho.record_chirho.placement_key_id_chirho.clone();
    let same_holder_context_chirho = TenantMigrationCapacityExpectationContextChirho {
        topology_grant_key_id_chirho: &placement_key_chirho,
        ..fixture_chirho.context_chirho()
    };
    let mut same_holder_chirho = fixture_chirho.record_chirho.clone();
    same_holder_chirho.topology_grant_key_id_chirho = placement_key_chirho.clone();
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            same_holder_chirho,
            same_holder_context_chirho,
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::AuthorityKeySeparationChirho)
    );
}

#[test]
fn current_config_and_resident_assignment_are_external_context_not_record_claims_chirho() {
    let fixture_chirho = fixture_chirho();
    let changed_config_chirho = "5".repeat(64);
    let changed_config_context_chirho = TenantMigrationCapacityExpectationContextChirho {
        cluster_config_blake3_chirho: &changed_config_chirho,
        ..fixture_chirho.context_chirho()
    };
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            fixture_chirho.record_chirho.clone(),
            changed_config_context_chirho,
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::ConfigBindingChirho)
    );

    let changed_assignment_chirho = "6".repeat(64);
    let changed_assignment_context_chirho = TenantMigrationCapacityExpectationContextChirho {
        placement_revision_chirho: fixture_chirho.record_chirho.placement_revision_chirho + 1,
        current_assignment_digest_chirho: &changed_assignment_chirho,
        ..fixture_chirho.context_chirho()
    };
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            fixture_chirho.record_chirho.clone(),
            changed_assignment_context_chirho,
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::PlacementRevisionBindingChirho)
    );
}

#[test]
fn loader_refuses_absent_unreadable_unstable_inside_root_and_tampered_distinctly_chirho() {
    let fixture_chirho = fixture_chirho();
    load_and_verify_tenant_migration_capacity_expectation_chirho(
        &fixture_chirho.record_path_chirho,
        &fixture_chirho.evidence_root_chirho,
        fixture_chirho.context_chirho(),
    )
    .expect("private outside-root signed record loads");

    let absent_chirho = fixture_chirho
        .record_path_chirho
        .with_file_name("absent-expectation-chirho.json");
    assert_eq!(
        load_and_verify_tenant_migration_capacity_expectation_chirho(
            &absent_chirho,
            &fixture_chirho.evidence_root_chirho,
            fixture_chirho.context_chirho(),
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::RecordAbsentChirho)
    );

    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let unreadable_chirho = PathBuf::from(OsString::from_vec(b"bad\0path-chirho".to_vec()));
        assert_eq!(
            load_and_verify_tenant_migration_capacity_expectation_chirho(
                &unreadable_chirho,
                &fixture_chirho.evidence_root_chirho,
                fixture_chirho.context_chirho(),
            ),
            Err(TenantMigrationCapacityExpectationRefusalChirho::RecordUnreadableChirho)
        );
    }

    let hard_link_chirho = fixture_chirho
        .record_path_chirho
        .with_file_name("hard-linked-expectation-chirho.json");
    std::fs::hard_link(&fixture_chirho.record_path_chirho, &hard_link_chirho)
        .expect("plant a second link");
    assert_eq!(
        load_and_verify_tenant_migration_capacity_expectation_chirho(
            &fixture_chirho.record_path_chirho,
            &fixture_chirho.evidence_root_chirho,
            fixture_chirho.context_chirho(),
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::RecordIdentityUnstableChirho)
    );
    std::fs::remove_file(&hard_link_chirho).expect("remove second link");

    let inside_chirho = fixture_chirho
        .evidence_root_chirho
        .join("capacity-expectation-chirho.json");
    write_record_chirho(&inside_chirho, &fixture_chirho.record_chirho);
    assert_eq!(
        load_and_verify_tenant_migration_capacity_expectation_chirho(
            &inside_chirho,
            &fixture_chirho.evidence_root_chirho,
            fixture_chirho.context_chirho(),
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::RecordInsideEvidenceRootChirho)
    );

    let mut tampered_chirho = fixture_chirho.record_chirho.clone();
    tampered_chirho.expected_capacity_load_snapshot_digest_chirho = "7".repeat(64);
    write_record_chirho(&fixture_chirho.record_path_chirho, &tampered_chirho);
    assert_eq!(
        load_and_verify_tenant_migration_capacity_expectation_chirho(
            &fixture_chirho.record_path_chirho,
            &fixture_chirho.evidence_root_chirho,
            fixture_chirho.context_chirho(),
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::PlacementSignatureChirho)
    );
}

#[test]
fn a_partial_record_proves_only_the_placement_signature_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut partial_chirho = fixture_chirho.record_chirho.clone();
    partial_chirho.topology_grant_sig_chirho.clear();
    verify_placement_signed_tenant_migration_capacity_expectation_chirho(
        &partial_chirho,
        fixture_chirho.context_chirho(),
    )
    .expect("placement half verifies before independent co-signing");
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            partial_chirho,
            fixture_chirho.context_chirho(),
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::TopologyGrantSignatureChirho)
    );
}

// ---------------------------------------------------------------------------------------------
// ONE VARIABLE AT A TIME
//
// Every arm below changes EXACTLY ONE thing. Measured 2026-08-21, fourteen of this enum's
// twenty-three refusal identities had no arm, and the reason the gap was invisible is instructive:
// `current_config_and_resident_assignment_are_external_context_not_record_claims_chirho` is named
// for the resident-assignment binding and moves BOTH `placement_revision_chirho` and
// `current_assignment_digest_chirho`. Revision is checked first, so the arm passes on the revision
// check alone and `CurrentAssignmentBindingChirho` is never reached. A two-variable fixture cannot
// attribute to either variable.
//
// These all vary the CONTEXT rather than the record wherever possible, so the record stays the
// genuine two-party-signed artifact and no re-signing can mask which check fired.
// ---------------------------------------------------------------------------------------------

/// Re-sign both signatures after a record-side edit, so a later signature check cannot be the reason
/// an earlier binding arm refuses.
fn resign_both_chirho(
    fixture_chirho: &FixtureChirho,
    record_chirho: &mut TenantMigrationCapacityExpectationChirho,
) {
    record_chirho.placement_sig_chirho = String::new();
    record_chirho.topology_grant_sig_chirho = String::new();
    let placement_message_chirho =
        unsigned_placement_capacity_expectation_message_chirho(record_chirho)
            .expect("placement message");
    let topology_message_chirho =
        unsigned_topology_grant_capacity_expectation_message_chirho(record_chirho)
            .expect("topology message");
    record_chirho.placement_sig_chirho = sign_message_chirho(
        &fixture_chirho.placement_sign_root_chirho,
        &placement_message_chirho,
    )
    .expect("placement signature");
    record_chirho.topology_grant_sig_chirho = sign_message_chirho(
        &fixture_chirho.topology_sign_root_chirho,
        &topology_message_chirho,
    )
    .expect("topology signature");
}

/// The resident ASSIGNMENT DIGEST alone must bind — the check the sibling arm's name promises.
#[test]
fn the_resident_assignment_digest_alone_binds_chirho() {
    let fixture_chirho = fixture_chirho();

    // POSITIVE CONTROL: the unmodified context verifies, so every refusal below is attributable.
    verify_tenant_migration_capacity_expectation_chirho(
        fixture_chirho.record_chirho.clone(),
        fixture_chirho.context_chirho(),
    )
    .expect("the genuine record verifies against its own context");

    let moved_assignment_chirho = "7".repeat(64);
    let context_chirho = TenantMigrationCapacityExpectationContextChirho {
        current_assignment_digest_chirho: &moved_assignment_chirho,
        ..fixture_chirho.context_chirho()
    };
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            fixture_chirho.record_chirho.clone(),
            context_chirho,
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::CurrentAssignmentBindingChirho),
        "the placement revision is held EQUAL here, so this cannot pass on the revision check the \
         way a two-variable fixture would"
    );
}

/// The resident TENANT alone must bind.
#[test]
fn the_resident_tenant_alone_binds_chirho() {
    let fixture_chirho = fixture_chirho();
    let other_tenant_chirho = "another-tenant-chirho".to_string();
    let context_chirho = TenantMigrationCapacityExpectationContextChirho {
        tenant_id_chirho: &other_tenant_chirho,
        ..fixture_chirho.context_chirho()
    };
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            fixture_chirho.record_chirho.clone(),
            context_chirho,
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::TenantBindingChirho)
    );
}

/// An expectation from ANOTHER GENERATION refuses, and revision zero is never a generation.
///
/// This is the arm that makes the one-generation-one-expectation ruling true at RUNTIME rather than
/// by staging convention. Both signatures are genuine throughout; the record is simply not this
/// generation's.
#[test]
fn an_expectation_from_another_generation_refuses_chirho() {
    let fixture_chirho = fixture_chirho();
    let context_chirho = TenantMigrationCapacityExpectationContextChirho {
        expectation_revision_chirho: fixture_chirho.record_chirho.expectation_revision_chirho + 1,
        ..fixture_chirho.context_chirho()
    };
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            fixture_chirho.record_chirho.clone(),
            context_chirho,
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::ExpectationRevisionChirho),
        "a validly two-party-signed expectation for a DIFFERENT generation must still refuse"
    );

    // The other half of the same clause: revision zero is refused even when record and context agree.
    let mut zero_chirho = fixture_chirho.record_chirho.clone();
    zero_chirho.expectation_revision_chirho = 0;
    resign_both_chirho(&fixture_chirho, &mut zero_chirho);
    let zero_context_chirho = TenantMigrationCapacityExpectationContextChirho {
        expectation_revision_chirho: 0,
        ..fixture_chirho.context_chirho()
    };
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(zero_chirho, zero_context_chirho),
        Err(TenantMigrationCapacityExpectationRefusalChirho::ExpectationRevisionChirho),
        "agreement is not enough — an unset revision is not a generation"
    );
}

/// Each declared authority key must equal the externally supplied one, by its OWN identity.
///
/// A record naming a different but well-formed key must refuse before any signature is checked;
/// otherwise a record could nominate the key that signed it rather than the key the operator
/// configured, which is self-certification of the authority arrangement.
#[test]
fn each_declared_authority_key_binds_to_the_external_one_chirho() {
    let fixture_chirho = fixture_chirho();
    let foreign_key_chirho = "a".repeat(64);

    let placement_context_chirho = TenantMigrationCapacityExpectationContextChirho {
        placement_key_id_chirho: &foreign_key_chirho,
        ..fixture_chirho.context_chirho()
    };
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            fixture_chirho.record_chirho.clone(),
            placement_context_chirho,
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::PlacementKeyChirho)
    );

    let topology_context_chirho = TenantMigrationCapacityExpectationContextChirho {
        topology_grant_key_id_chirho: &foreign_key_chirho,
        ..fixture_chirho.context_chirho()
    };
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            fixture_chirho.record_chirho.clone(),
            topology_context_chirho,
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::TopologyGrantKeyChirho),
        "and the two roles must refuse by DISTINCT identities, or an operator cannot tell which \
         half of the two-party arrangement is misconfigured"
    );
}

/// The two signature ROLE DOMAINS are not interchangeable.
///
/// Without this, "two signatures" is satisfiable at the crypto layer by one role signing the same
/// payload twice: the domains are the only thing making the two messages different bytes. Each
/// record here is RE-SIGNED under its swapped domain, so the signature itself is genuine and only
/// the domain check can be what refuses.
#[test]
fn the_two_signature_role_domains_are_not_interchangeable_chirho() {
    let fixture_chirho = fixture_chirho();

    let mut placement_as_topology_chirho = fixture_chirho.record_chirho.clone();
    placement_as_topology_chirho.placement_signature_domain_chirho =
        TENANT_MIGRATION_CAPACITY_EXPECTATION_TOPOLOGY_GRANT_DOMAIN_V1_CHIRHO.to_string();
    resign_both_chirho(&fixture_chirho, &mut placement_as_topology_chirho);
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            placement_as_topology_chirho,
            fixture_chirho.context_chirho(),
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::PlacementSignatureDomainChirho)
    );

    let mut topology_as_placement_chirho = fixture_chirho.record_chirho.clone();
    topology_as_placement_chirho.topology_grant_signature_domain_chirho =
        TENANT_MIGRATION_CAPACITY_EXPECTATION_PLACEMENT_DOMAIN_V1_CHIRHO.to_string();
    resign_both_chirho(&fixture_chirho, &mut topology_as_placement_chirho);
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            topology_as_placement_chirho,
            fixture_chirho.context_chirho(),
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::TopologyGrantSignatureDomainChirho)
    );
}

/// Neither pinned digest may be empty, zero, or malformed — and they refuse by DISTINCT identities.
///
/// These two fields ARE the coordinates admission compares against. An all-zero digest is the shape
/// a partially-authored record would carry, and it must not read as a pin.
#[test]
fn each_pinned_digest_must_be_a_real_digest_chirho() {
    let fixture_chirho = fixture_chirho();

    let mut zero_population_chirho = fixture_chirho.record_chirho.clone();
    zero_population_chirho.expected_placement_population_digest_chirho = "0".repeat(64);
    resign_both_chirho(&fixture_chirho, &mut zero_population_chirho);
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            zero_population_chirho,
            fixture_chirho.context_chirho(),
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::PopulationDigestChirho)
    );

    let mut zero_snapshot_chirho = fixture_chirho.record_chirho.clone();
    zero_snapshot_chirho.expected_capacity_load_snapshot_digest_chirho = "0".repeat(64);
    resign_both_chirho(&fixture_chirho, &mut zero_snapshot_chirho);
    assert_eq!(
        verify_tenant_migration_capacity_expectation_chirho(
            zero_snapshot_chirho,
            fixture_chirho.context_chirho(),
        ),
        Err(TenantMigrationCapacityExpectationRefusalChirho::CapacityLoadSnapshotDigestChirho),
        "and by an identity distinct from the population digest's"
    );
}
