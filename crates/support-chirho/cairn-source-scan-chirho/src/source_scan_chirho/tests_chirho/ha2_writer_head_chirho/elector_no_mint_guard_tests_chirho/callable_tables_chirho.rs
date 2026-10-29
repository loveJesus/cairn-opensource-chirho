// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The election guard's role tables: every public callable of the writer-head and gate-1 authority crates, classified read-only, forbidden, lifecycle-release or callback, and each crate's public module set.
//!
//! Split from `elector_no_mint_guard_tests_chirho.rs`, which had passed the 1500-line cap, so the tables each
//! brick extends grow here while the guard's visitors and tests stay put (C2.1, before 1b-1b).

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuthorityCallableRoleChirho(u8);

pub(super) const READ_ONLY_AUTHORITY_ROLE_CHIRHO: AuthorityCallableRoleChirho =
    AuthorityCallableRoleChirho(0);
pub(super) const FORBIDDEN_AUTHORITY_ROLE_CHIRHO: AuthorityCallableRoleChirho =
    AuthorityCallableRoleChirho(1);
pub(super) const LIFECYCLE_RELEASE_AUTHORITY_ROLE_CHIRHO: AuthorityCallableRoleChirho =
    AuthorityCallableRoleChirho(2);
pub(super) const CALLBACK_AUTHORITY_ROLE_CHIRHO: AuthorityCallableRoleChirho =
    AuthorityCallableRoleChirho(3);

pub(super) const WRITER_HEAD_PUBLIC_CALLABLES_CHIRHO: &[(&str, AuthorityCallableRoleChirho)] = &[
    (
        "CompositeWriterEpochRefusalChirho::fmt",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "pub-use:cairn_core_chirho::model_chirho::ConsistencyGroupIdChirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "pub-use:cairn_core_chirho::model_chirho::TaggedWriterFenceGroupDigestChirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "pub-use:cairn_core_chirho::model_chirho::consistency_group_digest_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "pub-use:cairn_core_chirho::model_chirho::tagged_writer_fence_group_digest_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "PreparedElectedWriterFenceChirho::durable_state_epoch_before_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "PreparedElectedWriterFenceChirho::replacement_state_bytes_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "PreparedElectedWriterFenceChirho::token_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "PreparedFenceLowerBoundChirho::canonical_root_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "PreparedFenceLowerBoundChirho::epoch_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "PreparedFenceLowerBoundChirho::group_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "PreparedFenceLowerBoundChirho::root_identity_matches_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "PreparedFenceObservationRefusalChirho::fmt",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "WriterFenceVerifyErrorChirho::fmt",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "compose_writer_epoch_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "consistency_group_for_root_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "issue_elected_writer_fence_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "issue_elected_writer_fence_for_root_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    ("issue_writer_fence_chirho", FORBIDDEN_AUTHORITY_ROLE_CHIRHO),
    (
        "issue_writer_fence_for_root_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "observe_prepared_fence_lower_bound_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "prepare_reused_or_issued_elected_writer_fence_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    ("split_writer_epoch_chirho", READ_ONLY_AUTHORITY_ROLE_CHIRHO),
    (
        "verify_writer_fence_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "verify_writer_fence_for_root_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "with_gate1_authority_scope_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    ("with_head_commit_chirho", FORBIDDEN_AUTHORITY_ROLE_CHIRHO),
    (
        "with_head_transition_scope_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "with_issued_writer_fence_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "with_issued_writer_fence_for_root_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "with_reused_or_issued_elected_writer_fence_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "writer_authority_era_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    ("writer_fence_path_chirho", READ_ONLY_AUTHORITY_ROLE_CHIRHO),
    (
        "writer_fence_storage_key_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
];

pub(super) const HEAD_TRANSITION_PUBLIC_CALLABLES_CHIRHO: &[(&str, AuthorityCallableRoleChirho)] =
    &[
        (
            "PreparedHeadTransitionChirho::next_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "PreparedHeadTransitionChirho::previous_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "PreparedHeadTransitionChirho::transition_id_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "bind_caller_verified_head_transition_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "bind_caller_verified_head_transition_from_prepared_fence_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "complete_head_transition_unlocked_chirho",
            FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "derive_head_transition_id_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "derive_head_transition_id_from_prepared_fence_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "head_transition_receipt_core_digest_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "pending_head_transition_index_unlocked_chirho",
            FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "preflight_head_transition_commit_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "recover_head_transition_chirho",
            FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "verified_head_transition_receipt_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
    ];

pub(super) const HEAD_TRANSITION_AUTHORITY_PUBLIC_CALLABLES_CHIRHO: &[(
    &str,
    AuthorityCallableRoleChirho,
)] = &[
    (
        "ElectedHeadTransitionScopeOutcomeChirho::into_result_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "ElectedHeadTransitionScopeOutcomeChirho::observed_fence_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "HeadTransitionAuthorityPortChirho::with_elected_head_transition_scope_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "HeadTransitionCommitActionChirho::call_chirho",
        CALLBACK_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "HeadTransitionCommitScopeChirho::complete_head_transition_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "HeadTransitionCommitScopeChirho::preflight_head_transition_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "HeadTransitionCommitScopeChirho::preflight_prepared_fence_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "HeadTransitionCommitScopeChirho::writer_fence_epoch_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "dispatch_head_transition_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "with_elected_head_transition_scope_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
];

/// Resident ownership is lifetime authority over one canonical writer identity. Election code may
/// inspect its redacted coordinates, but it must never reserve, open, or bind a resident lease; the
/// lifecycle-release methods only relinquish authority already held and are classified separately.
pub(super) const RESIDENT_WRITER_PUBLIC_CALLABLES_CHIRHO: &[(&str, AuthorityCallableRoleChirho)] =
    &[
        (
            "ResidentWriterBindingChirho::fmt",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterIdentityInspectionChirho::as_binding_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterIdentityInspectionChirho::canonical_identity_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterIdentityInspectionChirho::canonical_root_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterIdentityInspectionChirho::fmt",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterIdentityInspectionChirho::identity_digest_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterIdentityInspectionChirho::identity_kind_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterIdentityInspectionChirho::open_exact_chirho",
            FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterLeaseChirho::canonical_root_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterLeaseChirho::drop",
            LIFECYCLE_RELEASE_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterLeaseChirho::fmt",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterLeaseChirho::identity_digest_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterLeaseChirho::inspect_identity_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterLocalSlotChirho::drop",
            LIFECYCLE_RELEASE_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterLockGuardChirho::drop",
            LIFECYCLE_RELEASE_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterProvisioningLeaseChirho::bind_resident_writer_chirho",
            FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterProvisioningLeaseChirho::canonical_root_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterProvisioningLeaseChirho::fmt",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterProvisioningLeaseChirho::pending_identity_digest_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterRootCustodyChirho::canonical_root_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterRootCustodyChirho::fmt",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "ResidentWriterRootCustodyChirho::from_retained_directory_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "canonical_filesystem_path_digest_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "inspect_resident_writer_identity_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "open_resident_writer_chirho",
            FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "open_resident_writer_in_custody_chirho",
            FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
        ),
        // F4 moved these four constants (layout names + a path-length bound) into
        // cairn-durable-chirho, where the CAS lifecycle owns them; the re-exports keep this
        // module's callers source-compatible. Data, not callables — nothing here can mutate.
        (
            "pub-use:cairn_durable_chirho::MAX_CANONICAL_FILESYSTEM_PATH_BYTES_CHIRHO",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "pub-use:cairn_durable_chirho::RESIDENT_WRITER_DIR_CHIRHO",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "pub-use:cairn_durable_chirho::RESIDENT_WRITER_IDENTITY_FILE_CHIRHO",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "pub-use:cairn_durable_chirho::RESIDENT_WRITER_LOCK_FILE_CHIRHO",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "reserve_resident_writer_chirho",
            FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "reserve_resident_writer_in_custody_chirho",
            FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "resident_writer_identity_path_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
        (
            "try_inspect_resident_writer_identity_in_custody_chirho",
            READ_ONLY_AUTHORITY_ROLE_CHIRHO,
        ),
    ];

pub(super) const GATE1_AUTHORITY_LOG_PUBLIC_CALLABLES_CHIRHO: &[(
    &str,
    AuthorityCallableRoleChirho,
)] = &[
    (
        "VerifiedGate1AuthorityRecordsChirho::is_empty_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "VerifiedGate1AuthorityRecordsChirho::len_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "VerifiedGate1AuthorityRecordsChirho::records_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "append_gate1_authority_record_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "append_gate1_authority_record_unlocked_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "gate1_authority_head_path_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "gate1_authority_log_path_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "load_gate1_authority_records_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "reconcile_gate1_authority_current_family_tail_unlocked_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "reconcile_gate1_authority_prefix_unlocked_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "recover_gate1_authority_head_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "recover_gate1_authority_head_unlocked_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "repair_gate1_authority_torn_tail_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "repair_gate1_authority_torn_tail_unlocked_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "verified_gate1_authority_records_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "verify_gate1_authority_log_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
];

/// The control-plane law evidence module (C2.1 brick 1a-ii, claude2_chirho, 2026-10-26), classified
/// before the election guard trusts it.
/// - The two reads only observe: E1 through the existing era read, and E2 and E3 by presence or a
///   bounded parse. Neither creates or moves anything.
/// - The publication is a root mutation that fixes which key the root's control-plane records must
///   carry. It is therefore FORBIDDEN to the election plane, and only the lineage-law signing path may
///   call it.
pub(super) const CONTROL_PLANE_EVIDENCE_PUBLIC_CALLABLES_CHIRHO: &[(
    &str,
    AuthorityCallableRoleChirho,
)] = &[
    (
        "publish_control_plane_law_marker_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "read_control_plane_evidence_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "read_control_plane_law_marker_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
];

/// The control-plane root handle (C2.1 brick 1b-1a, claude2_chirho, 2026-10-27), classified before the
/// election guard trusts it.
/// - Binding, the freshness check, the accessors, the path deref and the scoped verified read only observe:
///   they read the evidence, stats and the EXISTING node public key, and never create or move anything.
/// - The write scope takes the law lock, and its signing publishes the law marker on a lineage root's first
///   signature and signs control-plane records. Both are FORBIDDEN to the election plane.
pub(super) const CONTROL_PLANE_ROOT_PUBLIC_CALLABLES_CHIRHO: &[(
    &str,
    AuthorityCallableRoleChirho,
)] = &[
    (
        "ControlPlaneRecordVerifierChirho::verify_control_plane_record_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "ControlPlaneRootChirho::bind_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "ControlPlaneRootChirho::check_fresh_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "ControlPlaneRootChirho::deref",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "ControlPlaneRootChirho::law_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "ControlPlaneRootChirho::operation_path_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "ControlPlaneRootChirho::with_verified_read_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "ControlPlaneRootChirho::with_control_plane_write_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "ControlPlaneWriteScopeChirho::operation_path_chirho",
        READ_ONLY_AUTHORITY_ROLE_CHIRHO,
    ),
    (
        "ControlPlaneWriteScopeChirho::sign_control_plane_record_chirho",
        FORBIDDEN_AUTHORITY_ROLE_CHIRHO,
    ),
];

pub(super) const WRITER_HEAD_CRATE_PUBLIC_MODULES_CHIRHO: &[&str] = &[
    "public-module:control_plane_evidence_chirho",
    "public-module:control_plane_root_chirho",
    "public-module:head_transition_authority_chirho",
    "public-module:head_transition_chirho",
    "public-module:resident_writer_chirho",
    "public-module:run_admission_authority_chirho",
    "public-module:writer_head_chirho",
];

pub(super) const GATE1_AUTHORITY_CRATE_PUBLIC_MODULES_CHIRHO: &[&str] =
    &["public-module:authority_log_chirho"];
