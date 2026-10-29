// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Builds the one real GD7 held world every HARNESS-1 arm starts from: TWO really-published tenant
//! roots sharing one consistency group, a real three-node elector whose winner genuinely deposes the
//! losing term, and the signed winner index/witness objects that mint an authenticated deposed-fork
//! observation.
//!
//! # WHY TWO ROOTS
//!
//! The winner is a NODE, not a key. Rung 2 and above drive the winner through
//! `ResidentGd7WinnerEvidenceHandleChirho`, which signs through a resident actor's own root custody,
//! so the winner side needs a root that really exists. Two roots normally mean two consistency
//! groups, which the single group digest in the GD7 identity would reject — but
//! `consistency_group_for_root_chirho` is path-derived only for PLATFORM roots. A root carrying a
//! tenant marker resolves to `TenantChirho { tenant_id_chirho }`, so two roots at different paths
//! under one tenant id share one group. That is a faithful model of two hosts serving one tenant,
//! which is exactly what a fork is.
//!
//! # THE TWO ROOTS ARE INDEPENDENTLY PUBLISHED, NOT COPIED — this is measured, not preferred
//!
//! Copying a published root and re-keying it does NOT work, and the refusals are worth recording so
//! nobody retries it: a copied root opened at a new path refuses with `resident ledger Bound
//! identity was refused`, and after re-keying it refuses with `shadow canary evidence head has an
//! invalid shape`. Both are the copy's own root-bound artifacts disagreeing with the new root
//! identity, and repairing them by hand would mean re-minting signed evidence — the forgery shape
//! this harness refuses everywhere else.
//!
//! Publishing twice avoids all of it. Each root provisions its OWN bound identity, canary window,
//! election state and fence state through the real publish path, and because the genesis record
//! binds only schema, format, cluster, epoch, hlc and the journal signer's key id — nothing
//! path-derived and nothing node-keypair-derived — two independent publishes of the same reviewed
//! plan produce a byte-identical journal. `assert_shared_pre_fork_ledger_chirho` proves that here
//! rather than assuming it.
//!
//! PRECISION, because this is the easiest thing in the module to over-read: byte-identical journals
//! are the PRE-FORK PRECONDITION, not the fork. The fork happens afterwards, and it happens twice —
//! once on each side, as a real append.
//!
//! # THE FORK IS AN OPERATION ON BOTH SIDES, AND BOTH HALVES ARE LOAD-BEARING
//!
//! A fork needs the held node to hold a record the winner never replicated. Two independent
//! publishes of one plan share their ENTIRE history, so a winner append onto that shared history
//! only EXTENDS it — measured: the winner's committed record inherits the very sequence the held
//! node holds as its tail, and `validate_identity_chirho` then refuses, because
//! `fork.seq < losing_journal_tail.seq` is false. There is nothing to reconcile.
//!
//! So the held node genuinely leads the losing term and commits under its OWN resident authority,
//! and only then is it deposed and the winner commits under ITS own. The two roots end with
//! DIFFERENT records at the SAME sequence, which is what a fork is. THE HELD NODE IS THEREFORE A
//! VOTER, not a learner: a learner can never lead, so a learner can never have written the record
//! that diverges — it could only ever be handed a divergence someone else invented.
//!
//! Nothing here builds a `LedgerRecordChirho`, picks a sequence, or signs a journal line. An earlier
//! form of this module did exactly that (`winner_first_record_evidence_chirho`) and it is gone: it
//! minted evidence for a record that was never appended, so the real append's own evidence collided
//! with it (`GD7 immutable winner evidence collided`) and was discarded. Fixture-written evidence
//! wearing the shape of a witness is the failure mode this whole harness exists to refuse.
//!
//! # WHAT BELONGS HERE AND WHAT DOES NOT
//!
//! This builder carries only the fixture's own PRECONDITIONS — the facts that must hold for the
//! world to be the world (the winner is not the held node; both roots resolve to one group; the two
//! ledgers really are one ledger before the fork; the held node really held the losing term and
//! really committed at it; the winner's term genuinely deposes it; the two sides' records at the
//! diverging sequence really differ). Assertions that are a SUITE'S CLAIM stay in that suite. If you
//! find yourself adding an `assert!` here that a reader would cite as evidence for a behaviour, it
//! belongs in the test, not in the builder.
//!
//! Nothing here is signed by a caller-supplied convenience. The winner's control signer is
//! `ExistingNodeGd7SignerChirho` opened on the winner root — the same adapter the production
//! resident actor uses — so every winner signature goes through that root's real key custody and
//! never through keypair bytes this module holds.

use super::{
    drive_campaign_chirho, drive_ticks_chirho, drive_transfer_chirho, hex_encode_chirho,
    refresh_fixture_activation_authorization_chirho, request_chirho, RegenesisFixtureChirho,
};
use crate::run_ledger_regenesis_chirho;
use cairn_config_chirho::config_chirho::{
    load_config_chirho, LedgerHostConfigChirho, LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO,
};
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitJournalPortChirho, EffectCommitJournalPortErrorChirho,
    EffectCommitJournalReceiptChirho, EffectCommitJournalViewPortChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho, EffectIntentChirho,
    EffectIntentJournalCutChirho, EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_host_chirho::reconciliation_chirho::{
    ExistingNodeGd7SignerChirho, Gd7ForkCoordinateChirho, Gd7JournalTailCoordinateChirho,
    Gd7ReconciliationIdentityChirho, Gd7WinnerWitnessStoreChirho,
};
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho,
    open_resident_effect_journal_handle_with_shared_elector_chirho, FsLedgerStorageChirho,
    HostLedgerSignersChirho, ResidentGd7HeldObservationImportChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::AttributionChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, LedgerJournalLineChirho,
};
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho;
use cairn_tenant_chirho::tenant_chirho::{TenantMarkerChirho, TENANT_MARKER_CHIRHO};
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho, split_writer_epoch_chirho,
    ConsistencyGroupIdChirho,
};
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The one tenant both HARNESS-1 roots belong to, and therefore the one consistency group.
const HARNESS1_TENANT_ID_CHIRHO: &str = "harness1-gd7-chirho";

/// Publish a fresh regenesis fixture as a TENANT root and return its canonical path.
///
/// THE ORDERING HERE IS PRODUCTION ORDERING, NOT A FIXTURE WORKAROUND. The activation statement
/// binds the root's consistency group, so a root's tenancy has to be decided before its activation
/// authorization is authored. Planting the marker after the fixture has already authored its
/// authorization makes the publish refuse `ActivationStatementRefusedChirho` — measured, not
/// assumed — which is the system correctly noticing that the authorization names a different group.
pub(super) fn publish_tenant_regenesis_root_chirho(
    fixture_chirho: &mut RegenesisFixtureChirho,
) -> PathBuf {
    let marker_chirho = TenantMarkerChirho {
        tenant_id_chirho: HARNESS1_TENANT_ID_CHIRHO.to_owned(),
    };
    std::fs::write(
        fixture_chirho.root_chirho.join(TENANT_MARKER_CHIRHO),
        serde_json::to_vec_pretty(&marker_chirho).unwrap(),
    )
    .unwrap();
    refresh_fixture_activation_authorization_chirho(fixture_chirho);
    run_ledger_regenesis_chirho(request_chirho(fixture_chirho))
        .expect("the reviewed H3 fixture publishes into a tenant root");
    fixture_chirho.root_chirho.canonicalize().unwrap()
}

/// Load a published fixture's host block at schema v4 with the held verifier roots this world pins.
pub(super) fn v4_ledger_config_chirho(config_path_chirho: &Path) -> LedgerHostConfigChirho {
    let mut ledger_config_chirho = load_config_chirho(config_path_chirho)
        .unwrap()
        .ledger_host_chirho
        .expect("fixture config carries the ledger host");
    ledger_config_chirho.schema_chirho = LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO.to_owned();
    let pins_chirho = ledger_config_chirho
        .held_verifier_pins_chirho
        .as_mut()
        .expect("fixture carries the historical journal verifier pin");
    pins_chirho.effect_intent_verifying_key_hex_chirho = Some(hex_encode_chirho(
        SigningKey::from_bytes(&[5; 32]).verifying_key().as_bytes(),
    ));
    pins_chirho.effect_terminal_verifying_key_hex_chirho = Some(hex_encode_chirho(
        SigningKey::from_bytes(&[6; 32]).verifying_key().as_bytes(),
    ));
    ledger_config_chirho
        .validate_chirho()
        .expect("v4 verifier roots are complete and pairwise distinct");
    ledger_config_chirho
}

fn load_root_signers_chirho(
    root_chirho: &Path,
    ledger_config_chirho: &LedgerHostConfigChirho,
) -> HostLedgerSignersChirho {
    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&ledger_config_chirho.signer_secrets_chirho)
            .unwrap();
    HostLedgerSignersChirho::load_existing_chirho(root_chirho, &signer_refs_chirho).unwrap()
}

fn journal_file_chirho(
    root_chirho: &Path,
    ledger_config_chirho: &LedgerHostConfigChirho,
) -> PathBuf {
    root_chirho
        .join(&ledger_config_chirho.storage_namespace_chirho)
        .join(&ledger_config_chirho.journal_path_chirho)
}

pub(super) struct TenantRootPairChirho {
    pub(super) held_root_chirho: PathBuf,
    pub(super) winner_root_chirho: PathBuf,
    pub(super) held_config_chirho: LedgerHostConfigChirho,
    pub(super) winner_config_chirho: LedgerHostConfigChirho,
}

/// A fork's two nodes must be the SAME LEDGER before they diverge, and here they are two separate
/// publishes — so the world proves it rather than trusting that the plan is deterministic.
///
/// This is the pre-fork precondition only. The fork itself happens later, when the winner appends
/// its own first record at the deposing term.
fn assert_shared_pre_fork_ledger_chirho(roots_chirho: &TenantRootPairChirho) {
    let held_journal_chirho = std::fs::read(journal_file_chirho(
        &roots_chirho.held_root_chirho,
        &roots_chirho.held_config_chirho,
    ))
    .unwrap();
    let winner_journal_chirho = std::fs::read(journal_file_chirho(
        &roots_chirho.winner_root_chirho,
        &roots_chirho.winner_config_chirho,
    ))
    .unwrap();
    assert!(
        held_journal_chirho == winner_journal_chirho,
        "the two independently published roots must be one ledger before the fork"
    );
}

/// One node commits ONE record through the resident authority its own root really owns, while it
/// holds leadership on the shared elector.
///
/// THIS IS AN OPERATION, NOT A FIXTURE WRITE, and the distinction is the whole point of the world.
/// The record is authored by that root's own resident actor under its own writer fence at its own
/// elected term; nothing here builds a `LedgerRecordChirho`, chooses a sequence number, or signs a
/// journal line. The winner term-first INDEX that every GD7 artifact depends on is a side effect of
/// this append (`ensure_append_winner_term_index_chirho`), so the evidence describes a record that
/// genuinely exists in that node's journal rather than one this module imagined.
///
/// Both sides of the fork use this: the held node commits at the losing term, and the winner commits
/// at the deposing term. The intent is the ordinary published-kind spend the resident append path
/// already accepts — its content is irrelevant to the fork; what matters is WHOSE authority signed
/// it and at WHICH term. `salt_chirho` only keeps the two sides' intents distinct.
/// The Result-returning form. `append_resident_record_chirho` is the expecting wrapper the world
/// builder uses; this exists so an ARM can drive the same real append path to its REFUSAL.
pub(super) fn try_append_resident_record_chirho(
    root_chirho: &Path,
    fixture_chirho: &RegenesisFixtureChirho,
    ledger_config_chirho: &LedgerHostConfigChirho,
    signers_chirho: &HostLedgerSignersChirho,
    elector_chirho: &Arc<RaftWriterElectorChirho>,
    salt_chirho: char,
) -> std::result::Result<
    (
        EffectCommitJournalReceiptChirho,
        EffectIntentJournalCutChirho,
    ),
    EffectCommitJournalPortErrorChirho,
> {
    let mut actor_chirho = open_resident_effect_journal_handle_with_shared_elector_chirho(
        root_chirho,
        &fixture_chirho.config_path_chirho,
        ledger_config_chirho,
        elector_chirho,
        None,
        None,
    )
    .expect("the root opens its own resident authority on the world's shared elector");
    let pre_append_cut_chirho = actor_chirho
        .effect_intent_cut_chirho()
        .expect("the resident reports its authenticated cut");
    let kind_id_chirho = AssetKindIdChirho(fixture_chirho.plan_chirho.kind_id_chirho.clone());
    let continuation_chirho = actor_chirho
        .current_continuation_chirho(&kind_id_chirho)
        .expect("the resident answers its continuation view")
        .expect("the root published the kind this world spends");
    let digest_chirho =
        |character_chirho: char| DigestChirho(character_chirho.to_string().repeat(64));
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: pre_append_cut_chirho,
            contract_set_digest_chirho: digest_chirho('a'),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "capability_fingerprint_chirho": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }))
            .unwrap(),
            reversion_contract_digest_chirho: digest_chirho('d'),
            request_ref_chirho: digest_chirho(salt_chirho),
            request_context_ref_chirho: digest_chirho('f'),
            evidence_refs_chirho: vec![digest_chirho('9')],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 10,
                kind_id_chirho: kind_id_chirho.clone(),
                kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: LogIdChirho::new_chirho(
                fixture_chirho.plan_chirho.initial_owner_chirho.clone(),
                kind_id_chirho,
            ),
            effect_step_chirho: 1,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: fixture_chirho.plan_chirho.initial_owner_chirho.clone(),
            },
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        signers_chirho.effect_intent_signer_chirho(),
    )
    .expect("the root's own effect-intent signer signs this world's intent");
    let intent_line_chirho =
        canonical_effect_intent_line_chirho(&intent_chirho).expect("the intent canonicalizes");
    let receipt_chirho = actor_chirho.append_hold_chirho(&intent_line_chirho)?;
    let post_append_cut_chirho = actor_chirho
        .effect_intent_cut_chirho()
        .expect("the resident reports the cut its own append produced");
    Ok((receipt_chirho, post_append_cut_chirho))
}

fn append_resident_record_chirho(
    root_chirho: &Path,
    fixture_chirho: &RegenesisFixtureChirho,
    ledger_config_chirho: &LedgerHostConfigChirho,
    signers_chirho: &HostLedgerSignersChirho,
    elector_chirho: &Arc<RaftWriterElectorChirho>,
    salt_chirho: char,
) -> (
    EffectCommitJournalReceiptChirho,
    EffectIntentJournalCutChirho,
) {
    try_append_resident_record_chirho(
        root_chirho,
        fixture_chirho,
        ledger_config_chirho,
        signers_chirho,
        elector_chirho,
        salt_chirho,
    )
    .expect("this node's resident authority commits its own record at its own term")
}

/// Everything a HARNESS-1 suite needs to open the held coordinator and drive it forward.
///
/// The observation import is returned already built but NOT installed: installing it is the first
/// step of every ladder, and a suite that wants to prove the install refuses must be able to
/// perturb the import first.
pub(super) struct ObservedGd7WorldChirho {
    pub(super) ledger_config_chirho: LedgerHostConfigChirho,
    pub(super) canonical_root_chirho: PathBuf,
    pub(super) group_chirho: ConsistencyGroupIdChirho,
    pub(super) group_digest_chirho: String,
    pub(super) held_node_chirho: NodeIdChirho,
    pub(super) winner_node_chirho: NodeIdChirho,
    /// The winner's real published root — the second node of the fork, not a subdirectory.
    pub(super) winner_source_root_chirho: PathBuf,
    pub(super) winner_config_path_chirho: PathBuf,
    pub(super) winner_ledger_config_chirho: LedgerHostConfigChirho,
    pub(super) winner_signers_chirho: HostLedgerSignersChirho,
    pub(super) nodes_chirho: Vec<Arc<RaftWriterElectorChirho>>,
    pub(super) winner_term_chirho: u64,
    /// Read straight off the resident's authenticated journal cut, so a suite asserting that the
    /// coordinator's bootstrap reports the right genesis is comparing against an INDEPENDENT read
    /// rather than against the identity this builder assembled from it.
    pub(super) losing_journal_genesis_digest_chirho: String,
    pub(super) identity_chirho: Gd7ReconciliationIdentityChirho,
    pub(super) observation_import_chirho: ResidentGd7HeldObservationImportChirho,
    pub(super) unchanged_journal_bytes_chirho: Vec<u8>,
    pub(super) signers_chirho: HostLedgerSignersChirho,
}

/// Publish both tenant roots, elect a genuine winner over the shared group, and seal the winner's
/// signed first-record index and fork witness into the winner's own root.
///
/// Both fixtures are owned by the caller so their temp roots outlive the world, and so that every
/// call site shows the two-root shape rather than hiding it behind one argument.
pub(super) fn build_observed_gd7_world_chirho(
    fixture_chirho: &mut RegenesisFixtureChirho,
    winner_fixture_chirho: &mut RegenesisFixtureChirho,
) -> ObservedGd7WorldChirho {
    let canonical_root_chirho = publish_tenant_regenesis_root_chirho(fixture_chirho);
    let winner_root_chirho = publish_tenant_regenesis_root_chirho(winner_fixture_chirho);
    let ledger_config_chirho = v4_ledger_config_chirho(&fixture_chirho.config_path_chirho);
    let winner_ledger_config_chirho =
        v4_ledger_config_chirho(&winner_fixture_chirho.config_path_chirho);
    assert_shared_pre_fork_ledger_chirho(&TenantRootPairChirho {
        held_root_chirho: canonical_root_chirho.clone(),
        winner_root_chirho: winner_root_chirho.clone(),
        held_config_chirho: ledger_config_chirho.clone(),
        winner_config_chirho: winner_ledger_config_chirho.clone(),
    });

    let signers_chirho = load_root_signers_chirho(&canonical_root_chirho, &ledger_config_chirho);
    let winner_signers_chirho =
        load_root_signers_chirho(&winner_root_chirho, &winner_ledger_config_chirho);

    let group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho).unwrap();
    assert_eq!(
        group_chirho,
        consistency_group_for_root_chirho(&winner_root_chirho).unwrap(),
        "two roots at different paths under one tenant id must resolve to one consistency group"
    );
    let group_digest_chirho = consistency_group_digest_chirho(&group_chirho).unwrap();

    let held_node_chirho =
        NodeIdChirho(existing_keypair_pubkey_hex_chirho(&canonical_root_chirho).unwrap());
    let winner_node_chirho =
        NodeIdChirho(existing_keypair_pubkey_hex_chirho(&winner_root_chirho).unwrap());
    assert_ne!(
        winner_node_chirho, held_node_chirho,
        "the winner root must be a different node from the held root"
    );
    let winner_control_signer_chirho =
        ExistingNodeGd7SignerChirho::open_existing_chirho(&winner_root_chirho, &winner_node_chirho)
            .expect("the winner root's own key custody opens as its GD7 control signer");

    // A roster peer that signs nothing here. Raft needs a third voter so that leadership can move
    // between the held node and the winner on real quorums rather than by fiat.
    let peer_voter_node_chirho = NodeIdChirho(hex_encode_chirho(
        SigningKey::from_bytes(&[10; 32]).verifying_key().as_bytes(),
    ));
    // THE HELD NODE IS A VOTER, AND THAT IS LOAD-BEARING. A fork requires the held node to hold a
    // record the winner never replicated, and the only way to get one without writing fixture bytes
    // is for the held node to have genuinely BEEN the writer at the losing term. A learner can never
    // lead, so a learner can never have forked — it could only ever be handed a divergence someone
    // else invented. It is deposed below and is not the leader from that point on.
    let voters_chirho = vec![
        (1, winner_node_chirho.clone()),
        (2, peer_voter_node_chirho),
        (3, held_node_chirho.clone()),
    ];
    // The warmup lease is what makes these electors usable by a resident actor at all: the
    // shared-elector opener requires a WARM AND LIVE local leadership lease, which is a stricter
    // predicate than `lease_valid_chirho` and is not satisfied by campaigning and ticking alone.
    // Without it neither root could open an actor on this elector, so the world would be able to
    // elect a writer it could never run.
    let nodes_chirho = (1..=3)
        .map(|raft_id_chirho| {
            Arc::new(
                RaftWriterElectorChirho::new_cluster_node_chirho(
                    group_chirho.clone(),
                    raft_id_chirho,
                    voters_chirho.clone(),
                )
                .unwrap()
                .with_leadership_warmup_lease_chirho(),
            )
        })
        .collect::<Vec<_>>();

    // ---- THE LOSING TERM: the held node really is the writer, and really commits ----
    drive_campaign_chirho(&nodes_chirho, 2);
    drive_ticks_chirho(&nodes_chirho, 2, 10);
    let held_leadership_chirho = nodes_chirho[2].current_leadership_chirho();
    assert!(
        held_leadership_chirho.is_leader_chirho,
        "the held node must genuinely hold the losing term before it can be deposed from it"
    );
    assert_eq!(
        held_leadership_chirho.leader_id_chirho.as_ref(),
        Some(&held_node_chirho),
        "the elected losing writer must be the held root's own node identity"
    );
    let (held_divergent_receipt_chirho, losing_cut_chirho) = append_resident_record_chirho(
        &canonical_root_chirho,
        fixture_chirho,
        &ledger_config_chirho,
        &signers_chirho,
        &nodes_chirho[2],
        '1',
    );
    let journal_text_chirho = std::fs::read_to_string(journal_file_chirho(
        &canonical_root_chirho,
        &ledger_config_chirho,
    ))
    .unwrap();
    let journal_records_chirho = journal_text_chirho
        .lines()
        .filter_map(|line_chirho| {
            match parse_canonical_ledger_journal_line_chirho(line_chirho).unwrap() {
                LedgerJournalLineChirho::GenesisChirho(_genesis_chirho) => None,
                LedgerJournalLineChirho::RecordChirho(record_chirho) => Some(record_chirho),
            }
        })
        .collect::<Vec<_>>();
    let losing_tail_chirho = journal_records_chirho
        .last()
        .expect("the held node has a committed losing record");
    assert_eq!(
        losing_tail_chirho.seq_chirho, held_divergent_receipt_chirho.seq_chirho,
        "the held journal's tail must be the record the held node's own authority committed"
    );
    let losing_term_chirho =
        u64::from(split_writer_epoch_chirho(losing_tail_chirho.epoch_chirho).geo_term_chirho);

    // ---- THE DEPOSING TERM: the winner takes the group and commits its own record ----
    drive_transfer_chirho(&nodes_chirho, 2, nodes_chirho[0].local_raft_id_chirho());
    drive_ticks_chirho(&nodes_chirho, 0, 10);
    let leadership_chirho = nodes_chirho[0].current_leadership_chirho();
    assert!(
        !nodes_chirho[2]
            .leadership_chirho(&group_chirho)
            .is_leader_chirho,
        "the held node must be deposed, not merely outranked on paper"
    );
    assert!(
        leadership_chirho.term_chirho > losing_term_chirho,
        "the fixture winner must genuinely depose the losing term"
    );
    assert_eq!(
        leadership_chirho.leader_id_chirho.as_ref(),
        Some(&winner_node_chirho),
        "the elected leader must be the pinned winner node"
    );

    // THE FORK ITSELF. The winner root now runs its own resident authority on this elector and
    // commits its own record at the deposing term, diverging from the held node at the last record
    // the two of them shared. Everything below READS that record's evidence; nothing below invents
    // it.
    let winner_source_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&winner_root_chirho).unwrap();
    let winner_store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
        &winner_source_storage_chirho,
        &winner_control_signer_chirho,
        winner_signers_chirho.journal_signer_chirho(),
    );
    let (fork_receipt_chirho, _winner_cut_chirho) = append_resident_record_chirho(
        &winner_root_chirho,
        winner_fixture_chirho,
        &winner_ledger_config_chirho,
        &winner_signers_chirho,
        &nodes_chirho[0],
        '8',
    );
    // THE FORK, STATED AS A PROPERTY RATHER THAN AS A STORY: the two nodes committed DIFFERENT
    // records at the SAME sequence, each under its own authority. That pair of facts is what makes
    // the rest of GD7 meaningful, and neither of them was arranged by writing bytes.
    assert_eq!(
        fork_receipt_chirho.seq_chirho, losing_tail_chirho.seq_chirho,
        "winner and held must diverge at the same sequence, not merely extend past each other"
    );
    assert_ne!(
        fork_receipt_chirho.record_digest_chirho.0, losing_cut_chirho.tail_record_digest_chirho.0,
        "the fork is only real if the two nodes committed DIFFERENT records at that sequence"
    );
    let winner_index_chirho = winner_store_chirho
        .load_winner_first_record_chirho(
            &group_digest_chirho,
            &winner_node_chirho.0,
            leadership_chirho.term_chirho,
            &losing_cut_chirho.journal_genesis_digest_chirho.0,
        )
        .expect("the winner term-first index re-verifies")
        .expect("the winner's own append persisted its term-first index");
    assert_eq!(
        winner_index_chirho
            .index_chirho()
            .first_record_chirho
            .seq_chirho,
        fork_receipt_chirho.seq_chirho,
        "the persisted winner index must describe the record the append actually committed"
    );
    // The fork coordinate is READ OFF the committed record's own inherited anchor rather than
    // assembled from the held journal, so the identity cannot describe a divergence point the
    // winner's ledger does not actually claim.
    let fork_anchor_chirho = winner_index_chirho
        .index_chirho()
        .first_record_chirho
        .anchor_chirho
        .clone()
        .expect("the winner's term-first record binds the epoch it inherited");
    let fork_chirho = Gd7ForkCoordinateChirho {
        epoch_chirho: fork_anchor_chirho.inherited_epoch_chirho,
        seq_chirho: fork_anchor_chirho.inherited_seq_chirho,
        record_digest_chirho: fork_anchor_chirho.inherited_digest_chirho.0.clone(),
    };
    let mut identity_chirho = Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        winner_node_chirho: winner_node_chirho.0.clone(),
        held_node_chirho: held_node_chirho.0.clone(),
        winner_term_chirho: leadership_chirho.term_chirho,
        losing_term_chirho,
        // One genesis digest serves both sides because the two roots ARE one ledger before the
        // fork, which `assert_shared_pre_fork_ledger_chirho` proved at the bytes above.
        winner_journal_genesis_digest_chirho: losing_cut_chirho
            .journal_genesis_digest_chirho
            .0
            .clone(),
        // Overwritten immediately below from the committed record's own index; this placeholder
        // exists only because the identity is one struct literal.
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: fork_chirho.epoch_chirho,
            seq_chirho: fork_chirho.seq_chirho + 1,
            record_digest_chirho: "0".repeat(64),
        },
        fork_chirho: fork_chirho.clone(),
        losing_journal_genesis_digest_chirho: losing_cut_chirho
            .journal_genesis_digest_chirho
            .0
            .clone(),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: losing_tail_chirho.epoch_chirho,
            seq_chirho: losing_tail_chirho.seq_chirho,
            record_digest_chirho: losing_cut_chirho.tail_record_digest_chirho.0.clone(),
        },
    };
    identity_chirho.winner_journal_tail_chirho = Gd7JournalTailCoordinateChirho {
        epoch_chirho: winner_index_chirho
            .index_chirho()
            .first_record_chirho
            .epoch_chirho,
        seq_chirho: winner_index_chirho
            .index_chirho()
            .first_record_chirho
            .seq_chirho,
        record_digest_chirho: winner_index_chirho
            .index_chirho()
            .first_record_digest_chirho
            .clone(),
    };
    let winner_witness_chirho = winner_store_chirho
        .seal_winner_fork_witness_chirho(identity_chirho.clone(), &winner_index_chirho)
        .unwrap();
    let observation_import_chirho = ResidentGd7HeldObservationImportChirho {
        identity_chirho: identity_chirho.clone(),
        winner_first_record_index_bytes_chirho: serde_json::to_vec(
            winner_index_chirho.index_chirho(),
        )
        .unwrap(),
        winner_fork_witness_bytes_chirho: serde_json::to_vec(
            winner_witness_chirho.witness_chirho(),
        )
        .unwrap(),
    };

    ObservedGd7WorldChirho {
        ledger_config_chirho,
        canonical_root_chirho,
        group_chirho,
        group_digest_chirho,
        held_node_chirho,
        winner_node_chirho,
        winner_source_root_chirho: winner_root_chirho,
        winner_config_path_chirho: winner_fixture_chirho.config_path_chirho.clone(),
        winner_ledger_config_chirho,
        winner_signers_chirho,
        nodes_chirho,
        winner_term_chirho: leadership_chirho.term_chirho,
        losing_journal_genesis_digest_chirho: losing_cut_chirho
            .journal_genesis_digest_chirho
            .0
            .clone(),
        identity_chirho,
        observation_import_chirho,
        unchanged_journal_bytes_chirho: journal_text_chirho.into_bytes(),
        signers_chirho,
    }
}
