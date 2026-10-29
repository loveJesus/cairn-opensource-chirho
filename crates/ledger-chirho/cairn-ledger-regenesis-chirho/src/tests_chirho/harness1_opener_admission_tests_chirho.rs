// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! HARNESS-1 negative controls: each admission check in the REAL resident-actor opener, proven
//! load-bearing by perturbing exactly one thing and reading the refusal BY NAME.
//!
//! # WHY THIS MODULE EXISTS
//!
//! `open_resident_effect_journal_handle_chirho` refuses to start unless a long list of custody,
//! signer, registry, canary, journal, and elector admissions all hold. Before this module every
//! one of those was proven only by the HAPPY PATH — the published fixture opens, so all the
//! admissions must have passed. That is evidence the checks are SATISFIABLE; it is not evidence
//! any of them is load-bearing. A check silently deleted, or narrowed to a tautology, would have
//! left the suite green.
//!
//! Each arm below therefore runs in two halves, and the FIRST half is what makes the second
//! meaningful:
//!   1. POSITIVE CONTROL — the unperturbed published world opens the real actor. A green arm can
//!      never come from a world that was never openable in the first place.
//!   2. THE PERTURBATION — exactly one admission input is broken, and the real opener must refuse
//!      with the refusal that names THAT admission. Asserting the refusal's identity, not merely
//!      that some error occurred, is the point: an opener that refused for an unrelated reason
//!      would otherwise read as a passing arm.
//!
//! # WHAT THESE ARMS DO AND DO NOT PROVE
//!
//! They prove the opener's ADMISSION barrier. They prove nothing about the GD7 mailbox path — the
//! wire commands, the dispatch arms, or a completed compensation. That is piece 10, and it has its
//! own module. Anything claiming a "live completed compensation path" needs that arm, not these.
//!
//! # MIGRATION PATH, stated here because whoever meets a red will not have this context
//!
//! - If a POSITIVE CONTROL fails, the published fixture stopped opening the real actor at all.
//!   Read that first and ignore the perturbation half: every arm in this module is vacuous until
//!   the control is green again.
//! - If a PERTURBATION half starts SUCCEEDING, an admission check stopped being load-bearing —
//!   that is exactly the regression this module exists to catch, and the fix belongs in the opener,
//!   not here.
//! - If a perturbation half still refuses but the refusal NAME no longer matches, the check moved
//!   or was renamed. RETARGET the assertion at the new name rather than loosening it to
//!   `is_err()`: an arm that accepts any error is an arm that has stopped measuring which barrier
//!   fired, and two of these admissions are checked one line apart.

use super::{fixture_chirho, request_chirho, set_private_mode_chirho, temp_root_chirho};
use crate::run_ledger_regenesis_chirho;
use cairn_config_chirho::config_chirho::{load_config_chirho, LedgerHostConfigChirho};
use cairn_ledger_host_chirho::{
    open_resident_effect_journal_handle_chirho,
    open_resident_effect_journal_handle_with_shared_elector_chirho,
};
use cairn_signer_chirho::signer_chirho::{existing_keypair_pubkey_hex_chirho, sign_message_chirho};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::consistency_group_for_root_chirho;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The published world every arm starts from: a real regenesis, then the real opener proven to
/// open it. Returning the config saves each arm re-reading it, and running the positive control
/// HERE means no arm can forget it.
struct PublishedWorldChirho {
    fixture_chirho: super::RegenesisFixtureChirho,
    ledger_config_chirho: LedgerHostConfigChirho,
}

impl PublishedWorldChirho {
    fn root_chirho(&self) -> &Path {
        &self.fixture_chirho.root_chirho
    }

    fn config_path_chirho(&self) -> &Path {
        &self.fixture_chirho.config_path_chirho
    }

    fn monitor_namespace_chirho(&self) -> PathBuf {
        self.root_chirho()
            .join(&self.ledger_config_chirho.monitor_evidence_namespace_chirho)
    }

    fn storage_namespace_chirho(&self) -> PathBuf {
        self.root_chirho()
            .join(&self.ledger_config_chirho.storage_namespace_chirho)
    }

    /// Open the real actor and immediately close it. Used as the positive control, and again by
    /// arms that need the sole-actor lease released before they perturb.
    fn open_and_close_chirho(&self, expectation_chirho: &str) {
        let actor_chirho = open_resident_effect_journal_handle_chirho(
            self.root_chirho(),
            self.config_path_chirho(),
            &self.ledger_config_chirho,
            None,
        )
        .unwrap_or_else(|error_chirho| panic!("{expectation_chirho}: {error_chirho:#}"));
        drop(actor_chirho);
    }

    /// Attempt the real opener and return the refusal chain as text. Panics if it SUCCEEDS —
    /// a perturbed world that still opens is the regression these arms exist to catch.
    fn refusal_text_chirho(&self, perturbation_chirho: &str) -> String {
        match open_resident_effect_journal_handle_chirho(
            self.root_chirho(),
            self.config_path_chirho(),
            &self.ledger_config_chirho,
            None,
        ) {
            Ok(actor_chirho) => {
                drop(actor_chirho);
                panic!(
                    "the real opener ADMITTED a world whose {perturbation_chirho} was broken; \
                     that admission check is no longer load-bearing"
                );
            }
            Err(error_chirho) => format!("{error_chirho:#}"),
        }
    }
}

/// Publish the reviewed H3 world and prove the real actor opens it before anything is perturbed.
fn published_world_chirho() -> PublishedWorldChirho {
    let fixture_chirho = fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the reviewed H3 fixture publishes");
    let ledger_config_chirho = load_config_chirho(&fixture_chirho.config_path_chirho)
        .expect("the fixture config loads")
        .ledger_host_chirho
        .expect("fixture config carries the ledger host");
    let world_chirho = PublishedWorldChirho {
        fixture_chirho,
        ledger_config_chirho,
    };
    world_chirho.open_and_close_chirho(
        "POSITIVE CONTROL: the unperturbed published world must open the real resident actor",
    );
    world_chirho
}

/// Assert a refusal names its own barrier. Kept as one helper so every arm reports the same way:
/// the failure message carries the WHOLE refusal chain, because the next reader needs to see which
/// barrier actually fired, not merely that the expected words were absent.
fn assert_refusal_names_chirho(refusal_chirho: &str, expected_chirho: &str, barrier_chirho: &str) {
    assert!(
        refusal_chirho.contains(expected_chirho),
        "the refusal must name the {barrier_chirho} barrier (looked for {expected_chirho:?}), \
         so a green arm cannot come from an unrelated refusal.\nrefusal chain: {refusal_chirho}"
    );
}

// ---------------------------------------------------------------------------------------------
// PIECE 1 / PIECE 6 — config custody. The opener verifies the config file's custody posture
// against the selected root BEFORE it reads any ledger state, so these two arms fire earliest.
// ---------------------------------------------------------------------------------------------

#[test]
fn real_opener_refuses_a_config_whose_permissions_went_broad_chirho() {
    let world_chirho = published_world_chirho();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            world_chirho.config_path_chirho(),
            fs::Permissions::from_mode(0o644),
        )
        .expect("widen the config mode");

        let refusal_chirho = world_chirho.refusal_text_chirho("config file mode");
        assert_refusal_names_chirho(
            &refusal_chirho,
            "ledger host config permissions are too broad",
            "config custody mode",
        );
    }
}

#[test]
fn real_opener_refuses_a_config_replaced_by_a_symlink_chirho() {
    let world_chirho = published_world_chirho();

    #[cfg(unix)]
    {
        // Move the real config aside and leave a symlink in its place. The bytes the opener would
        // read are IDENTICAL — only the custody shape changed, which is precisely the swap the
        // symlink check exists to refuse.
        let real_config_chirho = world_chirho
            .root_chirho()
            .join("relocated-config-chirho.toml");
        fs::rename(world_chirho.config_path_chirho(), &real_config_chirho)
            .expect("move the real config aside");
        set_private_mode_chirho(&real_config_chirho);
        std::os::unix::fs::symlink(&real_config_chirho, world_chirho.config_path_chirho())
            .expect("plant the symlink where the config was");

        let refusal_chirho = world_chirho.refusal_text_chirho("config file type");
        assert_refusal_names_chirho(
            &refusal_chirho,
            "ledger host config must not be a symlink",
            "config custody symlink",
        );
    }
}

// ---------------------------------------------------------------------------------------------
// PIECE 3 — the six signer files. The opener loads every runtime signer role from root custody.
// ---------------------------------------------------------------------------------------------

#[test]
fn real_opener_refuses_when_a_required_signer_file_is_absent_chirho() {
    let world_chirho = published_world_chirho();

    let journal_secret_chirho = world_chirho
        .root_chirho()
        .join("private-secrets-chirho")
        .join("ledger-journal-secret-chirho.secret-chirho");
    assert!(
        journal_secret_chirho.is_file(),
        "the published world must carry the journal signer secret before it is removed; \
         if this fails the secret layout moved and the perturbation below is aiming at nothing"
    );
    fs::remove_file(&journal_secret_chirho).expect("remove the journal signer secret");

    let refusal_chirho = world_chirho.refusal_text_chirho("journal signer file");
    assert_refusal_names_chirho(
        &refusal_chirho,
        // Names the ROLE as well as the secret: a refusal that merely echoed the path would not
        // prove the loader resolved this secret to its journal role before refusing.
        "journal-chirho secret ledger-journal-secret-chirho is unavailable",
        "signer custody",
    );
}

// ---------------------------------------------------------------------------------------------
// PIECE 4 — the verified kind registry. The opener loads it through the pinned issuer verifier,
// so a tampered registry row must refuse rather than be accepted as policy.
// ---------------------------------------------------------------------------------------------

#[test]
fn real_opener_refuses_a_tampered_kind_registry_chirho() {
    let world_chirho = published_world_chirho();

    let registry_chirho = world_chirho
        .storage_namespace_chirho()
        .join(&world_chirho.ledger_config_chirho.kind_registry_path_chirho);
    let published_chirho = fs::read_to_string(&registry_chirho).expect("read the kind registry");
    assert!(
        published_chirho.contains("prepaid-credit-chirho"),
        "the published registry must carry the fixture kind before it is tampered; \
         if this fails the registry path moved and the perturbation is aiming at nothing"
    );
    // Flip the declared unit inside a SIGNED row. The row stays well-formed JSON, so this is a
    // signature-coverage question and not a parse question — the distinction matters, because a
    // registry that only refused malformed bytes would pass a weaker version of this arm.
    let tampered_chirho = published_chirho.replace("credit-minor-chirho", "credit-major-chirho");
    assert_ne!(
        tampered_chirho, published_chirho,
        "the tamper must actually change the registry bytes"
    );
    fs::write(&registry_chirho, &tampered_chirho).expect("write the tampered registry");

    let refusal_chirho = world_chirho.refusal_text_chirho("kind registry contents");
    // `IssuerSignatureChirho` is the assertion that earns this arm its keep: the tampered row is
    // still well-formed JSON, so refusing on the ISSUER SIGNATURE proves the registry verifies
    // authorship rather than merely parsing. A refusal naming a parse error here would mean the
    // signature coverage this arm claims to pin was never exercised.
    assert_refusal_names_chirho(
        &refusal_chirho,
        "resident kind registry refused: IssuerSignatureChirho",
        "verified kind registry",
    );
}

// ---------------------------------------------------------------------------------------------
// PIECE 7 — the receipt-bound canary window. The opener requires a verified, NON-EMPTY window and
// then checks the journal against it; without the window there is no fence coordinate to align to.
// ---------------------------------------------------------------------------------------------

#[test]
fn real_opener_refuses_when_the_canary_evidence_window_is_gone_chirho() {
    let world_chirho = published_world_chirho();

    let canary_root_chirho = world_chirho
        .monitor_namespace_chirho()
        .join("writer-canary-chirho");
    assert!(
        canary_root_chirho.is_dir(),
        "the published world must carry a canary evidence root before it is removed; \
         if this fails the canary layout moved and the perturbation is aiming at nothing"
    );
    fs::remove_dir_all(&canary_root_chirho).expect("remove the canary evidence root");

    let refusal_chirho = world_chirho.refusal_text_chirho("canary evidence window");
    assert_refusal_names_chirho(
        &refusal_chirho,
        "shadow canary evidence store does not exist",
        "canary evidence window",
    );
}

// ---------------------------------------------------------------------------------------------
// PIECE 9 — elector alignment. A shared elector is supplied by the caller, so the opener must
// re-derive node and group FROM THE ROOT and refuse an elector that names either differently.
// These two checks sit one line apart, which is exactly why each arm asserts its own refusal
// name: an arm that accepted either message could not tell the two barriers apart.
// ---------------------------------------------------------------------------------------------

/// A bare provisioned root — enough to own a node identity and a consistency group, and nothing
/// else. Used only as a source of FOREIGN coordinates for the two elector arms.
fn foreign_identity_root_chirho() -> PathBuf {
    let root_chirho = temp_root_chirho();
    fs::create_dir(&root_chirho).expect("create the foreign identity root");
    sign_message_chirho(&root_chirho, b"provision a foreign node identity")
        .expect("provision the foreign node identity");
    root_chirho
}

#[test]
fn real_opener_refuses_a_shared_elector_naming_a_foreign_node_chirho() {
    let world_chirho = published_world_chirho();
    let foreign_root_chirho = foreign_identity_root_chirho();

    // The GROUP stays correct on purpose: the group check runs FIRST, so leaving it aligned is
    // what forces the node check to be the barrier that fires.
    let local_group_chirho =
        consistency_group_for_root_chirho(world_chirho.root_chirho()).expect("derive local group");
    let foreign_node_chirho = NodeIdChirho(
        existing_keypair_pubkey_hex_chirho(&foreign_root_chirho)
            .expect("read the foreign node key"),
    );
    let local_node_chirho = NodeIdChirho(
        existing_keypair_pubkey_hex_chirho(world_chirho.root_chirho()).expect("read the local key"),
    );
    assert_ne!(
        foreign_node_chirho, local_node_chirho,
        "the foreign root must own a different node identity, or this arm proves nothing"
    );

    // Its OWN fresh election directory on purpose: the point of this arm is an elector that is
    // internally valid and simply belongs to somebody else, not a corrupted one. A corrupted
    // elector would refuse for its own reasons and never reach the alignment check.
    let foreign_elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_durable_single_node_chirho(
            temp_root_chirho().join("foreign-writer-election-chirho"),
            foreign_node_chirho,
            local_group_chirho,
        )
        .expect("open the foreign-node elector"),
    );

    let refusal_chirho = match open_resident_effect_journal_handle_with_shared_elector_chirho(
        world_chirho.root_chirho(),
        world_chirho.config_path_chirho(),
        &world_chirho.ledger_config_chirho,
        &foreign_elector_chirho,
        None,
        None,
    ) {
        Ok(actor_chirho) => {
            drop(actor_chirho);
            panic!(
                "the real opener ADMITTED an elector naming a foreign node; \
                 the elector node-alignment check is no longer load-bearing"
            );
        }
        Err(error_chirho) => format!("{error_chirho:#}"),
    };
    assert_refusal_names_chirho(
        &refusal_chirho,
        "different local node",
        "shared elector node alignment",
    );
}

#[test]
fn real_opener_refuses_a_shared_elector_naming_a_foreign_group_chirho() {
    let world_chirho = published_world_chirho();
    let foreign_root_chirho = foreign_identity_root_chirho();

    // The NODE stays correct on purpose: this arm must fire on the group check, and the node check
    // is the one that would otherwise mask it.
    let local_node_chirho = NodeIdChirho(
        existing_keypair_pubkey_hex_chirho(world_chirho.root_chirho()).expect("read the local key"),
    );
    let foreign_group_chirho =
        consistency_group_for_root_chirho(&foreign_root_chirho).expect("derive foreign group");
    let local_group_chirho =
        consistency_group_for_root_chirho(world_chirho.root_chirho()).expect("derive local group");
    assert_ne!(
        foreign_group_chirho, local_group_chirho,
        "the foreign root must own a different consistency group, or this arm proves nothing"
    );

    // Same construction note as the node arm: internally valid, simply belonging to another group.
    let foreign_elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_durable_single_node_chirho(
            temp_root_chirho().join("foreign-group-writer-election-chirho"),
            local_node_chirho,
            foreign_group_chirho,
        )
        .expect("open the foreign-group elector"),
    );

    let refusal_chirho = match open_resident_effect_journal_handle_with_shared_elector_chirho(
        world_chirho.root_chirho(),
        world_chirho.config_path_chirho(),
        &world_chirho.ledger_config_chirho,
        &foreign_elector_chirho,
        None,
        None,
    ) {
        Ok(actor_chirho) => {
            drop(actor_chirho);
            panic!(
                "the real opener ADMITTED an elector naming a foreign consistency group; \
                 the elector group-alignment check is no longer load-bearing"
            );
        }
        Err(error_chirho) => format!("{error_chirho:#}"),
    };
    assert_refusal_names_chirho(
        &refusal_chirho,
        "different consistency group",
        "shared elector group alignment",
    );
}
