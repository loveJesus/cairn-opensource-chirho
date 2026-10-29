// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! HARNESS-1's SUCCESS half: the ladder from an observed GD7 world toward a compensation that
//! actually completes through the real mailbox.
//!
//! # WHERE THIS LADDER ACTUALLY STANDS — read this before citing any of it
//!
//! Rung 1 is landed here: the real held coordinator installs an authenticated observation, advances
//! to `PlanSealedChirho` one bounded page at a time, and re-verifies the exact sealed plan chain.
//! That is the SAME world `held_coordinator_tests_chirho` proves restart-stable; this module exists
//! so the ladder above it does not have to re-derive it.
//!
//! Rung 2 is landed here: the WINNER root runs a real resident actor on the world's own SHARED
//! elector, and its restricted evidence handle STAGES the current-view bundle to `ReadyChirho`.
//! Because the opener refuses unless the given root derives the elector's exact group AND its exact
//! local node, the rung passing is itself the evidence that the two tenant roots are one group and
//! that the winner root is the elected node.
//!
//! Staging works because the world now performs THE FORK as an operation: the winner's own resident
//! authority commits its own record at the deposing term, so the winner journal's tail epoch carries
//! the published raft term and the bundle builder's cut check is satisfied. The predecessor's pinned
//! `JournalCutMismatchChirho` refusal is closed, and this arm was retargeted by that pin's own
//! migration text rather than by anyone deciding to loosen it.
//!
//! # THE PRODUCTION GAP THAT HELD THIS MODULE RED IS CLOSED — and the record of it stays
//!
//! This module was RED, and the reason was never a rung bug or a world bug: making the fork real
//! moved the held node's losing suffix from the genesis MINT (which carries no effect intent) to a
//! genuine `EscrowHoldChirho` the held node committed under its own authority — and the GD7 plan
//! reducer requires the public INTENT EVIDENCE for every losing-suffix effect record it compensates
//! (`plan_chirho/reducer_chirho.rs`, `MissingIntentEvidenceChirho`). NOTHING IN PRODUCTION PUBLISHED
//! IT. The old world never hit this, because a fixture-built first record let the losing suffix stay
//! at the mint, where there is no intent to demand.
//!
//! The minimal-warrant privacy bundle landed the publisher: the resident commit boundary now
//! publishes its effect warrant, so the losing suffix carries the evidence it always should have
//! had. Rung 1 went green with NO edit to this module and NO edit to the world — the fork was
//! already right and was waiting on production to catch up. That is why the paragraph is kept
//! rather than deleted: the harness reaching a step production had not built is the thing this
//! module was FOR, and a reader who only sees the green cannot learn it.
//!
//! MIGRATION PATH FOR THIS PARAGRAPH: if rung 1 ever refuses with `MissingIntentEvidenceChirho`
//! again, the warrant publisher regressed at the resident commit boundary — do not look here, and
//! do not re-add a fixture-published intent line. That was measured and refused: a fixture that
//! publishes the evidence itself re-creates the exact shape this work removed, the world quietly
//! compensating for a step production does not perform.
//!
//! WHAT THIS MODULE NOW PROVES, and the line is drawn deliberately tight. It DOES prove a sealed
//! current view, a minted page grant, a fetched page, all three winner-signed evidence families at
//! durable `CompleteChirho`, and an ADOPTION COMMITTED through the real held mailbox — the last
//! two of the five coordinator commands, driven for the first time, with an exact retry reporting
//! `AlreadyAdoptedExactChirho` rather than adopting twice.
//!
//! It does NOT prove a provider-observed obligation, a term advance, or release -> complete —
//! those live in their own modules now, and partially LANDED (2026-08-05): the mint trigger arms
//! drive the real actor-owned mint against the adoption this module installs, and the capstone
//! arms (`harness1_compensated_terminal_arms_chirho`) carry one minted obligation to a PROVEN
//! `ProviderObservedChirho`, land the lawful advance, release the hold, and pin the completion
//! frontier at the missing post-adoption resume step. "A live completed compensation path" still
//! belongs to nobody — the capstone arms' header records exactly why. (Corrected at this line:
//! an earlier version said nothing public mints an obligation, which the mint trigger arms made
//! stale.)
//!
//! # THE MEASURED SHAPE OF THE REMAINING CLIMB
//!
//! The assignment's brick map named ONE missing fixture — the completed held-evidence transfer.
//! Measured at the bytes, the adoption request's evidence checkpoint is the THIRD of three
//! winner-signed artifact families that must each reach `CompleteChirho` in durable storage, in
//! this order, because each one's identity is an input to the next:
//!
//!   1. HELD-VIEW TRANSFER  — `Gd7HeldViewTransferStoreChirho` (pub): ensure_initialized ->
//!      commit_challenge_issued -> commit_sealed -> commit_received_page -> Complete. Needs a
//!      winner-signed current-view evidence object, a bundle root, a page, and a page grant.
//!   2. WINNER HANDOFF      — `Gd7WinnerHandoffStoreChirho` (pub): verify_complete_held_checkpoint
//!      -> verify_and_retain_plan_sealed_checkpoint -> commit_preparing -> commit_accepted. This
//!      is what mints `winner_handoff_attempt_digest_chirho`, the fourth field of the evidence
//!      identity, and it is the REAL accepted append barrier.
//!   3. EVIDENCE TRANSFER   — `Gd7HeldEvidenceTransferStoreChirho` (pub): stage both evidence
//!      families through the handoff store, build the manifest, then begin -> receive_page* ->
//!      Complete.
//!
//! Only then does `prepare_adoption_materialization_chirho` have something to load: it does NOT
//! trust its request — it re-loads the durable evidence checkpoint and requires both the exact ref
//! and `CompleteChirho` (`held_coordinator_chirho.rs:944-959`).
//!
//! ALL THREE FAMILIES ARE LANDED, AND FAMILY 3 COST A PRODUCTION FIX TO REACH. Climbing into it
//! found the ladder's SECOND unbuilt step (the first is the intent-evidence gap above): the winner
//! could not build the manifest on a genuine second root, because the one function that fetches its
//! input read a reconciliation group HEAD that only ever exists on the HELD root. The plan now
//! resolves by the accepted barrier's own checkpoint ref through the content-addressed loader, with
//! no head fallback — the full account is at `load_accepted_plan_chirho`, and the rung carries the
//! shorter version with its migration path.
//!
//! # WHY THE WINNER IS A SECOND REAL ROOT
//!
//! Every winner-signed artifact here is minted through a resident actor's REAL root custody, so the
//! winner could not stay a synthetic control key. `harness1_gd7_world_chirho` publishes TWO tenant
//! roots under one tenant id — one consistency group — and the winner signs through
//! `ExistingNodeGd7SignerChirho` on its own root, the same adapter production uses. The refusals
//! that make that necessary, and the positive control that keeps them meaningful, are pinned in
//! `harness1_two_root_world_tests_chirho`: a COPIED root refuses on its own root-bound artifacts
//! both before and after re-keying, so copy-and-re-key is not an available shortcut.
//!
//! # THE SEAM QUESTION, MEASURED AND CLOSED
//!
//! The geo-node driver that performs 1-3 in production is unreachable: `mod
//! held_evidence_transfer_chirho` is PRIVATE in geo-node's `lib.rs`, so its `pub(super)` driver
//! cannot be called from anywhere outside that crate, and its tests are `cfg(test)` unit tests
//! inside it. But the geo-node driver owns no state — it is an HTTP orchestrator over host-crate
//! stores, and every store above is `pub` and re-exported to
//! `cairn_ledger_host_chirho::reconciliation_chirho`. So the ladder needs NO new seam and NO
//! widening: it drives the real owners in-process instead of over the wire.
//!
//! Deliberately NOT taken: the host crate's own `complete_evidence_transfer_chirho` fixture is a
//! working recipe, but it is `pub(super)` inside a `cfg(test)` tree and takes a TEST winner signer.
//! Exporting it would be a forgery tool of exactly the shape the parked-portion record forbids for
//! `sign_converged_read_replica_for_test_chirho`. It is used here as a recipe to read, never as an
//! export to call.
//!
//! # MIGRATION PATH
//!
//! - If rung 1 starts REFUSING, the world builder and the coordinator disagree about the observed
//!   world; read `harness1_gd7_world_chirho` before touching this file.
//! - The standing rule that discharged itself once already and still applies: when a rung lands,
//!   this header loses the paragraph saying it has not, IN THE SAME COMMIT. A header that
//!   understates what is proven is a smaller sin than one that overstates it, but it is still a
//!   stale record — and a stale "not yet" paragraph is how a solved problem keeps being re-solved.
//! - The acceptance arms for the barrier-ref adoption fix live in
//!   `harness1_adoption_fix_arms_chirho`, driven from the shared helper below. They were moved out
//!   of this file when it crossed the 1500-line cap; that was a recorded loan repaid by the real
//!   refactor, not by trimming comments to get under a number.

use super::harness1_gd7_world_chirho::{build_observed_gd7_world_chirho, ObservedGd7WorldChirho};
use super::{drive_ticks_chirho, fixture_chirho};
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_ledger_host_chirho::reconciliation_chirho::{
    gd7_reconciliation_checkpoint_path_chirho, generate_gd7_winner_current_view_challenge_chirho,
    load_authenticated_active_gd7_reconciliation_for_group_chirho,
    parse_canonical_gd7_winner_current_view_challenge_chirho, ActiveGd7HeldViewTransferChirho,
    ExistingNodeGd7SignerChirho, Gd7HeldEvidenceTransferIdentityChirho,
    Gd7HeldEvidenceTransferPhaseChirho, Gd7HeldEvidenceTransferStoreChirho,
    Gd7HeldViewTransferIdentityChirho, Gd7HeldViewTransferPhaseChirho,
    Gd7HeldViewTransferStoreChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationStoreRefusalChirho, Gd7WinnerCurrentViewRefusalChirho,
    Gd7WinnerEvidenceManifestChirho, Gd7WinnerHandoffPhaseChirho,
    Gd7WinnerHandoffStoreRefusalChirho, PinnedNodeGd7VerifierChirho,
};
use cairn_ledger_host_chirho::{
    configured_held_gd7_journal_verifier_chirho,
    open_resident_effect_journal_handle_with_shared_elector_chirho,
    open_resident_gd7_held_coordinator_chirho, FsLedgerStorageChirho,
    ResidentGd7HeldAdoptionCommitOutcomeChirho,
    ResidentGd7HeldAdoptionMaterializationRequestChirho, ResidentGd7HeldSealedPlanSnapshotChirho,
    ResidentGd7WinnerAdoptionEvidenceInspectionChirho,
    ResidentGd7WinnerAdoptionEvidenceRefusalChirho, ResidentGd7WinnerEvidenceRefusalChirho,
    ResidentGd7WinnerViewStageInspectionChirho,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use std::sync::Arc;

/// Rung 1: the real coordinator carries the observed world all the way to a re-verified sealed plan.
///
/// This is the launch pad for every rung above it, and it is driven entirely through the real
/// mailbox commands — `install_authenticated_observation_chirho`, `advance_one_page_chirho`,
/// `verify_sealed_plan_chirho` — never by writing checkpoint bytes directly.
#[test]
fn success_ladder_rung_one_seals_the_plan_through_the_real_coordinator_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let world_chirho =
        build_observed_gd7_world_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    let mut coordinator_chirho = open_resident_gd7_held_coordinator_chirho(
        &world_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &world_chirho.ledger_config_chirho,
        Arc::clone(&world_chirho.nodes_chirho[2]),
    )
    .expect("schema v4 admits the observed world under the retained writer lock");

    let observed_chirho = coordinator_chirho
        .install_authenticated_observation_chirho(world_chirho.observation_import_chirho)
        .expect("the held coordinator authenticates and installs the exact winner observation");
    assert_eq!(
        observed_chirho.phase_chirho,
        Gd7ReconciliationPhaseChirho::ObservedHeldChirho
    );

    let mut current_chirho = observed_chirho;
    for _page_chirho in 0..16 {
        if current_chirho.phase_chirho == Gd7ReconciliationPhaseChirho::PlanSealedChirho {
            break;
        }
        current_chirho = coordinator_chirho
            .advance_one_page_chirho(current_chirho.checkpoint_ref_chirho.clone())
            .expect("each command advances exactly one bounded reconciliation page");
    }
    assert_eq!(
        current_chirho.phase_chirho,
        Gd7ReconciliationPhaseChirho::PlanSealedChirho,
        "the bounded page loop must reach a sealed plan, not run out of iterations"
    );

    let sealed_chirho = coordinator_chirho
        .verify_sealed_plan_chirho(current_chirho.checkpoint_ref_chirho.clone())
        .expect("the exact immutable plan chain re-verifies after sealing");
    assert_eq!(
        sealed_chirho.checkpoint_ref_chirho,
        current_chirho.checkpoint_ref_chirho
    );
    assert_eq!(
        sealed_chirho.winner_term_chirho,
        world_chirho.winner_term_chirho
    );
    assert!(sealed_chirho.plan_page_count_chirho > 0);
    assert!(sealed_chirho.manifest_record_count_chirho > 0);

    // The launch pad must not have moved the world it launches from.
    assert_eq!(
        std::fs::read(
            world_chirho
                .canonical_root_chirho
                .join(&world_chirho.ledger_config_chirho.storage_namespace_chirho)
                .join(&world_chirho.ledger_config_chirho.journal_path_chirho)
        )
        .unwrap(),
        world_chirho.unchanged_journal_bytes_chirho,
        "sealing a plan may not append to or adopt the losing journal"
    );
    // RETARGETED, not deleted. This used to read "the held learner remains non-electable at
    // PlanSealed" — a property that was an artifact of the observed-world fixture lineage, where the
    // held node was a learner and so could never have written anything. A learner cannot lead, and a
    // node that never led cannot be a fork origin; the held node is now a real VOTER that genuinely
    // held the losing term and committed under its own authority before being deposed. What the
    // property BECOMES is the part that still matters for reconciliation: having been deposed, the
    // held node must not regain leadership while it reconciles. Asserted by observation at the
    // elector rather than by construction, because it is no longer true by construction.
    assert!(
        !world_chirho.nodes_chirho[2]
            .leadership_chirho(&world_chirho.group_chirho)
            .is_leader_chirho,
        "the deposed held node must stay non-leader through PlanSealed"
    );

    coordinator_chirho.close_chirho().unwrap();
}

/// Rung 2a: the WINNER root runs a real resident actor on the world's own elector, and its
/// restricted evidence handle stages the current-view bundle to `Ready`.
///
/// This is the piece the two-root world existed to make possible, and it is the first time anything
/// in this crate has opened a second resident actor around a SHARED elector. Two properties carry
/// the weight. The actor refuses unless the root it is given derives the elector's exact consistency
/// group AND the elector's exact local node — so this test passing is itself evidence that the two
/// tenant roots really are one group and that the winner root really is the elected node, neither of
/// which any amount of reading could establish. And the staging runs through the restricted handle,
/// which by construction cannot append, compensate, adopt, or move a ref.
///
/// # WHAT THIS RUNG DOES NOT DO
///
/// It does not seal a view, mint a grant, or fetch a page. Those need a held-view transfer store to
/// supply the challenge's `transfer_identity_digest_chirho`, which is the first of the three
/// winner-signed artifact families named in this module's header — the next brick, not this one.
///
/// # MIGRATION PATH
///
/// If the OPEN starts refusing, read the refusal before touching this test: "names a different
/// consistency group" means the tenant marker/publish ordering in `harness1_gd7_world_chirho`
/// regressed, and "names a different local node" means the winner node id stopped coming from the
/// winner root's keypair. Both are world bugs, not rung bugs.
#[test]
fn success_ladder_rung_two_stages_the_winner_view_through_the_shared_elector_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let world_chirho =
        build_observed_gd7_world_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    // The shared-elector opener requires a warm promotable local leader. The world elects the winner
    // but deliberately does not tick it: warming the lease is this rung's precondition, not a fact
    // about the observed world, so it stays here.
    drive_ticks_chirho(&world_chirho.nodes_chirho, 0, 10);
    let leadership_chirho = world_chirho.nodes_chirho[0].current_leadership_chirho();
    assert!(leadership_chirho.is_leader_chirho);
    assert!(leadership_chirho.lease_valid_chirho);
    assert_eq!(
        leadership_chirho.leader_id_chirho.as_ref(),
        Some(&world_chirho.winner_node_chirho)
    );
    assert_eq!(
        leadership_chirho.term_chirho, world_chirho.winner_term_chirho,
        "warming the lease must not move the term the observation was already minted at"
    );

    let winner_actor_chirho = open_resident_effect_journal_handle_with_shared_elector_chirho(
        &world_chirho.winner_source_root_chirho,
        &world_chirho.winner_config_path_chirho,
        &world_chirho.winner_ledger_config_chirho,
        &world_chirho.nodes_chirho[0],
        None,
        None,
    )
    .expect("the winner root opens one resident actor around the world's own shared elector");

    let winner_evidence_chirho = winner_actor_chirho
        .gd7_winner_evidence_handle_chirho()
        .expect("derive the restricted winner-evidence facade from the winner's resident actor");
    let readiness_chirho = winner_evidence_chirho.probe_chirho().unwrap();
    assert_eq!(
        readiness_chirho.local_node_chirho, world_chirho.winner_node_chirho,
        "the winner actor's own node identity is the winner root's key custody"
    );
    assert_eq!(
        readiness_chirho.published_raft_term_chirho, world_chirho.winner_term_chirho,
        "the shared elector's deposing term is the term the winner actor publishes"
    );

    // STAGING NOW SUCCEEDS, and this arm is the retarget its predecessor's migration text called
    // for. The refusal it used to pin — `JournalCutMismatchChirho`, the bundle builder requiring the
    // winner journal's own tail epoch to carry the published raft term — is closed by the world's
    // fork-append: the winner's resident authority commits its own record at the deposing term, so
    // the tail epoch carries that term and the cut matches.
    //
    // The projection this world stages is one small page, so `ReadyChirho` arrives on the first
    // indexed stage rather than after a loop. Asserting the exact variant AND its counters keeps the
    // arm from going vacuous if the bundle ever stages an empty view.
    let staged_chirho = winner_evidence_chirho
        .stage_view_page_at_chirho(0)
        .expect("the forked winner journal stages its bounded current-view page");
    let ResidentGd7WinnerViewStageInspectionChirho::ReadyChirho {
        ref bundle_root_object_digest_chirho,
        page_count_chirho,
        row_count_chirho,
    } = staged_chirho
    else {
        panic!(
            "this world's projection is one page, so the first indexed stage must be Ready. An \
             AdvancedOnePage here means the fixture projection grew and this arm needs the bounded \
             loop the single-root recipe uses. Got: {staged_chirho:?}"
        );
    };
    assert!(
        page_count_chirho > 0 && row_count_chirho > 0,
        "a staged current view that is Ready with nothing in it would satisfy this arm while \
         proving nothing; pages={page_count_chirho} rows={row_count_chirho}"
    );

    // Retries must not advance the projection: the same coordinate returns the same inspection.
    assert_eq!(
        winner_evidence_chirho
            .stage_view_page_at_chirho(0)
            .expect("the immediately preceding stage retries idempotently"),
        ResidentGd7WinnerViewStageInspectionChirho::ReadyChirho {
            bundle_root_object_digest_chirho: bundle_root_object_digest_chirho.clone(),
            page_count_chirho,
            row_count_chirho,
        },
        "a network retry must not advance the projection twice"
    );
    // A skipped stage coordinate must fail closed — the negative control for the rung.
    assert!(
        winner_evidence_chirho.stage_view_page_at_chirho(2).is_err(),
        "a skipped stage coordinate must fail closed"
    );

    // The held side of the world must be untouched: this rung is winner-side evidence only.
    assert_eq!(
        std::fs::read(
            world_chirho
                .canonical_root_chirho
                .join(&world_chirho.ledger_config_chirho.storage_namespace_chirho)
                .join(&world_chirho.ledger_config_chirho.journal_path_chirho)
        )
        .unwrap(),
        world_chirho.unchanged_journal_bytes_chirho,
        "staging winner evidence may not append to the held journal"
    );

    drop(winner_evidence_chirho);
    drop(winner_actor_chirho);
}

/// Rung 3: the FIRST of the three winner-signed artifact families reaches durable `CompleteChirho`
/// — the held-view transfer, driven end to end through real owners on both sides.
///
/// # WHY THIS IS THE SHAPE IT IS
///
/// Production drives this family from `cairn-ledger-geo-node-chirho`'s `held_view_transfer_chirho`,
/// a restartable loop that reads the held-signed checkpoint's own phase and asks the winner for
/// exactly the next thing that phase needs. That driver is unreachable from this crate (its module
/// is private in geo-node's `lib.rs`), but it owns NO state: every durable transition belongs to
/// `Gd7HeldViewTransferStoreChirho`, and every winner-signed artifact belongs to
/// `ResidentGd7WinnerEvidenceHandleChirho`. Both are `pub`. So this test is that same loop with the
/// HTTP hop replaced by an in-process call to the winner's own handle — the identical owners, the
/// identical order, no new seam and no widening.
///
/// # WHAT MAKES IT A PROOF RATHER THAN A REPLAY
///
/// NOTHING HERE IS CALLER-SIGNED. The host crate has a working recipe for this family
/// (`complete_evidence_transfer_chirho` and its neighbours in
/// `held_evidence_transfer_chirho/account_net_composition_tests_chirho.rs`) which hand-builds the
/// winner evidence, the grant and the page and signs each with a TEST winner signer. It is read
/// here as a recipe and deliberately NOT called: a test that forges the winner's signature proves
/// the held store accepts what the test just wrote, which is not the property. Every winner-signed
/// artifact below is minted by the winner root's own resident actor out of its own key custody, and
/// the held side pins the winner by node id ALONE — `PinnedNodeGd7VerifierChirho`, never the
/// winner's signer — so the held store cannot produce winner evidence even by accident.
///
/// The challenge makes the round trip through canonical bytes exactly as it would over the wire:
/// minted from the elector's live observation, canonicalized, persisted BEFORE it is sent (the
/// store commits it as its own checkpoint first), then parsed back for the winner. A challenge that
/// never reached durable storage before it was answered would be unrecoverable across a restart,
/// which is why production persists first and why the store refuses the seal otherwise.
///
/// # MIGRATION PATH
///
/// If the loop hits its iteration ceiling, the phase machine gained a state this loop does not
/// answer — print `active_chirho.checkpoint_chirho.phase_chirho` and add the arm; do NOT raise the
/// ceiling. If `StaleChirho` appears, the winner refused something and the store recorded WHY in
/// `stale_reason_chirho`; read that before suspecting this test. If the winner ever returns
/// `AdvancedOnePageChirho` here, the fixture projection grew past one page — that is the loop
/// working as designed, not a failure.
#[test]
fn success_ladder_rungs_three_through_six_reach_a_committed_adoption_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    drive_ladder_through_adoption_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
}

/// The coordinates an already-adopted world exposes to a suite that did not drive it.
///
/// Deliberately OWNED and tiny. Returning the live stores or the world itself would hand the caller
/// borrows into the driver's own frame and force the whole ladder to be restructured around one
/// consumer; three owned paths let the arms module open its own handles and assert against the same
/// durable state.
pub(super) struct AdoptedLadderStateChirho {
    pub(super) canonical_root_chirho: std::path::PathBuf,
    pub(super) winner_source_root_chirho: std::path::PathBuf,
    pub(super) group_digest_chirho: String,
    /// The two ROOTS' node identities, carried so a consumer can open each root's OWN key custody.
    ///
    /// They are what makes a distinct operator principal reachable: the disposition tail signs in
    /// the winner root's custody and verifies against its key id on the held side, so a consumer
    /// needs both names to exercise the separation rather than letting one node sign its own
    /// permission slip.
    pub(super) held_node_chirho: NodeIdChirho,
    pub(super) winner_node_chirho: NodeIdChirho,
    /// Everything needed to REOPEN the held coordinator after the drive closed it.
    ///
    /// The drive closes its coordinator deliberately — a second handle on a live one would contend
    /// for the same writer lock — so a consumer that wants to send a further command reopens rather
    /// than borrows. These are the exact four arguments `open_resident_gd7_held_coordinator_chirho`
    /// takes, minus the config path, which the caller already owns through its own fixture.
    pub(super) ledger_config_chirho: LedgerHostConfigChirho,
    pub(super) held_elector_chirho: Arc<RaftWriterElectorChirho>,
    /// The sealed plan's own coordinate, carried so a consumer can name an obligation WITHOUT a new
    /// enumeration surface. The plan chain's walk starts at `sealed_plan_ref_chirho` and matches a
    /// selector when the visited page ref equals the selector's, so this ref IS the first plan
    /// page's ref — a lawful caller names `(sealed_plan_ref, index)` and nothing wider is needed.
    pub(super) sealed_plan_ref_chirho: String,
    /// The checkpoint the COMMITTED adoption produced, which is NOT the sealed plan's checkpoint.
    ///
    /// Carried because adoption ADVANCES the active checkpoint: a consumer that keeps using the
    /// pre-adoption sealed ref afterwards is refused `StaleCheckpointChirho`, which is a refusal
    /// about freshness and says nothing about the subject the consumer was actually asking after.
    pub(super) adopted_checkpoint_ref_chirho: String,
    /// How many obligations the sealed plan actually carries. Carried so a consumer can assert
    /// NON-VACUITY before minting: on a plan with zero obligations every mint arm would refuse for
    /// the honest reason "there is nothing to mint", and a suite of such arms is green while
    /// measuring nothing.
    pub(super) effect_obligation_count_chirho: u64,
}

/// Drive one real two-root world from an observed GD7 fork to a COMMITTED adoption.
///
/// EXTRACTED, NOT REWRITTEN. Every assertion below stood in the `#[test]` this replaced, in the same
/// order, and the suite passed unchanged across the move — the move's own proof, since a refactor
/// that alters behaviour while claiming not to is exactly what an unchanged green cannot show if the
/// bytes changed too. It exists so the adoption-fix arms can stand on a world they did not build:
/// re-deriving it would mean duplicating five rungs, and handing the arms a fixture-built barrier is
/// the forgery shape this ladder exists to refuse.
pub(super) fn drive_ladder_through_adoption_chirho(
    fixture_chirho: &mut super::RegenesisFixtureChirho,
    winner_fixture_chirho: &mut super::RegenesisFixtureChirho,
) -> AdoptedLadderStateChirho {
    let (state_chirho, _world_chirho) =
        drive_ladder_through_adoption_returning_world_chirho(fixture_chirho, winner_fixture_chirho);
    state_chirho
}

/// The same drive, additionally returning the WORLD the adoption ran on.
///
/// The owned state above is deliberately tiny and does not carry the winner-side coordinates.
/// Route (a) — the capstone arm — must reopen the WINNER's resident actor on the world's own
/// shared elector (a compensation executes only under current winner authority), which needs the
/// winner root, config path, ledger config, signers, and elector roster. Returning the world keeps
/// `AdoptedLadderStateChirho` unchanged for every existing consumer while letting the capstone
/// stand on the same mesh the adoption really ran on rather than re-deriving five rungs.
pub(super) fn drive_ladder_through_adoption_returning_world_chirho(
    fixture_chirho: &mut super::RegenesisFixtureChirho,
    winner_fixture_chirho: &mut super::RegenesisFixtureChirho,
) -> (AdoptedLadderStateChirho, ObservedGd7WorldChirho) {
    let world_chirho = build_observed_gd7_world_chirho(fixture_chirho, winner_fixture_chirho);

    // ---- rung 1 again, because the transfer identity is BOUND to the sealed plan's coordinate ----
    // The reconciliation checkpoint ref is a field of the transfer identity, so the transfer cannot
    // be opened before the plan it belongs to has been sealed. This is the dependency the brick map
    // named: each family's identity is an input to the next.
    let mut coordinator_chirho = open_resident_gd7_held_coordinator_chirho(
        &world_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &world_chirho.ledger_config_chirho,
        Arc::clone(&world_chirho.nodes_chirho[2]),
    )
    .expect("schema v4 admits the observed world under the retained writer lock");
    let mut current_chirho = coordinator_chirho
        // CLONED, not moved: the adoption body below borrows the whole world, and moving one field
        // out would partially move it. The import is `Clone` by its own derive.
        .install_authenticated_observation_chirho(world_chirho.observation_import_chirho.clone())
        .expect("the held coordinator authenticates and installs the exact winner observation");
    for _page_chirho in 0..16 {
        if current_chirho.phase_chirho == Gd7ReconciliationPhaseChirho::PlanSealedChirho {
            break;
        }
        current_chirho = coordinator_chirho
            .advance_one_page_chirho(current_chirho.checkpoint_ref_chirho.clone())
            .expect("each command advances exactly one bounded reconciliation page");
    }
    let sealed_chirho = coordinator_chirho
        .verify_sealed_plan_chirho(current_chirho.checkpoint_ref_chirho.clone())
        .expect("the exact immutable plan chain re-verifies after sealing");
    coordinator_chirho.close_chirho().unwrap();

    let state_chirho = adopt_sealed_world_chirho(&world_chirho, fixture_chirho, &sealed_chirho);
    (state_chirho, world_chirho)
}

/// Adopt a world whose plan is ALREADY SEALED — the ladder's rungs 3 through 6, without its rung 1.
///
/// EXTRACTED, NOT REWRITTEN, and for one reason: a second caller needs these rungs on a world it
/// drove ITSELF. The v4 restart oracle instruments its own rung 1 with restart probes — close,
/// reopen, assert the reloaded checkpoint is exact — and those probes ARE that suite's claim, so it
/// cannot delegate rung 1 to the drive above without deleting the thing it exists to prove. Nor can
/// it duplicate nine hundred lines of adoption. So rung 1 stays with whoever needs to instrument it,
/// and everything downstream of a sealed plan lives here, driven once.
///
/// Takes the world by REFERENCE so the caller keeps it: both callers still need its identity,
/// signers, and node ids after adoption returns.
pub(super) fn adopt_sealed_world_chirho(
    world_chirho: &ObservedGd7WorldChirho,
    fixture_chirho: &mut super::RegenesisFixtureChirho,
    sealed_chirho: &ResidentGd7HeldSealedPlanSnapshotChirho,
) -> AdoptedLadderStateChirho {
    let reconciliation_checkpoint_ref_chirho = sealed_chirho.checkpoint_ref_chirho.clone();

    // ---- the winner side: its own root, its own custody, on the world's shared elector ----
    drive_ticks_chirho(&world_chirho.nodes_chirho, 0, 10);
    let winner_actor_chirho = open_resident_effect_journal_handle_with_shared_elector_chirho(
        &world_chirho.winner_source_root_chirho,
        &world_chirho.winner_config_path_chirho,
        &world_chirho.winner_ledger_config_chirho,
        &world_chirho.nodes_chirho[0],
        None,
        None,
    )
    .expect("the winner root opens one resident actor around the world's own shared elector");
    let winner_evidence_chirho = winner_actor_chirho
        .gd7_winner_evidence_handle_chirho()
        .expect("derive the restricted winner-evidence facade from the winner's resident actor");

    // ---- the held side: real storage, real key custody, and a winner PINNED BY NODE ID ONLY ----
    let held_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&world_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens");
    let held_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        &world_chirho.canonical_root_chirho,
        &world_chirho.held_node_chirho,
    )
    .expect("the held root's own key custody opens as its GD7 checkpoint signer");
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(world_chirho.winner_node_chirho.clone())
            .expect("the held side pins the winner by node id, holding no winner signing power");
    let store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &held_storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        Gd7HeldViewTransferIdentityChirho {
            consistency_group_digest_chirho: world_chirho.group_digest_chirho.clone(),
            reconciliation_checkpoint_ref_chirho: reconciliation_checkpoint_ref_chirho.clone(),
            winner_node_chirho: world_chirho.winner_node_chirho.0.clone(),
            held_node_chirho: world_chirho.held_node_chirho.0.clone(),
            winner_term_chirho: world_chirho.winner_term_chirho,
        },
    )
    .expect("the held-view transfer store opens on the exact reconciliation coordinate");

    // The held node mints the challenge from ITS OWN elector's observation, as production does.
    // Asserted first so that a challenge refusal below is diagnosable as a world fact rather than
    // as a mystery: if the held node cannot see the winner leading at the winner term, nothing
    // downstream can be right.
    let held_view_of_leadership_chirho =
        world_chirho.nodes_chirho[2].leadership_chirho(&world_chirho.group_chirho);
    assert_eq!(
        held_view_of_leadership_chirho.leader_id_chirho.as_ref(),
        Some(&world_chirho.winner_node_chirho),
        "the deposed held node must observe the winner as leader before it may challenge it"
    );
    assert_eq!(
        held_view_of_leadership_chirho.term_chirho, world_chirho.winner_term_chirho,
        "the held node's observed term is the term its transfer identity is bound to"
    );

    let mut active_chirho = store_chirho
        .ensure_initialized_chirho()
        .expect("initialize the held winner-view transfer at its own coordinate");
    assert_eq!(
        active_chirho.checkpoint_chirho.phase_chirho,
        Gd7HeldViewTransferPhaseChirho::StagingChirho,
        "a fresh transfer begins at Staging with nothing staged"
    );

    // Every phase this run actually passed through, so the Complete below cannot have been reached
    // by a machine that skipped the work. A phase set, not a count: an extra staging round is
    // legitimate, a missing ChallengeIssued is not.
    let mut phases_seen_chirho = vec![active_chirho.checkpoint_chirho.phase_chirho];
    let mut wrong_requester_control_chirho = None;

    for _step_chirho in 0..16 {
        if active_chirho.checkpoint_chirho.phase_chirho
            == Gd7HeldViewTransferPhaseChirho::CompleteChirho
        {
            break;
        }
        let committed_chirho = match active_chirho.checkpoint_chirho.phase_chirho {
            Gd7HeldViewTransferPhaseChirho::StagingChirho => {
                let expected_stage_index_chirho =
                    active_chirho.checkpoint_chirho.expected_stage_index_chirho;
                match winner_evidence_chirho
                    .stage_view_page_at_chirho(expected_stage_index_chirho)
                    .expect("the winner stages exactly the page the held checkpoint expects")
                {
                    ResidentGd7WinnerViewStageInspectionChirho::AdvancedOnePageChirho => {
                        store_chirho
                            .commit_stage_advanced_chirho(
                                &active_chirho.checkpoint_ref_chirho,
                                expected_stage_index_chirho,
                            )
                            .expect("checkpoint one winner-view staging step")
                    }
                    ResidentGd7WinnerViewStageInspectionChirho::ReadyChirho {
                        bundle_root_object_digest_chirho,
                        page_count_chirho,
                        row_count_chirho,
                    } => {
                        assert!(
                            page_count_chirho > 0 && row_count_chirho > 0,
                            "an empty staged view would carry this ladder to Complete having \
                             transferred nothing; pages={page_count_chirho} rows={row_count_chirho}"
                        );
                        let issued_challenge_chirho =
                            generate_gd7_winner_current_view_challenge_chirho(
                                world_chirho.nodes_chirho[2].as_ref(),
                                &world_chirho.group_chirho,
                                &world_chirho.winner_node_chirho,
                                &world_chirho.held_node_chirho,
                                store_chirho.identity_digest_chirho(),
                            )
                            .expect(
                                "the held node mints a fresh challenge from its own observation",
                            );
                        let canonical_challenge_chirho = issued_challenge_chirho
                            .canonical_bytes_chirho()
                            .expect("canonicalize the held winner-view challenge");
                        store_chirho
                            .commit_challenge_issued_chirho(
                                &active_chirho.checkpoint_ref_chirho,
                                expected_stage_index_chirho,
                                bundle_root_object_digest_chirho,
                                page_count_chirho,
                                row_count_chirho,
                                &canonical_challenge_chirho,
                            )
                            .expect("persist the challenge BEFORE it is answered")
                    }
                }
            }
            Gd7HeldViewTransferPhaseChirho::ChallengeIssuedChirho => {
                // The challenge crosses to the winner as canonical bytes, exactly as it would on the
                // wire — read back out of the held checkpoint that persisted it, never kept in a
                // local variable, so what the winner answers is what durably survived.
                let canonical_challenge_chirho = active_chirho
                    .checkpoint_chirho
                    .canonical_challenge_chirho
                    .clone()
                    .expect("the ChallengeIssued checkpoint carries its own canonical challenge");
                let challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
                    canonical_challenge_chirho.as_bytes(),
                )
                .expect("the persisted challenge parses back canonically");
                let seal_chirho = winner_evidence_chirho
                    .seal_current_view_for_held_chirho(
                        challenge_chirho,
                        world_chirho.held_node_chirho.clone(),
                    )
                    .expect("the winner seals its challenged current view for this held node");
                assert!(
                    seal_chirho.first_page_grant_chirho.is_some(),
                    "a sealed non-empty view must mint the first page grant with it"
                );
                store_chirho
                    .commit_sealed_chirho(
                        &active_chirho.checkpoint_ref_chirho,
                        seal_chirho.inspection_chirho,
                        seal_chirho.first_page_grant_chirho,
                    )
                    .expect("checkpoint the winner-signed seal and its first page grant")
            }
            Gd7HeldViewTransferPhaseChirho::ReceivingChirho => {
                let grant_chirho = active_chirho
                    .checkpoint_chirho
                    .next_page_grant_chirho
                    .clone()
                    .expect("a Receiving checkpoint names the grant it is waiting on");
                // NEGATIVE CONTROL, taken once and on the real grant: a page grant is bound to its
                // RECIPIENT. Asking the winner for this exact page as anyone other than the held
                // node it was minted for must refuse. Run before the honest fetch so the refusal
                // cannot be an artifact of the page already having been delivered.
                if wrong_requester_control_chirho.is_none() {
                    wrong_requester_control_chirho = Some(
                        winner_evidence_chirho
                            .fetch_granted_page_chirho(
                                world_chirho.winner_node_chirho.clone(),
                                grant_chirho.clone(),
                            )
                            .expect_err(
                                "a grant minted for the held node must not be fetchable by another \
                                 requester",
                            ),
                    );
                }
                let transfer_chirho = winner_evidence_chirho
                    .fetch_granted_page_chirho(world_chirho.held_node_chirho.clone(), grant_chirho)
                    .expect("the winner serves exactly the granted page to its named recipient");
                store_chirho
                    .commit_received_page_chirho(
                        &active_chirho.checkpoint_ref_chirho,
                        transfer_chirho.grant_chirho,
                        &transfer_chirho.canonical_page_bytes_chirho,
                        transfer_chirho.next_grant_chirho,
                    )
                    .expect("persist one immutable winner-view page then advance the head")
            }
            other_phase_chirho => panic!(
                "the held-view transfer reached a phase this loop does not answer: \
                 {other_phase_chirho:?}. If this is StaleChirho, read stale_reason_chirho on the \
                 checkpoint — the winner refused something and the store recorded why."
            ),
        };
        active_chirho = ActiveGd7HeldViewTransferChirho {
            checkpoint_ref_chirho: committed_chirho.checkpoint_ref_chirho,
            checkpoint_chirho: committed_chirho.checkpoint_chirho,
        };
        phases_seen_chirho.push(active_chirho.checkpoint_chirho.phase_chirho);
    }

    assert_eq!(
        active_chirho.checkpoint_chirho.phase_chirho,
        Gd7HeldViewTransferPhaseChirho::CompleteChirho,
        "the bounded loop must reach a durable Complete, not run out of iterations"
    );
    for required_phase_chirho in [
        Gd7HeldViewTransferPhaseChirho::StagingChirho,
        Gd7HeldViewTransferPhaseChirho::ChallengeIssuedChirho,
        Gd7HeldViewTransferPhaseChirho::ReceivingChirho,
        Gd7HeldViewTransferPhaseChirho::CompleteChirho,
    ] {
        assert!(
            phases_seen_chirho.contains(&required_phase_chirho),
            "reaching Complete without passing through {required_phase_chirho:?} would mean the \
             state machine skipped the step that phase exists to perform; saw \
             {phases_seen_chirho:?}"
        );
    }
    // Assert the recipient-binding refusal BY EXACT VARIANT. `is_err()` alone would be satisfied by
    // a dead actor, a full mailbox, or a malformed grant — none of which is the property. The
    // variant is what says the winner looked at WHO was asking.
    assert!(
        matches!(
            wrong_requester_control_chirho,
            Some(ResidentGd7WinnerEvidenceRefusalChirho::OperationChirho(
                Gd7WinnerCurrentViewRefusalChirho::InvalidPageGrantChirho
            ))
        ),
        "the recipient-binding control must refuse as an OPERATION refusal naming an invalid page \
         grant. `None` means the control never ran and its silence proves nothing; \
         `ActorUnavailable`/`MailboxFull` mean the winner never evaluated the grant at all, so the \
         arm would be green for a reason that has nothing to do with recipient binding. Got: \
         {wrong_requester_control_chirho:?}"
    );
    assert!(
        active_chirho.checkpoint_chirho.received_page_count_chirho > 0
            && active_chirho.checkpoint_chirho.received_row_count_chirho > 0,
        "a Complete transfer that received no pages or no rows would satisfy the phase assertion \
         while having transferred nothing"
    );

    // The transfer must be DURABLE, not merely returned: a second store opened on the same
    // coordinate, with its own storage handle, must load the same Complete checkpoint.
    let reopened_store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &held_storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        store_chirho.identity_chirho().clone(),
    )
    .expect("the same coordinate reopens");
    let reloaded_chirho = reopened_store_chirho
        .load_active_chirho()
        .expect("the persisted head re-verifies on load")
        .expect("a completed transfer is still there after the store is dropped");
    assert_eq!(
        reloaded_chirho.checkpoint_ref_chirho, active_chirho.checkpoint_ref_chirho,
        "the durable head must name the exact checkpoint this run committed"
    );

    // NEGATIVE CONTROL: completion is bound to ONE reconciliation coordinate, not ambient. A store
    // at a different reconciliation checkpoint ref must find NOTHING — otherwise "the transfer is
    // complete" would be a fact about the root rather than about this reconciliation.
    let mut foreign_identity_chirho = store_chirho.identity_chirho().clone();
    foreign_identity_chirho.reconciliation_checkpoint_ref_chirho =
        world_chirho.losing_journal_genesis_digest_chirho.clone();
    assert_ne!(
        foreign_identity_chirho.reconciliation_checkpoint_ref_chirho,
        reconciliation_checkpoint_ref_chirho,
        "the control's coordinate must actually differ from the one that was driven"
    );
    let foreign_store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &held_storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        foreign_identity_chirho,
    )
    .expect("a different reconciliation coordinate is a legitimate store to open");
    // MUTATION-MEASURED, and the measurement taught something worth keeping: collapsing the
    // reconciliation ref out of the head-path derivation makes this load return
    // `Err(InvalidStateChirho)` rather than `Ok(None)` — because the identity is ALSO inside the
    // held-signed checkpoint and is re-checked on load. So the coordinate is defended TWICE, and
    // the path derivation alone is not the guarantee. Both outcomes are a correct refusal to serve
    // one coordinate's transfer at another; only `Ok(Some(..))` is the defect.
    match foreign_store_chirho.load_active_chirho() {
        Ok(None) => {}
        Ok(Some(found_chirho)) => panic!(
            "a transfer completed at one reconciliation coordinate must not appear at another — \
             this is the defect this control exists for: completion would be a fact about the ROOT \
             rather than about this reconciliation. Found checkpoint {} in phase {:?}",
            found_chirho.checkpoint_ref_chirho, found_chirho.checkpoint_chirho.phase_chirho
        ),
        Err(refusal_chirho) => panic!(
            "the foreign coordinate refused rather than finding nothing: {refusal_chirho:?}. That \
             is still a refusal to cross coordinates, but it means the two identities now resolve \
             to the SAME head path and the checkpoint's own identity check is what saved it. Read \
             `gd7_held_view_transfer_head_path_chirho` — the reconciliation ref feeds THREE path \
             segments (two shards and the leaf), and losing any of them narrows this control."
        ),
    }

    // Evidence transfer is READ-ONLY on the held journal. The whole family exists to move winner
    // evidence to the held node; if it appended anything, adoption would be building on a moved
    // world rather than on the losing one it is reconciling.
    assert_eq!(
        std::fs::read(
            world_chirho
                .canonical_root_chirho
                .join(&world_chirho.ledger_config_chirho.storage_namespace_chirho)
                .join(&world_chirho.ledger_config_chirho.journal_path_chirho)
        )
        .unwrap(),
        world_chirho.unchanged_journal_bytes_chirho,
        "completing a held-view transfer may not append to the losing journal"
    );

    // ================= RUNG 4: FAMILY 2, THE WINNER HANDOFF =================
    //
    // This is deliberately the SAME test rather than a new one. Family 2's inputs ARE family 1's
    // outputs — the completed held checkpoint, its ref, its bundle root digest and its challenge —
    // so driving them in sequence is the dependency made executable. Splitting them would mean
    // either re-driving family 1 in a second test (duplication) or handing family 2 a fixture-built
    // "completed" transfer, which is the forgery shape this ladder exists to avoid.
    //
    // The owner is `ResidentGd7WinnerHandoffHandleChirho::begin_chirho`, reached from the winner's
    // own resident actor. It performs the whole preparing step INSIDE the actor —
    // verify_complete_held_checkpoint -> verify_and_retain_plan_sealed_checkpoint ->
    // commit_preparing -> commit_accepted — so the barrier is minted by the winner's authority and
    // never by this test.
    //
    // The reconciliation checkpoint is LOADED, not carried: `verify_and_retain_plan_sealed_checkpoint`
    // re-checks it against the transfer identity field by field, so handing it the object this test
    // happened to be holding would prove less than handing it the object that is durably on disk.
    let active_reconciliation_chirho =
        load_authenticated_active_gd7_reconciliation_for_group_chirho(
            &held_storage_chirho,
            &held_signer_chirho,
            &world_chirho.group_digest_chirho,
        )
        .expect("the held root's active reconciliation head re-verifies on load")
        .expect("the sealed plan left an active reconciliation for this group");
    assert_eq!(
        active_reconciliation_chirho.checkpoint_ref_chirho, reconciliation_checkpoint_ref_chirho,
        "the loaded reconciliation must be the exact sealed coordinate the transfer is bound to"
    );

    let completed_inspection_chirho = active_chirho
        .checkpoint_chirho
        .inspection_chirho
        .as_ref()
        .expect("a Complete held-view transfer carries the winner inspection it verified");
    let expected_bundle_root_object_digest_chirho = completed_inspection_chirho
        .bundle_root_object_digest_chirho
        .clone();
    let completed_challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
        active_chirho
            .checkpoint_chirho
            .canonical_challenge_chirho
            .as_deref()
            .expect("a Complete held-view transfer carries its canonical challenge")
            .as_bytes(),
    )
    .expect("the completed transfer's challenge parses back canonically");

    let winner_handoff_chirho = winner_actor_chirho
        .gd7_winner_handoff_handle_chirho()
        .expect("derive the winner's own handoff facade from its resident actor");
    let handoff_status_chirho = winner_handoff_chirho
        .begin_chirho(
            store_chirho.identity_chirho().clone(),
            Box::new(active_reconciliation_chirho.checkpoint_chirho.clone()),
            active_chirho.checkpoint_ref_chirho.clone(),
            Box::new(active_chirho.checkpoint_chirho.clone()),
            expected_bundle_root_object_digest_chirho.clone(),
            completed_challenge_chirho,
        )
        .expect("the winner accepts the handoff its own verification admitted");
    assert_eq!(
        handoff_status_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::AcceptedChirho,
        "begin drives preparing THROUGH to accepted inside the actor; a Preparing here means the \
         accept half did not run and the append barrier is not really established"
    );
    assert!(
        !handoff_status_chirho.attempt_digest_chirho.is_empty(),
        "the accepted handoff must mint the attempt digest — it is the fourth field of the \
         evidence-transfer identity that family 3 is built on"
    );
    // The attempt is bound to THIS transfer, not merely to some transfer: the barrier's identity
    // must name the exact held checkpoint and bundle root that family 1 committed.
    assert_eq!(
        handoff_status_chirho
            .attempt_identity_chirho
            .held_transfer_checkpoint_ref_chirho,
        active_chirho.checkpoint_ref_chirho,
        "the accepted barrier must name the exact completed held checkpoint"
    );
    assert_eq!(
        handoff_status_chirho
            .attempt_identity_chirho
            .expected_bundle_root_object_digest_chirho,
        expected_bundle_root_object_digest_chirho,
        "the accepted barrier must name the exact bundle root the held side received"
    );
    assert_eq!(
        handoff_status_chirho
            .attempt_identity_chirho
            .held_transfer_identity_chirho,
        *store_chirho.identity_chirho(),
        "the accepted barrier must carry the same transfer identity, not a re-derived one"
    );

    // IDEMPOTENCE: the barrier is an append fence, so a retry of the same attempt must return the
    // SAME accepted attempt rather than minting a second one. A handoff that re-minted on retry
    // would let two barriers exist for one reconciliation.
    //
    // MEASURED SCOPE, because the mutation that established it was not the one I first aimed:
    // disabling the STORE's same-digest reuse branch in `commit_preparing_chirho` leaves this arm
    // GREEN. The actor short-circuits first — on an already-`AcceptedChirho` attempt it calls
    // `restore_handoff_chirho` and returns the existing status without ever reaching
    // `commit_preparing_chirho`. So what this arm pins is the ACTOR's accepted-replay path
    // (mutation-proven: breaking that short-circuit turns this arm red). The store's own reuse
    // branch is a SECOND, independent defence on the same property and is NOT covered here —
    // pinning it needs a test that drives the store directly, which the host crate's own
    // `winner_handoff_tests_chirho` is the right home for.
    let replayed_status_chirho = winner_handoff_chirho
        .begin_chirho(
            store_chirho.identity_chirho().clone(),
            Box::new(active_reconciliation_chirho.checkpoint_chirho.clone()),
            active_chirho.checkpoint_ref_chirho.clone(),
            Box::new(active_chirho.checkpoint_chirho.clone()),
            expected_bundle_root_object_digest_chirho.clone(),
            parse_canonical_gd7_winner_current_view_challenge_chirho(
                active_chirho
                    .checkpoint_chirho
                    .canonical_challenge_chirho
                    .as_deref()
                    .expect("the challenge is still there on replay")
                    .as_bytes(),
            )
            .expect("the challenge re-parses on replay"),
        )
        .expect("replaying the identical accepted handoff must not refuse");
    assert_eq!(
        replayed_status_chirho.attempt_digest_chirho, handoff_status_chirho.attempt_digest_chirho,
        "a replayed handoff must return the SAME attempt digest; a new digest would mean two \
         append barriers exist for one reconciliation"
    );
    assert_eq!(
        replayed_status_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::AcceptedChirho
    );

    // The handoff is winner-side state. It must not have moved the held journal either.
    assert_eq!(
        std::fs::read(
            world_chirho
                .canonical_root_chirho
                .join(&world_chirho.ledger_config_chirho.storage_namespace_chirho)
                .join(&world_chirho.ledger_config_chirho.journal_path_chirho)
        )
        .unwrap(),
        world_chirho.unchanged_journal_bytes_chirho,
        "accepting a winner handoff may not append to the losing journal"
    );

    // ============ RUNG 5: FAMILY 3, THE ADOPTION-INPUT EVIDENCE TRANSFER ============
    //
    // Same order as the production driver (`cairn-ledger-geo-node-chirho`'s
    // `held_evidence_transfer_chirho`): the winner stages BOTH evidence families behind its
    // accepted barrier, publishes one signed manifest, and the held side begins from that manifest
    // and receives recipient-bound immutable pages until Complete. The HTTP hop is replaced by an
    // in-process call to the winner's own handle; every owner is the production owner.
    //
    // The winner's surface is gated on the barrier family 2 just minted:
    // `require_accepted_attempt_digest_chirho` refuses `AcceptedBarrierMissingChirho` without it,
    // and `prepare_chirho` re-derives the transfer identity from its OWN accepted checkpoint. So
    // the manifest's identity is not something this test supplies — it is something the winner
    // computes and this test CHECKS, which is why the equality assertion below is a proof rather
    // than a tautology.
    let adoption_evidence_chirho = winner_actor_chirho
        .gd7_winner_adoption_evidence_handle_chirho()
        .expect("derive the winner's accepted-barrier-bound adoption-evidence facade");

    // THE WALL THIS RUNG HIT, AND WHY THE RECORD STAYS. When this rung was first built, the
    // winner could not prepare at all: `prepare_chirho` obtained the held-signed sealed plan
    // through a fixed group-HEAD read on the WINNER's own storage, and on a genuine second root
    // that head does not exist. It refused before any staging happened, and the whole
    // adoption-evidence surface was unreachable. That was measured three ways — one call site for
    // `load_accepted_plan_chirho`; every group-head write belonging to the held store on the held
    // root; and a success path that had never executed anywhere, its only unit test a negative
    // control and the host recipe hand-building the manifest with a test winner signer.
    //
    // The fix landed in the same branch: the plan now resolves BY THE ACCEPTED BARRIER'S OWN
    // checkpoint ref through the content-addressed loader documented valid after the head advances,
    // with no head fallback under any refusal. The paragraph is kept rather than deleted for the
    // same reason the intent-evidence one in this module's header is kept: the ladder reaching a
    // step production had not built is what it is FOR, and a reader who sees only the green cannot
    // learn it.
    //
    // MIGRATION PATH: if this rung starts refusing `StoreChirho(MissingCheckpointChirho)` again,
    // the plan resolution regressed to a head read — look at `load_accepted_plan_chirho`, not here.
    // `AcceptedBarrierMissingChirho` means family 2 regressed instead; read rung 4 first.
    // ARM 4 — THE RETAINED PLAN OBJECT IS AUTHENTICATED ON EVERY READ, not trusted because the
    // barrier names it. This runs HERE, before the first successful preparation, and the placement
    // is load-bearing: `prepare_chirho` memoises its manifest in actor-local state once it reaches
    // Ready, so the same call afterwards short-circuits without touching storage and any
    // perturbation arm run later would be green regardless of what is on disk. A refusal caches
    // nothing, so tamper-then-restore-then-prepare is the one ordering that measures the read.
    let winner_storage_for_tamper_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&world_chirho.winner_source_root_chirho)
            .expect("the winner root's own storage opens");
    let plan_object_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&reconciliation_checkpoint_ref_chirho)
            .expect("derive the retained plan object path");
    let retained_plan_bytes_chirho = winner_storage_for_tamper_chirho
        .read_all_chirho(&plan_object_path_chirho)
        .expect("read the retained plan object")
        .expect(
            "the winner must hold the plan object its own accepted barrier names — if this is \
             None, `verify_and_retain_plan_sealed_checkpoint_chirho` stopped retaining it at accept \
             time and the barrier-ref resolution has no object to find",
        );
    let mut tampered_plan_bytes_chirho = retained_plan_bytes_chirho.clone();
    let tamper_index_chirho = tampered_plan_bytes_chirho
        .iter()
        .position(|byte_chirho| *byte_chirho != b' ')
        .expect("the retained plan object has mutable bytes");
    tampered_plan_bytes_chirho[tamper_index_chirho] ^= 1;
    assert_ne!(tampered_plan_bytes_chirho, retained_plan_bytes_chirho);
    winner_storage_for_tamper_chirho
        .atomic_write_chirho(&plan_object_path_chirho, &tampered_plan_bytes_chirho)
        .expect("plant the tampered plan object");
    let tampered_refusal_chirho = adoption_evidence_chirho
        .prepare_next_chirho()
        .expect_err("a tampered retained plan object must refuse the adoption preparation");
    // ASSERTED BY EXACT VARIANT, and the first version of this arm was NOT — it matched the STORE
    // family, and a mutation proved that too weak. Deleting the content-address check from
    // `load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho` left the family version
    // GREEN, because a second defence caught the tampered bytes and produced a different store
    // refusal the family match still accepted. Naming the variant makes that mutation red.
    //
    // WHICH second defence, measured rather than assumed: re-running the mutation against THIS
    // version fails with `PlanCheckpointChirho(MalformedCheckpointChirho)` — the tampered byte
    // breaks JSON parsing, so the object never reaches the signature check at all. I had written
    // "the signature check one line later" here from reading; the mutation's own output says
    // otherwise, and the corrected version is the one a later reader inherits.
    //
    // MIGRATION PATH: if this starts arriving as any other `PlanCheckpointChirho(..)` — a signature
    // or shape refusal — the check ORDER changed and the content-address check no longer runs
    // first. That is worth knowing deliberately rather than absorbing silently, so retarget this
    // arm on purpose instead of widening it back to the family.
    assert!(
        matches!(
            &tampered_refusal_chirho,
            ResidentGd7WinnerAdoptionEvidenceRefusalChirho::StoreChirho(
                Gd7WinnerHandoffStoreRefusalChirho::PlanCheckpointChirho(
                    Gd7ReconciliationStoreRefusalChirho::CheckpointReferenceMismatchChirho
                )
            )
        ),
        "the tamper must refuse at the CONTENT ADDRESS specifically. AcceptedBarrierMissing would \
         mean the barrier stopped restoring and this arm never reached the plan read at all; \
         MailboxFull/ActorUnavailable would mean the actor died; any other PlanCheckpoint refusal \
         means a different defence fired first and this arm is no longer measuring the one it \
         names. Got: {tampered_refusal_chirho:?}"
    );
    winner_storage_for_tamper_chirho
        .atomic_write_chirho(&plan_object_path_chirho, &retained_plan_bytes_chirho)
        .expect("restore the retained plan object");
    assert_eq!(
        winner_storage_for_tamper_chirho
            .read_all_chirho(&plan_object_path_chirho)
            .expect("re-read the restored plan object")
            .expect("the restored plan object is present"),
        retained_plan_bytes_chirho,
        "the tamper arm must restore the plan object byte-for-byte"
    );

    // ARM 5, AND AN HONEST CORRECTION TO ITS PRE-REGISTERED FORM. The arm asked for a planted head
    // naming a DIFFERENT valid checkpoint, so a surviving fallback would visibly resolve the head's
    // object instead of the barrier's. That is NOT CONSTRUCTIBLE HERE, for a structural reason
    // rather than a gap in effort: in this world the head and the barrier name the SAME sealed
    // plan, and every held-signed head is bound to its own `active_checkpoint_ref`, so producing
    // one naming a different checkpoint would mean signing a head this test has no business
    // authoring. Deleting the barrier's object deletes the head's too, so absence cannot
    // discriminate between the paths either.
    //
    // The property is carried instead by CONSTRUCTION plus CENSUS, which is stronger than the arm
    // asked for: `load_accepted_plan_chirho` contains no head-loader call at all, so the fallback
    // branch is unrepresentable rather than merely unreachable, and the source census in
    // `cairn-source-scan-chirho` fails if one ever returns. Recorded at the arm rather than only in
    // a report, because the next reader meets the arm list first and would otherwise count arm 5
    // as silently dropped.

    let mut prepared_manifest_chirho: Option<Gd7WinnerEvidenceManifestChirho> = None;
    let mut history_stage_steps_chirho = 0_u32;
    for _step_chirho in 0..16 {
        match adoption_evidence_chirho
            .prepare_next_chirho()
            .expect("the winner prepares one bounded adoption-evidence step behind its barrier")
        {
            ResidentGd7WinnerAdoptionEvidenceInspectionChirho::AdvancedWinnerHistoryPageChirho => {
                history_stage_steps_chirho += 1;
            }
            ResidentGd7WinnerAdoptionEvidenceInspectionChirho::ReadyChirho(manifest_chirho) => {
                prepared_manifest_chirho = Some(*manifest_chirho);
                break;
            }
        }
    }
    let manifest_chirho = prepared_manifest_chirho.expect(
        "the bounded preparation loop must reach a Ready manifest, not run out of iterations. A \
         run of AdvancedWinnerHistoryPage to the ceiling means the winner history grew past it — \
         add pages deliberately, do NOT raise the ceiling blindly",
    );
    assert!(
        history_stage_steps_chirho < 16,
        "the preparation loop must not have consumed its whole ceiling reaching Ready"
    );

    // The identity the held side binds, derived exactly as the production driver derives it, and
    // it must equal what the winner INDEPENDENTLY computed from its own accepted checkpoint. This
    // is the driver's own `bail!("winner adoption-evidence manifest differs from the accepted held
    // coordinate")`, and it is a proof rather than a tautology precisely because the test does not
    // supply the winner's copy — `prepare_chirho` re-derives it from the barrier.
    let expected_evidence_identity_chirho = Gd7HeldEvidenceTransferIdentityChirho {
        reconciliation_identity_chirho: active_reconciliation_chirho
            .checkpoint_chirho
            .identity_chirho
            .clone(),
        reconciliation_checkpoint_ref_chirho: reconciliation_checkpoint_ref_chirho.clone(),
        held_view_transfer_checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho.clone(),
        winner_handoff_attempt_digest_chirho: handoff_status_chirho.attempt_digest_chirho.clone(),
    };
    assert_eq!(
        manifest_chirho.transfer_identity_chirho, expected_evidence_identity_chirho,
        "the winner's manifest must name the exact accepted coordinate the held side derived — \
         the fourth field is family 2's attempt digest, which is why family 3 cannot precede it"
    );

    // The held side verifies winner LEDGER records with the config-pinned journal verifier root,
    // which is a DIFFERENT trust root from the winner control key that signs the manifest. Built
    // through the same constructor the geo driver uses, so the roles stay separated here too.
    let winner_ledger_verifier_chirho = configured_held_gd7_journal_verifier_chirho(
        &world_chirho.ledger_config_chirho,
        &world_chirho.winner_node_chirho.0,
    )
    .expect("the held config's journal verifier root is distinct from the winner control key");
    let evidence_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
        &held_storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        &winner_ledger_verifier_chirho,
        expected_evidence_identity_chirho.clone(),
    )
    .expect("the held adoption-evidence store opens on the exact accepted coordinate");

    let mut active_evidence_chirho = evidence_store_chirho
        .begin_chirho(&manifest_chirho)
        .expect("the held side admits the winner-signed manifest and retains its roots");
    assert_eq!(
        active_evidence_chirho.checkpoint_chirho.phase_chirho,
        Gd7HeldEvidenceTransferPhaseChirho::ReceivingChirho,
        "a manifest whose roots verified leaves the transfer waiting on its first page"
    );

    let mut evidence_wrong_requester_control_chirho = None;
    for _step_chirho in 0..64 {
        if active_evidence_chirho.checkpoint_chirho.phase_chirho
            == Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho
        {
            break;
        }
        let grant_chirho = active_evidence_chirho
            .checkpoint_chirho
            .next_grant_chirho()
            .cloned()
            .expect("a Receiving evidence checkpoint names the grant it is waiting on");
        // NEGATIVE CONTROL, taken once and on the real grant: adoption-evidence pages are
        // recipient-bound too. Run BEFORE the honest fetch so a refusal cannot be an artifact of
        // the page already having been delivered.
        if evidence_wrong_requester_control_chirho.is_none() {
            evidence_wrong_requester_control_chirho = Some(
                adoption_evidence_chirho
                    .fetch_page_chirho(
                        world_chirho.winner_node_chirho.clone(),
                        grant_chirho.clone(),
                    )
                    .expect_err(
                        "an adoption-evidence grant minted for the held node must not be \
                         fetchable by another requester",
                    ),
            );
        }
        let transfer_chirho = adoption_evidence_chirho
            .fetch_page_chirho(world_chirho.held_node_chirho.clone(), grant_chirho)
            .expect("the winner serves exactly the granted evidence page to its named recipient");
        active_evidence_chirho = evidence_store_chirho
            .receive_page_chirho(
                &active_evidence_chirho.checkpoint_ref_chirho,
                &transfer_chirho,
            )
            .expect("verify and retain one held-local winner adoption-evidence page");
    }

    assert_eq!(
        active_evidence_chirho.checkpoint_chirho.phase_chirho,
        Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho,
        "the bounded receive loop must reach a durable Complete, not run out of iterations"
    );
    // BOTH families must have moved. A Complete carrying zero pages of either family would satisfy
    // the phase assertion while having transferred half — or none — of the adoption inputs.
    assert!(
        active_evidence_chirho
            .checkpoint_chirho
            .received_winner_history_pages_chirho
            > 0
            && active_evidence_chirho
                .checkpoint_chirho
                .received_fork_baseline_pages_chirho
                > 0,
        "a Complete adoption-evidence transfer must have received pages of BOTH families; \
         history={} baseline={}",
        active_evidence_chirho
            .checkpoint_chirho
            .received_winner_history_pages_chirho,
        active_evidence_chirho
            .checkpoint_chirho
            .received_fork_baseline_pages_chirho
    );
    assert!(
        matches!(
            evidence_wrong_requester_control_chirho,
            Some(ResidentGd7WinnerAdoptionEvidenceRefusalChirho::StoreChirho(
                _
            ))
        ),
        "the adoption-evidence recipient-binding control must refuse as a STORE refusal — the \
         winner evaluated the grant against its manifest. `None` means the control never ran; \
         `MailboxFull`/`ActorUnavailable`/`AcceptedBarrierMissing`/`InvalidRequest` all mean the \
         winner never reached the grant check, so the arm would be green for a reason that has \
         nothing to do with recipient binding. Got: \
         {evidence_wrong_requester_control_chirho:?}"
    );

    // Durability again: a second store on the same coordinate must load the same Complete.
    let reopened_evidence_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
        &held_storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        &winner_ledger_verifier_chirho,
        expected_evidence_identity_chirho.clone(),
    )
    .expect("the same adoption-evidence coordinate reopens");
    assert_eq!(
        reopened_evidence_store_chirho
            .load_active_chirho()
            .expect("the persisted evidence head re-verifies on load")
            .expect("a completed evidence transfer survives its store being dropped")
            .checkpoint_ref_chirho,
        active_evidence_chirho.checkpoint_ref_chirho,
        "the durable evidence head must name the exact checkpoint this run committed"
    );

    // NEGATIVE CONTROL: the evidence is bound to family 2's ATTEMPT DIGEST, not merely to the
    // reconciliation. A store at a different attempt digest must find nothing — otherwise
    // "the adoption inputs are present" would be a fact about the reconciliation rather than about
    // this accepted barrier, and a superseded attempt could supply another attempt's inputs.
    let mut foreign_attempt_identity_chirho = expected_evidence_identity_chirho.clone();
    foreign_attempt_identity_chirho.winner_handoff_attempt_digest_chirho =
        world_chirho.losing_journal_genesis_digest_chirho.clone();
    assert_ne!(
        foreign_attempt_identity_chirho.winner_handoff_attempt_digest_chirho,
        expected_evidence_identity_chirho.winner_handoff_attempt_digest_chirho,
        "the control's attempt digest must actually differ from the one that was driven"
    );
    let foreign_attempt_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
        &held_storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        &winner_ledger_verifier_chirho,
        foreign_attempt_identity_chirho,
    )
    .expect("a different attempt digest is a legitimate coordinate to open");
    match foreign_attempt_store_chirho.load_active_chirho() {
        Ok(None) => {}
        Ok(Some(found_chirho)) => panic!(
            "one accepted barrier's adoption evidence must not appear under another attempt \
             digest — found {} in phase {:?}",
            found_chirho.checkpoint_ref_chirho, found_chirho.checkpoint_chirho.phase_chirho
        ),
        Err(refusal_chirho) => panic!(
            "the foreign attempt digest refused rather than finding nothing: {refusal_chirho:?}. \
             That is still a refusal to cross barriers, but it means the two identities resolve to \
             the SAME head path and the checkpoint's own identity check is what saved it — read \
             `gd7_held_evidence_transfer_head_path_chirho` before narrowing this control."
        ),
    }

    // Still read-only on the losing journal: the whole point of moving winner evidence to the held
    // node is to prepare adoption WITHOUT having moved the world being reconciled.
    assert_eq!(
        std::fs::read(
            world_chirho
                .canonical_root_chirho
                .join(&world_chirho.ledger_config_chirho.storage_namespace_chirho)
                .join(&world_chirho.ledger_config_chirho.journal_path_chirho)
        )
        .unwrap(),
        world_chirho.unchanged_journal_bytes_chirho,
        "completing an adoption-evidence transfer may not append to the losing journal"
    );

    // ============ RUNG 6: ADOPTION THROUGH THE REAL HELD MAILBOX ============
    //
    // The last two of the five held-coordinator mailbox commands, and the first time anything has
    // driven them. `prepare_adoption_materialization_chirho` does NOT trust its request: it
    // re-opens the evidence store from the request's identity, re-loads the durable checkpoint,
    // and requires BOTH the exact ref and `CompleteChirho`. That is why the three families had to
    // reach durable Complete through real owners — a fixture-built "completed" evidence checkpoint
    // would be re-read and re-verified here, not taken on trust.
    let mut adopting_coordinator_chirho = open_resident_gd7_held_coordinator_chirho(
        &world_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &world_chirho.ledger_config_chirho,
        Arc::clone(&world_chirho.nodes_chirho[2]),
    )
    .expect("the held coordinator reopens on the sealed, evidence-complete coordinate");

    // NEGATIVE CONTROL, before the honest prepare: a request naming an evidence checkpoint ref
    // that is not the durable head must refuse. Without it, "prepare succeeded" is equally
    // consistent with a coordinator that ignores the expected ref entirely.
    let stale_evidence_refusal_chirho = adopting_coordinator_chirho
        .prepare_adoption_materialization_chirho(
            ResidentGd7HeldAdoptionMaterializationRequestChirho {
                transfer_identity_chirho: expected_evidence_identity_chirho.clone(),
                expected_evidence_checkpoint_ref_chirho: world_chirho
                    .losing_journal_genesis_digest_chirho
                    .clone(),
            },
        )
        .expect_err("a request naming a non-head evidence checkpoint must refuse");
    assert!(
        format!("{stale_evidence_refusal_chirho:?}").contains("StaleEvidence"),
        "the stale-evidence control must refuse for STALENESS specifically. Any other refusal \
         means the request failed before the coordinator compared the expected ref, so the arm \
         would be green without proving the comparison happens. Got: {stale_evidence_refusal_chirho:?}"
    );

    let prepared_chirho = adopting_coordinator_chirho
        .prepare_adoption_materialization_chirho(
            ResidentGd7HeldAdoptionMaterializationRequestChirho {
                transfer_identity_chirho: expected_evidence_identity_chirho.clone(),
                expected_evidence_checkpoint_ref_chirho: active_evidence_chirho
                    .checkpoint_ref_chirho
                    .clone(),
            },
        )
        .expect("the coordinator materializes immutable adoption candidates from real evidence");
    assert_eq!(
        prepared_chirho.evidence_checkpoint_ref_chirho(),
        active_evidence_chirho.checkpoint_ref_chirho,
        "the prepared adoption must bind the exact evidence checkpoint family 3 committed"
    );
    assert_eq!(
        prepared_chirho.plan_checkpoint_ref_chirho(),
        reconciliation_checkpoint_ref_chirho,
        "the prepared adoption must bind the exact sealed plan the transfer chain started from"
    );

    let commit_outcome_chirho = adopting_coordinator_chirho
        .commit_adoption_chirho(prepared_chirho.clone())
        .expect("the coordinator commits the exact prepared adoption selector");
    let ResidentGd7HeldAdoptionCommitOutcomeChirho::CommittedChirho(adopted_chirho) =
        commit_outcome_chirho
    else {
        panic!(
            "the FIRST commit of a freshly prepared adoption must be Committed. An \
             AlreadyAdoptedExact here would mean this world had adopted before this run, which \
             would make every assertion below a statement about a previous run: \
             {commit_outcome_chirho:?}"
        );
    };
    assert_eq!(
        adopted_chirho.plan_checkpoint_ref_chirho(),
        reconciliation_checkpoint_ref_chirho,
        "the adopted head must name the sealed plan it adopted"
    );

    // IDEMPOTENCE: re-committing the identical selector must fully reverify and report the exact
    // prior adoption rather than adopting twice.
    let replayed_commit_chirho = adopting_coordinator_chirho
        .commit_adoption_chirho(prepared_chirho)
        .expect("an exact retry reverifies the immutable candidate pair");
    let ResidentGd7HeldAdoptionCommitOutcomeChirho::AlreadyAdoptedExactChirho(
        replayed_adopted_chirho,
    ) = replayed_commit_chirho
    else {
        panic!(
            "an exact adoption retry must report AlreadyAdoptedExact. A second Committed would \
             mean the head moved twice for one selector: {replayed_commit_chirho:?}"
        );
    };
    assert_eq!(
        replayed_adopted_chirho, adopted_chirho,
        "the retry must report the byte-identical adopted snapshot, not a re-derived one"
    );

    // ADOPTION GRANTS NO WRITE AUTHORITY. The losing journal stays byte-unchanged: adoption
    // installs a read-only branch, it does not reopen the deposed node's write path.
    assert_eq!(
        std::fs::read(
            world_chirho
                .canonical_root_chirho
                .join(&world_chirho.ledger_config_chirho.storage_namespace_chirho)
                .join(&world_chirho.ledger_config_chirho.journal_path_chirho)
        )
        .unwrap(),
        world_chirho.unchanged_journal_bytes_chirho,
        "committing an adoption may not append to or adopt the losing journal in place"
    );
    assert!(
        !world_chirho.nodes_chirho[2]
            .leadership_chirho(&world_chirho.group_chirho)
            .is_leader_chirho,
        "the deposed held node must still be non-leader after adopting"
    );

    adopting_coordinator_chirho.close_chirho().unwrap();

    AdoptedLadderStateChirho {
        canonical_root_chirho: world_chirho.canonical_root_chirho.clone(),
        winner_source_root_chirho: world_chirho.winner_source_root_chirho.clone(),
        group_digest_chirho: world_chirho.group_digest_chirho.clone(),
        held_node_chirho: world_chirho.held_node_chirho.clone(),
        winner_node_chirho: world_chirho.winner_node_chirho.clone(),
        ledger_config_chirho: world_chirho.ledger_config_chirho.clone(),
        held_elector_chirho: Arc::clone(&world_chirho.nodes_chirho[2]),
        sealed_plan_ref_chirho: sealed_chirho.sealed_plan_ref_chirho.clone(),
        adopted_checkpoint_ref_chirho: adopted_chirho.checkpoint_ref_chirho().to_owned(),
        effect_obligation_count_chirho: sealed_chirho.effect_obligation_count_chirho,
    }
}
