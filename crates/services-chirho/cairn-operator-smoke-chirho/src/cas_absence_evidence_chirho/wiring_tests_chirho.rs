// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pins that the two SHIPPED absence claims are still ANSWERED by the helper, not by a bare `is_err()`.
//!
//! The helper's own arms (`../cas_absence_evidence_chirho/tests_chirho.rs`) prove the helper. They
//! say nothing about the two booleans that actually reach an operator's report, because a caller can
//! stop calling the helper and re-inline `cas_chirho::get_chirho(..).is_err()` without turning
//! anything red — an independent reviewer restored exactly that defect at both call sites and
//! measured this crate unchanged at 39 passed / 0 failed.
//!
//! So these arms drive the SHIPPED entry points and plant a present-but-unreadable object at the
//! address each one claims is absent. Correct wiring refuses. The `is_err()` shape reports ABSENT and
//! ships the sentence, so a re-inline turns these red.
//!
//! Both arms run their unplanted control FIRST. Without it, a refusal proves nothing: an arm whose
//! subject was already broken would refuse just as loudly, and the plant would be doing no work.

use cairn_chirho::cas_chirho;
use cairn_chirho::model_chirho::HashChirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::agent_authored_backend_smoke_chirho::{
    default_agent_authored_backend_brief_path_chirho,
    default_agent_authored_backend_manifest_path_chirho,
    default_agent_authored_backend_overcap_manifest_path_chirho,
    default_agent_authored_backend_undeclared_effect_manifest_path_chirho,
    run_agent_authored_backend_smoke_chirho,
};
use crate::contact_example_smoke_chirho::{
    contact_example_smoke_runtime_root_chirho, default_contact_example_manifest_path_chirho,
    run_contact_example_smoke_chirho,
};

/// The pre-policy body the agent-authored smoke posts, copied from its own `let` binding because the
/// shipped report exposes no address for it. The copy CANNOT drift silently: if the shipped bytes
/// change, the plant below lands at an unrelated address, the shipped surface finds its own body
/// genuinely absent, the run SUCCEEDS, and the arm dies on its `expect_err` rather than passing.
const AGENT_PRE_POLICY_BODY_CHIRHO: &[u8] = b"build safely";

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-{label_chirho}-{nanos_chirho}-{n_chirho}"))
}

/// Spelled out here rather than borrowed from a production path builder ON PURPOSE: an instrument
/// that shares code with its subject shares its blind spots, and this one exists to disagree with the
/// subject.
fn object_path_chirho(root_chirho: &Path, address_chirho: &HashChirho) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&address_chirho.0[0..2])
        .join(&address_chirho.0[2..])
}

/// Puts a PRESENT-BUT-UNREADABLE object at `address_chirho`, and proves it before returning.
///
/// A directory at the object path yields EISDIR. Mode 000 would not do: a test runner with privilege
/// ignores file modes, so a mode-000 fixture can silently become a readable one and take the arm's
/// meaning with it. Two things are asserted here, not one — that the plant LANDED, and that the plant
/// genuinely produces the outcome under test rather than merely differing from an absent path.
fn plant_unreadable_object_chirho(root_chirho: &Path, address_chirho: &HashChirho) {
    let planted_chirho = object_path_chirho(root_chirho, address_chirho);
    std::fs::create_dir_all(&planted_chirho).unwrap();
    assert!(
        planted_chirho.is_dir(),
        "the directory plant did not land at {}, so anything the arm below concludes is about an \
         ABSENT object rather than an unreadable one",
        planted_chirho.display()
    );
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(root_chirho, address_chirho),
            cas_chirho::CasReadOutcomeChirho::UnreadableChirho(_)
        ),
        "the plant did not make {} UNREADABLE, so this fixture does not violate the property under \
         test and the arm below would pass over some other outcome",
        address_chirho.0
    );
}

/// Asserts a refusal is THE unreadable refusal, by identity and not merely by failing.
///
/// Under the defect the shipped run does not fail at all, so a bare "it errored" would still be a
/// real signal — but only barely. Naming the surface and the address is what separates "the absence
/// claim refused" from "this smoke broke somewhere else today", and excluding the tamper wording is
/// what separates a refusal from a MISCLASSIFIED one.
fn assert_unreadable_refusal_identity_chirho(
    error_chirho: &anyhow::Error,
    surface_chirho: &str,
    address_chirho: &HashChirho,
) {
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("could not be read"),
        "the {surface_chirho} absence claim did not refuse: it answered an UNREADABLE object and \
         the run carried on, so whatever failed here failed LATER and for another reason. That is \
         the false negative, arriving as a downstream error instead of a clean one. Got: \
         {text_chirho}"
    );
    assert!(
        text_chirho.contains(surface_chirho),
        "the refusal must come from the {surface_chirho} absence claim rather than from some other \
         step of the same smoke, got: {text_chirho}"
    );
    assert!(
        text_chirho.contains(&address_chirho.0),
        "the refusal must name the object that was planted, which is what proves the shipped code \
         read the address this arm planted at, got: {text_chirho}"
    );
    // NEGATIVE IDENTITY: an unreadable object answered with the tamper wording would mean the outcome
    // is being misclassified, which is a different defect wearing this arm's green.
    assert!(
        !text_chirho.contains("tampered bytes"),
        "the unreadable object was misclassified as tamper, got: {text_chirho}"
    );
}

/// WIRING, agent-authored backend: `agent_authored_backend_smoke_chirho.rs:469` is the absence claim
/// that becomes `missing_policy_raw_body_absent_from_cas_chirho` in a shipped operator report.
///
/// MIGRATION PATH, with the shapes MEASURED rather than guessed — restoring the defect at this call
/// site was run, and this arm failed on its first identity assertion reading
/// `agent-authored backend did not serve the reviewed pure transform`. That is the tell: the absence
/// claim answered ABSENT over the plant, the run continued, and the planted object tripped something
/// downstream instead. A red naming any error that is not the unreadable refusal means the same
/// thing. If instead it goes red on the CONTROL, the smoke itself broke and this arm is a bystander.
/// If it goes red on `expect_err` with a successful run, the shipped body bytes moved and
/// `AGENT_PRE_POLICY_BODY_CHIRHO` above must move with them.
#[test]
fn the_shipped_agent_backend_absence_claim_refuses_an_unreadable_object_chirho() {
    let manifest_chirho = default_agent_authored_backend_manifest_path_chirho();
    let overcap_chirho = default_agent_authored_backend_overcap_manifest_path_chirho();
    let undeclared_chirho = default_agent_authored_backend_undeclared_effect_manifest_path_chirho();
    let brief_chirho = default_agent_authored_backend_brief_path_chirho();

    // POSITIVE CONTROL — the same shipped entry point, same fixture, nothing planted. It must reach
    // the absence claim and answer TRUE, which is what makes the refusal below attributable to the
    // plant rather than to a surface that was already refusing.
    let control_root_chirho = tmp_root_chirho("agent-backend-absence-control");
    let control_report_chirho = run_agent_authored_backend_smoke_chirho(
        &control_root_chirho,
        &manifest_chirho,
        &overcap_chirho,
        &undeclared_chirho,
        &brief_chirho,
    )
    .expect("the unplanted control run must complete, or the planted arm below proves nothing");
    assert!(
        control_report_chirho.missing_policy_raw_body_absent_from_cas_chirho,
        "the control run did not claim the pre-policy body absent, so the planted run cannot show \
         that a plant is what changes the answer"
    );
    let _ = std::fs::remove_dir_all(&control_root_chirho);

    let root_chirho = tmp_root_chirho("agent-backend-absence-wiring");
    let address_chirho = cas_chirho::hash_chirho(AGENT_PRE_POLICY_BODY_CHIRHO);
    plant_unreadable_object_chirho(&root_chirho, &address_chirho);

    let error_chirho = run_agent_authored_backend_smoke_chirho(
        &root_chirho,
        &manifest_chirho,
        &overcap_chirho,
        &undeclared_chirho,
        &brief_chirho,
    )
    .expect_err(
        "the shipped agent-authored smoke answered an UNREADABLE pre-policy body as absent — the \
         is_err() false negative is back at the call site and the report ships the claim",
    );
    assert_unreadable_refusal_identity_chirho(
        &error_chirho,
        "agent-authored backend pre-policy body",
        &address_chirho,
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// WIRING, contact example: `contact_example_smoke_chirho.rs:120` is the absence claim that becomes
/// `private_body_chirho.raw_body_absent_from_cas_chirho` in a shipped operator report and feeds the
/// launch-readiness AND-chain.
///
/// This arm inherits its subject's `#[ignore]`. `run_contact_example_smoke_chirho` builds the wasm32
/// guest before it ever reaches the absence claim, so the shipped contact surface is only exercised
/// under `operator-smoke-tests-chirho` at all; an arm over it has exactly the reach of the thing it
/// pins, and un-gating it would put a wasm32 toolchain requirement into the default gate.
///
/// MIGRATION PATH, MEASURED — restoring the defect at this call site was run, and this arm failed on
/// its `expect_err`: the smoke COMPLETED and printed its report with
/// `raw_body_absent_from_cas_chirho: true` for the very address a directory was sitting on. That red
/// is the false negative reproduced in shipped operator evidence, and it is what feeds the
/// launch-readiness AND-chain. A red on the CONTROL instead means the smoke itself broke.
#[test]
#[cfg_attr(
    not(feature = "operator-smoke-tests-chirho"),
    ignore = "operator smoke: builds wasm32 cargo examples and runs local HTTP contact flow; enable with --features operator-smoke-tests-chirho"
)]
fn the_shipped_contact_absence_claim_refuses_an_unreadable_object_chirho() {
    let manifest_chirho = default_contact_example_manifest_path_chirho();

    // POSITIVE CONTROL, and it does double duty: the shipped report carries the very address the
    // shipped code probed, so the plant below is aimed by the subject rather than by a literal this
    // file copied and could hold stale.
    let control_root_chirho = tmp_root_chirho("contact-absence-control");
    let control_report_chirho =
        run_contact_example_smoke_chirho(&control_root_chirho, &manifest_chirho).expect(
            "the unplanted control run must complete, or the planted arm below proves nothing",
        );
    assert!(
        control_report_chirho
            .private_body_chirho
            .raw_body_absent_from_cas_chirho,
        "the control run did not claim the raw contact body absent, so the planted run cannot show \
         that a plant is what changes the answer"
    );
    let address_chirho = control_report_chirho
        .private_body_chirho
        .request_chirho
        .clone();
    let _ = std::fs::remove_dir_all(&control_root_chirho);

    let root_chirho = tmp_root_chirho("contact-absence-wiring");
    // The claim is made against the tenant runtime root the smoke resolves for itself, not the root
    // handed in. Resolving it here first is idempotent — the smoke resolves the same path again.
    let runtime_root_chirho = contact_example_smoke_runtime_root_chirho(&root_chirho).unwrap();
    plant_unreadable_object_chirho(&runtime_root_chirho, &address_chirho);

    let error_chirho = run_contact_example_smoke_chirho(&root_chirho, &manifest_chirho).expect_err(
        "the shipped contact smoke answered an UNREADABLE raw body as absent — the is_err() false \
         negative is back at the call site and that sentence ships in operator evidence",
    );
    assert_unreadable_refusal_identity_chirho(
        &error_chirho,
        "contact example raw body",
        &address_chirho,
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
