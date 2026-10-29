// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Operator porcelain for the generic ledger-host config author: review a reviewed coordinate
//! document by DERIVING it, then emit the config/plan pair that document authorizes.
//!
//! Brick #6 of the generic ledger-host authoring program
//! (`spec-chirho/workstream-state-chirho/ledger-host-config-authoring-design-chirho.md` §5). It is
//! the brick that makes the program usable by a human, so it is also the first place the program's
//! laws can be quietly weakened by an ergonomic shortcut. The four that matter are stated here.
//!
//! **1. DERIVE BEFORE YOU PRINT — the rule this module exists to obey.**
//! `read_ledger_host_authoring_inputs_money_policy_unchecked_chirho` returns a document with ZERO
//! money-policy validation: a document minting 10,000 against a max supply of 2,000 passes it in
//! full, because that law lives with `validate_plan_policy_chirho` and runs only when a plan is
//! DERIVED. A review verb that printed the parsed document would therefore show an operator a
//! money statement that reads as checked and is not. So neither report builder below can SEE the
//! document: `ledger_host_author_review_report_chirho` takes
//! [`LedgerHostAuthoredArtifactsChirho`] and `ledger_host_author_report_chirho` takes
//! [`LedgerHostEmittedArtifactsChirho`], and both of those exist only downstream of a derivation
//! that ran every plan validator. The rule is a TYPE here rather than a habit, and a source guard
//! (`ledger_host_authoring_cli_guard_tests_chirho`) refuses a signature that reopens it.
//!
//! **2. NEVER MINT.** No flag on either verb accepts key material, and neither verb creates a
//! secret. The two authority arguments are secret NAMES: they select which pre-provisioned secret
//! this operator can reach, and a missing one is a hard refusal with no self-service path. That
//! friction is the intended shape — a config author that can mint is a config author that can
//! silently invent an authority.
//!
//! **3. THE MODE IS LEGIBILITY, NOT THE CONTROL, and this surface must not imply otherwise.**
//! `--mode-chirho` is required with no default, so no invocation drifts into production by
//! omission — but selecting `production` is not what keeps a test-kind issuer out of a production
//! root. CUSTODY is: the emitted pin is DERIVED from a secret that is either on this root or is
//! not, whatever the flag said. The reports below therefore print the mode as a coordinate beside
//! the custody counts, never as a verdict.
//!
//! **4. ONLY UNTRUSTED INPUTS CROSS THIS BOUNDARY — brick #4's question, asked of a CLI.** Every
//! argument is a path, a secret name, a digest to CHECK, a port, or a choice between two branches.
//! Nothing here can carry an already-derived artifacts value, a loaded runtime signer set, or a
//! pre-stamped test-kind marker; the emission road takes the same untrusted set and loads and
//! derives everything else itself. (The signer-set type is described rather than SPELLED: a source
//! guard censuses its name across this module's production text and treats any occurrence as a
//! use, so a doc mention would read to that guard exactly like a new parameter. The custody brick
//! names a crate the same way and for the same reason.)
//!
//! **Two things this module deliberately does NOT print.**
//! - **The derived verifier pins.** They are public halves and not secret, but a report that
//!   republishes them as text is a report an operator can paste into a hand-written config — which
//!   is the exact practice this whole program exists to replace. The emitted config file carries
//!   them, at mode `0600`, and that is where they belong.
//! - **A config digest from the review verb.** The config's bytes are composed with the selected
//!   root and serve port by the emission road, so only emission can produce them; recomputing them
//!   here would give that composition a second home that could drift from the first. Review
//!   reports the plan digest, which the derivation genuinely produces.
//!
//! Both digests this module prints are REVIEW digests. The plan digest is consumed by the later
//! activation-authoring road; the config digest must leave this process through an independent
//! deployment/review channel and is then required by every composed startup before config parsing.

use crate::args_chirho::ops_args_chirho::{
    DestinationAuthorityEnrollmentAuthorArgsChirho, LedgerHostActivationAuthorArgsChirho,
    LedgerHostAuthoringCoordinatesArgsChirho, LedgerHostAuthoringModeArgChirho,
};
use crate::args_chirho::CommandChirho;
use cairn_ledger_regenesis_chirho::{
    author_and_emit_ledger_host_artifacts_chirho, author_destination_authority_enrollment_chirho,
    author_ledger_regenesis_activation_chirho,
    bind_custody_and_derive_ledger_host_artifacts_chirho,
    read_destination_authority_enrollment_chirho,
    read_digest_bound_destination_authority_enrollment_chirho,
    read_digest_bound_ledger_host_authoring_inputs_money_policy_unchecked_chirho,
    read_ledger_host_authoring_inputs_money_policy_unchecked_chirho,
    DestinationAuthorityEnrollmentAuthorRequestChirho, LedgerHostAuthoredArtifactsChirho,
    LedgerHostAuthoringModeChirho, LedgerHostCustodyEvidenceChirho, LedgerHostCustodyRequestChirho,
    LedgerHostEmissionRequestChirho, LedgerHostEmittedArtifactsChirho,
    LedgerRegenesisActivationAuthorRequestChirho,
};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub const LEDGER_HOST_AUTHOR_REVIEW_REPORT_SCHEMA_V1_CHIRHO: &str =
    "ledger-host-author-review-report-v1-chirho";
pub const LEDGER_HOST_AUTHOR_REPORT_SCHEMA_V1_CHIRHO: &str = "ledger-host-author-report-v1-chirho";
pub const DESTINATION_AUTHORITY_ENROLLMENT_AUTHOR_REPORT_SCHEMA_V1_CHIRHO: &str =
    "destination-authority-enrollment-author-report-v1-chirho";
pub const LEDGER_HOST_ACTIVATION_AUTHOR_REPORT_SCHEMA_V1_CHIRHO: &str =
    "ledger-host-activation-author-report-v1-chirho";

/// The mode's stable report spelling. Fixed tokens rather than `Debug`, so a rename of the enum
/// variant cannot silently change an operator-visible evidence field.
const PRODUCTION_MODE_LABEL_CHIRHO: &str = "production-chirho";
const TEST_KIND_MODE_LABEL_CHIRHO: &str = "test-kind-chirho";

/// What one reviewed document authorizes, reported from the DERIVED artifacts and from nothing else.
///
/// Read the money fields as a statement about the derived PLAN: they exist only because
/// `validate_plan_policy_chirho` already accepted them, which is the whole difference between this
/// report and a pretty-printed input file.
#[derive(Debug, Serialize)]
struct LedgerHostAuthorReviewReportV1Chirho {
    schema_chirho: &'static str,
    authoring_mode_chirho: &'static str,
    inputs_digest_chirho: String,
    destination_authority_enrollment_digest_chirho: String,
    cluster_genesis_roster_head_blake3_chirho: String,
    plan_digest_chirho: String,
    /// Derived, never copied from a schema input: v1/v2 for the ordinary path, or v3 when the
    /// digest-bound shared-journal choice was custody-derived.
    config_schema_chirho: String,
    shared_journal_verifier_authored_chirho: bool,
    test_kind_marked_chirho: bool,
    activation_authority_authored_chirho: bool,
    kind_id_chirho: String,
    initial_owner_chirho: String,
    initial_mint_amount_chirho: u64,
    /// The derived policy bodies verbatim, so the mint ceiling an operator wants to check against
    /// the amount above is the one that will be signed. Serialized through the policy type itself
    /// rather than transcribed field by field, because a transcription is a second copy that drifts.
    initial_policy_chirho: serde_json::Value,
    amended_policy_chirho: serde_json::Value,
    member_count_chirho: usize,
    projection_route_count_chirho: usize,
    proven_runtime_signer_count_chirho: u64,
    proven_offline_authority_count_chirho: u64,
    provider_connection_secret_checked_chirho: bool,
}

/// What was written, reported from the EMISSION receipt and from nothing else.
#[derive(Debug, Serialize)]
struct LedgerHostAuthorReportV1Chirho {
    schema_chirho: &'static str,
    authoring_mode_chirho: &'static str,
    inputs_digest_chirho: String,
    destination_authority_enrollment_digest_chirho: String,
    config_schema_chirho: String,
    shared_journal_verifier_authored_chirho: bool,
    /// Published for independent deployment review; composed startup requires the reviewed value.
    config_digest_chirho: String,
    /// The digest a later `ledger-regenesis-chirho` run must be given as
    /// `--expected-plan-digest-chirho`.
    plan_digest_chirho: String,
    /// Relative to the selected root, so this report can be pasted into evidence without carrying
    /// an absolute host path — and so it reports where the artifact ACTUALLY landed rather than
    /// echoing back what was typed.
    config_path_chirho: String,
    plan_path_chirho: String,
    proven_runtime_signer_count_chirho: u64,
    proven_offline_authority_count_chirho: u64,
    provider_connection_secret_checked_chirho: bool,
}

/// What one create-new cluster-genesis enrollment authoring act produced. The report deliberately
/// omits the destination key text: the retained signed artifact carries it, and the host author
/// consumes only a fully verified typed value plus this exact digest.
#[derive(Debug, Serialize)]
struct DestinationAuthorityEnrollmentAuthorReportV1Chirho {
    schema_chirho: &'static str,
    enrollment_digest_chirho: String,
    cluster_genesis_roster_head_blake3_chirho: String,
    verified_roster_record_count_chirho: u64,
    verified_active_member_count_chirho: u64,
    output_chirho: String,
    output_created_chirho: bool,
    possession_proven_chirho: bool,
    legitimacy_autonomously_proven_chirho: bool,
    external_custody_autonomously_proven_chirho: bool,
}

/// What one activation authoring run produced, reported from the OFFLINE AUTHORING artifact and from
/// nothing else. The digest is the operator's whole reason to run this verb: it is what a later
/// regenesis/seed run must be given as `--expected-activation-authorization-digest-chirho`.
#[derive(Debug, Serialize)]
struct LedgerHostActivationAuthorReportV1Chirho {
    schema_chirho: &'static str,
    /// The `resident-ledger-activation-authorization-blake3-v1-chirho:`-prefixed digest the offline
    /// authoring road computed by VERIFYING the freshly signed authorization against the config's
    /// pinned activation authority. It is not recomputed here — echoing it would give the digest a
    /// second home that could drift from the one the consumer will bind.
    activation_authorization_digest_chirho: String,
    /// The output the signed authorization was written to, as the operator named it. Reported so a
    /// following seed invocation reads the same artifact this run created.
    activation_authorization_output_chirho: String,
    activation_authorization_output_created_chirho: bool,
}

/// Handle the ledger-host authoring verbs, returning `false` for any other command.
pub(crate) fn handle_ledger_host_author_command_chirho(
    selected_root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::LedgerDestinationAuthorityEnrollChirho(args_chirho) => {
            let report_chirho = run_destination_authority_enrollment_author_chirho(args_chirho)?;
            println!("{}", serde_json::to_string(&report_chirho)?);
            Ok(true)
        }
        CommandChirho::LedgerHostAuthorReviewChirho(args_chirho) => {
            run_ledger_host_author_review_chirho(
                selected_root_chirho,
                &args_chirho.coordinates_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::LedgerHostActivationAuthorChirho(args_chirho) => {
            let report_chirho =
                run_ledger_host_activation_author_chirho(selected_root_chirho, args_chirho)?;
            println!("{}", serde_json::to_string(&report_chirho)?);
            Ok(true)
        }
        CommandChirho::LedgerHostAuthorChirho(args_chirho) => {
            // The enrollment digest is decided before the enrollment is parsed, before a pin is
            // derived, and before the selected root's private signer custody is opened.
            let enrollment_coordinates_chirho = &args_chirho
                .coordinates_chirho
                .destination_authority_enrollment_chirho;
            let destination_authority_enrollment_chirho =
                read_digest_bound_destination_authority_enrollment_chirho(
                    &enrollment_coordinates_chirho.enrollment_path_chirho,
                    &args_chirho.expected_destination_authority_enrollment_digest_chirho,
                    &enrollment_coordinates_chirho.cluster_genesis_roster_path_chirho,
                    &enrollment_coordinates_chirho.cluster_genesis_roster_head_path_chirho,
                    &enrollment_coordinates_chirho
                        .cluster_genesis_roster_operator_pubkey_hex_chirho,
                )?;
            // The review binding is applied by the READ, before custody is proven and long before
            // anything is written: an operator authoring from a document other than the one they
            // reviewed is refused without this process having touched the secret store.
            let loaded_chirho =
                read_digest_bound_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
                    &args_chirho.coordinates_chirho.inputs_path_chirho,
                    &args_chirho.expected_inputs_digest_chirho,
                )?;
            let mode_chirho = authoring_mode_chirho(args_chirho.coordinates_chirho.mode_chirho);
            let emitted_chirho =
                author_and_emit_ledger_host_artifacts_chirho(LedgerHostEmissionRequestChirho {
                    selected_root_chirho,
                    inputs_chirho: &loaded_chirho.inputs_chirho,
                    destination_authority_enrollment_chirho:
                        &destination_authority_enrollment_chirho,
                    issuer_secret_name_chirho: &args_chirho
                        .coordinates_chirho
                        .issuer_secret_name_chirho,
                    activation_secret_name_chirho: args_chirho
                        .coordinates_chirho
                        .activation_secret_name_chirho
                        .as_deref(),
                    config_output_chirho: &args_chirho.config_output_chirho,
                    plan_output_chirho: &args_chirho.plan_output_chirho,
                    serve_port_chirho: args_chirho.serve_port_chirho,
                    mode_chirho,
                })?;
            let report_chirho = ledger_host_author_report_chirho(
                &emitted_chirho,
                mode_chirho,
                loaded_chirho.inputs_digest_chirho,
                selected_root_chirho,
            )?;
            println!("{}", serde_json::to_string(&report_chirho)?);
            Ok(true)
        }
        _other_command_chirho => Ok(false),
    }
}

/// Derive one reviewed document and print what it authorizes. Writes nothing at all.
///
/// It takes no expected digest because it asserts no authority and produces no artifact — it is the
/// command that PRODUCES the digest the authoring verb then requires. It does prove custody, so an
/// operator learns that a signer secret is missing here rather than halfway through an emission.
fn run_ledger_host_author_review_chirho(
    selected_root_chirho: &Path,
    coordinates_chirho: &LedgerHostAuthoringCoordinatesArgsChirho,
) -> anyhow::Result<()> {
    let enrollment_coordinates_chirho = &coordinates_chirho.destination_authority_enrollment_chirho;
    let destination_authority_enrollment_chirho = read_destination_authority_enrollment_chirho(
        &enrollment_coordinates_chirho.enrollment_path_chirho,
        &enrollment_coordinates_chirho.cluster_genesis_roster_path_chirho,
        &enrollment_coordinates_chirho.cluster_genesis_roster_head_path_chirho,
        &enrollment_coordinates_chirho.cluster_genesis_roster_operator_pubkey_hex_chirho,
    )?;
    let loaded_chirho = read_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
        &coordinates_chirho.inputs_path_chirho,
    )?;
    let mode_chirho = authoring_mode_chirho(coordinates_chirho.mode_chirho);
    // THE DERIVATION, and the reason this command can report a money fact at all. Everything
    // printed below comes from its output; the document read above never reaches a report builder.
    let bound_chirho =
        bind_custody_and_derive_ledger_host_artifacts_chirho(LedgerHostCustodyRequestChirho {
            selected_root_chirho,
            inputs_chirho: &loaded_chirho.inputs_chirho,
            destination_authority_enrollment_chirho: &destination_authority_enrollment_chirho,
            issuer_secret_name_chirho: &coordinates_chirho.issuer_secret_name_chirho,
            activation_secret_name_chirho: coordinates_chirho
                .activation_secret_name_chirho
                .as_deref(),
            mode_chirho,
        })?;
    let report_chirho = ledger_host_author_review_report_chirho(
        &bound_chirho.artifacts_chirho,
        &bound_chirho.custody_evidence_chirho,
        mode_chirho,
        loaded_chirho.inputs_digest_chirho,
        destination_authority_enrollment_chirho
            .enrollment_digest_chirho()
            .to_owned(),
        destination_authority_enrollment_chirho
            .cluster_genesis_roster_head_blake3_chirho()
            .to_owned(),
    )?;
    println!("{}", serde_json::to_string(&report_chirho)?);
    Ok(())
}

/// Author one stable cluster-genesis enrollment. The retained roster bundle is verified inside the
/// authoring road before it opens the external destination keypair, and the returned signed bytes
/// are written only after the road self-verifies them.
fn run_destination_authority_enrollment_author_chirho(
    args_chirho: &DestinationAuthorityEnrollmentAuthorArgsChirho,
) -> anyhow::Result<DestinationAuthorityEnrollmentAuthorReportV1Chirho> {
    if std::fs::symlink_metadata(&args_chirho.output_path_chirho).is_ok() {
        anyhow::bail!(
            "destination authority enrollment output already exists; refusing to overwrite {}",
            args_chirho.output_path_chirho.display()
        );
    }
    let authored_chirho = author_destination_authority_enrollment_chirho(
        DestinationAuthorityEnrollmentAuthorRequestChirho {
            destination_authority_signing_root_chirho: &args_chirho
                .destination_authority_signing_root_chirho,
            cluster_genesis_roster_path_chirho: &args_chirho.cluster_genesis_roster_path_chirho,
            cluster_genesis_roster_head_path_chirho: &args_chirho
                .cluster_genesis_roster_head_path_chirho,
            cluster_genesis_roster_operator_pubkey_hex_chirho: &args_chirho
                .cluster_genesis_roster_operator_pubkey_hex_chirho,
        },
    )?;
    write_private_create_new_operator_artifact_chirho(
        &args_chirho.output_path_chirho,
        &authored_chirho.canonical_record_bytes_chirho,
        "destination authority enrollment",
    )?;
    Ok(DestinationAuthorityEnrollmentAuthorReportV1Chirho {
        schema_chirho: DESTINATION_AUTHORITY_ENROLLMENT_AUTHOR_REPORT_SCHEMA_V1_CHIRHO,
        enrollment_digest_chirho: authored_chirho.enrollment_digest_chirho,
        cluster_genesis_roster_head_blake3_chirho: authored_chirho
            .cluster_genesis_roster_head_blake3_chirho,
        verified_roster_record_count_chirho: authored_chirho.verified_roster_record_count_chirho,
        verified_active_member_count_chirho: authored_chirho.verified_active_member_count_chirho,
        output_chirho: args_chirho.output_path_chirho.display().to_string(),
        output_created_chirho: true,
        possession_proven_chirho: true,
        legitimacy_autonomously_proven_chirho: false,
        external_custody_autonomously_proven_chirho: false,
    })
}

/// Author the pre-signed H3 activation authorization from an EXISTING config/plan pair, write it to
/// a fresh private artifact, and return the digest a later regenesis/seed run must be given.
///
/// **This verb is pure WIRING of the offline authoring road.** That road loads the runtime signers,
/// the config's pinned activation authority, and the offline activation SECRET by name from the
/// selected root's store, verifies the plan against the pasted digest, signs one activation
/// statement, and returns its canonical bytes plus the digest it computes by VERIFYING that
/// signature against the pinned authority. Nothing here signs, derives, or mints; the two secret
/// arguments are NAMES the road resolves, never key material. It exists because the config/plan
/// emission road deliberately stops short of this third artifact: its validity window is fixed at
/// 15 minutes, so it belongs beside the start it authorizes rather than beside the config it pins.
///
/// **The output law, this verb's only side effect.** The authorization is a short-window authority
/// artifact that sits beside a secret store, so it is written create-new at mode `0600` and never
/// overwrites. Freshness is fenced twice: a `symlink_metadata` refusal here, BEFORE the activation
/// key is read, so aiming at an existing artifact never touches the secret store; and
/// `create_new(true)` at the syscall, which closes the check-to-write window no pre-check can. The
/// bytes land at the path AS GIVEN — not resolved into the root — so the identical string can be
/// handed to the following seed run's `--activation-authorization-chirho`.
fn run_ledger_host_activation_author_chirho(
    selected_root_chirho: &Path,
    args_chirho: &LedgerHostActivationAuthorArgsChirho,
) -> anyhow::Result<LedgerHostActivationAuthorReportV1Chirho> {
    let output_chirho = args_chirho.activation_authorization_output_chirho.as_path();
    // The NAMED fence: refuse an occupied output before the offline road reads the activation key.
    // `create_new` in the writer is the atomic fence that actually prevents an overwrite.
    if std::fs::symlink_metadata(output_chirho).is_ok() {
        anyhow::bail!(
            "activation authorization output already exists; refusing to overwrite {}",
            output_chirho.display()
        );
    }

    let artifact_chirho =
        author_ledger_regenesis_activation_chirho(LedgerRegenesisActivationAuthorRequestChirho {
            selected_root_chirho,
            config_path_chirho: &args_chirho.config_path_chirho,
            plan_path_chirho: &args_chirho.plan_path_chirho,
            expected_plan_digest_chirho: &args_chirho.expected_plan_digest_chirho,
            issuer_secret_name_chirho: &args_chirho.issuer_secret_name_chirho,
            activation_secret_name_chirho: &args_chirho.activation_secret_name_chirho,
        })?;

    write_private_create_new_activation_authorization_chirho(
        output_chirho,
        &artifact_chirho.canonical_bytes_chirho,
    )?;

    Ok(LedgerHostActivationAuthorReportV1Chirho {
        schema_chirho: LEDGER_HOST_ACTIVATION_AUTHOR_REPORT_SCHEMA_V1_CHIRHO,
        activation_authorization_digest_chirho: artifact_chirho.authorization_digest_chirho,
        activation_authorization_output_chirho: output_chirho.display().to_string(),
        activation_authorization_output_created_chirho: true,
    })
}

/// Create the signed authorization artifact that did not exist, readable and writable by its owner
/// alone, with its bytes on the device before this returns.
///
/// `create_new(true)` is the atomic half of the no-overwrite law; the `symlink_metadata` check in
/// the caller is the named half. `mode(0o600)` is set at OPEN rather than chmod-ed after, so the
/// file is never momentarily group- or world-readable — this artifact carries a signing authority
/// and sits beside a secret store.
fn write_private_create_new_activation_authorization_chirho(
    path_chirho: &Path,
    bytes_chirho: &[u8],
) -> anyhow::Result<()> {
    write_private_create_new_operator_artifact_chirho(
        path_chirho,
        bytes_chirho,
        "activation authorization",
    )
}

fn write_private_create_new_operator_artifact_chirho(
    path_chirho: &Path,
    bytes_chirho: &[u8],
    artifact_label_chirho: &str,
) -> anyhow::Result<()> {
    let mut options_chirho = OpenOptions::new();
    options_chirho.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options_chirho.mode(0o600);
    }
    let mut file_chirho = options_chirho.open(path_chirho).map_err(|error_chirho| {
        anyhow::anyhow!(
            "create {artifact_label_chirho} output {}: {error_chirho}",
            path_chirho.display()
        )
    })?;
    file_chirho
        .write_all(bytes_chirho)
        .map_err(|error_chirho| {
            anyhow::anyhow!(
                "write {artifact_label_chirho} output {}: {error_chirho}",
                path_chirho.display()
            )
        })?;
    file_chirho.sync_all().map_err(|error_chirho| {
        anyhow::anyhow!(
            "sync {artifact_label_chirho} output {}: {error_chirho}",
            path_chirho.display()
        )
    })
}

/// Build the review report from DERIVED artifacts.
///
/// The parameter list is the enforcement, not a convention: this function cannot reach the reviewed
/// document, so it cannot print an un-derived money statement even if a later author wanted it to.
fn ledger_host_author_review_report_chirho(
    artifacts_chirho: &LedgerHostAuthoredArtifactsChirho,
    custody_evidence_chirho: &LedgerHostCustodyEvidenceChirho,
    mode_chirho: LedgerHostAuthoringModeChirho,
    inputs_digest_chirho: String,
    destination_authority_enrollment_digest_chirho: String,
    cluster_genesis_roster_head_blake3_chirho: String,
) -> anyhow::Result<LedgerHostAuthorReviewReportV1Chirho> {
    let plan_chirho = &artifacts_chirho.plan_chirho;
    let config_chirho = &artifacts_chirho.config_chirho;
    Ok(LedgerHostAuthorReviewReportV1Chirho {
        schema_chirho: LEDGER_HOST_AUTHOR_REVIEW_REPORT_SCHEMA_V1_CHIRHO,
        authoring_mode_chirho: authoring_mode_label_chirho(mode_chirho),
        inputs_digest_chirho,
        destination_authority_enrollment_digest_chirho,
        cluster_genesis_roster_head_blake3_chirho,
        plan_digest_chirho: artifacts_chirho.plan_digest_chirho.clone(),
        config_schema_chirho: config_chirho.schema_chirho.clone(),
        shared_journal_verifier_authored_chirho: custody_evidence_chirho
            .shared_journal_verifier_authored_chirho,
        test_kind_marked_chirho: config_chirho.test_kind_chirho.is_some(),
        activation_authority_authored_chirho: config_chirho.activation_authority_chirho.is_some(),
        kind_id_chirho: plan_chirho.kind_id_chirho.clone(),
        initial_owner_chirho: plan_chirho.initial_owner_chirho.clone(),
        initial_mint_amount_chirho: plan_chirho.initial_mint_amount_chirho,
        initial_policy_chirho: serde_json::to_value(&plan_chirho.initial_policy_chirho)?,
        amended_policy_chirho: serde_json::to_value(&plan_chirho.amended_policy_chirho)?,
        member_count_chirho: config_chirho.members_chirho.len(),
        projection_route_count_chirho: plan_chirho.projection_routes_chirho.len(),
        proven_runtime_signer_count_chirho: custody_evidence_chirho
            .proven_runtime_signer_count_chirho,
        proven_offline_authority_count_chirho: custody_evidence_chirho
            .proven_offline_authority_count_chirho,
        provider_connection_secret_checked_chirho: custody_evidence_chirho
            .provider_connection_secret_checked_chirho,
    })
}

/// Build the emission report from the EMISSION receipt.
///
/// Same enforcement as its sibling: the receipt only exists downstream of a custody-bound
/// derivation, so this report cannot describe artifacts that were never authored.
fn ledger_host_author_report_chirho(
    emitted_chirho: &LedgerHostEmittedArtifactsChirho,
    mode_chirho: LedgerHostAuthoringModeChirho,
    inputs_digest_chirho: String,
    selected_root_chirho: &Path,
) -> anyhow::Result<LedgerHostAuthorReportV1Chirho> {
    let canonical_root_chirho = selected_root_chirho.canonicalize()?;
    Ok(LedgerHostAuthorReportV1Chirho {
        schema_chirho: LEDGER_HOST_AUTHOR_REPORT_SCHEMA_V1_CHIRHO,
        authoring_mode_chirho: authoring_mode_label_chirho(mode_chirho),
        inputs_digest_chirho,
        destination_authority_enrollment_digest_chirho: emitted_chirho
            .destination_authority_enrollment_digest_chirho
            .clone(),
        config_schema_chirho: emitted_chirho.config_schema_chirho.clone(),
        shared_journal_verifier_authored_chirho: emitted_chirho
            .shared_journal_verifier_authored_chirho,
        config_digest_chirho: emitted_chirho.config_digest_chirho.clone(),
        plan_digest_chirho: emitted_chirho.plan_digest_chirho.clone(),
        config_path_chirho: root_relative_artifact_path_chirho(
            &canonical_root_chirho,
            &emitted_chirho.config_path_chirho,
        )?,
        plan_path_chirho: root_relative_artifact_path_chirho(
            &canonical_root_chirho,
            &emitted_chirho.plan_path_chirho,
        )?,
        proven_runtime_signer_count_chirho: emitted_chirho
            .custody_evidence_chirho
            .proven_runtime_signer_count_chirho,
        proven_offline_authority_count_chirho: emitted_chirho
            .custody_evidence_chirho
            .proven_offline_authority_count_chirho,
        provider_connection_secret_checked_chirho: emitted_chirho
            .custody_evidence_chirho
            .provider_connection_secret_checked_chirho,
    })
}

/// Express an emitted artifact's path relative to the selected root.
///
/// The emission road proves every output resolves inside the canonical root before it writes, so
/// this strip cannot fail against an artifact it produced. It is written as a hard error rather
/// than a lossy fallback for exactly that reason: if it ever fires, the in-root containment law
/// changed, and reporting a bare file name would hide that behind a tidy-looking path.
fn root_relative_artifact_path_chirho(
    canonical_root_chirho: &Path,
    artifact_path_chirho: &Path,
) -> anyhow::Result<String> {
    let relative_chirho = artifact_path_chirho
        .strip_prefix(canonical_root_chirho)
        .map_err(|_error_chirho| {
            anyhow::anyhow!(
                "an emitted ledger host artifact resolved outside the selected root, which the \
                 emission road's in-root law forbids"
            )
        })?;
    relative_chirho
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("an emitted ledger host artifact path is not valid UTF-8"))
}

/// Translate the CLI's own value enum into the authoring crate's typed mode.
///
/// The two enums are deliberately separate types: the CLI's exists to give clap a stable spelling,
/// and the crate's is the choice every authoring road requires. One `match` with no fallback arm
/// means adding a posture to either side is a compile error rather than a silent default.
fn authoring_mode_chirho(
    mode_argument_chirho: LedgerHostAuthoringModeArgChirho,
) -> LedgerHostAuthoringModeChirho {
    match mode_argument_chirho {
        LedgerHostAuthoringModeArgChirho::ProductionChirho => {
            LedgerHostAuthoringModeChirho::ProductionChirho
        }
        LedgerHostAuthoringModeArgChirho::TestKindChirho => {
            LedgerHostAuthoringModeChirho::TestKindChirho
        }
    }
}

fn authoring_mode_label_chirho(mode_chirho: LedgerHostAuthoringModeChirho) -> &'static str {
    match mode_chirho {
        LedgerHostAuthoringModeChirho::ProductionChirho => PRODUCTION_MODE_LABEL_CHIRHO,
        LedgerHostAuthoringModeChirho::TestKindChirho => TEST_KIND_MODE_LABEL_CHIRHO,
    }
}

#[cfg(test)]
#[path = "ledger_host_author_cli_chirho_tests.rs"]
mod ledger_host_author_cli_tests_chirho;
