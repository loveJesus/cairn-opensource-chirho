// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Prove, on THIS root, that every key the authored artifacts will pin or name is the key the
//! operator meant — and only then derive them.
//!
//! Brick #3 of the generic ledger-host authoring program
//! (`spec-chirho/workstream-state-chirho/ledger-host-config-authoring-design-chirho.md` §5), which
//! that design names the RISKIEST brick: bricks #2 and #5 fail loudly, and this one can fail
//! QUIETLY, because a bug here yields a config that validates, parses, boots, and is wrong.
//!
//! **Never mint.** Every key is read, never created. A missing secret is a hard refusal with a
//! named identity, not a generated convenience — that is the intended friction, and it is what
//! makes the test/production boundary rest on custody rather than on a flag.
//!
//! **What "custody" means here, stated as the four questions this module answers.**
//! 1. Do the six runtime signer secrets EXIST on this root, are they 32 bytes, are they nonzero,
//!    and are they pairwise distinct in NAME and in IDENTITY? (`load_existing_chirho` is the one
//!    home for all five; this module only translates its typed refusal into a named one.)
//! 2. Is the offline kind issuer a SEVENTH key — distinct from all six by name AND by identity?
//! 3. Is the offline ledger activation authority an EIGHTH key — distinct from the issuer and from
//!    all six, again by name AND by identity?
//! 4. Does the priced-effect provider's connection secret NAME collide with any of those eight?
//!
//! **Why the identity questions carry the weight the name questions cannot.** Two different names
//! over the same 32 secret bytes are one key wearing two labels. The config validates, the plan
//! binds, regenesis boots — and the registry's two-root containment (issuer signature plus runtime
//! `kind_root_chirho` signature) has silently collapsed into one root. A name comparison sees
//! nothing wrong. This is the exact "wrong-but-plausible key" the design warns of, and it is why
//! every collision here is asked twice.
//!
//! **THE ROAD IN SERVICE NOW COMES THROUGH HERE — brick #7 closed the gap this note used to
//! report, and the correction sits at the claim's own line rather than downstream.** Until brick #7,
//! `author_credits_demo_inputs_chirho` in the operator-smoke crate authored its own artifacts: it
//! proved the six runtime signers load and that the authority secret NAMES were pairwise distinct,
//! then discarded the loaded set and derived its two pins through thin helpers that took no signer
//! set, so it made no identity comparison at all. Measured at that commit, the same-bytes-different-
//! name issuer was ACCEPTED there and produced a bootable config pinning the `kind_root_chirho`
//! signer's own identity as the mint authority's outer trust root. That road is gone: the credits
//! demo is now a caller of the emission road, which calls this one, and the two thin helpers were
//! deleted rather than left as a second, weaker way to obtain a pin.
//!
//! What remains true, and is why this paragraph is not simply removed: this module's identity law
//! covers the roads that come THROUGH it. It is not a property of the workspace, and a future
//! authoring road that derives a pin some other way would not inherit it.
//!
//! **Why the provider question belongs to custody at all.** A connection secret is a low-trust
//! operational value; a signer secret is money authority. One NAME serving both means whoever may
//! rotate the DSN may overwrite a signing key. Brick #1 could only check the name's grammar; the
//! collision is a custody fact, so it is answered here.
//!
//! **One home per law.** Nothing below re-implements a check that already has an owner: the
//! document's laws are its own `validate_chirho`, the six-signer proof is
//! `HostLedgerSignersChirho::load_existing_chirho`, the issuer/activation collisions are
//! `issuer_chirho`'s shared predicates, and the money-policy law stays with the plan validators
//! that brick #2 runs. This module is the ORDER and the BINDING, not a second rulebook.
//!
//! **What this brick does NOT prove, said here rather than downstream.**
//! - Custody is per-root. The mechanism is strictly per-root (an identity is the Ed25519 public key
//!   of that root's own secret file) and exactly one production secret-write path exists, so
//!   group-sharing is achieved by the OPERATOR installing identical bytes on each node. This module
//!   has no cross-root input and invents none.
//! - Therefore the recorded FINDING A is NOT closed: the genesis record binds the key NAME, not the
//!   key, so two roots carrying identical names over DIFFERENT values still fail late, as a
//!   signature mismatch with no key check anywhere.
//! - The recorded FINDING B is NOT assumed away. Only the JOURNAL role's group-sharing requirement
//!   is established; an effect-intent mutation survived, which is an unanswered question rather
//!   than freedom. No check here needs an answer, because every check here is within one root.
//! - The provider connection secret is checked for NAME collision only. Its existence is not
//!   proven and its local-endpoint law is not applied: that law lives in the served-runtime crate,
//!   which this operator-only crate's source census forbids importing, and reaching for it to be
//!   thorough would trade a guarded boundary for a convenience. (The census matches on plain text,
//!   so that crate is named here in prose only — deliberately not spelled as its identifier.)

use crate::destination_authority_enrollment_chirho::VerifiedDestinationAuthorityEnrollmentChirho;
use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use crate::issuer_chirho::{derived_kind_issuer_pin_chirho, derived_ledger_activation_pin_chirho};
use crate::ledger_host_artifact_derivation_chirho::{
    derive_ledger_host_artifacts_chirho, LedgerHostAuthoredArtifactsChirho,
};
use crate::ledger_host_authoring_inputs_chirho::{
    LedgerHostAuthoringInputsV1Chirho, LedgerHostAuthoringSignerRefsInputChirho,
};
use crate::ledger_host_authoring_mode_chirho::LedgerHostAuthoringModeChirho;
use crate::plan_chirho::validate_config_binding_chirho;
use cairn_config_chirho::config_chirho::LedgerHostSignerRefsConfigChirho;
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho, HostLedgerSignerRefusalChirho,
    HostLedgerSignersChirho,
};
use std::path::Path;

/// One custody-bound authoring request. The two offline authority secret NAMES are arguments rather
/// than document fields for the same reason the pins are derived rather than typed: they select
/// which pre-provisioned secret the operator is exercising custody of, and the reviewed document is
/// about coordinates, not about which key the invoking operator can reach.
pub struct LedgerHostCustodyRequestChirho<'request_chirho> {
    pub selected_root_chirho: &'request_chirho Path,
    pub inputs_chirho: &'request_chirho LedgerHostAuthoringInputsV1Chirho,
    pub destination_authority_enrollment_chirho:
        &'request_chirho VerifiedDestinationAuthorityEnrollmentChirho,
    pub issuer_secret_name_chirho: &'request_chirho str,
    /// Absent authors a config with no activation authority. It is NOT defaulted to the issuer and
    /// never invented: an activation pin nobody can justify is exactly what ruling (e) forbids.
    pub activation_secret_name_chirho: Option<&'request_chirho str>,
    /// Production or synthetic test kind. Required with no default, so no road can author a
    /// production artifact by omission. It is LEGIBILITY, not the control — the control against a
    /// test-kind issuer reaching production is this module's own subject, custody: the pin is
    /// derived from a pre-provisioned secret, so a key that is not on this root cannot be pinned.
    pub mode_chirho: LedgerHostAuthoringModeChirho,
}

/// What was actually proven, in counts a reader can check against the module's four questions. No
/// key material, no hex, and deliberately no field that merely restates an input: a field with no
/// real claim behind it invites a reader to believe a check happened that did not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerHostCustodyEvidenceChirho {
    /// Runtime signer roles loaded, length-checked, nonzero-checked, and proven pairwise distinct
    /// in name and identity. Always the full six when this value exists at all.
    pub proven_runtime_signer_count_chirho: u64,
    /// Offline authorities derived from an existing secret and proven distinct from those six and
    /// from each other: one for the issuer alone, two when an activation authority was authored.
    pub proven_offline_authority_count_chirho: u64,
    /// Whether a priced-effect connection secret name was present and therefore collision-checked.
    pub provider_connection_secret_checked_chirho: bool,
    /// Whether the reviewed test-kind choice caused the loaded journal signer to derive the
    /// journal-only public verifier pin in the final schema-v3 config.
    pub shared_journal_verifier_authored_chirho: bool,
}

/// The artifacts plus the custody proof that authorized them. They travel together so a later brick
/// cannot emit the artifacts while leaving the proof behind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerHostCustodyBoundArtifactsChirho {
    pub artifacts_chirho: LedgerHostAuthoredArtifactsChirho,
    pub custody_evidence_chirho: LedgerHostCustodyEvidenceChirho,
}

/// Prove custody of the six runtime signers, the offline issuer, the optional offline activation
/// authority, and the optional provider connection secret NAME — then derive the config and plan.
///
/// Order is part of the contract, because a refusal identity is only useful if it names the FIRST
/// thing actually wrong: the reviewed document's own laws, then the declared authoring MODE's
/// naming laws, then the six runtime signers, then the provider name collisions, then the issuer,
/// then the activation authority, then derivation. Nothing is written and no key is created at any
/// step.
pub fn bind_custody_and_derive_ledger_host_artifacts_chirho(
    request_chirho: LedgerHostCustodyRequestChirho<'_>,
) -> LedgerRegenesisResultChirho<LedgerHostCustodyBoundArtifactsChirho> {
    // Run the document's own laws BEFORE touching a secret store, so a coordinate defect refuses
    // with a coordinate identity rather than with whichever custody question happened to be asked
    // first. The derivation runs them again; a law run twice is still a law with one home.
    request_chirho.inputs_chirho.validate_chirho()?;
    // Cheapest law, and it names the invocation rather than the root — so a mode slip refuses
    // before this process has read a single secret, exactly as an occupied output path does in the
    // emission brick.
    request_chirho
        .mode_chirho
        .refuse_mismatched_issuer_naming_chirho(
            request_chirho.issuer_secret_name_chirho,
            &request_chirho.inputs_chirho.issuer_principal_chirho,
        )?;
    if request_chirho.inputs_chirho.test_kind_shared_journal_chirho
        && request_chirho.mode_chirho != LedgerHostAuthoringModeChirho::TestKindChirho
    {
        return Err(LedgerRegenesisRefusalChirho::AuthoringSharedJournalRequiresTestKindChirho);
    }

    let runtime_signers_chirho = prove_runtime_signer_custody_chirho(
        request_chirho.selected_root_chirho,
        &request_chirho.inputs_chirho.signer_secrets_chirho,
    )?;
    let provider_connection_secret_checked_chirho = refuse_provider_secret_name_collisions_chirho(
        request_chirho.inputs_chirho,
        request_chirho.issuer_secret_name_chirho,
        request_chirho.activation_secret_name_chirho,
        &runtime_signers_chirho,
    )?;
    let issuer_pin_chirho = derived_kind_issuer_pin_chirho(
        request_chirho.selected_root_chirho,
        request_chirho.issuer_secret_name_chirho,
        &runtime_signers_chirho,
    )?;
    let activation_pin_chirho = match request_chirho.activation_secret_name_chirho {
        None => None,
        Some(activation_secret_name_chirho) => Some(derived_ledger_activation_pin_chirho(
            request_chirho.selected_root_chirho,
            activation_secret_name_chirho,
            request_chirho.issuer_secret_name_chirho,
            &issuer_pin_chirho,
            &runtime_signers_chirho,
        )?),
    };
    let proven_offline_authority_count_chirho = 1 + u64::from(activation_pin_chirho.is_some());
    let mut artifacts_chirho = derive_ledger_host_artifacts_chirho(
        request_chirho.inputs_chirho,
        &issuer_pin_chirho,
        activation_pin_chirho.as_ref(),
        request_chirho.destination_authority_enrollment_chirho,
        request_chirho.mode_chirho,
    )?;
    if request_chirho.inputs_chirho.test_kind_shared_journal_chirho {
        artifacts_chirho.config_chirho = runtime_signers_chirho
            .author_test_kind_shared_journal_config_chirho(&artifacts_chirho.config_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConfigInvalidChirho)?;
        // The augmentation changes only schema and held-verifier authority, neither of which is a
        // plan coordinate. Run the existing binding law again anyway so that remains a checked
        // fact rather than an inference attached to this implementation.
        validate_config_binding_chirho(
            &artifacts_chirho.plan_chirho,
            &artifacts_chirho.config_chirho,
        )?;
    }
    Ok(LedgerHostCustodyBoundArtifactsChirho {
        artifacts_chirho,
        custody_evidence_chirho: LedgerHostCustodyEvidenceChirho {
            proven_runtime_signer_count_chirho: PROVEN_RUNTIME_SIGNER_COUNT_CHIRHO,
            proven_offline_authority_count_chirho,
            provider_connection_secret_checked_chirho,
            shared_journal_verifier_authored_chirho: request_chirho
                .inputs_chirho
                .test_kind_shared_journal_chirho,
        },
    })
}

/// The six roles `HostLedgerSignersChirho` binds. This is a LITERAL mirroring that fixed role set,
/// not a number read back from the loader — the loader exposes no count — so the honest statement is
/// that it is checked by the arm that provisions exactly six runtime secrets and asserts this value,
/// never that it is derived. Said plainly here because a constant whose comment implies a derivation
/// is how a reader stops looking.
const PROVEN_RUNTIME_SIGNER_COUNT_CHIRHO: u64 = 6;

/// Prove all six runtime signer secrets in the one call that owns that law, and translate its typed
/// refusal into a named one. The translation exists so an arm can assert WHICH defect fired: absent,
/// short, all-zero, and duplicate-identity all mean "custody refused", and a fixture aimed at one of
/// them would otherwise pass on any other. Duplicate NAMES are not named here because the reviewed
/// document already refuses them before custody is asked.
fn prove_runtime_signer_custody_chirho(
    selected_root_chirho: &Path,
    signer_secrets_chirho: &LedgerHostAuthoringSignerRefsInputChirho,
) -> LedgerRegenesisResultChirho<HostLedgerSignersChirho> {
    let signer_config_chirho = LedgerHostSignerRefsConfigChirho {
        journal_chirho: signer_secrets_chirho.journal_chirho.clone(),
        config_chirho: signer_secrets_chirho.config_chirho.clone(),
        feeder_chirho: signer_secrets_chirho.feeder_chirho.clone(),
        kind_root_chirho: signer_secrets_chirho.kind_root_chirho.clone(),
        effect_intent_chirho: signer_secrets_chirho.effect_intent_chirho.clone(),
        effect_terminal_chirho: signer_secrets_chirho.effect_terminal_chirho.clone(),
    };
    let signer_refs_chirho = host_ledger_signer_refs_from_config_chirho(&signer_config_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::RuntimeSignerRefusedChirho)?;
    HostLedgerSignersChirho::load_existing_chirho(selected_root_chirho, &signer_refs_chirho)
        .map_err(|error_chirho| runtime_signer_refusal_chirho(&error_chirho))
}

/// Name the runtime-signer custody defect. An error carrying no typed detail stays the broad
/// `RuntimeSignerRefusedChirho`, so a widened failure can never quietly present as a narrow one.
fn runtime_signer_refusal_chirho(error_chirho: &anyhow::Error) -> LedgerRegenesisRefusalChirho {
    match error_chirho.downcast_ref::<HostLedgerSignerRefusalChirho>() {
        Some(HostLedgerSignerRefusalChirho::SecretUnavailableChirho { role_chirho, .. }) => {
            LedgerRegenesisRefusalChirho::RuntimeSignerSecretUnavailableChirho {
                runtime_role_chirho: *role_chirho,
            }
        }
        Some(HostLedgerSignerRefusalChirho::SecretLengthChirho { role_chirho, .. }) => {
            LedgerRegenesisRefusalChirho::RuntimeSignerSecretLengthChirho {
                runtime_role_chirho: *role_chirho,
            }
        }
        Some(HostLedgerSignerRefusalChirho::AllZeroSecretChirho { role_chirho, .. }) => {
            LedgerRegenesisRefusalChirho::RuntimeSignerSecretAllZeroChirho {
                runtime_role_chirho: *role_chirho,
            }
        }
        Some(HostLedgerSignerRefusalChirho::DuplicateIdentityChirho {
            first_role_chirho,
            second_role_chirho,
        }) => LedgerRegenesisRefusalChirho::RuntimeSignerDuplicateIdentityChirho {
            first_role_chirho: *first_role_chirho,
            second_role_chirho: *second_role_chirho,
        },
        _ => LedgerRegenesisRefusalChirho::RuntimeSignerRefusedChirho,
    }
}

/// Refuse a priced-effect connection secret that names a key from a different custody class, and
/// report whether such a name was present at all.
///
/// Only the NAME is compared, and that is the whole check by design: an identity comparison is not
/// available (a DSN is not a 32-byte key) and proving the secret exists is not this brick's to
/// claim. The runtime-signer arm asks the loaded signers rather than re-walking the document's six
/// names, so "which role owns this name" keeps the one home it already has.
fn refuse_provider_secret_name_collisions_chirho(
    inputs_chirho: &LedgerHostAuthoringInputsV1Chirho,
    issuer_secret_name_chirho: &str,
    activation_secret_name_chirho: Option<&str>,
    runtime_signers_chirho: &HostLedgerSignersChirho,
) -> LedgerRegenesisResultChirho<bool> {
    let Some(postgres_effect_chirho) = &inputs_chirho.postgres_effect_chirho else {
        return Ok(false);
    };
    let connection_secret_chirho = postgres_effect_chirho.connection_secret_chirho.as_str();
    if let Some(runtime_role_chirho) =
        runtime_signers_chirho.matching_secret_name_role_chirho(connection_secret_chirho)
    {
        return Err(
            LedgerRegenesisRefusalChirho::ProviderSecretNameCollidesRuntimeSignerChirho {
                runtime_role_chirho,
            },
        );
    }
    if connection_secret_chirho == issuer_secret_name_chirho {
        return Err(LedgerRegenesisRefusalChirho::ProviderSecretNameCollidesIssuerChirho);
    }
    if activation_secret_name_chirho == Some(connection_secret_chirho) {
        return Err(LedgerRegenesisRefusalChirho::ProviderSecretNameCollidesActivationChirho);
    }
    Ok(true)
}
