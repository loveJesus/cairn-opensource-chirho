// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Turn one reviewed authoring-inputs document plus two already-derived verifier pins into the
//! host config block and the regenesis plan, refusing every pair the existing laws refuse.
//!
//! Brick #2 of the generic ledger-host authoring program
//! (`spec-chirho/workstream-state-chirho/ledger-host-config-authoring-design-chirho.md` §5).
//! Pure derivation: no filesystem access, no signing, and no key derivation happen here.
//!
//! **The pins cannot be typed in.** A verifier pin reaches this module only as a
//! [`DerivedAuthorityPinChirho`], whose hex field is private and whose only constructor is
//! crate-internal, so no caller outside this crate can hand the author a literal. That constructor's
//! one production road is [`crate::issuer_chirho`]'s derivation from an EXISTING 32-byte secret,
//! which loads and errors and never creates. Brick #1 made a key hex unrepresentable in the reviewed
//! document; this type is the matching fence on the parameter road, so the two together leave no way
//! to launder an invented authority into a money surface.
//!
//! **Brick #2 flagged that a pin from that road was well-formed and UN-VOUCHED; brick #3 closed it
//! at the signature.** Those derivations now REQUIRE the loaded six runtime signers, and this
//! function plus both derivations are crate-internal, so the exported road is
//! [`crate::ledger_host_custody_binding_chirho`] alone. This note replaces the earlier one at its
//! own line rather than downstream, because a reader meets the claim first.
//!
//! **A pin also carries the ROLE it was derived for.** The config's own validator proves the issuer
//! and activation pins are DISTINCT but cannot know which is which, so a caller that swapped them
//! would pin the activation key as the mint authority's outer trust root and pass every existing
//! check. [`DerivedAuthorityPinRoleChirho`] is what refuses that.
//!
//! **One home, no drift.** Every law that already has a home is RUN here, never copied: the reviewed
//! document's own laws, `LedgerHostConfigChirho::validate_chirho` (including the verifier-pin shape,
//! the issuer/activation distinctness, and the schema gate), and the plan's coordinate, policy,
//! config-binding, and namespace-layout validators. Because both artifacts come from one document,
//! running the binding check makes `ConfigPlanMismatchChirho` a proof rather than a hope.
//!
//! **What this PURE brick cannot author, and says so instead of guessing.** Held-verifier pins are
//! key values and the reviewed document cannot carry them, so this baseline derivation always has
//! `held_verifier_pins_chirho: None` and schema v1/v2. The custody brick may subsequently honor the
//! document's digest-bound test-kind shared-journal CHOICE by asking its already-loaded six-signer
//! set to derive the journal public half and return a validated v3 config. No caller-supplied pin
//! reaches either stage, and v4 effect pins remain outside this authoring road.

use crate::destination_authority_enrollment_chirho::VerifiedDestinationAuthorityEnrollmentChirho;
use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use crate::ledger_host_authoring_inputs_chirho::LedgerHostAuthoringInputsV1Chirho;
use crate::ledger_host_authoring_mode_chirho::LedgerHostAuthoringModeChirho;
use crate::plan_chirho::{
    canonical_plan_bytes_chirho, plan_digest_chirho, validate_config_binding_chirho,
    validate_namespace_layout_chirho, validate_plan_coordinates_chirho,
    validate_plan_policy_chirho, LedgerRegenesisPlanV1Chirho,
    LedgerRegenesisProjectionRoutePlanChirho, LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO,
};
use cairn_config_chirho::config_chirho::{
    LedgerHostActivationPinConfigChirho, LedgerHostConfigChirho, LedgerHostIssuerPinConfigChirho,
    LedgerHostMemberConfigChirho, LedgerHostPostgresEffectConfigChirho,
    LedgerHostProjectionRouteConfigChirho, LedgerHostSignerRefsConfigChirho,
    LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO, LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
    LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO,
};

/// Which offline authority a derived pin belongs to. The two are separate identities with separate
/// custody, and the config validator can only prove they differ — not which one is which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivedAuthorityPinRoleChirho {
    KindIssuerChirho,
    LedgerActivationChirho,
}

/// One verifier pin that came from an existing secret, tagged with the role it was derived for.
///
/// The hex is deliberately private and there is no public constructor: outside this crate a pin can
/// only be obtained from a derivation over a pre-provisioned secret, never written down. No shape
/// law is re-implemented here — the config's own `validate_chirho` owns "64 lowercase hex, nonzero"
/// and is run over the emitted block, so a malformed pin is refused by the one home that law has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedAuthorityPinChirho {
    role_chirho: DerivedAuthorityPinRoleChirho,
    verifying_key_hex_chirho: String,
}

impl DerivedAuthorityPinChirho {
    /// The only way a pin comes into existence. Called by the offline-authority derivation, which
    /// loads an EXISTING 32-byte secret and errors when it is absent, short, or all zero.
    pub(crate) fn from_existing_secret_derivation_chirho(
        role_chirho: DerivedAuthorityPinRoleChirho,
        verifying_key_hex_chirho: String,
    ) -> Self {
        Self {
            role_chirho,
            verifying_key_hex_chirho,
        }
    }

    pub fn role_chirho(&self) -> DerivedAuthorityPinRoleChirho {
        self.role_chirho
    }

    /// The derived PUBLIC half, crate-internal so the activation derivation can prove it differs
    /// from the issuer's. This is not the boundary ruling (d) protects: that ruling is about the six
    /// RUNTIME signers, whose public bytes never leave `RoleBoundLedgerSignerChirho`. This value is
    /// an OFFLINE authority's public key, which the emitted config carries in plaintext by design —
    /// there is nothing here to keep secret, only a constructor to keep closed.
    pub(crate) fn verifying_key_hex_chirho(&self) -> &str {
        &self.verifying_key_hex_chirho
    }
}

/// The two artifacts one reviewed document authorizes, plus the plan's review digest. Emission —
/// fresh, in-root, non-overwriting, mode `0600` — belongs to the next brick; nothing is written here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerHostAuthoredArtifactsChirho {
    pub config_chirho: LedgerHostConfigChirho,
    pub plan_chirho: LedgerRegenesisPlanV1Chirho,
    pub canonical_plan_bytes_chirho: Vec<u8>,
    pub plan_digest_chirho: String,
}

/// Derive the host config block and the regenesis plan from one reviewed document.
///
/// Refuses, in order: a document that does not satisfy its own laws; a pin supplied for the wrong
/// authority; an activation pin and an activation principal that do not arrive together; and then
/// anything the config's own validator or the plan's own validators refuse about the derived pair.
///
/// Crate-internal since brick #3: the only exported road into this function is
/// [`crate::ledger_host_custody_binding_chirho::bind_custody_and_derive_ledger_host_artifacts_chirho`],
/// which proves custody of every key it is about to pin BEFORE calling here. Exporting this instead
/// would export a shape whose pins are well-formed and un-vouched.
pub(crate) fn derive_ledger_host_artifacts_chirho(
    inputs_chirho: &LedgerHostAuthoringInputsV1Chirho,
    issuer_pin_chirho: &DerivedAuthorityPinChirho,
    activation_pin_chirho: Option<&DerivedAuthorityPinChirho>,
    destination_authority_enrollment_chirho: &VerifiedDestinationAuthorityEnrollmentChirho,
    mode_chirho: LedgerHostAuthoringModeChirho,
) -> LedgerRegenesisResultChirho<LedgerHostAuthoredArtifactsChirho> {
    // The programmatic road gets the same laws as the parsed one: a caller that builds the struct
    // in code must not reach derivation by skipping the reviewed document's parser.
    inputs_chirho.validate_chirho()?;
    if issuer_pin_chirho.role_chirho != DerivedAuthorityPinRoleChirho::KindIssuerChirho {
        return Err(LedgerRegenesisRefusalChirho::AuthoringPinRoleRefusedChirho);
    }
    let activation_authority_chirho = match (
        &inputs_chirho.activation_principal_chirho,
        activation_pin_chirho,
    ) {
        (None, None) => None,
        (Some(activation_principal_chirho), Some(activation_pin_chirho)) => {
            if activation_pin_chirho.role_chirho
                != DerivedAuthorityPinRoleChirho::LedgerActivationChirho
            {
                return Err(LedgerRegenesisRefusalChirho::AuthoringPinRoleRefusedChirho);
            }
            Some(LedgerHostActivationPinConfigChirho {
                principal_chirho: activation_principal_chirho.clone(),
                verifying_key_hex_chirho: activation_pin_chirho.verifying_key_hex_chirho.clone(),
            })
        }
        // A reviewed principal with no pin would silently drop the activation authority the
        // document asked for; a pin with no principal would attach an authority nobody reviewed.
        _ => return Err(LedgerRegenesisRefusalChirho::AuthoringActivationPinPairingRefusedChirho),
    };

    let plan_chirho = derive_plan_chirho(inputs_chirho);
    let config_chirho = derive_config_chirho(
        inputs_chirho,
        issuer_pin_chirho,
        activation_authority_chirho,
        destination_authority_enrollment_chirho,
        mode_chirho,
    );

    // Every law below already has a home. Running them is what keeps this author from growing a
    // second copy that can drift away from the boundary the serve runtime actually enforces.
    config_chirho
        .validate_chirho()
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConfigInvalidChirho)?;
    validate_plan_coordinates_chirho(&plan_chirho)?;
    validate_plan_policy_chirho(&plan_chirho)?;
    validate_config_binding_chirho(&plan_chirho, &config_chirho)?;
    validate_namespace_layout_chirho(&plan_chirho)?;

    let canonical_plan_bytes_chirho = canonical_plan_bytes_chirho(&plan_chirho)?;
    let plan_digest_chirho = plan_digest_chirho(&canonical_plan_bytes_chirho);
    Ok(LedgerHostAuthoredArtifactsChirho {
        config_chirho,
        plan_chirho,
        canonical_plan_bytes_chirho,
        plan_digest_chirho,
    })
}

fn derive_plan_chirho(
    inputs_chirho: &LedgerHostAuthoringInputsV1Chirho,
) -> LedgerRegenesisPlanV1Chirho {
    LedgerRegenesisPlanV1Chirho {
        schema_chirho: LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO.to_owned(),
        fresh_parent_chirho: inputs_chirho.fresh_parent_chirho.clone(),
        staging_parent_chirho: inputs_chirho.staging_parent_chirho.clone(),
        storage_namespace_chirho: inputs_chirho.storage_namespace_chirho.clone(),
        monitor_evidence_namespace_chirho: inputs_chirho.monitor_evidence_namespace_chirho.clone(),
        monitor_evidence_path_chirho: inputs_chirho.monitor_evidence_path_chirho.clone(),
        money_group_id_chirho: inputs_chirho.money_group_id_chirho.clone(),
        cluster_id_chirho: inputs_chirho.cluster_id_chirho.clone(),
        journal_path_chirho: inputs_chirho.journal_path_chirho.clone(),
        local_epoch_chirho: inputs_chirho.local_epoch_chirho,
        kind_registry_path_chirho: inputs_chirho.kind_registry_path_chirho.clone(),
        kind_registry_id_chirho: inputs_chirho.kind_registry_id_chirho.clone(),
        projection_registry_path_chirho: inputs_chirho.projection_registry_path_chirho.clone(),
        projection_registry_id_chirho: inputs_chirho.projection_registry_id_chirho.clone(),
        source_registry_path_chirho: inputs_chirho.source_registry_path_chirho.clone(),
        source_registry_id_chirho: inputs_chirho.source_registry_id_chirho.clone(),
        projection_routes_chirho: inputs_chirho
            .projection_routes_chirho
            .iter()
            .map(|route_chirho| LedgerRegenesisProjectionRoutePlanChirho {
                projection_name_chirho: route_chirho.projection_name_chirho.clone(),
                head_path_chirho: route_chirho.head_path_chirho.clone(),
            })
            .collect(),
        monitor_cadence_ms_chirho: inputs_chirho.monitor_cadence_ms_chirho,
        issuer_principal_chirho: inputs_chirho.issuer_principal_chirho.clone(),
        initial_owner_chirho: inputs_chirho.initial_owner_chirho.clone(),
        kind_id_chirho: inputs_chirho.kind_id_chirho.clone(),
        initial_policy_chirho: inputs_chirho.initial_policy_chirho.clone(),
        amended_policy_chirho: inputs_chirho.amended_policy_chirho.clone(),
        initial_mint_amount_chirho: inputs_chirho.initial_mint_amount_chirho,
        genesis_physical_ms_chirho: inputs_chirho.genesis_physical_ms_chirho,
        mint_physical_ms_chirho: inputs_chirho.mint_physical_ms_chirho,
    }
}

fn derive_config_chirho(
    inputs_chirho: &LedgerHostAuthoringInputsV1Chirho,
    issuer_pin_chirho: &DerivedAuthorityPinChirho,
    activation_authority_chirho: Option<LedgerHostActivationPinConfigChirho>,
    destination_authority_enrollment_chirho: &VerifiedDestinationAuthorityEnrollmentChirho,
    mode_chirho: LedgerHostAuthoringModeChirho,
) -> LedgerHostConfigChirho {
    LedgerHostConfigChirho {
        // Derived from what the document CONTAINS, never copied from a tag an operator wrote: an
        // operator cannot select a schema that silently drops an authority they also supplied.
        // Only v1 and v2 are reachable, because held-verifier pins are not authorable here.
        schema_chirho: if activation_authority_chirho.is_some() {
            LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO.to_owned()
        } else {
            LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO.to_owned()
        },
        storage_namespace_chirho: inputs_chirho.storage_namespace_chirho.clone(),
        monitor_evidence_namespace_chirho: inputs_chirho.monitor_evidence_namespace_chirho.clone(),
        monitor_evidence_path_chirho: inputs_chirho.monitor_evidence_path_chirho.clone(),
        money_group_id_chirho: inputs_chirho.money_group_id_chirho.clone(),
        cluster_id_chirho: inputs_chirho.cluster_id_chirho.clone(),
        journal_path_chirho: inputs_chirho.journal_path_chirho.clone(),
        local_epoch_chirho: inputs_chirho.local_epoch_chirho,
        members_chirho: inputs_chirho
            .members_chirho
            .iter()
            .map(|member_chirho| LedgerHostMemberConfigChirho {
                owner_chirho: member_chirho.owner_chirho.clone(),
                kind_id_chirho: member_chirho.kind_id_chirho.clone(),
            })
            .collect(),
        kind_registry_path_chirho: inputs_chirho.kind_registry_path_chirho.clone(),
        kind_registry_id_chirho: inputs_chirho.kind_registry_id_chirho.clone(),
        kind_issuer_chirho: LedgerHostIssuerPinConfigChirho {
            principal_chirho: inputs_chirho.issuer_principal_chirho.clone(),
            verifying_key_hex_chirho: issuer_pin_chirho.verifying_key_hex_chirho.clone(),
        },
        activation_authority_chirho,
        projection_registry_path_chirho: inputs_chirho.projection_registry_path_chirho.clone(),
        projection_registry_id_chirho: inputs_chirho.projection_registry_id_chirho.clone(),
        source_registry_path_chirho: inputs_chirho.source_registry_path_chirho.clone(),
        source_registry_id_chirho: inputs_chirho.source_registry_id_chirho.clone(),
        projection_routes_chirho: inputs_chirho
            .projection_routes_chirho
            .iter()
            .map(|route_chirho| LedgerHostProjectionRouteConfigChirho {
                projection_name_chirho: route_chirho.projection_name_chirho.clone(),
                head_path_chirho: route_chirho.head_path_chirho.clone(),
            })
            .collect(),
        signer_secrets_chirho: LedgerHostSignerRefsConfigChirho {
            journal_chirho: inputs_chirho.signer_secrets_chirho.journal_chirho.clone(),
            config_chirho: inputs_chirho.signer_secrets_chirho.config_chirho.clone(),
            feeder_chirho: inputs_chirho.signer_secrets_chirho.feeder_chirho.clone(),
            kind_root_chirho: inputs_chirho.signer_secrets_chirho.kind_root_chirho.clone(),
            effect_intent_chirho: inputs_chirho
                .signer_secrets_chirho
                .effect_intent_chirho
                .clone(),
            effect_terminal_chirho: inputs_chirho
                .signer_secrets_chirho
                .effect_terminal_chirho
                .clone(),
        },
        // Not authorable from a reviewed document that carries no key material, and not derivable
        // from this root's own secrets: these are another root's public halves.
        held_verifier_pins_chirho: None,
        // A freshly derived host must not trust a caller-written destination authority. The old
        // posture therefore emitted `None` and forced a deliberate later operator edit. That
        // ruling is superseded only by this verified cluster-genesis enrollment: authenticity is
        // now bound here, while legitimacy review remains a deliberate procedural genesis act.
        // The corresponding destination seed never enters this root; only its public half does.
        migration_destination_authority_chirho: Some(
            destination_authority_enrollment_chirho.destination_authority_config_chirho(),
        ),
        monitor_cadence_ms_chirho: inputs_chirho.monitor_cadence_ms_chirho,
        postgres_effect_chirho: inputs_chirho.postgres_effect_chirho.as_ref().map(
            |postgres_effect_chirho| LedgerHostPostgresEffectConfigChirho {
                schema_chirho: LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO.to_owned(),
                posture_chirho: postgres_effect_chirho.posture_chirho,
                connection_secret_chirho: postgres_effect_chirho.connection_secret_chirho.clone(),
                billing_kind_chirho: postgres_effect_chirho.billing_kind_chirho.clone(),
            },
        ),
        // Stamped from the authoring MODE, never from the reviewed document: the document is about
        // coordinates, and which posture an invocation is authoring is a property of the invocation.
        // A document field here would also be a field an operator could set while the invocation
        // said the opposite, which is a second source of truth for one authority question.
        control_plane_chirho: None,
        test_kind_chirho: mode_chirho.authored_test_kind_marker_chirho(),
        adopt_migrated_root_chirho: false,
    }
}
