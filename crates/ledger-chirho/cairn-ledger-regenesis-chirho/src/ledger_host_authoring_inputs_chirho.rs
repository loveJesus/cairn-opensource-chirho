// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The one reviewed coordinate document a generic ledger-host config/plan author reads, carrying
//! every operator-supplied coordinate and no key material at all.
//!
//! Brick #1 of the generic ledger-host authoring program
//! (`spec-chirho/workstream-state-chirho/ledger-host-config-authoring-design-chirho.md` §5).
//! Pure types plus validation: no signing, no key derivation, no filesystem access.
//!
//! **No key material is representable here, by construction.** There is no verifying-key field on
//! any type in this module, `deny_unknown_fields` refuses one that an operator adds, and
//! [`refuse_key_material_shaped_runs_chirho`] refuses a pin smuggled into a field that legitimately
//! accepts free-form lowercase tokens. The two verifier pins are DERIVED from pre-provisioned
//! secrets by the custody brick (`derived_kind_issuer_pin_chirho` /
//! `derived_ledger_activation_pin_chirho`, both `pub(crate)` and both requiring the loaded runtime
//! signers), never accepted as text — a config author that can accept a pin is a config author that
//! can launder an invented authority into a money surface.
//!
//! **What this document deliberately does NOT carry.** Held-verifier pins
//! (`LedgerHostHeldVerifierPinsConfigChirho`) are key hex; admitting them here would contradict the
//! rule above. It can carry one BOOLEAN choice asking the custody brick to derive this root's
//! JOURNAL public half for a shared test-kind runtime. That choice is part of these canonical bytes,
//! so review and author cannot disagree about it while reusing one inputs digest; the pin value is
//! still derived only after the six signer secrets have been loaded and bound. The test-kind marker
//! and the emitted config's own digest law likewise belong to their own bricks; a field with no
//! consumer invites a reader to believe a check happens that does not.
//!
//! **Where the authority for each law lives.** These checks are an EARLY, NAMED pre-check, never
//! the authority: the emitted config is still serialized through `serialize_config_chirho`, which
//! validates, serializes, and re-parses its own bytes at the serving boundary, and the emitted plan
//! is still checked by the plan validators. So a future divergence between this grammar and the
//! config's fails closed and loudly at emission rather than silently at boot. One law here is not a
//! pre-check but a CLOSURE: `LedgerHostConfigChirho::validate_chirho` has no path-distinctness
//! check at all, so a plan-less config can point two registries at one object and validate cleanly.
//! [`LedgerHostAuthoringInputsV1Chirho::validate_chirho`] refuses that aliasing here, for every
//! config this author emits.
//!
//! The money-policy law (`validate_plan_policy_chirho`) is NOT re-implemented here; the later
//! derivation brick runs the existing plan validators on the plan it derives, so that law keeps one
//! home and cannot drift into a second copy.

use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use cairn_config_chirho::config_chirho::{
    validate_ledger_account_owner_chirho, LedgerHostPostgresEffectPostureChirho,
    MAX_LEDGER_MONITOR_CADENCE_MS_CHIRHO, MIN_LEDGER_MONITOR_CADENCE_MS_CHIRHO,
};
use cairn_kind_registry_chirho::record_chirho::KindPolicyBodyChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The document's OWN schema tag. It is not a `LEDGER_HOST_CONFIG_SCHEMA_V*` value: the emitted
/// config's schema is derived from what these inputs actually contain, never copied from here.
pub const LEDGER_HOST_AUTHORING_INPUTS_SCHEMA_V1_CHIRHO: &str =
    "ledger-host-authoring-inputs-v1-chirho";

/// Longest hex-shaped run any authored coordinate may carry. A verifier pin is exactly 64 hex
/// characters, so refusing every run at or past that length keeps a pin out of the document even
/// when the field it sits in accepts free-form lowercase tokens.
const MAX_AUTHORING_INPUT_HEX_RUN_CHIRHO: usize = 63;

const MAX_AUTHORING_INPUT_TOKEN_BYTES_CHIRHO: usize = 128;

/// One account admitted to the local cluster, mirroring `LedgerHostMemberConfigChirho`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostAuthoringMemberInputChirho {
    pub owner_chirho: String,
    pub kind_id_chirho: String,
}

/// One projection route, mirroring both the config route and the plan route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostAuthoringRouteInputChirho {
    pub projection_name_chirho: String,
    pub head_path_chirho: String,
}

/// The six runtime signer secret NAMES. Values never appear here or in any authored artifact; the
/// secrets themselves stay in the selected root's secret store and are proven to exist by the
/// custody brick, which also proves their identities are pairwise distinct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostAuthoringSignerRefsInputChirho {
    pub journal_chirho: String,
    pub config_chirho: String,
    pub feeder_chirho: String,
    pub kind_root_chirho: String,
    pub effect_intent_chirho: String,
    pub effect_terminal_chirho: String,
}

/// Optional priced-effect provider composition, mirroring `LedgerHostPostgresEffectConfigChirho`
/// minus its schema tag, which the emitting brick supplies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostAuthoringPostgresEffectInputChirho {
    pub posture_chirho: LedgerHostPostgresEffectPostureChirho,
    pub connection_secret_chirho: String,
    pub billing_kind_chirho: String,
}

/// The complete reviewed coordinate set for one ledger host. Money amounts and timestamps live
/// only in this document, never in CLI flags, exactly as they do for the regenesis plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostAuthoringInputsV1Chirho {
    pub schema_chirho: String,
    pub fresh_parent_chirho: String,
    pub staging_parent_chirho: String,
    pub storage_namespace_chirho: String,
    pub monitor_evidence_namespace_chirho: String,
    pub monitor_evidence_path_chirho: String,
    pub money_group_id_chirho: String,
    pub cluster_id_chirho: String,
    pub local_epoch_chirho: u64,
    pub journal_path_chirho: String,
    pub kind_registry_path_chirho: String,
    pub kind_registry_id_chirho: String,
    pub projection_registry_path_chirho: String,
    pub projection_registry_id_chirho: String,
    pub source_registry_path_chirho: String,
    pub source_registry_id_chirho: String,
    pub projection_routes_chirho: Vec<LedgerHostAuthoringRouteInputChirho>,
    pub monitor_cadence_ms_chirho: u64,
    /// The kind issuer's PRINCIPAL only. Its verifying key is derived from a pre-provisioned
    /// secret by a later brick and can never be supplied as text.
    pub issuer_principal_chirho: String,
    /// Absent selects a config schema with no activation authority; present selects one with it.
    /// As with the issuer, only the principal appears — never the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_principal_chirho: Option<String>,
    pub members_chirho: Vec<LedgerHostAuthoringMemberInputChirho>,
    pub signer_secrets_chirho: LedgerHostAuthoringSignerRefsInputChirho,
    pub initial_owner_chirho: String,
    pub kind_id_chirho: String,
    pub initial_policy_chirho: KindPolicyBodyChirho,
    pub amended_policy_chirho: KindPolicyBodyChirho,
    pub initial_mint_amount_chirho: u64,
    pub genesis_physical_ms_chirho: u64,
    pub mint_physical_ms_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres_effect_chirho: Option<LedgerHostAuthoringPostgresEffectInputChirho>,
    /// Ask the custody-bound author to derive a journal-only held-verifier pin from the already
    /// loaded runtime journal signer and emit schema v3. This is a CHOICE, never a key value, and
    /// it is accepted only for a test-kind authoring invocation.
    #[serde(default, skip_serializing_if = "bool_is_false_chirho")]
    pub test_kind_shared_journal_chirho: bool,
}

fn bool_is_false_chirho(value_chirho: &bool) -> bool {
    !*value_chirho
}

/// The one encoding of this document. Review, digest, and byte comparison all speak these bytes.
pub fn canonical_ledger_host_authoring_inputs_bytes_chirho(
    inputs_chirho: &LedgerHostAuthoringInputsV1Chirho,
) -> LedgerRegenesisResultChirho<Vec<u8>> {
    serde_json::to_vec(inputs_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::AuthoringInputsInvalidChirho)
}

/// The review digest of already-canonical bytes, matching the plan digest's shape.
pub fn ledger_host_authoring_inputs_digest_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

/// Parse reviewed document bytes and bind them to exactly one encoding and this module's law set.
/// Refuses, in order: bytes that are not this document, a foreign schema, a non-canonical encoding,
/// and then every coordinate law including the key-material scan.
///
/// **The name says `money_policy_unchecked` because it is, and a shorter name misled a reader.**
/// A document that mints 10,000 against a max supply of 2,000 passes this function in full: the
/// money-policy law lives with `validate_plan_policy_chirho`, which runs only when a plan is
/// DERIVED. So a returned document is a well-formed set of coordinates, never a sound money
/// statement, and an operator surface must derive before it prints — the one exported road that
/// does so is
/// [`crate::ledger_host_custody_binding_chirho::bind_custody_and_derive_ledger_host_artifacts_chirho`].
/// Duplicating the policy law here would give it two homes; naming the gap costs nothing and stops
/// the next reader believing a check happened that did not.
pub fn parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
    raw_bytes_chirho: &[u8],
) -> LedgerRegenesisResultChirho<LedgerHostAuthoringInputsV1Chirho> {
    let inputs_chirho: LedgerHostAuthoringInputsV1Chirho = serde_json::from_slice(raw_bytes_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::AuthoringInputsInvalidChirho)?;
    if inputs_chirho.schema_chirho != LEDGER_HOST_AUTHORING_INPUTS_SCHEMA_V1_CHIRHO {
        return Err(LedgerRegenesisRefusalChirho::AuthoringInputsSchemaRefusedChirho);
    }
    let canonical_bytes_chirho =
        canonical_ledger_host_authoring_inputs_bytes_chirho(&inputs_chirho)?;
    if raw_bytes_chirho != canonical_bytes_chirho.as_slice() {
        return Err(LedgerRegenesisRefusalChirho::AuthoringInputsNonCanonicalChirho);
    }
    inputs_chirho.validate_chirho()?;
    Ok(inputs_chirho)
}

impl LedgerHostAuthoringInputsV1Chirho {
    /// Every law this document can decide about itself, with a distinct refusal identity per law.
    pub fn validate_chirho(&self) -> LedgerRegenesisResultChirho<()> {
        if self.schema_chirho != LEDGER_HOST_AUTHORING_INPUTS_SCHEMA_V1_CHIRHO {
            return Err(LedgerRegenesisRefusalChirho::AuthoringInputsSchemaRefusedChirho);
        }
        // Scanning this document's own canonical bytes covers the programmatic construction road
        // as well as the parsed one, so a caller that builds the struct in code cannot carry a pin
        // that parsed bytes could not.
        refuse_key_material_shaped_runs_chirho(
            &canonical_ledger_host_authoring_inputs_bytes_chirho(self)?,
        )?;
        self.validate_coordinates_chirho()?;
        self.validate_namespace_layout_chirho()?;
        self.validate_path_distinctness_chirho()?;
        self.validate_authority_principals_chirho()?;
        self.validate_membership_chirho()?;
        self.validate_signer_refs_chirho()?;
        self.validate_provider_binding_chirho()
    }

    fn validate_coordinates_chirho(&self) -> LedgerRegenesisResultChirho<()> {
        for value_chirho in [
            &self.fresh_parent_chirho,
            &self.staging_parent_chirho,
            &self.money_group_id_chirho,
            &self.cluster_id_chirho,
            &self.kind_registry_id_chirho,
            &self.projection_registry_id_chirho,
            &self.source_registry_id_chirho,
            &self.kind_id_chirho,
        ] {
            validate_authoring_token_chirho(value_chirho)?;
        }
        for value_chirho in [
            &self.storage_namespace_chirho,
            &self.monitor_evidence_namespace_chirho,
            &self.monitor_evidence_path_chirho,
            &self.journal_path_chirho,
            &self.kind_registry_path_chirho,
            &self.projection_registry_path_chirho,
            &self.source_registry_path_chirho,
        ] {
            validate_authoring_path_chirho(value_chirho)?;
        }
        validate_ledger_account_owner_chirho(&self.initial_owner_chirho).map_err(
            |_error_chirho| LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
        )?;
        if !(MIN_LEDGER_MONITOR_CADENCE_MS_CHIRHO..=MAX_LEDGER_MONITOR_CADENCE_MS_CHIRHO)
            .contains(&self.monitor_cadence_ms_chirho)
        {
            return Err(LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho);
        }
        if self.initial_mint_amount_chirho == 0
            || self.genesis_physical_ms_chirho == 0
            || self.mint_physical_ms_chirho <= self.genesis_physical_ms_chirho
        {
            return Err(LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho);
        }
        if self.projection_routes_chirho.is_empty() {
            return Err(LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho);
        }
        for route_chirho in &self.projection_routes_chirho {
            validate_authoring_token_chirho(&route_chirho.projection_name_chirho)?;
            validate_authoring_path_chirho(&route_chirho.head_path_chirho)?;
        }
        Ok(())
    }

    /// The plan's namespace-layout law: both namespaces are distinct children of one fresh parent,
    /// and the staging parent is a different top-level name. It subsumes the config's weaker
    /// disjointness rule, because two different children of one parent can never prefix each other.
    fn validate_namespace_layout_chirho(&self) -> LedgerRegenesisResultChirho<()> {
        if self.fresh_parent_chirho == self.staging_parent_chirho
            || self.fresh_parent_chirho.contains('/')
            || self.staging_parent_chirho.contains('/')
        {
            return Err(LedgerRegenesisRefusalChirho::AuthoringInputsNamespaceLayoutRefusedChirho);
        }
        let storage_parts_chirho = self.storage_namespace_chirho.split('/').collect::<Vec<_>>();
        let monitor_parts_chirho = self
            .monitor_evidence_namespace_chirho
            .split('/')
            .collect::<Vec<_>>();
        if storage_parts_chirho.len() != 2
            || monitor_parts_chirho.len() != 2
            || storage_parts_chirho[0] != self.fresh_parent_chirho
            || monitor_parts_chirho[0] != self.fresh_parent_chirho
            || storage_parts_chirho[1] == monitor_parts_chirho[1]
        {
            return Err(LedgerRegenesisRefusalChirho::AuthoringInputsNamespaceLayoutRefusedChirho);
        }
        Ok(())
    }

    /// The plan's path-distinctness law, applied where the CONFIG's own validator has none: the
    /// journal and the three registry paths are four distinct storage objects, and no projection
    /// head aliases any of them or another head. The monitor evidence path is deliberately absent
    /// from this set — it resolves inside the monitor namespace, not the storage namespace.
    fn validate_path_distinctness_chirho(&self) -> LedgerRegenesisResultChirho<()> {
        let mut storage_paths_chirho = BTreeSet::from([
            self.journal_path_chirho.as_str(),
            self.kind_registry_path_chirho.as_str(),
            self.projection_registry_path_chirho.as_str(),
            self.source_registry_path_chirho.as_str(),
        ]);
        if storage_paths_chirho.len() != 4 {
            return Err(LedgerRegenesisRefusalChirho::AuthoringInputsPathAliasRefusedChirho);
        }
        let mut projection_names_chirho = BTreeSet::new();
        for route_chirho in &self.projection_routes_chirho {
            if !projection_names_chirho.insert(route_chirho.projection_name_chirho.as_str()) {
                return Err(LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho);
            }
            if !storage_paths_chirho.insert(route_chirho.head_path_chirho.as_str()) {
                return Err(LedgerRegenesisRefusalChirho::AuthoringInputsPathAliasRefusedChirho);
            }
        }
        Ok(())
    }

    fn validate_authority_principals_chirho(&self) -> LedgerRegenesisResultChirho<()> {
        validate_authoring_principal_chirho(&self.issuer_principal_chirho)?;
        if let Some(activation_principal_chirho) = &self.activation_principal_chirho {
            validate_authoring_principal_chirho(activation_principal_chirho)?;
            if activation_principal_chirho == &self.issuer_principal_chirho {
                return Err(
                    LedgerRegenesisRefusalChirho::AuthoringInputsAuthorityPrincipalRefusedChirho,
                );
            }
        }
        Ok(())
    }

    fn validate_membership_chirho(&self) -> LedgerRegenesisResultChirho<()> {
        if self.members_chirho.is_empty() {
            return Err(LedgerRegenesisRefusalChirho::AuthoringInputsMembershipRefusedChirho);
        }
        let mut members_chirho = BTreeSet::new();
        for member_chirho in &self.members_chirho {
            validate_ledger_account_owner_chirho(&member_chirho.owner_chirho).map_err(
                |_error_chirho| {
                    LedgerRegenesisRefusalChirho::AuthoringInputsMembershipRefusedChirho
                },
            )?;
            if validate_authoring_token_chirho(&member_chirho.kind_id_chirho).is_err()
                || !members_chirho.insert(member_chirho)
            {
                return Err(LedgerRegenesisRefusalChirho::AuthoringInputsMembershipRefusedChirho);
            }
        }
        Ok(())
    }

    fn validate_signer_refs_chirho(&self) -> LedgerRegenesisResultChirho<()> {
        let mut unique_names_chirho = BTreeSet::new();
        for name_chirho in [
            &self.signer_secrets_chirho.journal_chirho,
            &self.signer_secrets_chirho.config_chirho,
            &self.signer_secrets_chirho.feeder_chirho,
            &self.signer_secrets_chirho.kind_root_chirho,
            &self.signer_secrets_chirho.effect_intent_chirho,
            &self.signer_secrets_chirho.effect_terminal_chirho,
        ] {
            if validate_authoring_token_chirho(name_chirho).is_err()
                || !unique_names_chirho.insert(name_chirho)
            {
                return Err(LedgerRegenesisRefusalChirho::AuthoringInputsSignerRefsRefusedChirho);
            }
        }
        Ok(())
    }

    /// The priced effect charges an asset kind that is resolved against the verified kind registry
    /// at serve time, so it can only ever name the kind this document's own plan will create.
    fn validate_provider_binding_chirho(&self) -> LedgerRegenesisResultChirho<()> {
        let Some(postgres_effect_chirho) = &self.postgres_effect_chirho else {
            return Ok(());
        };
        match postgres_effect_chirho.posture_chirho {
            LedgerHostPostgresEffectPostureChirho::LocalPhaseBChirho => {}
        }
        validate_authoring_token_chirho(&postgres_effect_chirho.connection_secret_chirho)?;
        validate_authoring_token_chirho(&postgres_effect_chirho.billing_kind_chirho)?;
        if postgres_effect_chirho.billing_kind_chirho != self.kind_id_chirho {
            return Err(LedgerRegenesisRefusalChirho::AuthoringInputsBillingKindMismatchChirho);
        }
        Ok(())
    }
}

/// Refuse any hex-shaped run long enough to be a verifier pin. Case-insensitive on purpose: a pin
/// is lowercase, and an uppercase copy would be a pin one `to_lowercase` away.
fn refuse_key_material_shaped_runs_chirho(bytes_chirho: &[u8]) -> LedgerRegenesisResultChirho<()> {
    let mut run_chirho = 0usize;
    for byte_chirho in bytes_chirho {
        if byte_chirho.is_ascii_hexdigit() {
            run_chirho += 1;
            if run_chirho > MAX_AUTHORING_INPUT_HEX_RUN_CHIRHO {
                return Err(LedgerRegenesisRefusalChirho::AuthoringInputsKeyMaterialRefusedChirho);
            }
        } else {
            run_chirho = 0;
        }
    }
    Ok(())
}

fn validate_authoring_principal_chirho(value_chirho: &str) -> LedgerRegenesisResultChirho<()> {
    validate_authoring_token_chirho(value_chirho).map_err(|_error_chirho| {
        LedgerRegenesisRefusalChirho::AuthoringInputsAuthorityPrincipalRefusedChirho
    })
}

fn validate_authoring_path_chirho(value_chirho: &str) -> LedgerRegenesisResultChirho<()> {
    if value_chirho.starts_with('/')
        || value_chirho
            .split('/')
            .any(|part_chirho| part_chirho.is_empty() || part_chirho == "." || part_chirho == "..")
    {
        return Err(LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho);
    }
    for part_chirho in value_chirho.split('/') {
        validate_authoring_token_chirho(part_chirho)?;
    }
    Ok(())
}

fn validate_authoring_token_chirho(value_chirho: &str) -> LedgerRegenesisResultChirho<()> {
    if value_chirho.is_empty()
        || value_chirho.len() > MAX_AUTHORING_INPUT_TOKEN_BYTES_CHIRHO
        || !value_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase()
                || byte_chirho.is_ascii_digit()
                || matches!(byte_chirho, b'-' | b'_' | b':' | b'.')
        })
    {
        return Err(LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho);
    }
    Ok(())
}
