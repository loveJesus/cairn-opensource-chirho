// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Config — the `cairn-chirho.toml` that `up` reads to run the platform: store root, HTTP port,
//! tenant, and limits. A missing file or missing fields fall back to defaults, so `up` works out of the box.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

pub const LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO: &str = "ledger-host-config-v1-chirho";
pub const LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO: &str = "ledger-host-config-v2-chirho";
pub const LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO: &str = "ledger-host-config-v3-chirho";
pub const LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO: &str = "ledger-host-config-v4-chirho";
pub const LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO: &str =
    "ledger-host-postgres-effect-config-v1-chirho";
pub const LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO: &str =
    "ledger-host-test-kind-marker-v1-chirho";
/// The reserved kind-issuer principal prefix a test-kind host config must use, and which a config
/// WITHOUT the marker may not use. See [`LedgerHostTestKindMarkerConfigChirho`] for why the two are
/// laws about each other rather than two independent conventions.
pub const LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO: &str = "test-kind-chirho-";
pub const MIN_LEDGER_MONITOR_CADENCE_MS_CHIRHO: u64 = 1_000;
pub const MAX_LEDGER_MONITOR_CADENCE_MS_CHIRHO: u64 = 3_600_000;
pub const MAX_CONFIG_FILE_BYTES_CHIRHO: u64 = 1024 * 1024;

/// Failures owned by the deployment-channel config binding rather than TOML parsing or custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestBoundConfigRefusalChirho {
    ExpectedDigestInvalidChirho,
    ConfigFileMissingChirho,
    ConfigDigestMismatchChirho,
}

impl Display for DigestBoundConfigRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut Formatter<'_>) -> std::fmt::Result {
        formatter_chirho.write_str(match self {
            Self::ExpectedDigestInvalidChirho => "LedgerHostConfigExpectedDigestInvalidChirho",
            Self::ConfigFileMissingChirho => "LedgerHostConfigFileMissingChirho",
            Self::ConfigDigestMismatchChirho => "LedgerHostConfigDigestMismatchChirho",
        })
    }
}

impl std::error::Error for DigestBoundConfigRefusalChirho {}

/// One exact account in the local cluster's static declaration. Membership is account-scoped:
/// an owner admitted for one stable kind gains no authority over another kind.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostMemberConfigChirho {
    pub owner_chirho: String,
    pub kind_id_chirho: String,
}

/// Verifier-only kind issuer authority. There is deliberately no issuer-secret coordinate in
/// this type: the issuer private key remains operator-only and cannot enter the serving process.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostIssuerPinConfigChirho {
    pub principal_chirho: String,
    pub verifying_key_hex_chirho: String,
}

/// Verifier-only H3 activation authority. The private activation key stays operator-only and is
/// deliberately distinct from both the kind issuer and every runtime signer.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostActivationPinConfigChirho {
    pub principal_chirho: String,
    pub verifying_key_hex_chirho: String,
}

/// The one external authority permitted to authorize tenant-migration DESTINATIONS.
///
/// Carries a public key only, and there is no signing counterpart anywhere in the host: a node
/// verifies destination authorizations and can never author one. Absent means no destination may be
/// selected at all, which is the safe default rather than an incomplete configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostMigrationDestinationAuthorityConfigChirho {
    pub key_id_chirho: String,
    pub verifying_key_hex_chirho: String,
}

/// The geo control plane's role-bound key (C2.1 brick 1a-iii): the public pin its records must carry,
/// and the lineage they are signed for, plus the signer's secret name on the placement's voters.
///
/// The pin and the lineage are required together. TOML carries the signer's name only; its value
/// stays in the root's secret store, and a node off the voter set never resolves it.
///
/// Design: `spec-chirho/workstream-state-chirho/c2-durability-chirho/brick1-control-plane-signer-design-chirho.md`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostControlPlaneConfigChirho {
    pub verifying_key_hex_chirho: String,
    pub tenant_id_chirho: String,
    pub genesis_instance_id_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_secret_chirho: Option<String>,
}

/// Six pairwise-distinct runtime signer coordinates. Secret values remain in the root's secret
/// store; TOML carries names only.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostSignerRefsConfigChirho {
    pub journal_chirho: String,
    pub config_chirho: String,
    pub feeder_chirho: String,
    pub kind_root_chirho: String,
    pub effect_intent_chirho: String,
    pub effect_terminal_chirho: String,
}

/// Public-only roots admitted to a held GD7 process. Labels remain derived from the corresponding
/// signer-secret names, so the pin block cannot relabel any role. V3 carries only the journal root;
/// V4 requires both effect roots as well.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostHeldVerifierPinsConfigChirho {
    pub journal_verifying_key_hex_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_intent_verifying_key_hex_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_terminal_verifying_key_hex_chirho: Option<String>,
}

/// Says out loud that this host config was authored for a SYNTHETIC TEST KIND, so a production
/// composition can refuse to take authority from it.
///
/// **This marker is NOT the control, and saying so is part of shipping it.** An operator with write
/// access to the config file can delete this block; what actually makes a test-kind issuer unusable
/// in production is CUSTODY — a test-kind issuer secret that has never been in a production root's
/// secret store cannot sign that root's registry, because the pin is DERIVED from the secret rather
/// than asserted. The marker is defence in depth on top of that, and it buys two things custody does
/// not: a named refusal an operator can read, and a fence that fires before a resident actor starts.
///
/// **What deleting the block costs, measured rather than asserted.** It cannot be deleted alone:
/// `validate_chirho` requires the marker and the reserved
/// [`LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO`] issuer principal to agree in BOTH
/// directions, so a marker-less config naming a `test-kind-chirho-` issuer fails to parse anywhere.
/// Deleting the marker therefore forces an issuer-principal RENAME — and the principal string sits
/// inside each registry record's issuer-signed content (`issuer_signed_content_chirho` canonicalizes
/// the whole record), while the pinned verifier refuses any record whose issuer name differs from
/// the configured principal. So a renamed principal makes the test-kind registry unverifiable, and
/// the money path fails closed at registry load. Re-signing a registry under the new name needs the
/// private issuer half — which is the custody boundary again, and exactly where the guarantee lives.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostTestKindMarkerConfigChirho {
    pub schema_chirho: String,
    /// Opt a test-kind root OUT of the CF8 loss-witness requirement.
    ///
    /// The CF8 canary-window loss sequence is a MULTI-NODE HA drill; a single-node dev served-money
    /// test-kind root (a1's shape) has no loss sequence to witness. When this is `true` the resident
    /// actor MAY derive no loss-witness plan — but ONLY when the actor was opened through the dedicated
    /// normal-settlement dev door (which passes the exemption-permitted opener mode) on a single-node
    /// self-election with no compensation provider; every drill / shared-elector / compensation door
    /// passes the mandatory-witness mode and FAILS CLOSED on an exempt marker
    /// (`Cf8LossWitnessDrillExemptionRefusedChirho`), so a drill can never suppress its own witness by
    /// copying this flag. When `false`/absent (every existing config, via `#[serde(default)]`) the drill
    /// posture is unchanged: a marked config still REQUIRES `postgres_effect_chirho` and otherwise fails
    /// closed. The exemption is an EXPLICIT positive opt-out and never relaxes the drill guard.
    #[serde(default)]
    pub loss_witness_exempt_chirho: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostProjectionRouteConfigChirho {
    pub projection_name_chirho: String,
    pub head_path_chirho: String,
}

/// The only PostgreSQL host posture representable in this increment. Adding a hosted/client-
/// serving variant requires its own reviewed async-driver and custody slice.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LedgerHostPostgresEffectPostureChirho {
    LocalPhaseBChirho,
}

/// Optional Descriptor-D provider composition. Configuration carries only a secret name and one
/// billing-kind coordinate; callers cannot supply a DSN value, payer, price, amount, or route.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostPostgresEffectConfigChirho {
    pub schema_chirho: String,
    pub posture_chirho: LedgerHostPostgresEffectPostureChirho,
    pub connection_secret_chirho: String,
    pub billing_kind_chirho: String,
}

impl LedgerHostPostgresEffectConfigChirho {
    pub fn validate_chirho(&self) -> Result<()> {
        if self.schema_chirho != LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO {
            bail!("unsupported ledger host PostgreSQL effect config schema");
        }
        validate_config_token_chirho(
            "postgres_effect.connection_secret_chirho",
            &self.connection_secret_chirho,
        )?;
        validate_config_token_chirho(
            "postgres_effect.billing_kind_chirho",
            &self.billing_kind_chirho,
        )?;
        match self.posture_chirho {
            LedgerHostPostgresEffectPostureChirho::LocalPhaseBChirho => {}
        }
        Ok(())
    }
}

/// Optional CF6 host composition block. The outer runtime config remains backward-compatible;
/// presence of this block opts into a strict, versioned, no-default authority surface.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerHostConfigChirho {
    pub schema_chirho: String,
    pub storage_namespace_chirho: String,
    pub monitor_evidence_namespace_chirho: String,
    pub monitor_evidence_path_chirho: String,
    pub money_group_id_chirho: String,
    pub cluster_id_chirho: String,
    pub journal_path_chirho: String,
    pub local_epoch_chirho: u64,
    pub members_chirho: Vec<LedgerHostMemberConfigChirho>,
    pub kind_registry_path_chirho: String,
    pub kind_registry_id_chirho: String,
    pub kind_issuer_chirho: LedgerHostIssuerPinConfigChirho,
    #[serde(default)]
    pub activation_authority_chirho: Option<LedgerHostActivationPinConfigChirho>,
    /// ADOPT the journal already in this root when it has no resident writer identity.
    ///
    /// Set by an operator on a MIGRATION TARGET, for the one start that turns a staged root into a
    /// serving one. A migrated root carries the tenant's journal and cannot carry an identity — an
    /// identity binds the root's device and inode — and birth issues one only over a pristine
    /// journal, so without this a migrated root can never be opened.
    ///
    /// Default FALSE, and deliberately narrow at the point of use: it acts only when the identity is
    /// genuinely ABSENT, never when one is present-but-unreadable or bound to another root, so it
    /// cannot paper over a corrupt or foreign identity. It lives in the ledger config because that
    /// file already carries this root's identity-critical settings under the same custody check.
    #[serde(default)]
    pub adopt_migrated_root_chirho: bool,
    pub projection_registry_path_chirho: String,
    pub projection_registry_id_chirho: String,
    pub source_registry_path_chirho: String,
    pub source_registry_id_chirho: String,
    pub projection_routes_chirho: Vec<LedgerHostProjectionRouteConfigChirho>,
    pub signer_secrets_chirho: LedgerHostSignerRefsConfigChirho,
    #[serde(default)]
    pub held_verifier_pins_chirho: Option<LedgerHostHeldVerifierPinsConfigChirho>,
    #[serde(default)]
    pub migration_destination_authority_chirho:
        Option<LedgerHostMigrationDestinationAuthorityConfigChirho>,
    pub monitor_cadence_ms_chirho: u64,
    pub postgres_effect_chirho: Option<LedgerHostPostgresEffectConfigChirho>,
    /// Absent means this config claims to be a production host config. Present means it was authored
    /// for a synthetic test kind and every production resident-actor door refuses it. Defaulted
    /// ABSENT rather than required, because an old reviewed production config must keep parsing —
    /// and absence is the refusing-nothing posture, so the default cannot grant anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_kind_chirho: Option<LedgerHostTestKindMarkerConfigChirho>,
    /// The geo control plane's pin, lineage and voter signer name. Absent keeps today's node-key
    /// control plane, and absence grants nothing; present is admitted only beside held-verifier
    /// authority (schema v3 or v4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_plane_chirho: Option<LedgerHostControlPlaneConfigChirho>,
}

impl LedgerHostConfigChirho {
    pub fn validate_chirho(&self) -> Result<()> {
        match self.schema_chirho.as_str() {
            LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO
                if self.activation_authority_chirho.is_none()
                    && self.held_verifier_pins_chirho.is_none() => {}
            LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO => {
                bail!(
                    "ledger host config schema v1 cannot carry activation or held-verifier authority"
                );
            }
            LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO if self.held_verifier_pins_chirho.is_none() => {}
            LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO => {
                bail!("ledger host config schema v2 cannot carry held-verifier authority");
            }
            LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO
                if self
                    .held_verifier_pins_chirho
                    .as_ref()
                    .is_some_and(|pins_chirho| {
                        pins_chirho.effect_intent_verifying_key_hex_chirho.is_none()
                            && pins_chirho
                                .effect_terminal_verifying_key_hex_chirho
                                .is_none()
                    }) => {}
            LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO if self.held_verifier_pins_chirho.is_none() => {
                bail!("ledger host config schema v3 requires held-verifier authority");
            }
            LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO => {
                bail!("ledger host config schema v3 admits only journal held-verifier authority");
            }
            LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO
                if self
                    .held_verifier_pins_chirho
                    .as_ref()
                    .is_some_and(|pins_chirho| {
                        pins_chirho.effect_intent_verifying_key_hex_chirho.is_some()
                            && pins_chirho
                                .effect_terminal_verifying_key_hex_chirho
                                .is_some()
                    }) => {}
            LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO => {
                bail!(
                    "ledger host config schema v4 requires journal, effect-intent, and effect-terminal held-verifier authority"
                );
            }
            _ => bail!("unsupported ledger host config schema"),
        }
        validate_config_path_chirho("storage_namespace_chirho", &self.storage_namespace_chirho)?;
        validate_config_path_chirho(
            "monitor_evidence_namespace_chirho",
            &self.monitor_evidence_namespace_chirho,
        )?;
        validate_config_path_chirho(
            "monitor_evidence_path_chirho",
            &self.monitor_evidence_path_chirho,
        )?;
        if logical_namespaces_overlap_chirho(
            &self.storage_namespace_chirho,
            &self.monitor_evidence_namespace_chirho,
        ) {
            bail!("ledger and monitor evidence namespaces must be disjoint");
        }
        validate_config_token_chirho("money_group_id_chirho", &self.money_group_id_chirho)?;
        validate_config_token_chirho("cluster_id_chirho", &self.cluster_id_chirho)?;
        validate_config_path_chirho("journal_path_chirho", &self.journal_path_chirho)?;
        validate_config_path_chirho("kind_registry_path_chirho", &self.kind_registry_path_chirho)?;
        validate_config_token_chirho("kind_registry_id_chirho", &self.kind_registry_id_chirho)?;
        validate_config_token_chirho(
            "kind_issuer.principal_chirho",
            &self.kind_issuer_chirho.principal_chirho,
        )?;
        validate_verifying_key_hex_chirho(&self.kind_issuer_chirho.verifying_key_hex_chirho)?;
        // The marker and the reserved issuer-principal prefix are laws about EACH OTHER, in both
        // directions. One direction stops a test-kind config from wearing a production-looking
        // issuer name; the other stops the marker being deleted on its own, which is what turns
        // "delete one block" into "delete one block AND rename the authority the registry records
        // are signed under". Neither direction is the guarantee — custody is — but together they
        // make the cheap edit stop being cheap.
        let reserved_issuer_prefix_chirho = self
            .kind_issuer_chirho
            .principal_chirho
            .starts_with(LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO);
        match &self.test_kind_chirho {
            Some(test_kind_chirho) => {
                if test_kind_chirho.schema_chirho != LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO {
                    bail!("unsupported ledger host test-kind marker schema");
                }
                if !reserved_issuer_prefix_chirho {
                    bail!(
                        "test-kind ledger host config must name a {LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO}prefixed kind issuer principal"
                    );
                }
            }
            None if reserved_issuer_prefix_chirho => {
                bail!(
                    "a {LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO}prefixed kind issuer principal requires the test-kind marker"
                );
            }
            None => {}
        }
        if let Some(activation_authority_chirho) = &self.activation_authority_chirho {
            validate_config_token_chirho(
                "activation_authority.principal_chirho",
                &activation_authority_chirho.principal_chirho,
            )?;
            validate_verifying_key_hex_chirho(
                &activation_authority_chirho.verifying_key_hex_chirho,
            )?;
            if activation_authority_chirho.principal_chirho
                == self.kind_issuer_chirho.principal_chirho
                || activation_authority_chirho.verifying_key_hex_chirho
                    == self.kind_issuer_chirho.verifying_key_hex_chirho
            {
                bail!("ledger activation authority must be distinct from the kind issuer");
            }
        }
        if let Some(destination_authority_chirho) = &self.migration_destination_authority_chirho {
            validate_config_token_chirho(
                "migration_destination_authority.key_id_chirho",
                &destination_authority_chirho.key_id_chirho,
            )?;
            validate_verifying_key_hex_chirho(
                &destination_authority_chirho.verifying_key_hex_chirho,
            )?;
            // Distinct from the kind issuer for the same reason the activation authority is: one key
            // that can both mint kinds and authorize where a tenant moves is two authorities wearing
            // one hat. The check that a node cannot authorize ITSELF lives in the actor, where the
            // node's own key is known; config cannot see it.
            if destination_authority_chirho.verifying_key_hex_chirho
                == self.kind_issuer_chirho.verifying_key_hex_chirho
            {
                bail!(
                    "ledger migration destination authority must be distinct from the kind issuer"
                );
            }
            if self.activation_authority_chirho.as_ref().is_some_and(
                |activation_authority_chirho| {
                    destination_authority_chirho.verifying_key_hex_chirho
                        == activation_authority_chirho.verifying_key_hex_chirho
                },
            ) {
                bail!(
                    "ledger migration destination authority must be distinct from the resident-writer activation authority"
                );
            }
        }
        if let Some(held_verifier_pins_chirho) = &self.held_verifier_pins_chirho {
            validate_verifying_key_hex_chirho(
                &held_verifier_pins_chirho.journal_verifying_key_hex_chirho,
            )?;
            if let Some(effect_intent_verifying_key_hex_chirho) =
                &held_verifier_pins_chirho.effect_intent_verifying_key_hex_chirho
            {
                validate_verifying_key_hex_chirho(effect_intent_verifying_key_hex_chirho)?;
            }
            if let Some(effect_terminal_verifying_key_hex_chirho) =
                &held_verifier_pins_chirho.effect_terminal_verifying_key_hex_chirho
            {
                validate_verifying_key_hex_chirho(effect_terminal_verifying_key_hex_chirho)?;
            }
            let mut authority_keys_chirho =
                BTreeSet::from([&self.kind_issuer_chirho.verifying_key_hex_chirho]);
            authority_keys_chirho
                .insert(&held_verifier_pins_chirho.journal_verifying_key_hex_chirho);
            let mut expected_distinct_chirho = 2;
            if let Some(effect_intent_verifying_key_hex_chirho) =
                &held_verifier_pins_chirho.effect_intent_verifying_key_hex_chirho
            {
                authority_keys_chirho.insert(effect_intent_verifying_key_hex_chirho);
                expected_distinct_chirho += 1;
            }
            if let Some(effect_terminal_verifying_key_hex_chirho) =
                &held_verifier_pins_chirho.effect_terminal_verifying_key_hex_chirho
            {
                authority_keys_chirho.insert(effect_terminal_verifying_key_hex_chirho);
                expected_distinct_chirho += 1;
            }
            if let Some(activation_authority_chirho) = &self.activation_authority_chirho {
                authority_keys_chirho.insert(&activation_authority_chirho.verifying_key_hex_chirho);
                expected_distinct_chirho += 1;
            }
            if authority_keys_chirho.len() != expected_distinct_chirho {
                if self.schema_chirho == LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO {
                    bail!("held journal verifier root must be distinct from other authorities");
                }
                bail!(
                    "held verifier roots must be pairwise distinct from each other and other authorities"
                );
            }
        }
        validate_config_path_chirho(
            "projection_registry_path_chirho",
            &self.projection_registry_path_chirho,
        )?;
        validate_config_token_chirho(
            "projection_registry_id_chirho",
            &self.projection_registry_id_chirho,
        )?;
        validate_config_path_chirho(
            "source_registry_path_chirho",
            &self.source_registry_path_chirho,
        )?;
        validate_config_token_chirho("source_registry_id_chirho", &self.source_registry_id_chirho)?;
        if !(MIN_LEDGER_MONITOR_CADENCE_MS_CHIRHO..=MAX_LEDGER_MONITOR_CADENCE_MS_CHIRHO)
            .contains(&self.monitor_cadence_ms_chirho)
        {
            bail!(
                "ledger monitor cadence must be within {}..={} ms",
                MIN_LEDGER_MONITOR_CADENCE_MS_CHIRHO,
                MAX_LEDGER_MONITOR_CADENCE_MS_CHIRHO
            );
        }
        if self.members_chirho.is_empty() {
            bail!("ledger host static membership must not be empty");
        }
        let mut members_chirho = BTreeSet::new();
        for member_chirho in &self.members_chirho {
            validate_ledger_account_owner_chirho(&member_chirho.owner_chirho)?;
            validate_config_token_chirho("member.kind_id_chirho", &member_chirho.kind_id_chirho)?;
            if !members_chirho.insert(member_chirho) {
                bail!("ledger host static membership contains a duplicate account");
            }
        }
        if self.projection_routes_chirho.is_empty() {
            bail!("ledger host projection routes must not be empty");
        }
        let mut projection_names_chirho = BTreeSet::new();
        for route_chirho in &self.projection_routes_chirho {
            validate_config_token_chirho(
                "projection_route.projection_name_chirho",
                &route_chirho.projection_name_chirho,
            )?;
            validate_config_path_chirho(
                "projection_route.head_path_chirho",
                &route_chirho.head_path_chirho,
            )?;
            if !projection_names_chirho.insert(&route_chirho.projection_name_chirho) {
                bail!("ledger host projection routes contain a duplicate name");
            }
        }
        let signer_names_chirho = [
            &self.signer_secrets_chirho.journal_chirho,
            &self.signer_secrets_chirho.config_chirho,
            &self.signer_secrets_chirho.feeder_chirho,
            &self.signer_secrets_chirho.kind_root_chirho,
            &self.signer_secrets_chirho.effect_intent_chirho,
            &self.signer_secrets_chirho.effect_terminal_chirho,
        ];
        let mut unique_signer_names_chirho = BTreeSet::new();
        for signer_name_chirho in signer_names_chirho {
            validate_config_token_chirho("signer secret name", signer_name_chirho)?;
            if !unique_signer_names_chirho.insert(signer_name_chirho) {
                bail!("ledger host signer secret names must be pairwise distinct");
            }
        }
        if let Some(postgres_effect_chirho) = &self.postgres_effect_chirho {
            postgres_effect_chirho.validate_chirho()?;
        }
        self.validate_control_plane_chirho()
    }

    /// Check the control-plane block against everything else this config names. Config sees only its
    /// own pins and secret names; the node key, the GD7 control key and the loaded runtime signer keys
    /// are checked at startup by the composition that holds them.
    fn validate_control_plane_chirho(&self) -> Result<()> {
        let Some(control_plane_chirho) = &self.control_plane_chirho else {
            return Ok(());
        };
        if !matches!(
            self.schema_chirho.as_str(),
            LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO | LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO
        ) {
            bail!("control-plane authority requires held-verifier authority (ledger host config schema v3 or v4)");
        }
        validate_nonzero_lower_hex_32_chirho(
            "control_plane.verifying_key_hex_chirho",
            &control_plane_chirho.verifying_key_hex_chirho,
        )?;
        validate_config_token_chirho(
            "control_plane.tenant_id_chirho",
            &control_plane_chirho.tenant_id_chirho,
        )?;
        validate_nonzero_lower_hex_32_chirho(
            "control_plane.genesis_instance_id_chirho",
            &control_plane_chirho.genesis_instance_id_chirho,
        )?;
        let mut pinned_keys_chirho = vec![&self.kind_issuer_chirho.verifying_key_hex_chirho];
        if let Some(activation_authority_chirho) = &self.activation_authority_chirho {
            pinned_keys_chirho.push(&activation_authority_chirho.verifying_key_hex_chirho);
        }
        if let Some(destination_authority_chirho) = &self.migration_destination_authority_chirho {
            pinned_keys_chirho.push(&destination_authority_chirho.verifying_key_hex_chirho);
        }
        if let Some(held_verifier_pins_chirho) = &self.held_verifier_pins_chirho {
            pinned_keys_chirho.push(&held_verifier_pins_chirho.journal_verifying_key_hex_chirho);
            pinned_keys_chirho.extend(
                held_verifier_pins_chirho
                    .effect_intent_verifying_key_hex_chirho
                    .iter(),
            );
            pinned_keys_chirho.extend(
                held_verifier_pins_chirho
                    .effect_terminal_verifying_key_hex_chirho
                    .iter(),
            );
        }
        if pinned_keys_chirho.iter().any(|pinned_key_chirho| {
            **pinned_key_chirho == control_plane_chirho.verifying_key_hex_chirho
        }) {
            bail!("control-plane verifying key must be distinct from every other key this config pins");
        }
        if let Some(signer_secret_chirho) = &control_plane_chirho.signer_secret_chirho {
            validate_config_token_chirho(
                "control_plane.signer_secret_chirho",
                signer_secret_chirho,
            )?;
            let mut named_secrets_chirho = vec![
                &self.signer_secrets_chirho.journal_chirho,
                &self.signer_secrets_chirho.config_chirho,
                &self.signer_secrets_chirho.feeder_chirho,
                &self.signer_secrets_chirho.kind_root_chirho,
                &self.signer_secrets_chirho.effect_intent_chirho,
                &self.signer_secrets_chirho.effect_terminal_chirho,
            ];
            if let Some(postgres_effect_chirho) = &self.postgres_effect_chirho {
                named_secrets_chirho.push(&postgres_effect_chirho.connection_secret_chirho);
            }
            if named_secrets_chirho.contains(&signer_secret_chirho) {
                bail!("control-plane signer secret name must be distinct from every other secret this config names");
            }
        }
        Ok(())
    }
}

fn logical_namespaces_overlap_chirho(left_chirho: &str, right_chirho: &str) -> bool {
    let left_parts_chirho = left_chirho.split('/').collect::<Vec<_>>();
    let right_parts_chirho = right_chirho.split('/').collect::<Vec<_>>();
    left_parts_chirho.starts_with(&right_parts_chirho)
        || right_parts_chirho.starts_with(&left_parts_chirho)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ConfigChirho {
    /// Where the content-addressed + versioned stores live.
    pub root_chirho: String,
    /// Optional tenant id; when set, `up` serves `root/tenants-chirho/<tenant>`.
    pub tenant_chirho: Option<String>,
    /// HTTP serve port.
    pub port_chirho: u16,
    /// Max concurrent in-flight invokes (backpressure; 429 past this).
    pub inflight_limit_chirho: usize,
    /// Monotonic rolling window for the engine-owned served-DAG abuse floor.
    pub served_request_window_ms_chirho: u64,
    /// Maximum served DAG requests per verified principal or normalized client network per window.
    pub served_request_actor_max_chirho: u64,
    /// Maximum raw request-body bytes per principal or normalized client network per window.
    pub served_request_actor_body_bytes_chirho: u64,
    /// Maximum served DAG requests across this tenant root per window.
    pub served_request_global_max_chirho: u64,
    /// Maximum raw request-body bytes across this tenant root per window.
    pub served_request_global_body_bytes_chirho: u64,
    /// Maximum live principal/network quota buckets retained in process memory.
    pub served_request_actor_bucket_cap_chirho: usize,
    /// Successful sign-ins (login or scoped-token issue) per principal per hour; past it, every attempt for that
    /// principal is refused before its credential is checked (brick 4a).
    pub sign_in_principal_successes_per_hour_chirho: u64,
    /// Successful sign-ins per normalized client network per hour, counted in process memory only (brick 4a).
    pub sign_in_source_successes_per_hour_chirho: u64,
    /// FAILED attempts per normalized client network per 15-minute failure window, one budget across login, token and
    /// recover, counted in process memory only (R12).
    pub sign_in_source_failures_per_window_chirho: u64,
    /// Admin Bearer token accepted by POST /publish-chirho and GET /dashboard-chirho.
    /// Empty disables admin-token auth; owner-session publish can still work.
    pub publish_token_chirho: String,
    /// Server-side token required by public HTTP registration. Empty disables public registration.
    pub registration_token_chirho: String,
    /// When true, unmatched requests are resolved through the signed domain-binding table
    /// (host + path -> app route). Off by default: unmatched requests 404 exactly as before.
    pub domain_routing_enabled_chirho: bool,
    /// When true, the engine-rendered connection issuance road answers (K4 Part 3). Off by default: both of its routes
    /// answer 503 before reading anything. Customer issuance stays closed until it is opened deliberately.
    pub connection_issuance_enabled_chirho: bool,
    /// Optional existing durable geo-election JSON. Relative paths resolve beside this TOML.
    /// Presence selects the winner-only shared-elector `up` composition.
    pub geo_cluster_config_chirho: Option<String>,
    /// Absent means the ledger host is uncomposed. Present opts into the strict H2 authority block.
    pub ledger_host_chirho: Option<LedgerHostConfigChirho>,
}

impl Default for ConfigChirho {
    fn default() -> Self {
        Self {
            root_chirho: ".".to_string(),
            tenant_chirho: None,
            port_chirho: 8787,
            inflight_limit_chirho: 32,
            served_request_window_ms_chirho: 60_000,
            served_request_actor_max_chirho: 60,
            served_request_actor_body_bytes_chirho: 8 * 1024 * 1024,
            served_request_global_max_chirho: 600,
            served_request_global_body_bytes_chirho: 64 * 1024 * 1024,
            served_request_actor_bucket_cap_chirho: 4_096,
            sign_in_principal_successes_per_hour_chirho: 10,
            sign_in_source_successes_per_hour_chirho: 60,
            sign_in_source_failures_per_window_chirho: 100,
            publish_token_chirho: String::new(),
            registration_token_chirho: String::new(),
            domain_routing_enabled_chirho: false,
            connection_issuance_enabled_chirho: false,
            geo_cluster_config_chirho: None,
            ledger_host_chirho: None,
        }
    }
}

impl ConfigChirho {
    fn validate_chirho(&self) -> Result<()> {
        if self
            .geo_cluster_config_chirho
            .as_deref()
            .is_some_and(|path_chirho| path_chirho.trim().is_empty())
        {
            bail!("geo cluster config path must not be empty");
        }
        if let Some(ledger_host_chirho) = &self.ledger_host_chirho {
            ledger_host_chirho.validate_chirho()?;
            // The control plane's lineage names the tenant this runtime serves (agy #29556). A config
            // naming a different tenant, or none, points the lineage at the wrong root.
            if let Some(control_plane_chirho) = &ledger_host_chirho.control_plane_chirho {
                if self.tenant_chirho.as_deref()
                    != Some(control_plane_chirho.tenant_id_chirho.as_str())
                {
                    bail!("control-plane tenant must equal the runtime tenant_chirho");
                }
            }
        }
        Ok(())
    }
}

/// Load `cairn-chirho.toml`; if it is absent, return defaults (so `up` runs out of the box).
pub fn load_config_chirho(path_chirho: &Path) -> Result<ConfigChirho> {
    let Some(bytes_chirho) = read_config_file_bytes_chirho(path_chirho)? else {
        return Ok(ConfigChirho::default());
    };
    parse_config_chirho(std::str::from_utf8(&bytes_chirho)?)
}

/// Load only the exact config bytes reviewed through an external deployment channel.
///
/// The comparison precedes UTF-8 decoding and TOML parsing, and the returned value is parsed from
/// the same byte buffer that was hashed. Callers can therefore derive tenant and root coordinates
/// only from the reviewed bytes rather than parsing first and authenticating a later read.
pub fn load_digest_bound_config_chirho(
    path_chirho: &Path,
    expected_digest_chirho: &str,
) -> Result<ConfigChirho> {
    if !is_canonical_blake3_hex_chirho(expected_digest_chirho) {
        return Err(DigestBoundConfigRefusalChirho::ExpectedDigestInvalidChirho.into());
    }
    let bytes_chirho = read_config_file_bytes_chirho(path_chirho)?
        .ok_or(DigestBoundConfigRefusalChirho::ConfigFileMissingChirho)?;
    if blake3::hash(&bytes_chirho).to_hex().as_str() != expected_digest_chirho {
        return Err(DigestBoundConfigRefusalChirho::ConfigDigestMismatchChirho.into());
    }
    parse_config_chirho(std::str::from_utf8(&bytes_chirho)?)
}

fn read_config_file_bytes_chirho(path_chirho: &Path) -> Result<Option<Vec<u8>>> {
    let file_chirho = match File::open(path_chirho) {
        Ok(file_chirho) => file_chirho,
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error_chirho) => return Err(error_chirho.into()),
    };
    let metadata_chirho = file_chirho.metadata()?;
    if !metadata_chirho.is_file() {
        bail!("cairn config path must name a regular file");
    }
    if metadata_chirho.len() > MAX_CONFIG_FILE_BYTES_CHIRHO {
        bail!(
            "cairn config exceeds the {} byte limit",
            MAX_CONFIG_FILE_BYTES_CHIRHO
        );
    }
    let mut bytes_chirho =
        Vec::with_capacity(metadata_chirho.len().min(MAX_CONFIG_FILE_BYTES_CHIRHO) as usize);
    file_chirho
        .take(MAX_CONFIG_FILE_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)?;
    if bytes_chirho.len() as u64 > MAX_CONFIG_FILE_BYTES_CHIRHO {
        bail!(
            "cairn config exceeds the {} byte limit",
            MAX_CONFIG_FILE_BYTES_CHIRHO
        );
    }
    Ok(Some(bytes_chirho))
}

fn is_canonical_blake3_hex_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f'))
}

pub fn parse_config_chirho(text_chirho: &str) -> Result<ConfigChirho> {
    let config_chirho: ConfigChirho = toml::from_str(text_chirho)?;
    config_chirho.validate_chirho()?;
    Ok(config_chirho)
}

/// Serialize through the same typed host-config model that `up` parses, then parse and validate
/// the emitted bytes before returning them. Operator authors therefore cannot drift a second TOML
/// field/schema law away from the serving boundary.
pub fn serialize_config_chirho(config_chirho: &ConfigChirho) -> Result<String> {
    config_chirho.validate_chirho()?;
    let text_chirho = toml::to_string(config_chirho)?;
    parse_config_chirho(&text_chirho)?;
    Ok(text_chirho)
}

/// Account owners retain the existing static-token arm and add only the two exact principal
/// shapes emitted by `identity_chirho::next_principal_chirho`. Host membership, regenesis initial
/// owner, and the completed packet verifier use this single-coded H3 grammar; keep it aligned with
/// that emitter and the dependency-light credits-demo viewer check.
///
/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
pub fn validate_ledger_account_owner_chirho(value_chirho: &str) -> Result<()> {
    let identity_principal_chirho =
        value_chirho
            .split_once('/')
            .is_some_and(|(principal_kind_chirho, principal_id_chirho)| {
                matches!(principal_kind_chirho, "user" | "owner")
                    && principal_id_chirho.len() == 16
                    && principal_id_chirho.bytes().all(|byte_chirho| {
                        byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f')
                    })
            });
    if !config_token_is_valid_chirho(value_chirho) && !identity_principal_chirho {
        bail!(
            "ledger account owner must be one bounded lowercase token or exact platform principal"
        );
    }
    Ok(())
}

fn validate_config_token_chirho(field_chirho: &str, value_chirho: &str) -> Result<()> {
    if !config_token_is_valid_chirho(value_chirho) {
        bail!("{field_chirho} must be one bounded lowercase token");
    }
    Ok(())
}

fn config_token_is_valid_chirho(value_chirho: &str) -> bool {
    !value_chirho.is_empty()
        && value_chirho.len() <= 128
        && value_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase()
                || byte_chirho.is_ascii_digit()
                || matches!(byte_chirho, b'-' | b'_' | b':' | b'.')
        })
}

fn validate_config_path_chirho(field_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.starts_with('/')
        || value_chirho
            .split('/')
            .any(|part_chirho| part_chirho.is_empty() || part_chirho == "." || part_chirho == "..")
    {
        bail!("{field_chirho} must be a relative logical path without aliases");
    }
    for part_chirho in value_chirho.split('/') {
        validate_config_token_chirho(field_chirho, part_chirho)?;
    }
    Ok(())
}

fn validate_verifying_key_hex_chirho(value_chirho: &str) -> Result<()> {
    validate_nonzero_lower_hex_32_chirho("kind issuer verifying key", value_chirho)
}

fn validate_nonzero_lower_hex_32_chirho(field_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.len() != 64
        || !value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f'))
        || value_chirho.bytes().all(|byte_chirho| byte_chirho == b'0')
    {
        bail!("{field_chirho} must be one nonzero 32-byte lowercase-hex value");
    }
    Ok(())
}

#[cfg(test)]
#[path = "config_tests_chirho.rs"]
mod config_tests_chirho;
