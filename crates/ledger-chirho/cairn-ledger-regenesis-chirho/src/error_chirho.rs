// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fixed, value-redacted refusals at the operator regenesis boundary.

use crate::ledger_host_artifact_emission_chirho::LedgerHostArtifactKindChirho;
use crate::ledger_host_authoring_mode_chirho::LedgerHostAuthoringModeCoordinateChirho;
use crate::shareable_evidence_chirho::ShareableEvidenceRefusalReasonChirho;
use cairn_ledger_host_chirho::LedgerSignerRoleChirho;
use std::error::Error;
use std::fmt;

pub type LedgerRegenesisResultChirho<ValueChirho> =
    Result<ValueChirho, LedgerRegenesisRefusalChirho>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerRegenesisRefusalChirho {
    SelectedRootUnavailableChirho,
    ConfigCustodyRefusedChirho,
    ConfigUnavailableChirho,
    ConfigUncomposedChirho,
    ConfigInvalidChirho,
    PlanUnavailableChirho,
    PlanNotRegularChirho,
    PlanInvalidChirho,
    PlanSchemaRefusedChirho,
    PlanNonCanonicalChirho,
    PlanDigestInvalidChirho,
    PlanDigestMismatchChirho,
    PlanCoordinateRefusedChirho,
    PlanPolicyRefusedChirho,
    AuthoringInputsInvalidChirho,
    /// The reviewed authoring document is absent or unreadable. Mirrors `PlanUnavailableChirho`.
    AuthoringInputsUnavailableChirho,
    /// The reviewed authoring document is not one stable regular file within its size ceiling — a
    /// symlink, a hard link, a directory, or a file that grew between stat and read. Mirrors
    /// `PlanNotRegularChirho`.
    AuthoringInputsNotRegularChirho,
    /// The pasted expected digest is not 64 lowercase hex characters, so it was never a digest this
    /// program emitted. Distinct from the mismatch below so a typo cannot read as a changed file.
    AuthoringInputsDigestInvalidChirho,
    /// The reviewed authoring document's bytes do not digest to the value pasted from review, so
    /// the document being authored from is not the document that was reviewed.
    AuthoringInputsDigestMismatchChirho,
    DestinationAuthorityEnrollmentSigningKeyRefusedChirho,
    DestinationAuthorityEnrollmentInvalidChirho,
    DestinationAuthorityEnrollmentUnavailableChirho,
    DestinationAuthorityEnrollmentNotRegularChirho,
    DestinationAuthorityEnrollmentDigestInvalidChirho,
    DestinationAuthorityEnrollmentDigestMismatchChirho,
    DestinationAuthorityEnrollmentNonCanonicalChirho,
    DestinationAuthorityEnrollmentSchemaRefusedChirho,
    DestinationAuthorityEnrollmentAuthorityBindingRefusedChirho,
    DestinationAuthorityEnrollmentIntentDigestMismatchChirho,
    DestinationAuthorityEnrollmentSignatureRefusedChirho,
    DestinationAuthorityEnrollmentGenesisBindingRefusedChirho,
    ClusterGenesisRosterOperatorKeyInvalidChirho,
    ClusterGenesisRosterUnavailableChirho,
    ClusterGenesisRosterNotRegularChirho,
    ClusterGenesisRosterHeadUnavailableChirho,
    ClusterGenesisRosterHeadNotRegularChirho,
    ClusterGenesisRosterVerificationRefusedChirho,
    AuthoringInputsSchemaRefusedChirho,
    AuthoringInputsNonCanonicalChirho,
    AuthoringInputsKeyMaterialRefusedChirho,
    AuthoringInputsCoordinateRefusedChirho,
    AuthoringInputsNamespaceLayoutRefusedChirho,
    AuthoringInputsPathAliasRefusedChirho,
    AuthoringInputsAuthorityPrincipalRefusedChirho,
    AuthoringInputsMembershipRefusedChirho,
    AuthoringInputsSignerRefsRefusedChirho,
    AuthoringInputsBillingKindMismatchChirho,
    AuthoringPinRoleRefusedChirho,
    AuthoringActivationPinPairingRefusedChirho,
    /// A reviewed document requested the shared-journal test-kind augmentation while the
    /// invocation declared production. The mode is a tripwire rather than the authority boundary,
    /// but producing a production-looking v3 artifact from this drill-only choice is still refused
    /// before any secret is read.
    AuthoringSharedJournalRequiresTestKindChirho,
    /// A `TestKindChirho` authoring run named an issuer coordinate WITHOUT the reserved test-kind
    /// prefix. Carries which coordinate, because one is typed on the invocation and the other comes
    /// from the reviewed document — different places to go and fix it.
    AuthoringTestKindReservedNameMissingChirho {
        coordinate_chirho: LedgerHostAuthoringModeCoordinateChirho,
    },
    /// A `ProductionChirho` authoring run named an issuer coordinate WITH the reserved test-kind
    /// prefix. Deliberately a separate identity from its mirror above: "you forgot the drill naming"
    /// and "you reached for the drill's key while authoring a real host" are opposite mistakes, and
    /// a fixture aimed at one would otherwise pass on the other.
    AuthoringProductionReservedNameRefusedChirho {
        coordinate_chirho: LedgerHostAuthoringModeCoordinateChirho,
    },
    /// An emission output path could not be resolved at all: no parent, no file name, a parent that
    /// does not exist, or a parent this process cannot inspect. Distinct from the two below because
    /// "I could not tell" and "I could tell, and the answer is no" are different operator problems.
    AuthoringOutputPathRefusedChirho {
        artifact_chirho: LedgerHostArtifactKindChirho,
    },
    /// An emission output resolved to a parent outside the selected root. Resolution happens before
    /// this check, so a symlinked parent cannot pass it by looking in-root as text.
    AuthoringOutputOutsideRootChirho {
        artifact_chirho: LedgerHostArtifactKindChirho,
    },
    /// The named half of the no-overwrite law: something already occupies the output path. It
    /// carries the artifact because one road writes two files and an unlabelled refusal would send
    /// an operator to inspect the wrong one. A dangling symlink counts as occupied.
    AuthoringOutputExistsChirho {
        artifact_chirho: LedgerHostArtifactKindChirho,
    },
    /// Both emission outputs resolved to one object. There is no per-artifact label because the
    /// defect is the PAIR, and naming one of them would imply the other was acceptable.
    AuthoringOutputsAliasChirho,
    /// Creating, writing, or syncing an artifact failed — including `create_new` refusing a path
    /// that became occupied after it was checked, which is the atomic half of the no-overwrite law.
    AuthoringOutputWriteRefusedChirho {
        artifact_chirho: LedgerHostArtifactKindChirho,
    },
    /// The emitted config re-parsed cleanly but its `root_chirho` does not resolve to the root this
    /// authoring selected. Separate from `ConfigInvalidChirho` because such a config is perfectly
    /// valid — it is valid for somebody else's tree.
    AuthoringConfigRootBindingRefusedChirho,
    ConfigPlanMismatchChirho,
    NamespaceLayoutRefusedChirho,
    /// The catch-all for a runtime-signer custody failure that carries no typed detail. The five
    /// role-labelled variants below exist because the custody brick's arms must be able to assert
    /// WHICH law refused: absent, short, all-zero, duplicate-name, and duplicate-identity are five
    /// different defects with one shape, and a fixture aimed at one of them can otherwise pass on
    /// another. This variant stays for the pre-existing money-stage call sites and for an untyped
    /// error, so a broadened refusal never quietly becomes a narrower claim.
    RuntimeSignerRefusedChirho,
    RuntimeSignerSecretUnavailableChirho {
        runtime_role_chirho: LedgerSignerRoleChirho,
    },
    RuntimeSignerSecretLengthChirho {
        runtime_role_chirho: LedgerSignerRoleChirho,
    },
    RuntimeSignerSecretAllZeroChirho {
        runtime_role_chirho: LedgerSignerRoleChirho,
    },
    /// Two roles over ONE secret value under two different names. There is deliberately no sibling
    /// for two roles over one NAME: the reviewed document's own signer-refs law already refuses
    /// that before custody is asked, so a named variant for it would be a refusal no road can
    /// produce — and an unreachable refusal reads as a check that happens. A duplicate name that
    /// somehow reached the loader degrades to the broad `RuntimeSignerRefusedChirho` above, which
    /// is the fail-safe direction.
    RuntimeSignerDuplicateIdentityChirho {
        first_role_chirho: LedgerSignerRoleChirho,
        second_role_chirho: LedgerSignerRoleChirho,
    },
    ProviderSecretNameCollidesRuntimeSignerChirho {
        runtime_role_chirho: LedgerSignerRoleChirho,
    },
    ProviderSecretNameCollidesIssuerChirho,
    ProviderSecretNameCollidesActivationChirho,
    IssuerSecretRefusedChirho,
    IssuerSecretLengthChirho,
    IssuerSecretAllZeroChirho,
    IssuerPinMismatchChirho,
    IssuerSecretNameCollisionChirho {
        runtime_role_chirho: LedgerSignerRoleChirho,
    },
    IssuerIdentityCollisionChirho {
        runtime_role_chirho: LedgerSignerRoleChirho,
    },
    IssuerMessageClassRefusedChirho,
    ActivationConfigMissingChirho,
    ActivationSecretRefusedChirho,
    ActivationSecretLengthChirho,
    ActivationSecretAllZeroChirho,
    ActivationPinMismatchChirho,
    ActivationSecretMatchesIssuerChirho,
    ActivationIdentityMatchesIssuerChirho,
    ActivationSecretNameCollisionChirho {
        runtime_role_chirho: LedgerSignerRoleChirho,
    },
    ActivationIdentityCollisionChirho {
        runtime_role_chirho: LedgerSignerRoleChirho,
    },
    ActivationStatementRefusedChirho,
    ActivationAuthorizationUnavailableChirho,
    ActivationAuthorizationRefusedChirho,
    ActivationAuthorizationDigestMismatchChirho,
    FinalNamespaceExistsChirho,
    StagingNamespaceExistsChirho,
    StageFilesystemRefusedChirho,
    MoneyProvisionRefusedChirho,
    StalePolicyWasAcceptedChirho,
    StalePolicyWrongRefusalChirho,
    ProjectionCompletionRefusedChirho,
    ConservationRefusedChirho,
    EvidencePacketRefusedChirho,
    StageCompletionRequiredChirho,
    PublicationProofRefusedChirho,
    ShareableEvidenceRefusedChirho {
        reason_chirho: ShareableEvidenceRefusalReasonChirho,
    },
}

impl fmt::Display for LedgerRegenesisRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message_chirho = match self {
            Self::SelectedRootUnavailableChirho => "selected regenesis root is unavailable",
            Self::ConfigCustodyRefusedChirho => "ledger host config custody refused",
            Self::ConfigUnavailableChirho => "ledger host config is unavailable",
            Self::ConfigUncomposedChirho => "ledger host config block is absent",
            Self::ConfigInvalidChirho => "ledger host config is invalid",
            Self::PlanUnavailableChirho => "ledger regenesis plan is unavailable",
            Self::PlanNotRegularChirho => "ledger regenesis plan must be one regular file",
            Self::PlanInvalidChirho => "ledger regenesis plan is invalid",
            Self::PlanSchemaRefusedChirho => "ledger regenesis plan schema is unsupported",
            Self::PlanNonCanonicalChirho => "ledger regenesis plan bytes are not canonical",
            Self::PlanDigestInvalidChirho => "expected ledger regenesis plan digest is invalid",
            Self::PlanDigestMismatchChirho => "ledger regenesis plan digest does not match review",
            Self::PlanCoordinateRefusedChirho => "ledger regenesis plan coordinate is invalid",
            Self::PlanPolicyRefusedChirho => "ledger regenesis policy is invalid",
            Self::AuthoringInputsInvalidChirho => "ledger host authoring inputs are invalid",
            Self::AuthoringInputsUnavailableChirho => {
                "ledger host authoring inputs are unavailable"
            }
            Self::AuthoringInputsNotRegularChirho => {
                "ledger host authoring inputs must be one regular file"
            }
            Self::AuthoringInputsDigestInvalidChirho => {
                "expected ledger host authoring inputs digest is invalid"
            }
            Self::AuthoringInputsDigestMismatchChirho => {
                "ledger host authoring inputs digest does not match review"
            }
            Self::DestinationAuthorityEnrollmentSigningKeyRefusedChirho => {
                "destination authority enrollment signing-key custody refused"
            }
            Self::DestinationAuthorityEnrollmentInvalidChirho => {
                "destination authority enrollment is invalid"
            }
            Self::DestinationAuthorityEnrollmentUnavailableChirho => {
                "destination authority enrollment is unavailable"
            }
            Self::DestinationAuthorityEnrollmentNotRegularChirho => {
                "destination authority enrollment must be one regular file"
            }
            Self::DestinationAuthorityEnrollmentDigestInvalidChirho => {
                "expected destination authority enrollment digest is invalid"
            }
            Self::DestinationAuthorityEnrollmentDigestMismatchChirho => {
                "destination authority enrollment digest does not match review"
            }
            Self::DestinationAuthorityEnrollmentNonCanonicalChirho => {
                "destination authority enrollment bytes are not canonical"
            }
            Self::DestinationAuthorityEnrollmentSchemaRefusedChirho => {
                "destination authority enrollment schema or signature domain is unsupported"
            }
            Self::DestinationAuthorityEnrollmentAuthorityBindingRefusedChirho => {
                "destination authority enrollment public-key binding is invalid"
            }
            Self::DestinationAuthorityEnrollmentIntentDigestMismatchChirho => {
                "destination authority enrollment intent digest does not match its intent"
            }
            Self::DestinationAuthorityEnrollmentSignatureRefusedChirho => {
                "destination authority enrollment signature was refused"
            }
            Self::DestinationAuthorityEnrollmentGenesisBindingRefusedChirho => {
                "destination authority enrollment does not bind the verified cluster genesis"
            }
            Self::ClusterGenesisRosterOperatorKeyInvalidChirho => {
                "cluster-genesis roster operator public key is invalid"
            }
            Self::ClusterGenesisRosterUnavailableChirho => {
                "cluster-genesis membership roster is unavailable"
            }
            Self::ClusterGenesisRosterNotRegularChirho => {
                "cluster-genesis membership roster must be one regular file"
            }
            Self::ClusterGenesisRosterHeadUnavailableChirho => {
                "cluster-genesis membership roster head is unavailable"
            }
            Self::ClusterGenesisRosterHeadNotRegularChirho => {
                "cluster-genesis membership roster head must be one regular file"
            }
            Self::ClusterGenesisRosterVerificationRefusedChirho => {
                "cluster-genesis membership roster and signed head verification refused"
            }
            Self::AuthoringInputsSchemaRefusedChirho => {
                "ledger host authoring inputs schema is unsupported"
            }
            Self::AuthoringInputsNonCanonicalChirho => {
                "ledger host authoring inputs bytes are not canonical"
            }
            Self::AuthoringInputsKeyMaterialRefusedChirho => {
                "ledger host authoring inputs must carry no key material"
            }
            Self::AuthoringInputsCoordinateRefusedChirho => {
                "ledger host authoring inputs coordinate is invalid"
            }
            Self::AuthoringInputsNamespaceLayoutRefusedChirho => {
                "ledger host authoring inputs namespaces are not disjoint siblings"
            }
            Self::AuthoringInputsPathAliasRefusedChirho => {
                "ledger host authoring inputs alias one storage object twice"
            }
            Self::AuthoringInputsAuthorityPrincipalRefusedChirho => {
                "ledger host authoring inputs authority principal is invalid"
            }
            Self::AuthoringInputsMembershipRefusedChirho => {
                "ledger host authoring inputs membership is invalid"
            }
            Self::AuthoringInputsSignerRefsRefusedChirho => {
                "ledger host authoring inputs signer secret names are invalid"
            }
            Self::AuthoringInputsBillingKindMismatchChirho => {
                "ledger host authoring inputs billing kind does not bind the authored kind"
            }
            Self::AuthoringPinRoleRefusedChirho => {
                "derived verifier pin was supplied for the wrong offline authority"
            }
            Self::AuthoringActivationPinPairingRefusedChirho => {
                "activation principal and activation verifier pin must arrive together"
            }
            Self::AuthoringSharedJournalRequiresTestKindChirho => {
                "shared journal verifier authoring requires test-kind mode"
            }
            Self::AuthoringTestKindReservedNameMissingChirho { .. } => {
                "test-kind ledger host authoring requires the reserved issuer naming"
            }
            Self::AuthoringProductionReservedNameRefusedChirho { .. } => {
                "production ledger host authoring must not name a reserved test-kind issuer"
            }
            Self::AuthoringOutputPathRefusedChirho { .. } => {
                "ledger host authoring output path could not be resolved"
            }
            Self::AuthoringOutputOutsideRootChirho { .. } => {
                "ledger host authoring output must remain inside the selected root"
            }
            Self::AuthoringOutputExistsChirho { .. } => {
                "ledger host authoring output already exists; refusing overwrite"
            }
            Self::AuthoringOutputsAliasChirho => {
                "ledger host authoring outputs must not name one object"
            }
            Self::AuthoringOutputWriteRefusedChirho { .. } => {
                "ledger host authoring output could not be created, written, or synced"
            }
            Self::AuthoringConfigRootBindingRefusedChirho => {
                "authored ledger host config does not bind the selected root"
            }
            Self::ConfigPlanMismatchChirho => "ledger regenesis plan does not bind host config",
            Self::NamespaceLayoutRefusedChirho => {
                "ledger regenesis namespaces are not disjoint siblings"
            }
            Self::RuntimeSignerRefusedChirho => "runtime ledger signer custody refused",
            Self::RuntimeSignerSecretUnavailableChirho { .. } => {
                "runtime ledger signer secret is unavailable"
            }
            Self::RuntimeSignerSecretLengthChirho { .. } => {
                "runtime ledger signer secret must be exactly 32 bytes"
            }
            Self::RuntimeSignerSecretAllZeroChirho { .. } => {
                "runtime ledger signer secret must not be all zero"
            }
            Self::RuntimeSignerDuplicateIdentityChirho { .. } => {
                "runtime ledger signer roles must derive distinct identities"
            }
            Self::ProviderSecretNameCollidesRuntimeSignerChirho { .. } => {
                "provider connection secret name collides with a runtime signer role"
            }
            Self::ProviderSecretNameCollidesIssuerChirho => {
                "provider connection secret name collides with the offline kind issuer"
            }
            Self::ProviderSecretNameCollidesActivationChirho => {
                "provider connection secret name collides with the offline ledger activation authority"
            }
            Self::IssuerSecretRefusedChirho => "offline issuer secret is unavailable",
            Self::IssuerSecretLengthChirho => "offline issuer secret must be exactly 32 bytes",
            Self::IssuerSecretAllZeroChirho => "offline issuer secret must not be all zero",
            Self::IssuerPinMismatchChirho => {
                "offline issuer identity does not match the configured verifier pin"
            }
            Self::IssuerSecretNameCollisionChirho { .. } => {
                "offline issuer secret name collides with a runtime signer role"
            }
            Self::IssuerIdentityCollisionChirho { .. } => {
                "offline issuer identity collides with a runtime signer role"
            }
            Self::IssuerMessageClassRefusedChirho => {
                "offline issuer refused a foreign canonical message class"
            }
            Self::ActivationConfigMissingChirho => "ledger activation authority is not configured",
            Self::ActivationSecretRefusedChirho => {
                "offline ledger activation secret is unavailable"
            }
            Self::ActivationSecretLengthChirho => {
                "offline ledger activation secret must be exactly 32 bytes"
            }
            Self::ActivationSecretAllZeroChirho => {
                "offline ledger activation secret must not be all zero"
            }
            Self::ActivationPinMismatchChirho => {
                "offline ledger activation identity does not match the configured verifier pin"
            }
            Self::ActivationSecretMatchesIssuerChirho => {
                "offline ledger activation secret name matches the kind issuer"
            }
            Self::ActivationIdentityMatchesIssuerChirho => {
                "offline ledger activation identity matches the kind issuer"
            }
            Self::ActivationSecretNameCollisionChirho { .. } => {
                "offline ledger activation secret name collides with a runtime signer role"
            }
            Self::ActivationIdentityCollisionChirho { .. } => {
                "offline ledger activation identity collides with a runtime signer role"
            }
            Self::ActivationStatementRefusedChirho => {
                "offline ledger activation statement was refused"
            }
            Self::ActivationAuthorizationUnavailableChirho => {
                "pre-signed ledger activation authorization is unavailable"
            }
            Self::ActivationAuthorizationRefusedChirho => {
                "pre-signed ledger activation authorization file was refused"
            }
            Self::ActivationAuthorizationDigestMismatchChirho => {
                "pre-signed ledger activation authorization digest does not match review"
            }
            Self::FinalNamespaceExistsChirho => "final regenesis namespace already exists",
            Self::StagingNamespaceExistsChirho => {
                "regenesis staging namespace exists and requires operator inspection"
            }
            Self::StageFilesystemRefusedChirho => "regenesis staging filesystem operation refused",
            Self::MoneyProvisionRefusedChirho => "regenesis money provisioning refused",
            Self::StalePolicyWasAcceptedChirho => "superseded policy was accepted after amendment",
            Self::StalePolicyWrongRefusalChirho => {
                "superseded policy did not reach its distinct admission refusal"
            }
            Self::ProjectionCompletionRefusedChirho => "regenesis projection completion refused",
            Self::ConservationRefusedChirho => "regenesis conservation proof refused",
            Self::EvidencePacketRefusedChirho => "regenesis evidence packet refused",
            Self::StageCompletionRequiredChirho => {
                "regenesis stage cannot publish before the H3-B packet is complete"
            }
            Self::PublicationProofRefusedChirho => {
                "regenesis resident publication proof was refused"
            }
            Self::ShareableEvidenceRefusedChirho { .. } => "shareable item-6 evidence was refused",
        };
        formatter_chirho.write_str(message_chirho)?;
        match self {
            Self::IssuerSecretNameCollisionChirho {
                runtime_role_chirho,
            }
            | Self::IssuerIdentityCollisionChirho {
                runtime_role_chirho,
            }
            | Self::ActivationSecretNameCollisionChirho {
                runtime_role_chirho,
            }
            | Self::ActivationIdentityCollisionChirho {
                runtime_role_chirho,
            }
            | Self::RuntimeSignerSecretUnavailableChirho {
                runtime_role_chirho,
            }
            | Self::RuntimeSignerSecretLengthChirho {
                runtime_role_chirho,
            }
            | Self::RuntimeSignerSecretAllZeroChirho {
                runtime_role_chirho,
            }
            | Self::ProviderSecretNameCollidesRuntimeSignerChirho {
                runtime_role_chirho,
            } => write!(formatter_chirho, ": {runtime_role_chirho}"),
            Self::RuntimeSignerDuplicateIdentityChirho {
                first_role_chirho,
                second_role_chirho,
            } => write!(
                formatter_chirho,
                ": {first_role_chirho} and {second_role_chirho}"
            ),
            Self::ShareableEvidenceRefusedChirho { reason_chirho } => {
                write!(formatter_chirho, ": {reason_chirho}")
            }
            _ => Ok(()),
        }
    }
}

impl Error for LedgerRegenesisRefusalChirho {}
