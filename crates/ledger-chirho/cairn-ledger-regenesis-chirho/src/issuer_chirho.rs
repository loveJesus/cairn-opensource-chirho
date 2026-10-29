// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Operator-only offline authorities. The seventh identity signs only the kind-registry schema;
//! the distinct eighth identity signs only one canonical H3 activation statement. Both are checked
//! by name and identity against all six runtime signers and neither enters served composition.

use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use crate::ledger_host_artifact_derivation_chirho::{
    DerivedAuthorityPinChirho, DerivedAuthorityPinRoleChirho,
};
use cairn_config_chirho::config_chirho::{
    LedgerHostActivationPinConfigChirho, LedgerHostIssuerPinConfigChirho,
};
use cairn_kind_registry_chirho::record_chirho::KIND_REGISTRY_SCHEMA_V1_CHIRHO;
use cairn_ledger_host_chirho::{
    canonical_resident_ledger_activation_statement_chirho, HostLedgerSignersChirho,
    ResidentLedgerActivationAuthorizationChirho, ResidentLedgerActivationStatementChirho,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerSignerPortChirho;
use cairn_secret_chirho::secret_chirho::{resolve_secret_ref_chirho, secret_ref_chirho};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use std::fmt;
use std::path::Path;
use zeroize::Zeroize;

const SCHEMA_PREFIX_CHIRHO: &str = r#"{"schema_chirho":""#;
const OFFLINE_ISSUER_KEY_LABEL_CHIRHO: &str = "offline-kind-issuer-redacted-chirho";

pub(crate) struct OfflineKindIssuerSignerChirho {
    signing_key_chirho: SigningKey,
}

pub(crate) struct OfflineLedgerActivationSignerChirho {
    principal_chirho: String,
    signing_key_chirho: SigningKey,
}

impl fmt::Debug for OfflineKindIssuerSignerChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("OfflineKindIssuerSignerChirho")
            .field("key_material_chirho", &"<redacted-chirho>")
            .finish()
    }
}

impl OfflineKindIssuerSignerChirho {
    pub(crate) fn load_existing_chirho(
        selected_root_chirho: &Path,
        secret_name_chirho: &str,
        configured_pin_chirho: &LedgerHostIssuerPinConfigChirho,
        runtime_signers_chirho: &HostLedgerSignersChirho,
    ) -> LedgerRegenesisResultChirho<Self> {
        refuse_issuer_secret_name_collision_chirho(secret_name_chirho, runtime_signers_chirho)?;
        let signing_key_chirho =
            load_offline_issuer_signing_key_chirho(selected_root_chirho, secret_name_chirho)?;
        let identity_chirho = *signing_key_chirho.verifying_key().as_bytes();
        if hex_encode_chirho(&identity_chirho) != configured_pin_chirho.verifying_key_hex_chirho {
            return Err(LedgerRegenesisRefusalChirho::IssuerPinMismatchChirho);
        }
        refuse_issuer_identity_collision_chirho(&identity_chirho, runtime_signers_chirho)?;
        Ok(Self { signing_key_chirho })
    }

    fn admits_message_chirho(&self, signed_content_chirho: &str) -> bool {
        let Some(remainder_chirho) = signed_content_chirho.strip_prefix(SCHEMA_PREFIX_CHIRHO)
        else {
            return false;
        };
        let Some(end_chirho) = remainder_chirho.find('"') else {
            return false;
        };
        &remainder_chirho[..end_chirho] == KIND_REGISTRY_SCHEMA_V1_CHIRHO
    }
}

impl fmt::Debug for OfflineLedgerActivationSignerChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("OfflineLedgerActivationSignerChirho")
            .field("principal_chirho", &self.principal_chirho)
            .field("key_material_chirho", &"<redacted-chirho>")
            .finish()
    }
}

impl OfflineLedgerActivationSignerChirho {
    pub(crate) fn load_existing_chirho(
        selected_root_chirho: &Path,
        secret_name_chirho: &str,
        issuer_secret_name_chirho: &str,
        configured_pin_chirho: &LedgerHostActivationPinConfigChirho,
        configured_issuer_pin_chirho: &LedgerHostIssuerPinConfigChirho,
        runtime_signers_chirho: &HostLedgerSignersChirho,
    ) -> LedgerRegenesisResultChirho<Self> {
        refuse_activation_secret_name_collisions_chirho(
            secret_name_chirho,
            issuer_secret_name_chirho,
            runtime_signers_chirho,
        )?;
        let signing_key_chirho =
            load_offline_activation_signing_key_chirho(selected_root_chirho, secret_name_chirho)?;
        let identity_chirho = *signing_key_chirho.verifying_key().as_bytes();
        let identity_hex_chirho = hex_encode_chirho(&identity_chirho);
        if identity_hex_chirho != configured_pin_chirho.verifying_key_hex_chirho {
            return Err(LedgerRegenesisRefusalChirho::ActivationPinMismatchChirho);
        }
        refuse_activation_identity_collisions_chirho(
            &identity_chirho,
            &identity_hex_chirho,
            &configured_issuer_pin_chirho.verifying_key_hex_chirho,
            runtime_signers_chirho,
        )?;
        Ok(Self {
            principal_chirho: configured_pin_chirho.principal_chirho.clone(),
            signing_key_chirho,
        })
    }

    pub(crate) fn authorize_statement_chirho(
        &self,
        statement_chirho: ResidentLedgerActivationStatementChirho,
    ) -> LedgerRegenesisResultChirho<ResidentLedgerActivationAuthorizationChirho> {
        let canonical_statement_chirho = canonical_resident_ledger_activation_statement_chirho(
            &statement_chirho,
        )
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ActivationStatementRefusedChirho)?;
        Ok(ResidentLedgerActivationAuthorizationChirho {
            principal_chirho: self.principal_chirho.clone(),
            statement_chirho,
            signature_hex_chirho: hex_encode_chirho(
                &self
                    .signing_key_chirho
                    .sign(&canonical_statement_chirho)
                    .to_bytes(),
            ),
        })
    }
}

// **DELETED IN BRICK #7, and the deletion is the point rather than a tidy-up.** Two thin `pub`
// helpers used to live here — `offline_issuer_verifying_key_hex_chirho` and its activation twin —
// which derived a verifier pin from an existing secret and returned it as a bare `String`, taking
// no runtime signer set and therefore making NO identity comparison. They were the UN-VOUCHED pin
// road: an exported way to obtain the value a config pins without proving whose key it is. Their
// only caller was the credits-demo author, and brick #7 moved that road onto the custody binding,
// leaving them with zero callers.
//
// They are removed rather than left in place because a second, weaker road to the same value is
// exactly the drift this program exists to close: with them gone, the only way any crate can
// obtain a pin is `derived_kind_issuer_pin_chirho` / `derived_ledger_activation_pin_chirho` below,
// both `pub(crate)`, both requiring the loaded six, and both reachable from outside only through
// `bind_custody_and_derive_ledger_host_artifacts_chirho`. The key-shape law itself did not move —
// it lives, as it always did, in `load_offline_issuer_signing_key_chirho` /
// `load_offline_activation_signing_key_chirho`, which read an EXISTING secret and refuse an absent,
// short, or all-zero one.

/// The one home for "does this candidate offline-issuer secret NAME already belong to a runtime
/// signer role". Two callers share it — the signing loader above and the pin derivation below — so
/// the law cannot drift into two copies that disagree about what a collision is.
fn refuse_issuer_secret_name_collision_chirho(
    secret_name_chirho: &str,
    runtime_signers_chirho: &HostLedgerSignersChirho,
) -> LedgerRegenesisResultChirho<()> {
    match runtime_signers_chirho.matching_secret_name_role_chirho(secret_name_chirho) {
        Some(runtime_role_chirho) => Err(
            LedgerRegenesisRefusalChirho::IssuerSecretNameCollisionChirho {
                runtime_role_chirho,
            },
        ),
        None => Ok(()),
    }
}

/// The one home for "is this candidate offline-issuer IDENTITY already a runtime signer's". This is
/// the check a name comparison cannot make: two different names over the same 32 secret bytes are
/// one key wearing two labels, which silently collapses the two-roots containment into one root.
/// Only the candidate's own public bytes cross the boundary; the runtime side returns a role label.
fn refuse_issuer_identity_collision_chirho(
    identity_chirho: &[u8; 32],
    runtime_signers_chirho: &HostLedgerSignersChirho,
) -> LedgerRegenesisResultChirho<()> {
    match runtime_signers_chirho.matching_verifying_identity_role_chirho(identity_chirho) {
        Some(runtime_role_chirho) => Err(
            LedgerRegenesisRefusalChirho::IssuerIdentityCollisionChirho {
                runtime_role_chirho,
            },
        ),
        None => Ok(()),
    }
}

/// The activation counterparts of the two predicates above, in one place for the same reason.
fn refuse_activation_secret_name_collisions_chirho(
    secret_name_chirho: &str,
    issuer_secret_name_chirho: &str,
    runtime_signers_chirho: &HostLedgerSignersChirho,
) -> LedgerRegenesisResultChirho<()> {
    if secret_name_chirho == issuer_secret_name_chirho {
        return Err(LedgerRegenesisRefusalChirho::ActivationSecretMatchesIssuerChirho);
    }
    match runtime_signers_chirho.matching_secret_name_role_chirho(secret_name_chirho) {
        Some(runtime_role_chirho) => Err(
            LedgerRegenesisRefusalChirho::ActivationSecretNameCollisionChirho {
                runtime_role_chirho,
            },
        ),
        None => Ok(()),
    }
}

fn refuse_activation_identity_collisions_chirho(
    identity_chirho: &[u8; 32],
    identity_hex_chirho: &str,
    issuer_identity_hex_chirho: &str,
    runtime_signers_chirho: &HostLedgerSignersChirho,
) -> LedgerRegenesisResultChirho<()> {
    if identity_hex_chirho == issuer_identity_hex_chirho {
        return Err(LedgerRegenesisRefusalChirho::ActivationIdentityMatchesIssuerChirho);
    }
    match runtime_signers_chirho.matching_verifying_identity_role_chirho(identity_chirho) {
        Some(runtime_role_chirho) => Err(
            LedgerRegenesisRefusalChirho::ActivationIdentityCollisionChirho {
                runtime_role_chirho,
            },
        ),
        None => Ok(()),
    }
}

/// The role-tagged issuer derivation, and the ONLY road by which the generic authoring path can
/// obtain a kind-issuer pin. It creates nothing: the loader it wraps reads an EXISTING secret and
/// errors when that secret is absent, not 32 bytes, or all zero.
///
/// **The un-vouched road brick 2 flagged is closed twice over, and BOTH closures are load-bearing.**
/// Brick 3 wrote the wrong reason here and it was corrected at this line; the seal brick then made
/// the original reason true, so the history is worth one sentence: the claim "a pin cannot be
/// produced without a `HostLedgerSignersChirho`, and the only way to hold one is to have called
/// `load_existing_chirho`" was TRUE IN CONCLUSION and FALSE IN JUSTIFICATION for the window between
/// those two bricks, because the type's six fields were `pub`.
///
/// Measured, not argued, at the type: those six fields are now `pub(crate)`, read from outside only
/// through per-role accessors that hand back a shared borrow. For THIS crate — which is not
/// `cairn-ledger-host-chirho` — the struct literal and the field-assignment splice are both rejected
/// by the compiler, so holding a `&HostLedgerSignersChirho` here does prove `load_existing_chirho`
/// produced it, from ONE root, past its duplicate-name and duplicate-identity refusals. The two
/// doctests on that type are `compile_fail` and are the executable record of exactly that.
///
/// **The module-boundary closure still matters and must be kept**, for two reasons. The seal's
/// residual is in-crate: a module inside `cairn-ledger-host-chirho` could still overwrite one role
/// on a set it loaded, so the type's proof is a statement about foreign crates, not a universal one.
/// And independently of the type, this crate never accepts a caller's set: the single exported road
/// in [`crate::ledger_host_custody_binding_chirho`] BUILDS the set itself from the selected root, and
/// both derivations plus the artifact derivation are `pub(crate)`. Anyone adding a SECOND caller (the
/// later operator-facing authoring bricks) must keep that property: the set has to be loaded on the
/// road, never accepted as a parameter from outside this crate.
///
/// What it still does NOT prove is stated where a reader meets it: custody is proven on THIS root
/// only. Nothing here can show the same six secret VALUES are installed on a peer root, because no
/// cross-root input exists and none is invented.
pub(crate) fn derived_kind_issuer_pin_chirho(
    selected_root_chirho: &Path,
    secret_name_chirho: &str,
    runtime_signers_chirho: &HostLedgerSignersChirho,
) -> LedgerRegenesisResultChirho<DerivedAuthorityPinChirho> {
    refuse_issuer_secret_name_collision_chirho(secret_name_chirho, runtime_signers_chirho)?;
    let signing_key_chirho =
        load_offline_issuer_signing_key_chirho(selected_root_chirho, secret_name_chirho)?;
    let identity_chirho = *signing_key_chirho.verifying_key().as_bytes();
    refuse_issuer_identity_collision_chirho(&identity_chirho, runtime_signers_chirho)?;
    Ok(
        DerivedAuthorityPinChirho::from_existing_secret_derivation_chirho(
            DerivedAuthorityPinRoleChirho::KindIssuerChirho,
            hex_encode_chirho(&identity_chirho),
        ),
    )
}

/// The activation counterpart, tagged with its own role so the two pins can never be installed in
/// each other's config position, and fenced the same way: custody first, then load, never create.
/// It additionally takes the already-derived ISSUER pin, because the activation authority must be a
/// different identity from the issuer and the cheapest honest way to know that is to compare the
/// two derived public halves rather than to trust that two names imply two keys.
pub(crate) fn derived_ledger_activation_pin_chirho(
    selected_root_chirho: &Path,
    secret_name_chirho: &str,
    issuer_secret_name_chirho: &str,
    issuer_pin_chirho: &DerivedAuthorityPinChirho,
    runtime_signers_chirho: &HostLedgerSignersChirho,
) -> LedgerRegenesisResultChirho<DerivedAuthorityPinChirho> {
    // UNREACHABLE FROM THE EXPORTED ROAD TODAY, AND KEPT ON PURPOSE. There is exactly one caller —
    // `bind_custody_and_derive_ledger_host_artifacts_chirho` — and it derives the issuer pin itself
    // one statement earlier, so the pin it passes is always already tagged `KindIssuerChirho`. No
    // test can drive this arm without a second caller, which is why it has none: the honest label is
    // "unreachable", not "untested".
    //
    // It stays because the thing it guards is the pin ROLE TAG, and the tag exists precisely so the
    // issuer and activation pins can never be installed in each other's config position. The moment
    // a second caller appears — the later bricks add operator-facing authoring roads — this is what
    // turns "wired the wrong pin in" from a config that validates, parses and boots into a named
    // refusal. Deleting it would make exactly that mis-wiring silent, and a reader who finds it
    // should know it is a fence for the callers to come rather than one that fires today.
    if issuer_pin_chirho.role_chirho() != DerivedAuthorityPinRoleChirho::KindIssuerChirho {
        return Err(LedgerRegenesisRefusalChirho::AuthoringPinRoleRefusedChirho);
    }
    refuse_activation_secret_name_collisions_chirho(
        secret_name_chirho,
        issuer_secret_name_chirho,
        runtime_signers_chirho,
    )?;
    let signing_key_chirho =
        load_offline_activation_signing_key_chirho(selected_root_chirho, secret_name_chirho)?;
    let identity_chirho = *signing_key_chirho.verifying_key().as_bytes();
    let identity_hex_chirho = hex_encode_chirho(&identity_chirho);
    refuse_activation_identity_collisions_chirho(
        &identity_chirho,
        &identity_hex_chirho,
        issuer_pin_chirho.verifying_key_hex_chirho(),
        runtime_signers_chirho,
    )?;
    Ok(
        DerivedAuthorityPinChirho::from_existing_secret_derivation_chirho(
            DerivedAuthorityPinRoleChirho::LedgerActivationChirho,
            identity_hex_chirho,
        ),
    )
}

fn load_offline_issuer_signing_key_chirho(
    selected_root_chirho: &Path,
    secret_name_chirho: &str,
) -> LedgerRegenesisResultChirho<SigningKey> {
    let secret_ref_chirho = secret_ref_chirho(secret_name_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::IssuerSecretRefusedChirho)?;
    let secret_value_chirho =
        resolve_secret_ref_chirho(selected_root_chirho, &secret_ref_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::IssuerSecretRefusedChirho)?;
    if secret_value_chirho.as_bytes_chirho().len() != 32 {
        return Err(LedgerRegenesisRefusalChirho::IssuerSecretLengthChirho);
    }
    if secret_value_chirho
        .as_bytes_chirho()
        .iter()
        .all(|byte_chirho| *byte_chirho == 0)
    {
        return Err(LedgerRegenesisRefusalChirho::IssuerSecretAllZeroChirho);
    }
    let mut seed_chirho = [0_u8; 32];
    seed_chirho.copy_from_slice(secret_value_chirho.as_bytes_chirho());
    let signing_key_chirho = SigningKey::from_bytes(&seed_chirho);
    seed_chirho.zeroize();
    Ok(signing_key_chirho)
}

fn load_offline_activation_signing_key_chirho(
    selected_root_chirho: &Path,
    secret_name_chirho: &str,
) -> LedgerRegenesisResultChirho<SigningKey> {
    let secret_ref_chirho = secret_ref_chirho(secret_name_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ActivationSecretRefusedChirho)?;
    let secret_value_chirho =
        resolve_secret_ref_chirho(selected_root_chirho, &secret_ref_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ActivationSecretRefusedChirho)?;
    if secret_value_chirho.as_bytes_chirho().len() != 32 {
        return Err(LedgerRegenesisRefusalChirho::ActivationSecretLengthChirho);
    }
    if secret_value_chirho
        .as_bytes_chirho()
        .iter()
        .all(|byte_chirho| *byte_chirho == 0)
    {
        return Err(LedgerRegenesisRefusalChirho::ActivationSecretAllZeroChirho);
    }
    let mut seed_chirho = [0_u8; 32];
    seed_chirho.copy_from_slice(secret_value_chirho.as_bytes_chirho());
    let signing_key_chirho = SigningKey::from_bytes(&seed_chirho);
    seed_chirho.zeroize();
    Ok(signing_key_chirho)
}

impl LedgerSignerPortChirho for OfflineKindIssuerSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> anyhow::Result<String> {
        if !self.admits_message_chirho(signed_content_line_chirho) {
            return Err(LedgerRegenesisRefusalChirho::IssuerMessageClassRefusedChirho.into());
        }
        Ok(hex_encode_chirho(
            &self
                .signing_key_chirho
                .sign(signed_content_line_chirho.as_bytes())
                .to_bytes(),
        ))
    }

    fn key_id_chirho(&self) -> String {
        OFFLINE_ISSUER_KEY_LABEL_CHIRHO.to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        if !self.admits_message_chirho(signed_content_line_chirho) {
            return false;
        }
        let Some(signature_bytes_chirho) = hex_decode_64_chirho(sig_chirho) else {
            return false;
        };
        self.signing_key_chirho
            .verifying_key()
            .verify(
                signed_content_line_chirho.as_bytes(),
                &Signature::from_bytes(&signature_bytes_chirho),
            )
            .is_ok()
    }
}

fn hex_encode_chirho(bytes_chirho: &[u8]) -> String {
    let mut encoded_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        use std::fmt::Write;
        write!(&mut encoded_chirho, "{byte_chirho:02x}").expect("writing to a String cannot fail");
    }
    encoded_chirho
}

fn hex_decode_64_chirho(encoded_chirho: &str) -> Option<[u8; 64]> {
    if encoded_chirho.len() != 128 || !encoded_chirho.is_ascii() {
        return None;
    }
    let mut decoded_chirho = [0_u8; 64];
    for (index_chirho, byte_chirho) in decoded_chirho.iter_mut().enumerate() {
        let start_chirho = index_chirho * 2;
        *byte_chirho =
            u8::from_str_radix(&encoded_chirho[start_chirho..start_chirho + 2], 16).ok()?;
    }
    Some(decoded_chirho)
}
