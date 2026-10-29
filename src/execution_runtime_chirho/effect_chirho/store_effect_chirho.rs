// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Store-effect dispatch, sealing, and viewer-state namespace isolation.

use super::{
    query_prefix_within_scope_chirho, viewer_state_chirho, ScopedWriteStoreRequestChirho,
    SCOPED_WRITE_STORE_SCHEMA_CHIRHO,
};
use crate::dag_private_value_chirho::{PrivateValueOwnerChirho, RunAttributionSourceChirho};
use crate::model_chirho::{CapabilityChirho, HashChirho, RequestContextChirho};
use crate::versioned_chirho;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use std::path::Path;

pub(super) fn versioned_path_chirho(root_chirho: &Path) -> std::path::PathBuf {
    root_chirho.join("versioned-chirho.redb")
}

/// A store effect's response, and the private domain it must rest under: its seal subject and whose
/// container that subject is (the viewer's own, or the app owner's), when the response is private.
pub(super) struct StoreEffectOutputChirho {
    pub(super) response_chirho: Vec<u8>,
    pub(super) private_domain_chirho: Option<(String, PrivateValueOwnerChirho)>,
}

pub(super) fn decode_viewer_state_request_chirho(
    request_bytes_chirho: &[u8],
) -> Result<Option<super::ViewerStateRequestChirho>> {
    viewer_state_chirho::decode_request_chirho(request_bytes_chirho)
}

pub(super) fn run_write_store_chirho(
    root_chirho: &Path,
    capability_prefix_chirho: &str,
    request_bytes_chirho: &[u8],
    idempotency_chirho: &HashChirho,
    request_context_chirho: Option<&RequestContextChirho>,
    attribution_source_chirho: &RunAttributionSourceChirho<'_>,
) -> Result<StoreEffectOutputChirho> {
    if let Some(request_chirho) = decode_viewer_state_request_chirho(request_bytes_chirho)? {
        let output_chirho = viewer_state_chirho::run_write_chirho(
            root_chirho,
            capability_prefix_chirho,
            &request_chirho,
            request_bytes_chirho,
            idempotency_chirho,
            request_context_chirho,
        )?;
        return Ok(StoreEffectOutputChirho {
            response_chirho: output_chirho.response_chirho,
            private_domain_chirho: Some((
                output_chirho.private_subject_chirho,
                PrivateValueOwnerChirho::RequestActorChirho,
            )),
        });
    }
    refuse_reserved_prefix_chirho(capability_prefix_chirho)?;
    // App store state is the app owner's container; the signed-in user, if any, is the actor.
    let attribution_chirho =
        attribution_source_chirho.resolve_chirho(PrivateValueOwnerChirho::AppContainerChirho)?;
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))?;
    let (key_chirho, value_chirho) = scoped_write_store_target_chirho(
        root_chirho,
        capability_prefix_chirho,
        request_bytes_chirho,
    )?;
    let sealed_chirho = crate::store_seal_chirho::seal_and_put_store_value_chirho(
        root_chirho,
        &store_chirho,
        &attribution_chirho,
        request_context_chirho.map(|context_chirho| context_chirho.app_chirho.as_str()),
        &key_chirho,
        &value_chirho,
    )?;
    Ok(StoreEffectOutputChirho {
        response_chirho: value_chirho,
        private_domain_chirho: Some((
            sealed_chirho.sealed_chirho.subject_chirho,
            PrivateValueOwnerChirho::AppContainerChirho,
        )),
    })
}

pub(super) fn run_read_store_chirho(
    root_chirho: &Path,
    capability_prefix_chirho: &str,
    request_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<StoreEffectOutputChirho> {
    if let Some(request_chirho) = decode_viewer_state_request_chirho(request_bytes_chirho)? {
        let output_chirho = viewer_state_chirho::run_read_chirho(
            root_chirho,
            capability_prefix_chirho,
            &request_chirho,
            request_context_chirho,
        )?;
        return Ok(StoreEffectOutputChirho {
            response_chirho: output_chirho.response_chirho,
            private_domain_chirho: Some((
                output_chirho.private_subject_chirho,
                PrivateValueOwnerChirho::RequestActorChirho,
            )),
        });
    }
    // The publication status road: a live read of the viewer's own intents and the platform's
    // verified outcomes; public by construction (an intent is the act that made the page public),
    // so no private subject is bound to the response.
    if let Some(request_chirho) =
        crate::publication_chirho::status_chirho::decode_publication_status_request_chirho(
            request_bytes_chirho,
        )?
    {
        let response_chirho =
            crate::publication_chirho::status_chirho::run_publication_status_read_chirho(
                root_chirho,
                capability_prefix_chirho,
                &request_chirho,
                request_context_chirho,
            )?;
        return Ok(StoreEffectOutputChirho {
            response_chirho,
            private_domain_chirho: None,
        });
    }
    // The owner's keys (K3): a live read of the signed-in viewer's own key list, private to her.
    if let Some(request_chirho) =
        crate::oauth_chirho::decode_own_keys_read_request_chirho(request_bytes_chirho)?
    {
        let output_chirho = crate::oauth_chirho::run_own_keys_read_chirho(
            root_chirho,
            capability_prefix_chirho,
            &request_chirho,
            request_context_chirho,
        )?;
        return Ok(StoreEffectOutputChirho {
            response_chirho: output_chirho.response_chirho,
            private_domain_chirho: Some((
                output_chirho.private_subject_chirho,
                PrivateValueOwnerChirho::RequestActorChirho,
            )),
        });
    }
    refuse_reserved_prefix_chirho(capability_prefix_chirho)?;
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))?;
    let key_chirho = crate::tenant_chirho::validated_store_key_for_root_chirho(
        root_chirho,
        capability_prefix_chirho,
    )?;
    let row_chirho = store_chirho.get_chirho(&key_chirho)?.unwrap_or_default();
    match crate::store_seal_chirho::detect_sealed_store_value_chirho(&row_chirho)? {
        crate::store_seal_chirho::StoreValueViewChirho::SealedChirho(sealed_chirho) => {
            crate::store_seal_chirho::ensure_store_seal_subject_binds_key_chirho(
                &sealed_chirho.subject_chirho,
                &key_chirho,
            )?;
            let plaintext_chirho =
                crate::store_seal_chirho::unseal_store_value_chirho(root_chirho, &sealed_chirho)?;
            Ok(StoreEffectOutputChirho {
                response_chirho: plaintext_chirho,
                private_domain_chirho: Some((
                    sealed_chirho.subject_chirho,
                    PrivateValueOwnerChirho::AppContainerChirho,
                )),
            })
        }
        crate::store_seal_chirho::StoreValueViewChirho::NotSealedChirho => {
            Ok(StoreEffectOutputChirho {
                response_chirho: row_chirho,
                private_domain_chirho: None,
            })
        }
    }
}

/// The private domain (subject and owner source) under which a store effect response must rest.
///
/// Both execution and DAG-value resolution use this function family. A concurrent write between a
/// read here and execution fails in the safe direction because the response cannot resolve under an
/// unrelated subject.
pub(crate) fn store_seal_response_subject_chirho(
    root_chirho: &Path,
    capability_chirho: &CapabilityChirho,
    request_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<Option<(String, PrivateValueOwnerChirho)>> {
    let actor_chirho =
        |subject_chirho: String| (subject_chirho, PrivateValueOwnerChirho::RequestActorChirho);
    let app_chirho =
        |subject_chirho: String| (subject_chirho, PrivateValueOwnerChirho::AppContainerChirho);
    match capability_chirho {
        CapabilityChirho::WriteStoreChirho { prefix_chirho } => {
            if let Some(request_chirho) = decode_viewer_state_request_chirho(request_bytes_chirho)?
            {
                return viewer_state_chirho::response_subject_chirho(
                    &request_chirho,
                    request_context_chirho,
                )
                .map(|subject_chirho| Some(actor_chirho(subject_chirho)));
            }
            let (key_chirho, _value_chirho) =
                scoped_write_store_target_chirho(root_chirho, prefix_chirho, request_bytes_chirho)?;
            Ok(Some(app_chirho(
                crate::store_seal_chirho::store_seal_subject_chirho(
                    request_context_chirho.map(|context_chirho| context_chirho.app_chirho.as_str()),
                    &key_chirho,
                )?,
            )))
        }
        CapabilityChirho::ReadStoreChirho { prefix_chirho } => {
            if let Some(request_chirho) = decode_viewer_state_request_chirho(request_bytes_chirho)?
            {
                return viewer_state_chirho::response_subject_chirho(
                    &request_chirho,
                    request_context_chirho,
                )
                .map(|subject_chirho| Some(actor_chirho(subject_chirho)));
            }
            if let Some(request_chirho) =
                crate::oauth_chirho::decode_own_keys_read_request_chirho(request_bytes_chirho)?
            {
                return crate::oauth_chirho::own_keys_response_subject_chirho(
                    prefix_chirho,
                    &request_chirho,
                    request_context_chirho,
                )
                .map(|subject_chirho| Some(actor_chirho(subject_chirho)));
            }
            if crate::oauth_chirho::reserved_own_keys_prefix_chirho(prefix_chirho) {
                bail!("reserved own-keys capability prefix requires an OwnKeysReadRequestChirho");
            }
            // The publication status road is a virtual read with no store row behind it, and its
            // response is public by construction (the intent is the act that made the page
            // public); resolving it as a store key refused every served status read.
            if crate::publication_chirho::status_chirho::reserved_publication_prefix_chirho(
                prefix_chirho,
            ) {
                return Ok(None);
            }
            let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
                &versioned_path_chirho(root_chirho),
            )?;
            let key_chirho = crate::tenant_chirho::validated_store_key_for_root_chirho(
                root_chirho,
                prefix_chirho,
            )?;
            let Some(row_chirho) = store_chirho.get_chirho(&key_chirho)? else {
                return Ok(None);
            };
            match crate::store_seal_chirho::detect_sealed_store_value_chirho(&row_chirho)? {
                crate::store_seal_chirho::StoreValueViewChirho::SealedChirho(sealed_chirho) => {
                    Ok(Some(app_chirho(sealed_chirho.subject_chirho)))
                }
                crate::store_seal_chirho::StoreValueViewChirho::NotSealedChirho => Ok(None),
            }
        }
        CapabilityChirho::PaidEffectChirho { effect_chirho, .. }
            if effect_chirho
                == cairn_undo_plan_chirho::contract_chirho::LLM_SERVED_EFFECT_SUBTYPE_CHIRHO =>
        {
            // The served-LLM effect seals its response (and, per ruling 4, its prompt) to the
            // requesting viewer — the SAME subject the effect arm anchors under
            // (`request_context.user_principal_chirho`; see the LLM-subtype seal in the sibling
            // `effect_chirho` finalization). run_dag's value resolver must register the sealed response
            // under this subject, or `note_dag_output_bytes` reads the deliberately-private completion
            // as public CAS and fails closed. This resolves NOTHING new about who may read it — the
            // completion stays viewer-private; it only lets the same viewer's run find the value it just
            // sealed. Requiring the request context mirrors the effect arm exactly: a served-LLM effect
            // with no viewer context cannot seal, so it never reaches this point on a completion.
            let subject_chirho = request_context_chirho
                .map(|context_chirho| context_chirho.user_principal_chirho.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "served LLM effect has no request context to derive its viewer seal subject"
                    )
                })?;
            Ok(Some(actor_chirho(subject_chirho)))
        }
        _ => Ok(None),
    }
}

fn refuse_reserved_prefix_chirho(capability_prefix_chirho: &str) -> Result<()> {
    if viewer_state_chirho::reserved_capability_prefix_chirho(capability_prefix_chirho) {
        bail!("reserved viewer-state capability prefix requires a ViewerStateRequestChirho");
    }
    if crate::publication_chirho::status_chirho::reserved_publication_prefix_chirho(
        capability_prefix_chirho,
    ) {
        bail!("reserved publication capability prefix requires a PublicationStatusRequestChirho and is read-only");
    }
    if crate::oauth_chirho::reserved_own_keys_prefix_chirho(capability_prefix_chirho) {
        bail!("reserved own-keys capability prefix requires an OwnKeysReadRequestChirho and is read-only");
    }
    Ok(())
}

fn scoped_write_store_target_chirho(
    root_chirho: &Path,
    capability_prefix_chirho: &str,
    request_bytes_chirho: &[u8],
) -> Result<(String, Vec<u8>)> {
    let Some(request_chirho) = decode_scoped_write_request_chirho(request_bytes_chirho)? else {
        let key_chirho = crate::tenant_chirho::validated_store_key_for_root_chirho(
            root_chirho,
            capability_prefix_chirho,
        )?;
        return Ok((key_chirho, request_bytes_chirho.to_vec()));
    };
    if !query_prefix_within_scope_chirho(capability_prefix_chirho, &request_chirho.key_chirho) {
        bail!(
            "WriteStoreChirho request key '{}' is outside capability prefix '{}'",
            request_chirho.key_chirho,
            capability_prefix_chirho
        );
    }
    if request_chirho
        .key_chirho
        .starts_with(viewer_state_chirho::VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO)
    {
        bail!("legacy WriteStoreChirho requests cannot address the viewer-state namespace");
    }
    if crate::oauth_chirho::reserved_own_keys_prefix_chirho(&request_chirho.key_chirho) {
        bail!("WriteStoreChirho requests cannot address the own-keys namespace");
    }
    let key_chirho = crate::tenant_chirho::validated_store_key_for_root_chirho(
        root_chirho,
        &request_chirho.key_chirho,
    )?;
    let value_chirho = BASE64_CHIRHO
        .decode(request_chirho.value_base64_chirho.as_bytes())
        .context("decode ScopedWriteStoreRequestChirho value_base64_chirho")?;
    Ok((key_chirho, value_chirho))
}

fn decode_scoped_write_request_chirho(
    request_bytes_chirho: &[u8],
) -> Result<Option<ScopedWriteStoreRequestChirho>> {
    let Ok(value_chirho) = serde_json::from_slice::<serde_json::Value>(request_bytes_chirho) else {
        return Ok(None);
    };
    let Some(schema_chirho) = value_chirho
        .get("schema_chirho")
        .and_then(|schema_chirho| schema_chirho.as_str())
    else {
        return Ok(None);
    };
    if schema_chirho != SCOPED_WRITE_STORE_SCHEMA_CHIRHO {
        return Ok(None);
    }
    serde_json::from_value(value_chirho)
        .map(Some)
        .context("decode ScopedWriteStoreRequestChirho")
}
