// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! App-route deployment, recovery, policy, and verified selection behind the root-owned app
//! authority boundary. The parent retains app identity, owner verification, and signed append
//! primitives; this child orchestrates those capabilities without widening them.

use super::*;

struct DeployAppRouteWithAuthorityInputChirho<'input_chirho> {
    root_chirho: &'input_chirho Path,
    app_chirho: &'input_chirho str,
    route_chirho: &'input_chirho str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &'input_chirho str,
    request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    unreviewed_dev_chirho: bool,
    authority_chirho: Option<&'input_chirho dyn HeadTransitionAuthorityPortChirho>,
}

pub fn deploy_app_route_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &str,
) -> Result<AppRouteRecordChirho> {
    deploy_app_route_with_request_body_policy_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        dag_chirho,
        owner_principal_chirho,
        None,
        false,
    )
}

pub fn deploy_app_route_with_head_transition_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &str,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<AppRouteRecordChirho> {
    deploy_app_route_with_request_body_policy_and_authority_chirho(
        DeployAppRouteWithAuthorityInputChirho {
            root_chirho,
            app_chirho,
            route_chirho,
            dag_chirho,
            owner_principal_chirho,
            request_body_policy_chirho: None,
            unreviewed_dev_chirho: false,
            authority_chirho: Some(authority_chirho),
        },
    )
}

pub fn deploy_app_route_unreviewed_dev_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &str,
) -> Result<AppRouteRecordChirho> {
    deploy_app_route_with_request_body_policy_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        dag_chirho,
        owner_principal_chirho,
        None,
        true,
    )
}

pub fn deploy_app_route_unreviewed_dev_with_head_transition_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &str,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<AppRouteRecordChirho> {
    deploy_app_route_with_request_body_policy_and_authority_chirho(
        DeployAppRouteWithAuthorityInputChirho {
            root_chirho,
            app_chirho,
            route_chirho,
            dag_chirho,
            owner_principal_chirho,
            request_body_policy_chirho: None,
            unreviewed_dev_chirho: true,
            authority_chirho: Some(authority_chirho),
        },
    )
}

impl AppRouteAuthorityPortChirho for RootAppRouteAuthorityPortChirho {
    fn verified_app_route_records_chirho(
        &self,
        root_chirho: &Path,
    ) -> Result<Vec<AppRouteRecordChirho>> {
        crate::app_chirho::verified_app_route_records_chirho(root_chirho)
    }

    fn validate_app_route_deploy_evidence_chirho(
        &self,
        root_chirho: &Path,
        state_chirho: &AppRouteAuthorityStateChirho,
    ) -> Result<()> {
        validate_app_route_deploy_chirho(
            root_chirho,
            &state_chirho.app_chirho,
            &state_chirho.route_chirho,
            &state_chirho.dag_chirho,
            &state_chirho.owner_principal_chirho,
        )?;
        app_deploy_evidence_chirho::validate_exact_dag_closure_chirho(
            root_chirho,
            &state_chirho.dag_chirho,
        )
    }

    fn sign_app_route_record_chirho(
        &self,
        root_chirho: &Path,
        record_chirho: &AppRouteRecordChirho,
    ) -> Result<String> {
        signer_chirho::sign_message_chirho(
            root_chirho,
            &app_route_record_message_chirho(record_chirho)?,
        )
    }

    fn sign_app_route_record_with_key_possession_chirho(
        &self,
        root_chirho: &Path,
        record_chirho: &AppRouteRecordChirho,
    ) -> Result<(String, String)> {
        let message_chirho = app_route_record_message_chirho(record_chirho)?;
        let possession_chirho =
            signer_chirho::sign_with_existing_key_possession_chirho(root_chirho, &message_chirho)?;
        let key_id_chirho = possession_chirho.key_id_chirho().to_string();
        Ok((key_id_chirho, possession_chirho.into_signature_hex_chirho()))
    }

    fn current_root_signing_key_id_chirho(&self, root_chirho: &Path) -> Result<String> {
        signer_chirho::existing_pubkey_hex_chirho(root_chirho)
    }

    fn append_signed_app_route_undeploy_record_unlocked_chirho(
        &self,
        root_chirho: &Path,
        app_chirho: &str,
        route_chirho: &str,
        owner_principal_chirho: &str,
    ) -> Result<AppRouteRecordChirho> {
        append_app_route_record_unlocked_chirho(
            root_chirho,
            app_chirho,
            route_chirho,
            owner_principal_chirho,
            None,
            None,
            AppRouteActionChirho::UndeployRouteChirho,
        )
    }
}

pub(crate) fn deploy_app_route_with_request_body_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &str,
    request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    unreviewed_dev_chirho: bool,
) -> Result<AppRouteRecordChirho> {
    deploy_app_route_with_request_body_policy_and_authority_chirho(
        DeployAppRouteWithAuthorityInputChirho {
            root_chirho,
            app_chirho,
            route_chirho,
            dag_chirho,
            owner_principal_chirho,
            request_body_policy_chirho,
            unreviewed_dev_chirho,
            authority_chirho: None,
        },
    )
}

pub(crate) fn deploy_app_route_with_request_body_policy_and_head_transition_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &str,
    request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<AppRouteRecordChirho> {
    deploy_app_route_with_request_body_policy_and_authority_chirho(
        DeployAppRouteWithAuthorityInputChirho {
            root_chirho,
            app_chirho,
            route_chirho,
            dag_chirho,
            owner_principal_chirho,
            request_body_policy_chirho,
            unreviewed_dev_chirho: false,
            authority_chirho: Some(authority_chirho),
        },
    )
}

fn deploy_app_route_with_request_body_policy_and_authority_chirho(
    input_chirho: DeployAppRouteWithAuthorityInputChirho<'_>,
) -> Result<AppRouteRecordChirho> {
    let DeployAppRouteWithAuthorityInputChirho {
        root_chirho,
        app_chirho,
        route_chirho,
        dag_chirho,
        owner_principal_chirho,
        request_body_policy_chirho,
        unreviewed_dev_chirho,
        authority_chirho,
    } = input_chirho;
    validate_app_route_deploy_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        &dag_chirho,
        owner_principal_chirho,
    )?;
    let state_chirho = AppRouteAuthorityStateChirho {
        schema_chirho: APP_ROUTE_AUTHORITY_STATE_SCHEMA_CHIRHO.to_string(),
        app_chirho: app_chirho.to_string(),
        route_chirho: route_chirho.to_string(),
        owner_principal_chirho: owner_principal_chirho.to_string(),
        dag_chirho,
        action_chirho: if unreviewed_dev_chirho {
            AppRouteActionChirho::DeployRouteUnreviewedDevChirho
        } else {
            AppRouteActionChirho::DeployRouteChirho
        },
        request_body_policy_chirho,
    };
    match authority_chirho {
        Some(authority_chirho) => {
            cairn_app_control_chirho::deploy_app_route_authority_with_head_transition_authority_chirho(
                &RootAppRouteAuthorityPortChirho,
                root_chirho,
                state_chirho,
                authority_chirho,
            )
        }
        None => cairn_app_control_chirho::deploy_app_route_authority_chirho(
            &RootAppRouteAuthorityPortChirho,
            root_chirho,
            state_chirho,
        ),
    }
}

pub fn recover_app_route_head_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
) -> Result<
    Option<cairn_writer_head_chirho::head_transition_chirho::HeadTransitionRecoveryOutcomeChirho>,
> {
    cairn_app_control_chirho::recover_app_route_head_chirho(
        &RootAppRouteAuthorityPortChirho,
        root_chirho,
        app_chirho,
        route_chirho,
    )
}

pub fn recover_app_route_head_removal_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
) -> Result<
    Option<
        cairn_app_control_chirho::app_route_head_removal_chirho::AppRouteHeadRemovalRecoveryOutcomeChirho,
    >,
>{
    validate_app_name_chirho(app_chirho)?;
    validate_route_name_chirho(route_chirho)?;
    cairn_app_control_chirho::app_route_head_removal_chirho::recover_app_route_head_removal_chirho(
        &RootAppRouteAuthorityPortChirho,
        root_chirho,
        app_chirho,
        route_chirho,
    )
}

pub fn undeploy_app_route_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<bool> {
    validate_app_name_chirho(app_chirho)?;
    validate_route_name_chirho(route_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        cairn_app_control_chirho::recover_app_route_head_unlocked_chirho(
            &RootAppRouteAuthorityPortChirho,
            root_chirho,
            app_chirho,
            route_chirho,
            fence_chirho,
        )?;
        cairn_app_control_chirho::app_route_head_removal_chirho::undeploy_app_route_head_unlocked_chirho(
            &RootAppRouteAuthorityPortChirho,
            root_chirho,
            app_chirho,
            route_chirho,
            owner_principal_chirho,
            fence_chirho,
        )
    })
}

pub fn set_app_route_response_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
    response_content_type_chirho: &str,
) -> Result<AppRouteResponsePolicyRecordChirho> {
    validate_app_name_chirho(app_chirho)?;
    validate_route_name_chirho(route_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let response_content_type_chirho =
        normalize_app_route_response_content_type_chirho(response_content_type_chirho)?;
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let _route_dag_chirho = resolve_app_route_chirho(
        root_chirho,
        &refs_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
    )?;
    append_app_route_response_policy_record_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
        &response_content_type_chirho,
    )
}

pub fn app_route_response_content_type_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<Option<String>> {
    validate_app_name_chirho(app_chirho)?;
    validate_route_name_chirho(route_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let records_chirho = verified_app_route_response_policy_records_chirho(root_chirho)?;
    Ok(
        app_route_response_content_type_from_verified_records_chirho(
            &records_chirho,
            app_chirho,
            route_chirho,
            owner_principal_chirho,
        ),
    )
}

pub fn resolve_app_route_chirho(
    root_chirho: &Path,
    refs_chirho: &crate::model_chirho::RefsChirho,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<HashChirho> {
    let selected_chirho = verified_selected_app_route_record_chirho(
        root_chirho,
        refs_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
    )?;
    selected_chirho
        .dag_chirho
        .ok_or_else(|| anyhow!("selected app route deploy record has no DAG"))
}

pub fn verified_selected_app_route_record_chirho(
    root_chirho: &Path,
    refs_chirho: &crate::model_chirho::RefsChirho,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<AppRouteRecordChirho> {
    validate_app_name_chirho(app_chirho)?;
    validate_route_name_chirho(route_chirho)?;
    // The verified selection is a pure function of the root fingerprint plus these refs-derived
    // hashes and the owner principal; cache by that exact key. Absent refs targets fall through to
    // the uncached body so its "not deployed" errors are byte-identical.
    match (
        app_ref_dag_chirho(refs_chirho, app_chirho),
        app_route_ref_target_chirho(refs_chirho, app_chirho, route_chirho),
    ) {
        (Some(app_ref_dag_chirho), Some(route_ref_target_chirho)) => {
            let selection_key_chirho = verified_view_cache_chirho::SelectedRouteKeyChirho {
                app_chirho: app_chirho.to_string(),
                route_chirho: route_chirho.to_string(),
                app_ref_dag_chirho: app_ref_dag_chirho.0,
                route_ref_target_chirho: route_ref_target_chirho.0,
                owner_principal_chirho: owner_principal_chirho.to_string(),
            };
            Ok(
                verified_view_cache_chirho::cached_selected_route_record_chirho(
                    root_chirho,
                    selection_key_chirho,
                    || {
                        verified_selected_app_route_record_uncached_chirho(
                            root_chirho,
                            refs_chirho,
                            app_chirho,
                            route_chirho,
                            owner_principal_chirho,
                        )
                    },
                )?
                .as_ref()
                .clone(),
            )
        }
        _ => verified_selected_app_route_record_uncached_chirho(
            root_chirho,
            refs_chirho,
            app_chirho,
            route_chirho,
            owner_principal_chirho,
        ),
    }
}

fn verified_selected_app_route_record_uncached_chirho(
    root_chirho: &Path,
    refs_chirho: &crate::model_chirho::RefsChirho,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<AppRouteRecordChirho> {
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let resolved_app_chirho = resolve_app_dag_chirho(root_chirho, refs_chirho, app_chirho)?;
    if resolved_app_chirho.owner_principal_chirho != owner_principal_chirho {
        bail!(
            "app '{app_chirho}' is owned by '{}', not '{owner_principal_chirho}'",
            resolved_app_chirho.owner_principal_chirho
        );
    }
    let ref_target_chirho = app_route_ref_target_chirho(refs_chirho, app_chirho, route_chirho)
        .ok_or_else(|| anyhow!("app route '{app_chirho}/{route_chirho}' is not deployed"))?;
    cairn_app_control_chirho::verified_selected_app_route_record_chirho(
        &RootAppRouteAuthorityPortChirho,
        root_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
        &ref_target_chirho,
    )
}

pub fn app_route_unreviewed_dev_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
    dag_chirho: &HashChirho,
) -> Result<bool> {
    validate_app_name_chirho(app_chirho)?;
    validate_route_name_chirho(route_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let selected_chirho = verified_selected_app_route_record_chirho(
        root_chirho,
        &refs_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
    )?;
    Ok(selected_chirho.dag_chirho.as_ref() == Some(dag_chirho)
        && app_route_action_is_unreviewed_dev_chirho(&selected_chirho.action_chirho))
}

pub fn load_app_route_records_chirho(root_chirho: &Path) -> Result<Vec<AppRouteRecordChirho>> {
    load_counted_serialized_jsonl_chirho(&app_route_records_path_chirho(root_chirho))
}

pub fn load_app_route_response_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppRouteResponsePolicyRecordChirho>> {
    load_counted_serialized_jsonl_chirho(&app_route_response_policy_records_path_chirho(
        root_chirho,
    ))
}

pub fn verify_app_routes_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_app_route_records_chirho(root_chirho)?;
    verify_app_route_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho.len())
}

pub fn verified_app_route_records_chirho(root_chirho: &Path) -> Result<Vec<AppRouteRecordChirho>> {
    Ok(
        verified_view_cache_chirho::cached_app_route_records_chirho(root_chirho, || {
            let records_chirho = load_app_route_records_chirho(root_chirho)?;
            verify_app_route_records_chirho(root_chirho, &records_chirho)?;
            Ok(records_chirho)
        })?
        .as_ref()
        .clone(),
    )
}

fn verify_app_route_records_chirho(
    root_chirho: &Path,
    records_chirho: &[AppRouteRecordChirho],
) -> Result<()> {
    if records_chirho.is_empty() {
        return Ok(());
    }
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let mut owner_check_chirho = AppOwnerLoopCheckChirho::new_chirho();
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        validate_app_route_record_schema_chirho(record_chirho)?;
        validate_app_route_record_transition_shape_chirho(
            record_chirho,
            cairn_writer_head_chirho::head_transition_chirho::HEAD_TRANSITION_ID_PREFIX_CHIRHO,
        )?;
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "app route record seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_app_name_chirho(&record_chirho.app_chirho)?;
        validate_route_name_chirho(&record_chirho.route_chirho)?;
        owner_check_chirho.ensure_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        if let Some(dag_chirho) = &record_chirho.dag_chirho {
            let _dag_obj_chirho: DagChirho =
                store_chirho::get_object_chirho(root_chirho, dag_chirho).with_context(|| {
                    format!(
                        "app route record {} points at missing DAG {}",
                        record_chirho.seq_chirho, dag_chirho.0
                    )
                })?;
        }
        let message_chirho = app_route_record_message_chirho(record_chirho)?;
        if !verify_record_sig_chirho(&pubkey_chirho, &message_chirho, &record_chirho.sig_chirho)? {
            bail!(
                "app route record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        if record_chirho.schema_chirho == APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO {
            let _state_chirho =
                cairn_app_control_chirho::verified_authority_state_for_app_route_record_chirho(
                    root_chirho,
                    record_chirho,
                )?;
        }
    }
    Ok(())
}

pub fn verify_app_route_response_policies_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_app_route_response_policy_records_chirho(root_chirho)?;
    verify_app_route_response_policy_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho.len())
}

fn verified_app_route_response_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppRouteResponsePolicyRecordChirho>> {
    Ok(
        verified_view_cache_chirho::cached_route_response_policy_records_chirho(
            root_chirho,
            || {
                let records_chirho = load_app_route_response_policy_records_chirho(root_chirho)?;
                verify_app_route_response_policy_records_chirho(root_chirho, &records_chirho)?;
                Ok(records_chirho)
            },
        )?
        .as_ref()
        .clone(),
    )
}

fn verify_app_route_response_policy_records_chirho(
    root_chirho: &Path,
    records_chirho: &[AppRouteResponsePolicyRecordChirho],
) -> Result<()> {
    if records_chirho.is_empty() {
        return Ok(());
    }
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let mut owner_check_chirho = AppOwnerLoopCheckChirho::new_chirho();
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        validate_app_route_response_policy_record_shape_chirho(record_chirho, i_chirho)?;
        owner_check_chirho.ensure_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        let message_chirho = app_route_response_policy_record_message_chirho(record_chirho)?;
        if !verify_record_sig_chirho(&pubkey_chirho, &message_chirho, &record_chirho.sig_chirho)? {
            bail!(
                "app route response policy record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

fn append_app_route_response_policy_record_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
    response_content_type_chirho: &str,
) -> Result<AppRouteResponsePolicyRecordChirho> {
    let path_chirho = app_route_response_policy_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = AppRouteResponsePolicyRecordChirho {
            seq_chirho,
            schema_chirho: APP_ROUTE_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            route_chirho: route_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            response_content_type_chirho: response_content_type_chirho.to_string(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = app_route_response_policy_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}
