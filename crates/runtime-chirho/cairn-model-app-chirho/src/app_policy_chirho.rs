// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure app input, response, and route-selection policy over verified records.

use crate::{
    AppInputModeChirho, AppInputPolicyRecordChirho, AppInputPolicyWarningChirho, AppRecordChirho,
    AppResponsePolicyRecordChirho, AppRouteRequestBodyPolicyChirho,
    AppRouteResponsePolicyRecordChirho, AppStatusChirho, ResolvedAppDagChirho,
    APP_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO, APP_ROUTE_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO,
};
use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::{HashChirho, RefsChirho};
use std::collections::BTreeMap;

pub fn validate_record_schema_chirho(
    schema_chirho: &str,
    expected_chirho: &str,
    label_chirho: &str,
) -> Result<()> {
    if !schema_chirho.is_empty() && schema_chirho != expected_chirho {
        bail!("unsupported {label_chirho} schema '{schema_chirho}'");
    }
    Ok(())
}

pub fn validate_app_response_policy_record_shape_chirho(
    record_chirho: &AppResponsePolicyRecordChirho,
    index_chirho: usize,
) -> Result<()> {
    validate_record_schema_chirho(
        &record_chirho.schema_chirho,
        APP_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO,
        "app response policy record",
    )?;
    if record_chirho.seq_chirho != index_chirho as u64 {
        bail!(
            "app response policy record seq gap at index {index_chirho}: entry seq is {}",
            record_chirho.seq_chirho
        );
    }
    crate::validate_app_name_chirho(&record_chirho.app_chirho)?;
    let normalized_chirho = crate::normalize_app_response_content_type_chirho(
        &record_chirho.response_content_type_chirho,
    )?;
    if normalized_chirho != record_chirho.response_content_type_chirho {
        bail!(
            "app response policy record {} content type is not canonical",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

pub fn validate_app_route_response_policy_record_shape_chirho(
    record_chirho: &AppRouteResponsePolicyRecordChirho,
    index_chirho: usize,
) -> Result<()> {
    validate_record_schema_chirho(
        &record_chirho.schema_chirho,
        APP_ROUTE_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO,
        "app route response policy record",
    )?;
    if record_chirho.seq_chirho != index_chirho as u64 {
        bail!(
            "app route response policy record seq gap at index {index_chirho}: entry seq is {}",
            record_chirho.seq_chirho
        );
    }
    crate::validate_app_name_chirho(&record_chirho.app_chirho)?;
    crate::validate_route_name_chirho(&record_chirho.route_chirho)?;
    let normalized_chirho = crate::normalize_app_route_response_content_type_chirho(
        &record_chirho.response_content_type_chirho,
    )?;
    if normalized_chirho != record_chirho.response_content_type_chirho {
        bail!(
            "app route response policy record {} content type is not canonical",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

pub fn app_ref_dag_chirho(refs_chirho: &RefsChirho, app_chirho: &str) -> Option<HashChirho> {
    refs_chirho
        .branches_chirho
        .get(&format!("app/{app_chirho}"))
        .cloned()
}

pub fn app_route_ref_target_chirho(
    refs_chirho: &RefsChirho,
    app_chirho: &str,
    route_chirho: &str,
) -> Option<HashChirho> {
    refs_chirho
        .branches_chirho
        .get(&format!("app-route/{app_chirho}/{route_chirho}"))
        .cloned()
}

pub fn deployed_app_names_chirho(refs_chirho: &RefsChirho) -> Vec<String> {
    refs_chirho
        .branches_chirho
        .keys()
        .filter_map(|branch_chirho| branch_chirho.strip_prefix("app/").map(str::to_string))
        .collect()
}

pub fn deployed_app_route_names_chirho(refs_chirho: &RefsChirho, app_chirho: &str) -> Vec<String> {
    let prefix_chirho = format!("app-route/{app_chirho}/");
    refs_chirho
        .branches_chirho
        .keys()
        .filter_map(|branch_chirho| {
            branch_chirho
                .strip_prefix(&prefix_chirho)
                .map(str::to_string)
        })
        .collect()
}

pub fn deployed_app_routes_from_refs_chirho(
    refs_chirho: &RefsChirho,
) -> BTreeMap<String, Vec<String>> {
    let apps_chirho = refs_chirho
        .branches_chirho
        .keys()
        .filter_map(|branch_chirho| branch_chirho.strip_prefix("app/").map(str::to_string))
        .collect::<std::collections::BTreeSet<_>>();
    let mut routes_chirho = BTreeMap::<String, Vec<String>>::new();
    for branch_chirho in refs_chirho.branches_chirho.keys() {
        if let Some(target_chirho) = branch_chirho.strip_prefix("app-route/") {
            if let Some((app_chirho, route_chirho)) = target_chirho.split_once('/') {
                routes_chirho
                    .entry(app_chirho.to_string())
                    .or_default()
                    .push(route_chirho.to_string());
            }
        }
    }
    apps_chirho
        .into_iter()
        .map(|app_chirho| {
            let app_routes_chirho = routes_chirho.remove(&app_chirho).unwrap_or_default();
            (app_chirho, app_routes_chirho)
        })
        .collect()
}

pub fn app_status_from_verified_state_chirho(
    app_chirho: &str,
    records_chirho: &[AppRecordChirho],
    resolved_chirho: Option<&ResolvedAppDagChirho>,
    routes_chirho: BTreeMap<String, HashChirho>,
) -> AppStatusChirho {
    AppStatusChirho {
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: records_chirho
            .last()
            .map(|record_chirho| record_chirho.owner_principal_chirho.clone()),
        dag_chirho: resolved_chirho.map(|resolved_chirho| resolved_chirho.dag_chirho.clone()),
        routes_chirho,
        active_chirho: resolved_chirho.is_some(),
        records_chirho: records_chirho.len(),
    }
}

pub fn app_input_mode_from_verified_records_chirho(
    records_chirho: &[AppInputPolicyRecordChirho],
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
    fail_closed_missing_policy_chirho: bool,
) -> Result<AppInputModeChirho> {
    if let Some(route_chirho) = route_chirho {
        if let Some(record_chirho) = records_chirho.iter().rev().find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.route_chirho.as_deref() == Some(route_chirho)
                && record_chirho.owner_principal_chirho == owner_principal_chirho
        }) {
            if fail_closed_missing_policy_chirho
                && matches!(record_chirho.mode_chirho, AppInputModeChirho::PlainChirho)
                && input_surface_had_private_policy_chirho(
                    records_chirho,
                    app_chirho,
                    Some(route_chirho),
                    owner_principal_chirho,
                )
            {
                bail!(
                    "app input surface '{route_chirho}' cannot downgrade to PlainChirho after a signed PrivateBlobRefChirho policy"
                );
            }
            return Ok(record_chirho.mode_chirho.clone());
        }
    }
    if let Some(record_chirho) = records_chirho.iter().rev().find(|record_chirho| {
        record_chirho.app_chirho == app_chirho
            && record_chirho.route_chirho.is_none()
            && record_chirho.owner_principal_chirho == owner_principal_chirho
    }) {
        if fail_closed_missing_policy_chirho {
            if let Some(route_chirho) = route_chirho {
                if matches!(record_chirho.mode_chirho, AppInputModeChirho::PlainChirho) {
                    bail!(
                        "app input surface '{route_chirho}' needs a signed route input policy before request bodies can be handled"
                    );
                }
            } else if matches!(record_chirho.mode_chirho, AppInputModeChirho::PlainChirho)
                && input_surface_had_private_policy_chirho(
                    records_chirho,
                    app_chirho,
                    None,
                    owner_principal_chirho,
                )
            {
                bail!(
                    "app input surface '{app_chirho}' cannot downgrade to PlainChirho after a signed PrivateBlobRefChirho policy"
                );
            }
        }
        return Ok(record_chirho.mode_chirho.clone());
    }
    if fail_closed_missing_policy_chirho {
        let label_chirho = route_chirho.unwrap_or(app_chirho);
        bail!(
            "app input surface '{label_chirho}' needs a signed input policy before request bodies can be handled"
        );
    }
    Ok(AppInputModeChirho::PlainChirho)
}

/// Resolve the root request-body declaration from verified input-surface history. `None` means no
/// author declared a body policy; it is deliberately distinct from an explicit `AcceptBodyChirho`
/// declaration even though both currently accept at serve time. Once `NoBodyChirho` appears, the
/// restrictive policy is sticky and later mode-only records cannot weaken it.
pub fn app_root_request_body_policy_from_verified_records_chirho(
    records_chirho: &[AppInputPolicyRecordChirho],
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Option<AppRouteRequestBodyPolicyChirho> {
    let root_records_chirho = records_chirho.iter().filter(|record_chirho| {
        record_chirho.app_chirho == app_chirho
            && record_chirho.route_chirho.is_none()
            && record_chirho.owner_principal_chirho == owner_principal_chirho
    });
    if root_records_chirho.clone().any(|record_chirho| {
        matches!(
            record_chirho.request_body_policy_chirho,
            Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho)
        )
    }) {
        return Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho);
    }
    root_records_chirho
        .rev()
        .find_map(|record_chirho| record_chirho.request_body_policy_chirho.clone())
}

pub fn root_input_surface_had_no_body_policy_chirho(
    records_chirho: &[AppInputPolicyRecordChirho],
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> bool {
    matches!(
        app_root_request_body_policy_from_verified_records_chirho(
            records_chirho,
            app_chirho,
            owner_principal_chirho,
        ),
        Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho)
    )
}

/// The descriptor's typed input-mode resolution over ALREADY-VERIFIED records: distinguishes a
/// surface whose verified history proves no applicable signed policy (honestly "unset") from a
/// verified-history anomaly (an illegal Plain-after-Private downgrade record), so read surfaces
/// can fail closed on the anomaly instead of collapsing every non-Set outcome into a benign
/// label. Pure and total; Set outcomes mirror `app_input_mode_from_verified_records_chirho`
/// with `fail_closed_missing_policy_chirho = true` exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppInputModeResolutionChirho {
    SetChirho(AppInputModeChirho),
    UnsetChirho,
    RefusedDowngradeChirho,
}

pub fn app_input_mode_descriptor_resolution_chirho(
    records_chirho: &[AppInputPolicyRecordChirho],
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
) -> AppInputModeResolutionChirho {
    if let Some(route_chirho) = route_chirho {
        if let Some(record_chirho) = records_chirho.iter().rev().find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.route_chirho.as_deref() == Some(route_chirho)
                && record_chirho.owner_principal_chirho == owner_principal_chirho
        }) {
            if matches!(record_chirho.mode_chirho, AppInputModeChirho::PlainChirho)
                && input_surface_had_private_policy_chirho(
                    records_chirho,
                    app_chirho,
                    Some(route_chirho),
                    owner_principal_chirho,
                )
            {
                return AppInputModeResolutionChirho::RefusedDowngradeChirho;
            }
            return AppInputModeResolutionChirho::SetChirho(record_chirho.mode_chirho.clone());
        }
    }
    if let Some(record_chirho) = records_chirho.iter().rev().find(|record_chirho| {
        record_chirho.app_chirho == app_chirho
            && record_chirho.route_chirho.is_none()
            && record_chirho.owner_principal_chirho == owner_principal_chirho
    }) {
        if route_chirho.is_some() {
            // A route never inherits a root Plain policy — it needs its own signed policy.
            if matches!(record_chirho.mode_chirho, AppInputModeChirho::PlainChirho) {
                return AppInputModeResolutionChirho::UnsetChirho;
            }
        }
        return AppInputModeResolutionChirho::SetChirho(record_chirho.mode_chirho.clone());
    }
    AppInputModeResolutionChirho::UnsetChirho
}

fn input_surface_had_private_policy_chirho(
    records_chirho: &[AppInputPolicyRecordChirho],
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
) -> bool {
    records_chirho.iter().any(|record_chirho| {
        record_chirho.app_chirho == app_chirho
            && record_chirho.owner_principal_chirho == owner_principal_chirho
            && matches!(
                record_chirho.mode_chirho,
                AppInputModeChirho::PrivateBlobRefChirho { .. }
            )
            && match route_chirho {
                Some(route_chirho) => record_chirho.route_chirho.as_deref() == Some(route_chirho),
                None => record_chirho.route_chirho.is_none(),
            }
    })
}

pub fn input_surface_label_likely_pii_chirho(label_chirho: &str) -> bool {
    const TOKENS_CHIRHO: &[&str] = &[
        "address", "billing", "birth", "checkout", "client", "contact", "customer", "dob", "email",
        "feedback", "inbox", "lead", "message", "name", "payment", "phone", "profile", "register",
        "signup", "support", "ticket",
    ];
    label_chirho
        .split(|char_chirho: char| !char_chirho.is_ascii_alphanumeric())
        .filter(|token_chirho| !token_chirho.is_empty())
        .map(str::to_ascii_lowercase)
        .any(|token_chirho| TOKENS_CHIRHO.contains(&token_chirho.as_str()))
}

pub fn pii_input_policy_warning_reason_chirho(label_chirho: &str) -> String {
    format!(
        "'{label_chirho}' looks like a PII-bearing app input surface; set PrivateBlobRefChirho if request bodies may contain personal data"
    )
}

pub fn app_input_policy_warnings_from_verified_state_chirho(
    records_chirho: &[AppInputPolicyRecordChirho],
    deployed_routes_chirho: &BTreeMap<String, Vec<String>>,
    owners_chirho: &BTreeMap<String, String>,
) -> Result<Vec<AppInputPolicyWarningChirho>> {
    let mut warnings_chirho = Vec::new();
    for (app_chirho, routes_chirho) in deployed_routes_chirho {
        let Some(owner_chirho) = owners_chirho.get(app_chirho) else {
            continue;
        };
        let root_mode_chirho = app_input_mode_from_verified_records_chirho(
            records_chirho,
            app_chirho,
            None,
            owner_chirho,
            false,
        )?;
        if matches!(root_mode_chirho, AppInputModeChirho::PlainChirho)
            && input_surface_label_likely_pii_chirho(app_chirho)
        {
            warnings_chirho.push(AppInputPolicyWarningChirho {
                app_chirho: app_chirho.clone(),
                route_chirho: None,
                mode_chirho: root_mode_chirho,
                reason_chirho: pii_input_policy_warning_reason_chirho(app_chirho),
            });
        }
        for route_chirho in routes_chirho {
            let route_mode_chirho = app_input_mode_from_verified_records_chirho(
                records_chirho,
                app_chirho,
                Some(route_chirho),
                owner_chirho,
                false,
            )?;
            if matches!(route_mode_chirho, AppInputModeChirho::PlainChirho)
                && input_surface_label_likely_pii_chirho(route_chirho)
            {
                warnings_chirho.push(AppInputPolicyWarningChirho {
                    app_chirho: app_chirho.clone(),
                    route_chirho: Some(route_chirho.clone()),
                    mode_chirho: route_mode_chirho,
                    reason_chirho: pii_input_policy_warning_reason_chirho(route_chirho),
                });
            }
        }
    }
    Ok(warnings_chirho)
}

pub fn app_response_content_type_from_verified_records_chirho(
    records_chirho: &[AppResponsePolicyRecordChirho],
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Option<String> {
    records_chirho
        .iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.owner_principal_chirho == owner_principal_chirho
        })
        .map(|record_chirho| record_chirho.response_content_type_chirho.clone())
}

pub fn app_route_response_content_type_from_verified_records_chirho(
    records_chirho: &[AppRouteResponsePolicyRecordChirho],
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
) -> Option<String> {
    records_chirho
        .iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.route_chirho == route_chirho
                && record_chirho.owner_principal_chirho == owner_principal_chirho
        })
        .map(|record_chirho| record_chirho.response_content_type_chirho.clone())
}
