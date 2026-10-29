// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Deploy-time openings of named routes to limited keys: each opening is checked against its route's DAG, and a deploy
//! that opens anything, or redeploys an app already in limited-key mode, retires the app's legacy keys and records the
//! opening in one locked section, so no legacy key outlives the opt-in and none is live beside the opening.
//! Workflow: limited-key authority (K1),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.

use super::{AppDeployManifestChirho, ValidatedAppDeployRouteChirho};
use crate::model_chirho::{CapabilityChirho, HashChirho};
use crate::{app_chirho, seqlog_chirho};
use anyhow::{bail, Context, Result};
use cairn_capability_chirho::capability_key_grant_chirho::{
    dag_key_action_class_chirho, KeyActionClassChirho, VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
};
use cairn_model_app_chirho::{AppKeyAuthorityRouteChirho, AppRouteKeyAccessChirho};
use std::path::Path;

/// An opening must name a valid action and list valid resources (viewer-state's logical-key grammar; returned sorted and
/// deduplicated), and every capability of the route's DAG must be one a key may reach. An opened route that holds
/// viewer-state must declare at least one resource, since a limited key may touch nothing else there.
/// Workflow: limited-key authority (K1),
/// `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.
pub(super) fn validate_route_key_access_chirho(
    root_chirho: &Path,
    route_chirho: &str,
    dag_chirho: &HashChirho,
    access_chirho: &AppRouteKeyAccessChirho,
) -> Result<AppRouteKeyAccessChirho> {
    let AppRouteKeyAccessChirho::OpenChirho {
        action_chirho,
        resources_chirho,
    } = access_chirho;
    cairn_model_app_chirho::validate_key_action_name_chirho(action_chirho)?;
    let mut resources_chirho = resources_chirho.clone();
    resources_chirho.sort();
    resources_chirho.dedup();
    for resource_chirho in &resources_chirho {
        crate::effect_chirho::validate_viewer_state_logical_key_chirho(resource_chirho)?;
    }
    let capabilities_chirho = crate::dag_capability_scan_chirho::collect_dag_capabilities_chirho(
        root_chirho,
        dag_chirho,
    )?;
    if dag_key_action_class_chirho(&capabilities_chirho) == KeyActionClassChirho::NeverChirho {
        bail!(
            "the route '{route_chirho}' cannot be opened to keys: its DAG holds a capability no key may reach"
        );
    }
    let holds_viewer_state_chirho = capabilities_chirho.iter().any(|capability_chirho| {
        matches!(
            capability_chirho,
            CapabilityChirho::ReadStoreChirho { prefix_chirho }
                | CapabilityChirho::WriteStoreChirho { prefix_chirho }
                if prefix_chirho == VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO
        )
    });
    if holds_viewer_state_chirho && resources_chirho.is_empty() {
        bail!(
            "the route '{route_chirho}' is opened to keys but declares no viewer-state resources"
        );
    }
    Ok(AppRouteKeyAccessChirho::OpenChirho {
        action_chirho: action_chirho.clone(),
        resources_chirho,
    })
}

/// After the routes are deployed: an app that opens any route, or that is already in limited-key mode, retires every
/// legacy key it still has and records its whole key authority at this deploy, each opening bound to the DAG just
/// deployed, in one locked section (`open_app_to_limited_keys_chirho`).
pub(super) fn record_app_key_authority_chirho(
    root_chirho: &Path,
    manifest_chirho: &AppDeployManifestChirho,
    routes_chirho: &[ValidatedAppDeployRouteChirho],
) -> Result<()> {
    let mut opened_chirho: Vec<AppKeyAuthorityRouteChirho> = routes_chirho
        .iter()
        .filter_map(|route_chirho| {
            route_chirho.key_access_chirho.as_ref().map(
                |AppRouteKeyAccessChirho::OpenChirho {
                     action_chirho,
                     resources_chirho,
                 }| AppKeyAuthorityRouteChirho {
                    route_chirho: route_chirho.route_chirho.clone(),
                    action_chirho: action_chirho.clone(),
                    dag_chirho: route_chirho.dag_chirho.clone(),
                    resources_chirho: resources_chirho.clone(),
                },
            )
        })
        .collect();
    let already_limited_chirho =
        app_chirho::app_key_authority_record_chirho(root_chirho, &manifest_chirho.app_chirho)?
            .is_some();
    if opened_chirho.is_empty() && !already_limited_chirho {
        return Ok(());
    }
    opened_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho.route_chirho.cmp(&right_chirho.route_chirho)
    });
    open_app_to_limited_keys_chirho(
        root_chirho,
        &manifest_chirho.app_chirho,
        &manifest_chirho.owner_chirho,
        opened_chirho,
    )
}

/// The opt-in, as one section under the root-wide append lock: retire every live legacy key of the app (each
/// revocation durable, and honoured by every engine down to the rollback floor), then record the opening.
/// - No token can be appended inside the section, so a racing legacy issuance either lands before it and is retired
///   here, or after it and is refused by its own re-check under the same lock.
/// - On an app's initial opt-in, a stop anywhere before the record leaves no opening, only retired keys, which no
///   engine honours: the opening is never on disk beside a live legacy key, for an older engine to honour after a
///   rollback (PFE #26596). An already-limited app's interrupted redeploy keeps its prior record; its own retirements
///   are still durable before any new record.
/// - A failure after the retirement began says so: the root was changed, and deploying again finishes the opt-in.
///
/// Workflow: limited-key authority (K1),
/// `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.
pub(crate) fn open_app_to_limited_keys_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    opened_chirho: Vec<AppKeyAuthorityRouteChirho>,
) -> Result<()> {
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        // K4: an app's initial opening refuses while it has a legacy client, before any retirement or record.
        crate::oauth_chirho::refuse_initial_opening_with_legacy_client_under_append_lock_chirho(
            root_chirho,
            app_chirho,
        )?;
        let retired_chirho =
            crate::oauth_chirho::retire_legacy_keys_for_app_under_append_lock_chirho(
                root_chirho,
                app_chirho,
            )
            .with_context(|| {
                format!(
                    "retiring the legacy keys of '{app_chirho}' stopped before its opening was recorded; some may \
                     already be retired; deploy again to finish"
                )
            })?;
        run_opt_in_hold_chirho()
            .and_then(|()| {
                app_chirho::append_app_key_authority_record_under_append_lock_chirho(
                    root_chirho,
                    app_chirho,
                    owner_principal_chirho,
                    opened_chirho,
                )
            })
            .with_context(|| {
                format!(
                    "{retired_chirho} legacy key(s) of '{app_chirho}' were retired, but its opening to limited keys \
                     was not recorded; deploy again to finish"
                )
            })?;
        Ok(())
    })
}

#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
type OptInHoldChirho = Box<dyn FnOnce() -> Result<()>>;

#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
thread_local! {
    static OPT_IN_HOLD_CHIRHO: std::cell::RefCell<Option<OptInHoldChirho>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only: a step the next opt-in on this thread runs inside its locked section, after its retirements and before
/// its record. Returning an error stops the opt-in there, as a crash would; holding lets a racing request meet the lock.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub fn set_opt_in_hold_chirho(hold_chirho: impl FnOnce() -> Result<()> + 'static) {
    OPT_IN_HOLD_CHIRHO.with(|slot_chirho| *slot_chirho.borrow_mut() = Some(Box::new(hold_chirho)));
}

fn run_opt_in_hold_chirho() -> Result<()> {
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    if let Some(hold_chirho) =
        OPT_IN_HOLD_CHIRHO.with(|slot_chirho| slot_chirho.borrow_mut().take())
    {
        return hold_chirho();
    }
    Ok(())
}
