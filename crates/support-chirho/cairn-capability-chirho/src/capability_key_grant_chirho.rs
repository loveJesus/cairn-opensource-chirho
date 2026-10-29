// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! What a limited key may run: which capabilities any key may reach at all, the finite signed set of actions a limited
//! key holds, and the one decision that combines a route's opening, its current capabilities and that set.
//!
//! - **The eligibility ceiling is derived, never declared.** Each capability has a class: `ReadChirho` and
//!   `WriteChirho` are reachable by a key that holds a grant; `NeverChirho` is reachable by no key however it is
//!   granted. The match is exhaustive with no wildcard, so a new capability does not compile until someone classifies
//!   it.
//! - **A grant is an action, not a class.** A limited key holds a finite set of named actions. Each names the routes
//!   that declared that action when the key was issued, the capabilities those routes held then, and the logical
//!   resources they declared. A route added later never joins an old key, even under an old action name. A redeployed
//!   route whose capabilities widened refuses the old key, while a harmless change that keeps them passes: capabilities
//!   are bound, implementation bytes are not.
//! - **Capabilities do not bind data, so resources are enforced where the data is.** Two routes can hold the very same
//!   viewer-state capability and touch different logical keys. So a key's matched grant becomes a limit in its request
//!   context, and the viewer-state door refuses any logical key outside it. Store capabilities whose data authority
//!   cannot be bound that way are ineligible.
//! - **The set is signed through the key record's existing signature.** The record's signed scopes carry a marker and
//!   the canonical digest of the grant set; the set itself rides beside them. Engines that predate limited keys parse
//!   and verify such a record unchanged, and never honour it: a limited key's token is hashed under its own domain,
//!   so they never find it.
//!
//! Workflow: limited-key authority (K1),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.

use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::{CapabilityChirho, HashChirho};
use cairn_core_chirho::store_chirho;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The reserved store prefix of the owner's own keys (the browser-only read). An account power: no key may reach it.
pub const OWN_KEYS_CAPABILITY_PREFIX_CHIRHO: &str = "own-keys-chirho/";
/// The viewer-state store prefix: the one store road whose logical keys the door can bound per key. It must equal the
/// effect layer's own constant; a root test pins that.
pub const VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO: &str = "viewer-state-chirho/";

/// The scope that marks a key record as a limited key.
pub const LIMITED_KEY_SCOPE_MARKER_CHIRHO: &str = "limited-key-v1-chirho";
/// The scope prefix that carries the canonical digest of a limited key's grant set.
pub const LIMITED_KEY_GRANTS_DIGEST_SCOPE_PREFIX_CHIRHO: &str = "limited-key-grants-v1-chirho:";
/// The schema of a limited key's grant set.
pub const LIMITED_KEY_GRANTS_SCHEMA_CHIRHO: &str = "limited-key-grants-v1-chirho";

/// Whether, and how far, a key may reach a node holding a capability. Ordered: a DAG takes its highest class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyActionClassChirho {
    /// Pure computation, a viewer-state read, and request attribution.
    ReadChirho,
    /// A viewer-state write.
    WriteChirho,
    /// No key may reach it however it is granted: every other store prefix (its data authority cannot be bound per
    /// key), query (until its own authority is reviewed), publication, money and provider effects, network, secrets,
    /// realtime sessions, support actions, causal reversion, and node invocation.
    NeverChirho,
}

/// The class of one capability.
pub fn capability_key_action_class_chirho(
    capability_chirho: &CapabilityChirho,
) -> KeyActionClassChirho {
    match capability_chirho {
        CapabilityChirho::ReadStoreChirho { prefix_chirho }
            if prefix_chirho == VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO =>
        {
            KeyActionClassChirho::ReadChirho
        }
        CapabilityChirho::WriteStoreChirho { prefix_chirho }
            if prefix_chirho == VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO =>
        {
            KeyActionClassChirho::WriteChirho
        }
        CapabilityChirho::UserIdentityChirho { .. }
        | CapabilityChirho::AppContextChirho { .. }
        | CapabilityChirho::ClockChirho
        | CapabilityChirho::RandomChirho => KeyActionClassChirho::ReadChirho,
        CapabilityChirho::ReadStoreChirho { .. }
        | CapabilityChirho::WriteStoreChirho { .. }
        | CapabilityChirho::QueryChirho { .. }
        | CapabilityChirho::PaidEffectChirho { .. }
        | CapabilityChirho::SecretRefChirho { .. }
        | CapabilityChirho::RealtimeSessionChirho { .. }
        | CapabilityChirho::SupportIssueChirho { .. }
        | CapabilityChirho::CausalReversionChirho { .. }
        | CapabilityChirho::NetChirho { .. }
        | CapabilityChirho::InvokeChirho { .. }
        | CapabilityChirho::TemplateAppDeployChirho { .. } => KeyActionClassChirho::NeverChirho,
    }
}

/// The class of a DAG: the highest class among its capabilities. A DAG with none is pure, so `ReadChirho`.
pub fn dag_key_action_class_chirho<'a>(
    capabilities_chirho: impl IntoIterator<Item = &'a CapabilityChirho>,
) -> KeyActionClassChirho {
    capabilities_chirho
        .into_iter()
        .map(capability_key_action_class_chirho)
        .max()
        .unwrap_or(KeyActionClassChirho::ReadChirho)
}

/// One action a limited key holds: the routes that declared it when the key was issued, the capabilities those routes
/// held then (deduplicated in first-seen order over the sorted routes), and the logical resources they declared
/// (sorted, deduplicated).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitedKeyActionGrantChirho {
    pub action_chirho: String,
    pub routes_chirho: Vec<String>,
    pub authority_chirho: Vec<CapabilityChirho>,
    pub resources_chirho: Vec<String>,
}

/// A limited key's whole grant set, sorted by action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitedKeyGrantsChirho {
    pub schema_chirho: String,
    pub app_chirho: String,
    pub actions_chirho: Vec<LimitedKeyActionGrantChirho>,
}

/// One route an app currently opens to limited keys: its action, its current DAG's capabilities, and the logical
/// resources its opening declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedKeyRouteChirho {
    pub route_chirho: String,
    pub action_chirho: String,
    pub capabilities_chirho: Vec<CapabilityChirho>,
    pub resources_chirho: Vec<String>,
}

/// What a limited key may touch on one request: the action its matched grant is for, and that grant's resources. The
/// bearer door puts it into the request context, and the viewer-state door enforces it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitedKeyRequestLimitChirho {
    pub action_chirho: String,
    pub resources_chirho: Vec<String>,
}

/// Build the grant set for `requested_actions_chirho` from the routes the app opens now. Every requested action must
/// be declared by at least one opened route, no action twice, and every capability eligible.
pub fn limited_key_grants_for_actions_chirho(
    app_chirho: &str,
    requested_actions_chirho: &[String],
    opened_routes_chirho: &[OpenedKeyRouteChirho],
) -> Result<LimitedKeyGrantsChirho> {
    if requested_actions_chirho.is_empty() {
        bail!("a limited key must hold at least one action");
    }
    let mut actions_chirho = requested_actions_chirho.to_vec();
    actions_chirho.sort();
    if actions_chirho
        .windows(2)
        .any(|pair_chirho| pair_chirho[0] == pair_chirho[1])
    {
        bail!("a limited key's actions must not repeat");
    }
    let mut grants_chirho = Vec::with_capacity(actions_chirho.len());
    for action_chirho in actions_chirho {
        let mut declaring_chirho: Vec<&OpenedKeyRouteChirho> = opened_routes_chirho
            .iter()
            .filter(|route_chirho| route_chirho.action_chirho == action_chirho)
            .collect();
        if declaring_chirho.is_empty() {
            bail!("no route this app opens to keys declares the action '{action_chirho}'");
        }
        declaring_chirho.sort_by(|left_chirho, right_chirho| {
            left_chirho.route_chirho.cmp(&right_chirho.route_chirho)
        });
        let mut authority_chirho: Vec<CapabilityChirho> = Vec::new();
        let mut resources_chirho: Vec<String> = Vec::new();
        for route_chirho in &declaring_chirho {
            resources_chirho.extend(route_chirho.resources_chirho.iter().cloned());
            for capability_chirho in &route_chirho.capabilities_chirho {
                if capability_key_action_class_chirho(capability_chirho)
                    == KeyActionClassChirho::NeverChirho
                {
                    bail!(
                        "the route '{}' holds a capability no key may reach",
                        route_chirho.route_chirho
                    );
                }
                if !authority_chirho.contains(capability_chirho) {
                    authority_chirho.push(capability_chirho.clone());
                }
            }
        }
        grants_chirho.push(LimitedKeyActionGrantChirho {
            action_chirho,
            routes_chirho: declaring_chirho
                .iter()
                .map(|route_chirho| route_chirho.route_chirho.clone())
                .collect(),
            authority_chirho,
            resources_chirho: {
                resources_chirho.sort();
                resources_chirho.dedup();
                resources_chirho
            },
        });
    }
    Ok(LimitedKeyGrantsChirho {
        schema_chirho: LIMITED_KEY_GRANTS_SCHEMA_CHIRHO.to_string(),
        app_chirho: app_chirho.to_string(),
        actions_chirho: grants_chirho,
    })
}

/// The canonical digest of a grant set: the content address of its canonical encoding.
pub fn limited_key_grants_digest_chirho(
    grants_chirho: &LimitedKeyGrantsChirho,
) -> Result<HashChirho> {
    store_chirho::hash_object_chirho(grants_chirho)
}

/// The scopes a limited key's record is signed with: the marker and the grant set's digest, sorted as the issuer
/// normalizes every scope list.
pub fn limited_key_scopes_chirho(grants_chirho: &LimitedKeyGrantsChirho) -> Result<Vec<String>> {
    let mut scopes_chirho = vec![
        LIMITED_KEY_SCOPE_MARKER_CHIRHO.to_string(),
        format!(
            "{LIMITED_KEY_GRANTS_DIGEST_SCOPE_PREFIX_CHIRHO}{}",
            limited_key_grants_digest_chirho(grants_chirho)?.0
        ),
    ];
    scopes_chirho.sort();
    Ok(scopes_chirho)
}

/// Whether a key record's signed scopes mark it limited.
pub fn scopes_mark_limited_key_chirho(scopes_chirho: &[String]) -> bool {
    scopes_chirho
        .iter()
        .any(|scope_chirho| scope_chirho == LIMITED_KEY_SCOPE_MARKER_CHIRHO)
}

/// Check that a limited key's grant set is the one its signed scopes bind: the marker, exactly one digest scope, the
/// digest equal to the set's own, the schema current, and the set's app the key's app.
pub fn verify_limited_key_grants_chirho(
    scopes_chirho: &[String],
    key_app_chirho: &str,
    grants_chirho: &LimitedKeyGrantsChirho,
) -> Result<()> {
    if !scopes_mark_limited_key_chirho(scopes_chirho) {
        bail!("a limited key's scopes must carry its marker");
    }
    let mut digests_chirho = scopes_chirho.iter().filter_map(|scope_chirho| {
        scope_chirho.strip_prefix(LIMITED_KEY_GRANTS_DIGEST_SCOPE_PREFIX_CHIRHO)
    });
    let (Some(signed_digest_chirho), None) = (digests_chirho.next(), digests_chirho.next()) else {
        bail!("a limited key's scopes must carry exactly one grant digest");
    };
    if grants_chirho.schema_chirho != LIMITED_KEY_GRANTS_SCHEMA_CHIRHO {
        bail!("a limited key's grant set has an unknown schema");
    }
    if grants_chirho.app_chirho != key_app_chirho {
        bail!("a limited key's grant set names another app");
    }
    if limited_key_grants_digest_chirho(grants_chirho)?.0 != signed_digest_chirho {
        bail!("a limited key's grant set does not match its signed digest");
    }
    Ok(())
}

/// Why a limited key may not run a route. Each has a fixed public identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRouteRefusalChirho {
    /// The route is not open to keys with its current DAG, or its DAG holds a capability no key may reach.
    RouteNotOpenChirho,
    /// The route is open, but this key holds no grant for its action that names it.
    ActionNotGrantedChirho,
    /// The route's current capabilities exceed what this key's grant for its action consented to.
    AuthorityChangedChirho,
}

impl KeyRouteRefusalChirho {
    /// The refusal's fixed public identity.
    pub fn identity_chirho(&self) -> &'static str {
        match self {
            Self::RouteNotOpenChirho => "key-route-not-open-chirho",
            Self::ActionNotGrantedChirho => "key-action-not-granted-chirho",
            Self::AuthorityChangedChirho => "key-action-authority-changed-chirho",
        }
    }
}

impl fmt::Display for KeyRouteRefusalChirho {
    fn fmt(&self, f_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        f_chirho.write_str(match self {
            Self::RouteNotOpenChirho => "this route does not accept this key",
            Self::ActionNotGrantedChirho => "this key is not granted this route's action",
            Self::AuthorityChangedChirho => {
                "this route can now do more than this key was granted; issue a new key"
            }
        })
    }
}

impl std::error::Error for KeyRouteRefusalChirho {}

/// Whether a limited key holding `grants_chirho` may run `route_chirho`, and if so the limit its request carries.
/// `opened_action_chirho` is the action the app's latest key-authority record opens the route for, present only when
/// that record names the route's current DAG. `route_capabilities_chirho` are that DAG's capabilities now.
pub fn limited_key_route_decision_chirho(
    grants_chirho: &LimitedKeyGrantsChirho,
    route_chirho: &str,
    opened_action_chirho: Option<&str>,
    route_capabilities_chirho: &[CapabilityChirho],
) -> Result<LimitedKeyRequestLimitChirho, KeyRouteRefusalChirho> {
    let Some(opened_action_chirho) = opened_action_chirho else {
        return Err(KeyRouteRefusalChirho::RouteNotOpenChirho);
    };
    if dag_key_action_class_chirho(route_capabilities_chirho) == KeyActionClassChirho::NeverChirho {
        return Err(KeyRouteRefusalChirho::RouteNotOpenChirho);
    }
    let Some(grant_chirho) = grants_chirho.actions_chirho.iter().find(|grant_chirho| {
        grant_chirho.action_chirho == opened_action_chirho
            && grant_chirho
                .routes_chirho
                .iter()
                .any(|granted_route_chirho| granted_route_chirho == route_chirho)
    }) else {
        return Err(KeyRouteRefusalChirho::ActionNotGrantedChirho);
    };
    if !route_capabilities_chirho
        .iter()
        .all(|capability_chirho| grant_chirho.authority_chirho.contains(capability_chirho))
    {
        return Err(KeyRouteRefusalChirho::AuthorityChangedChirho);
    }
    Ok(LimitedKeyRequestLimitChirho {
        action_chirho: grant_chirho.action_chirho.clone(),
        resources_chirho: grant_chirho.resources_chirho.clone(),
    })
}

#[cfg(test)]
#[path = "capability_key_grant_chirho/tests_chirho.rs"]
mod tests_chirho;
