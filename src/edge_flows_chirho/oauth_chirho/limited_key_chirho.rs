// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Limited keys (K1): issue one holding a finite signed action set, resolve a presented bearer as a legacy or a limited
//! key, and retire an app's legacy keys when it opts in to limited keys.
//!
//! - **Hashed under its own domain.** A limited key's stored token hash is blake3 in derive-key mode under
//!   `cairn-limited-key-token-v1-chirho`. Every engine before limited keys looks a bearer up by its plain blake3, so it
//!   never finds a limited key and refuses it as unknown: a rollback cannot widen one.
//! - **Signed through the existing signature.** The record keeps today's schema and signed message; its signed scopes
//!   carry the limited marker and the grant set's digest, and the grant set rides beside them (oauth_chirho.rs,
//!   `scoped_token_message_chirho`). So engines before limited keys verify the record and their token log keeps
//!   working, while this engine refuses a limited key whose grant set is missing or does not match its digest.
//! - **Granted from the app's current openings.** Issuance reads the app's latest key-authority record, keeps only the
//!   openings whose DAG is the route's current one, and expands the requested actions over them.
//! - **Legacy keys of an opted-in app are retired** through the session-revocation door, which every engine down to the
//!   rollback floor honours, so a retired key stays dead after a rollback too.
//! - **Everything else is today's key:** the same token view, rate policy, live-key cap, session liveness, listing and
//!   revoke by key id.
//!
//! Workflow: limited-key authority (K1),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.

use super::{
    find_client_chirho, issue_scoped_token_after_login_at_chirho, live_key_chirho, now_ms_chirho,
    public_default_rate_limit_chirho, token_hash_chirho, token_view_chirho,
    validate_requested_rate_limit_chirho, KeyStoreChirho, ScopedTokenIssueChirho,
    ScopedTokenRateLimitChirho, ScopedTokenRecordChirho,
};
use crate::model_chirho::{HashChirho, RequestKeyLimitChirho};
use crate::{app_chirho, dag_capability_scan_chirho, identity_chirho, refs_chirho, seqlog_chirho};
use anyhow::{anyhow, bail, Result};
use cairn_capability_chirho::capability_key_grant_chirho::{
    limited_key_grants_for_actions_chirho, limited_key_route_decision_chirho,
    scopes_mark_limited_key_chirho, verify_limited_key_grants_chirho, KeyRouteRefusalChirho,
    LimitedKeyGrantsChirho, OpenedKeyRouteChirho,
};
use cairn_signer_chirho::signer_chirho;
use std::path::Path;

/// The derive-key context of a limited key's stored token hash: a domain of its own, so no engine that looks bearers up
/// by plain blake3 ever finds one.
const LIMITED_KEY_TOKEN_HASH_CONTEXT_CHIRHO: &str = "cairn-limited-key-token-v1-chirho";
const LEGACY_KEY_RETIRE_ACTOR_CHIRHO: &str = "limited-key-opt-in-chirho";
const LEGACY_KEY_RETIRE_REASON_CHIRHO: &str = "app-opened-to-limited-keys-chirho";

/// A limited key's stored token hash.
pub(super) fn limited_token_hash_chirho(token_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new_derive_key(LIMITED_KEY_TOKEN_HASH_CONTEXT_CHIRHO);
    hasher_chirho.update(token_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

/// A presented bearer, resolved for an app: a legacy key, with today's meaning, or a limited key with its verified grant
/// set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BearerKeyChirho {
    LegacyChirho(ScopedTokenRecordChirho),
    LimitedChirho {
        record_chirho: ScopedTokenRecordChirho,
        grants_chirho: LimitedKeyGrantsChirho,
    },
}

impl BearerKeyChirho {
    /// The key's verified record, whichever kind it is.
    pub fn record_chirho(&self) -> &ScopedTokenRecordChirho {
        match self {
            Self::LegacyChirho(record_chirho) => record_chirho,
            Self::LimitedChirho { record_chirho, .. } => record_chirho,
        }
    }
}

/// Resolve `token_chirho` for `app_chirho`: `None` for an unknown, expired or ended key, as today. A record found by the
/// plain hash that claims to be limited is refused, and so is a limited record whose grant set is missing or does not
/// match its signed digest: a broken binding never falls back to the legacy meaning.
pub fn resolve_bearer_for_app_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    token_chirho: &str,
) -> Result<Option<BearerKeyChirho>> {
    resolve_bearer_for_app_at_chirho(root_chirho, app_chirho, token_chirho, now_ms_chirho())
}

pub(super) fn resolve_bearer_for_app_at_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    token_chirho: &str,
    now_ms_chirho: u64,
) -> Result<Option<BearerKeyChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let for_app_chirho =
        |record_chirho: &ScopedTokenRecordChirho| record_chirho.app_chirho == app_chirho;
    if let Some(record_chirho) = token_view_chirho::latest_token_with_hash_chirho(
        root_chirho,
        &pubkey_chirho,
        &token_hash_chirho(token_chirho),
        for_app_chirho,
    )? {
        let Some(record_chirho) =
            live_key_chirho(root_chirho, &pubkey_chirho, record_chirho, now_ms_chirho)?
        else {
            return Ok(None);
        };
        if scopes_mark_limited_key_chirho(&record_chirho.scopes_chirho) {
            bail!("a key found by its plain hash claims to be a limited key");
        }
        return Ok(Some(BearerKeyChirho::LegacyChirho(record_chirho)));
    }
    let Some(record_chirho) = token_view_chirho::latest_token_with_hash_chirho(
        root_chirho,
        &pubkey_chirho,
        &limited_token_hash_chirho(token_chirho),
        for_app_chirho,
    )?
    else {
        return Ok(None);
    };
    let Some(record_chirho) =
        live_key_chirho(root_chirho, &pubkey_chirho, record_chirho, now_ms_chirho)?
    else {
        return Ok(None);
    };
    let grants_chirho = record_chirho
        .limited_grants_chirho
        .clone()
        .ok_or_else(|| anyhow!("a limited key's record carries no grant set"))?;
    verify_limited_key_grants_chirho(
        &record_chirho.scopes_chirho,
        &record_chirho.app_chirho,
        &grants_chirho,
    )?;
    Ok(Some(BearerKeyChirho::LimitedChirho {
        record_chirho,
        grants_chirho,
    }))
}

/// The grant set `actions_chirho` expands to over the routes `app_chirho` opens to limited keys now: only openings whose
/// DAG is the route's current one count.
pub fn limited_key_grants_now_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    actions_chirho: &[String],
) -> Result<LimitedKeyGrantsChirho> {
    let opened_chirho = opened_key_routes_now_chirho(root_chirho, app_chirho)?
        .ok_or_else(|| anyhow!("the app '{app_chirho}' opens no route to limited keys"))?;
    limited_key_grants_for_actions_chirho(app_chirho, actions_chirho, &opened_chirho)
}

/// The routes `app_chirho` opens to limited keys now, in its key-authority record's order: only openings whose DAG is
/// the route's current one count. `None` for an app with no key-authority record. An error is a read that failed, never
/// a request that cannot be granted, so K4 Part 3's served road can tell the two apart.
pub(super) fn opened_key_routes_now_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<Vec<OpenedKeyRouteChirho>>> {
    let Some(record_chirho) = app_chirho::app_key_authority_record_chirho(root_chirho, app_chirho)?
    else {
        return Ok(None);
    };
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let mut opened_chirho = Vec::with_capacity(record_chirho.routes_chirho.len());
    for route_chirho in &record_chirho.routes_chirho {
        let current_chirho = app_chirho::resolve_app_route_chirho(
            root_chirho,
            &refs_chirho,
            app_chirho,
            &route_chirho.route_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        if current_chirho != route_chirho.dag_chirho {
            continue;
        }
        opened_chirho.push(OpenedKeyRouteChirho {
            route_chirho: route_chirho.route_chirho.clone(),
            action_chirho: route_chirho.action_chirho.clone(),
            capabilities_chirho: dag_capability_scan_chirho::collect_dag_capabilities_chirho(
                root_chirho,
                &route_chirho.dag_chirho,
            )?,
            resources_chirho: route_chirho.resources_chirho.clone(),
        });
    }
    Ok(Some(opened_chirho))
}

/// Issue a limited key for `principal_chirho` through `client_id_chirho`, holding `actions_chirho` over the app's current
/// openings. The key always carries a rate policy (the public default when none is named), so it counts toward the
/// live-key cap. A connection client's key is a connection (K4 Part 2): its own road proves the credential, decides the
/// cap, and only then writes the connection's 30-day session and the key. Any other client's key is proved by a fresh
/// sign-in, with a browser session's 24 hours, as before.
pub fn issue_limited_key_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    client_id_chirho: &str,
    actions_chirho: &[String],
    rate_limit_chirho: Option<ScopedTokenRateLimitChirho>,
) -> Result<ScopedTokenIssueChirho> {
    let rate_limit_chirho = rate_limit_chirho.unwrap_or_else(public_default_rate_limit_chirho);
    validate_requested_rate_limit_chirho(Some(&rate_limit_chirho))?;
    let client_chirho = find_client_chirho(root_chirho, client_id_chirho)?
        .ok_or_else(|| anyhow!("unknown oauth client '{client_id_chirho}'"))?;
    let grants_chirho =
        limited_key_grants_now_chirho(root_chirho, &client_chirho.app_chirho, actions_chirho)?;
    if KeyStoreChirho::of_client_chirho(&client_chirho) == KeyStoreChirho::ConnectionChirho {
        return super::connection_chirho::issue_connection_key_at_chirho(
            root_chirho,
            &client_chirho,
            principal_chirho,
            credential_chirho,
            grants_chirho,
            rate_limit_chirho,
            now_ms_chirho,
        );
    }
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        root_chirho,
        principal_chirho,
        credential_chirho,
    )?;
    issue_scoped_token_after_login_at_chirho(
        root_chirho,
        client_chirho,
        login_chirho,
        super::IssuedKeyKindChirho::LimitedChirho(grants_chirho),
        Some(rate_limit_chirho),
        now_ms_chirho,
    )
}

/// Retire every unexpired legacy key of `app_chirho` whose session is still live, by revoking that session through the
/// revocation door: idempotent, and honoured by every engine down to the rollback floor. Returns how many were retired.
pub fn retire_legacy_keys_for_app_chirho(root_chirho: &Path, app_chirho: &str) -> Result<usize> {
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        retire_legacy_keys_for_app_under_append_lock_chirho(root_chirho, app_chirho)
    })
}

/// The same retirement for a caller that already holds the root-wide append lock. Under that lock no token can be
/// appended, so the keys it reads are every legacy key the app has, and each revocation is durable before the caller's
/// next append.
pub fn retire_legacy_keys_for_app_under_append_lock_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<usize> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let now_chirho = now_ms_chirho();
    let mut retired_chirho = 0;
    for key_chirho in token_view_chirho::unexpired_keys_for_app_chirho(
        root_chirho,
        &pubkey_chirho,
        app_chirho,
        now_chirho,
    )? {
        if scopes_mark_limited_key_chirho(&key_chirho.scopes_chirho) {
            continue;
        }
        if !identity_chirho::key_session_live_chirho(
            root_chirho,
            &pubkey_chirho,
            &key_chirho.principal_chirho,
            key_chirho.session_seq_chirho,
            now_chirho,
        )? {
            continue;
        }
        identity_chirho::revoke_session_by_seq_under_append_lock_chirho(
            root_chirho,
            &key_chirho.principal_chirho,
            key_chirho.session_seq_chirho,
            LEGACY_KEY_RETIRE_ACTOR_CHIRHO,
            LEGACY_KEY_RETIRE_REASON_CHIRHO,
        )?;
        retired_chirho += 1;
    }
    Ok(retired_chirho)
}

/// Which entry a bearer request came through, for the key gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEntryChirho<'a> {
    /// A named app route.
    NamedRouteChirho(&'a str),
    /// Any other entry that runs an app DAG: the app root, `/invoke-chirho`, `/ws-chirho`, SSR. No limited-key opening
    /// exists there.
    OtherEntryChirho,
}

/// What the bearer door admits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyAdmissionChirho {
    /// A legacy key on an app that never opened a route to limited keys: today's meaning, on every entry.
    LegacyChirho(ScopedTokenRecordChirho),
    /// A limited key granted this named route: the limit its request carries, and the route and DAG it was checked
    /// against, which the request must still be running after route selection.
    LimitedChirho {
        record_chirho: ScopedTokenRecordChirho,
        limit_chirho: RequestKeyLimitChirho,
        route_chirho: String,
        dag_chirho: HashChirho,
    },
}

impl KeyAdmissionChirho {
    /// The admitted key's verified record.
    pub fn record_chirho(&self) -> &ScopedTokenRecordChirho {
        match self {
            Self::LegacyChirho(record_chirho) => record_chirho,
            Self::LimitedChirho { record_chirho, .. } => record_chirho,
        }
    }
}

/// The bearer door's decision for `token_chirho` on `app_chirho` through `entry_chirho`. `Ok(None)` is an unknown,
/// expired or ended key, refused as today. A `KeyRouteRefusalChirho` error is a key this entry or route does not admit:
/// - a legacy key on an app in limited-key mode, on any entry;
/// - a limited key on an app that opens nothing, on any entry other than a named route, or on a named route that is not
///   opened with its current DAG, whose action the key is not granted for that route, or whose capabilities now exceed
///   the key's consent.
///
/// It reads and appends nothing: the caller records the key's use only after it admits.
/// Workflow: limited-key authority (K1),
/// `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.
pub fn admit_bearer_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    entry_chirho: KeyEntryChirho<'_>,
    token_chirho: &str,
) -> Result<Option<KeyAdmissionChirho>> {
    let Some(bearer_chirho) = resolve_bearer_for_app_chirho(root_chirho, app_chirho, token_chirho)?
    else {
        return Ok(None);
    };
    let authority_chirho = app_chirho::app_key_authority_record_chirho(root_chirho, app_chirho)?;
    let (record_chirho, grants_chirho, authority_chirho) = match (bearer_chirho, authority_chirho) {
        (BearerKeyChirho::LegacyChirho(record_chirho), None) => {
            return Ok(Some(KeyAdmissionChirho::LegacyChirho(record_chirho)))
        }
        (BearerKeyChirho::LegacyChirho(_), Some(_))
        | (BearerKeyChirho::LimitedChirho { .. }, None) => {
            return Err(KeyRouteRefusalChirho::RouteNotOpenChirho.into())
        }
        (
            BearerKeyChirho::LimitedChirho {
                record_chirho,
                grants_chirho,
            },
            Some(authority_chirho),
        ) => (record_chirho, grants_chirho, authority_chirho),
    };
    let KeyEntryChirho::NamedRouteChirho(route_chirho) = entry_chirho else {
        return Err(KeyRouteRefusalChirho::RouteNotOpenChirho.into());
    };
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let current_dag_chirho = app_chirho::resolve_app_route_chirho(
        root_chirho,
        &refs_chirho,
        app_chirho,
        route_chirho,
        &authority_chirho.owner_principal_chirho,
    )?;
    let opened_action_chirho = authority_chirho
        .routes_chirho
        .iter()
        .find(|opened_chirho| {
            opened_chirho.route_chirho == route_chirho
                && opened_chirho.dag_chirho == current_dag_chirho
        })
        .map(|opened_chirho| opened_chirho.action_chirho.as_str());
    let capabilities_chirho = dag_capability_scan_chirho::collect_dag_capabilities_chirho(
        root_chirho,
        &current_dag_chirho,
    )?;
    let limit_chirho = limited_key_route_decision_chirho(
        &grants_chirho,
        route_chirho,
        opened_action_chirho,
        &capabilities_chirho,
    )?;
    Ok(Some(KeyAdmissionChirho::LimitedChirho {
        record_chirho,
        limit_chirho: RequestKeyLimitChirho {
            action_chirho: limit_chirho.action_chirho,
            resources_chirho: limit_chirho.resources_chirho,
        },
        route_chirho: route_chirho.to_string(),
        dag_chirho: current_dag_chirho,
    }))
}
