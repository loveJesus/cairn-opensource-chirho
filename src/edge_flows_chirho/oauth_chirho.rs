// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Registers app OAuth clients and issues scoped identity tokens for those clients.

use crate::{cas_chirho, identity_chirho, seqlog_chirho};
use anyhow::{anyhow, bail, Result};
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;
use cairn_signer_chirho::signer_chirho;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const OAUTH_CLIENT_RECORD_SCHEMA_CHIRHO: &str = "oauth-client-record-v1-chirho";
const SCOPED_TOKEN_RECORD_SCHEMA_CHIRHO: &str = "scoped-token-record-v1-chirho";
const SCOPED_TOKEN_USE_RECORD_SCHEMA_CHIRHO: &str = "scoped-token-use-record-v1-chirho";
/// The largest rate policy a token may carry (brick 4a-2; PFE #25915): a window of at most one hour, which is also the
/// history the use window keeps...
pub const TOKEN_RATE_WINDOW_CEILING_MS_CHIRHO: u64 = 60 * 60 * 1000;
/// ...and at most 3,600 invokes in it.
pub const TOKEN_RATE_MAX_INVOKES_CEILING_CHIRHO: u64 = 3_600;
/// The policy a PUBLIC token request without one is issued with, stated in the issuance output (brick 4a-2b; PFE
/// #25915): one hour...
pub const PUBLIC_TOKEN_DEFAULT_WINDOW_MS_CHIRHO: u64 = 60 * 60 * 1000;
/// ...and 600 invokes in it.
pub const PUBLIC_TOKEN_DEFAULT_MAX_INVOKES_CHIRHO: u64 = 600;
/// At most this many live rate-limited tokens per principal (brick 4a-2b; PFE #25915). A token lives as long as the
/// session it was issued from (brick 4b-1), and the cap counts only LIVE ones (brick 4b-2), so revoking a key, or
/// resetting the credential, frees its slot at once.
pub const LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO: usize = 5;

#[path = "oauth_chirho/connection_chirho/connection_chirho.rs"]
mod connection_chirho;
#[path = "oauth_chirho/key_listing_chirho.rs"]
mod key_listing_chirho;
#[path = "oauth_chirho/key_row_chirho.rs"]
mod key_row_chirho;
#[path = "oauth_chirho/limited_key_chirho.rs"]
mod limited_key_chirho;
#[path = "oauth_chirho/own_keys_read_chirho.rs"]
mod own_keys_read_chirho;
#[path = "oauth_chirho/token_use_view_chirho.rs"]
mod token_use_view_chirho;
#[path = "oauth_chirho/token_view_chirho.rs"]
mod token_view_chirho;
pub(crate) use connection_chirho::refuse_initial_opening_with_legacy_client_under_append_lock_chirho;
/// K4 Part 3: the served issuance road's engine half, and its daily limit; Account Create brick 1's selection by app
/// and its return path.
pub use connection_chirho::{
    connection_app_selector_well_formed_chirho, connection_form_choices_chirho,
    connection_return_path_for_app_chirho, connection_return_path_well_formed_chirho,
    issue_connection_key_served_chirho, ConnectionDailyLimitReachedChirho,
    ConnectionFormChoicesChirho, ConnectionSelectorChirho, ConnectionServedOutcomeChirho,
    ConnectionServedRefusalChirho, ConnectionServedRequestChirho,
    CONNECTION_APP_SELECTOR_MAX_BYTES_CHIRHO, CONNECTION_ISSUANCES_PER_DAY_CHIRHO,
    CONNECTION_RETURN_MAX_BYTES_CHIRHO,
};
pub use connection_chirho::{
    connection_token_hash_recorded_chirho, find_client_in_store_chirho,
    load_connection_clients_chirho, load_connection_token_uses_chirho,
    load_connection_tokens_chirho, register_client_in_store_chirho,
    verify_connection_clients_chirho, verify_connection_token_uses_chirho,
    verify_connection_tokens_chirho, ConnectionIssueFaultChirho, KeyStoreChirho,
};
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub use connection_chirho::{
    set_issuance_hold_chirho, set_registration_hold_chirho, with_k1_era_opening_chirho,
};
pub use key_listing_chirho::{
    list_own_keys_chirho, revoke_own_key_chirho, scoped_key_id_chirho, ScopedKeyRowChirho,
    UnknownScopedKeyChirho,
};
pub use limited_key_chirho::{
    admit_bearer_chirho, issue_limited_key_chirho, limited_key_grants_now_chirho,
    resolve_bearer_for_app_chirho, retire_legacy_keys_for_app_chirho,
    retire_legacy_keys_for_app_under_append_lock_chirho, BearerKeyChirho, KeyAdmissionChirho,
    KeyEntryChirho,
};
pub use own_keys_read_chirho::{
    decode_own_keys_read_request_chirho, own_keys_response_subject_chirho,
    reserved_own_keys_prefix_chirho, run_own_keys_read_chirho, OwnKeysReadChirho,
    OwnKeysReadOutputChirho, OwnKeysReadRequestChirho, OwnKeysStateChirho,
    BROWSER_SESSION_CLIENT_ID_CHIRHO, OWN_KEYS_READ_REQUEST_SCHEMA_CHIRHO,
    OWN_KEYS_READ_SCHEMA_CHIRHO, OWN_KEYS_UNAVAILABLE_REASON_CHIRHO,
};
pub use token_use_view_chirho::{
    spawn_scoped_token_views_warm_up_chirho, warm_scoped_token_views_chirho,
};
#[cfg(test)]
#[path = "oauth_chirho/issuance_policy_tests_chirho.rs"]
mod issuance_policy_tests_chirho;
#[cfg(test)]
#[path = "oauth_chirho/key_listing_tests_chirho.rs"]
mod key_listing_tests_chirho;
#[cfg(test)]
#[path = "oauth_chirho/key_liveness_tests_chirho.rs"]
mod key_liveness_tests_chirho;
#[cfg(test)]
#[path = "oauth_chirho/limited_key_tests_chirho.rs"]
mod limited_key_tests_chirho;
#[cfg(test)]
#[path = "oauth_chirho/own_keys_read_tests_chirho.rs"]
mod own_keys_read_tests_chirho;
#[cfg(test)]
#[path = "oauth_chirho/token_view_metrics_chirho.rs"]
pub(crate) mod token_view_metrics_chirho;
#[cfg(test)]
#[path = "oauth_chirho/token_views_tests_chirho.rs"]
mod token_views_tests_chirho;

/// A rate policy above today's ceiling: refused when a key is requested with it, before any credential work (brick
/// 4a-2b), and at use for a key issued before the ceiling, with a reason to reissue it (agy #25928 ruling (c)).
/// Today's verifier still accepts such a policy in HISTORY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedTokenPolicyAboveCeilingChirho;

impl fmt::Display for ScopedTokenPolicyAboveCeilingChirho {
    fn fmt(&self, f_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f_chirho,
            "this rate policy exceeds the current limits (a window of at most {} ms and at most {} invokes); issue a \
             key within them",
            TOKEN_RATE_WINDOW_CEILING_MS_CHIRHO, TOKEN_RATE_MAX_INVOKES_CEILING_CHIRHO
        )
    }
}

impl std::error::Error for ScopedTokenPolicyAboveCeilingChirho {}

/// The principal already holds the most live rate-limited keys. Checked only AFTER the credential is proved, so a
/// caller without the password learns nothing from it (brick 4a-2b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedTokenCapReachedChirho;

impl fmt::Display for ScopedTokenCapReachedChirho {
    fn fmt(&self, f_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f_chirho,
            "this principal already holds {} active rate-limited keys, the most allowed; another can be issued when \
             one of them expires",
            LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO
        )
    }
}

impl std::error::Error for ScopedTokenCapReachedChirho {}

/// The app has opened routes to limited keys, so it issues no legacy key: a legacy key there would be refused on every
/// entry, and after a rollback an older engine would honour it unrestricted. Checked before any credential work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyKeyForLimitedAppChirho;

impl fmt::Display for LegacyKeyForLimitedAppChirho {
    fn fmt(&self, f_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        f_chirho.write_str("this app accepts only limited keys; issue one with named actions")
    }
}

impl std::error::Error for LegacyKeyForLimitedAppChirho {}

/// What an issuance appends: a legacy key with its free-text scopes, or a limited key with its grant set.
enum IssuedKeyKindChirho {
    LegacyChirho(Vec<String>),
    LimitedChirho(cairn_capability_chirho::capability_key_grant_chirho::LimitedKeyGrantsChirho),
}

/// Refuse a legacy key for an app in limited-key mode. A key-authority log that fails verification refuses too.
fn refuse_legacy_key_for_limited_app_chirho(
    root_chirho: &Path,
    client_chirho: &OauthClientRecordChirho,
) -> Result<()> {
    if crate::app_chirho::app_key_authority_record_chirho(root_chirho, &client_chirho.app_chirho)?
        .is_some()
    {
        return Err(LegacyKeyForLimitedAppChirho.into());
    }
    Ok(())
}

/// The use window cannot decide this key's rate exactly right now: the clock stepped back beyond the tolerance, and
/// uses its window covers may have been pruned. Transient: the rebuilt index is on its way (HTTP 503).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UseWindowCatchingUpChirho;

impl fmt::Display for UseWindowCatchingUpChirho {
    fn fmt(&self, f_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f_chirho,
            "this key's rate cannot be decided while the server's clock catches up; retry shortly"
        )
    }
}

impl std::error::Error for UseWindowCatchingUpChirho {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OauthClientRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub client_id_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedTokenRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub principal_chirho: String,
    pub client_id_chirho: String,
    pub app_chirho: String,
    pub scopes_chirho: Vec<String>,
    pub session_seq_chirho: u64,
    pub token_hash_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_chirho: Option<ScopedTokenRateLimitChirho>,
    pub issued_ms_chirho: u64,
    pub expires_ms_chirho: u64,
    pub sig_chirho: String,
    /// A limited key's grant set. It is NOT in the signed message, which keeps exactly the shape engines before limited
    /// keys verify; the signed `scopes_chirho` bind it instead, through its canonical digest. Absent on every other key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limited_grants_chirho:
        Option<cairn_capability_chirho::capability_key_grant_chirho::LimitedKeyGrantsChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedTokenRateLimitChirho {
    pub window_ms_chirho: u64,
    pub max_invokes_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id_chirho: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedTokenUseRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub scoped_token_seq_chirho: u64,
    pub principal_chirho: String,
    pub client_id_chirho: String,
    pub app_chirho: String,
    pub token_hash_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id_chirho: Option<String>,
    pub window_ms_chirho: u64,
    pub max_invokes_chirho: u64,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitExceededChirho {
    pub principal_chirho: String,
    pub app_chirho: String,
    pub device_id_chirho: Option<String>,
    pub window_ms_chirho: u64,
    pub max_invokes_chirho: u64,
}

impl fmt::Display for RateLimitExceededChirho {
    fn fmt(&self, f_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.device_id_chirho {
            Some(device_id_chirho) => write!(
                f_chirho,
                "rate limit exceeded for principal '{}' app '{}' device '{}' (max {} in {} ms)",
                self.principal_chirho,
                self.app_chirho,
                device_id_chirho,
                self.max_invokes_chirho,
                self.window_ms_chirho
            ),
            None => write!(
                f_chirho,
                "rate limit exceeded for principal '{}' app '{}' (max {} in {} ms)",
                self.principal_chirho,
                self.app_chirho,
                self.max_invokes_chirho,
                self.window_ms_chirho
            ),
        }
    }
}

impl std::error::Error for RateLimitExceededChirho {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedTokenIssueChirho {
    pub record_chirho: ScopedTokenRecordChirho,
    pub token_chirho: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedTokenRequestChirho {
    #[serde(default)]
    pub principal_chirho: String,
    #[serde(default)]
    pub credential_chirho: String,
    #[serde(default)]
    pub client_id_chirho: String,
    #[serde(default)]
    pub scopes_chirho: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_chirho: Option<ScopedTokenRateLimitChirho>,
}

fn clients_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("oauth-clients-chirho.jsonl")
}

fn scoped_tokens_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("scoped-tokens-chirho.jsonl")
}

fn scoped_token_uses_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("scoped-token-uses-chirho.jsonl")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

/// Register a client for `app_chirho`. The store follows the app's mode, decided under the root's append lock (K4):
/// an app opened to limited keys gets a connection client, from its verified owner only; an app that opens nothing
/// gets a legacy client, exactly as before. See `register_client_in_store_chirho`.
pub fn register_client_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<OauthClientRecordChirho> {
    register_client_in_store_chirho(root_chirho, app_chirho, owner_principal_chirho)
        .map(|(record_chirho, _store_chirho)| record_chirho)
}

pub fn issue_scoped_token_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    client_id_chirho: &str,
    scopes_chirho: Vec<String>,
) -> Result<ScopedTokenIssueChirho> {
    issue_scoped_token_with_rate_limit_chirho(
        root_chirho,
        principal_chirho,
        credential_chirho,
        client_id_chirho,
        scopes_chirho,
        None,
    )
}

pub fn issue_scoped_token_with_rate_limit_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    client_id_chirho: &str,
    scopes_chirho: Vec<String>,
    rate_limit_chirho: Option<ScopedTokenRateLimitChirho>,
) -> Result<ScopedTokenIssueChirho> {
    validate_requested_rate_limit_chirho(rate_limit_chirho.as_ref())?;
    let client_chirho = find_client_chirho(root_chirho, client_id_chirho)?
        .ok_or_else(|| anyhow!("unknown oauth client '{client_id_chirho}'"))?;
    refuse_legacy_key_for_limited_app_chirho(root_chirho, &client_chirho)?;
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        root_chirho,
        principal_chirho,
        credential_chirho,
    )?;
    issue_scoped_token_after_login_chirho(
        root_chirho,
        client_chirho,
        login_chirho,
        scopes_chirho,
        rate_limit_chirho,
    )
}

pub fn issue_scoped_token_with_public_auth_limit_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    client_id_chirho: &str,
    scopes_chirho: Vec<String>,
    rate_limit_chirho: Option<ScopedTokenRateLimitChirho>,
    velocity_chirho: &identity_chirho::SignInVelocityChirho,
) -> Result<ScopedTokenIssueChirho> {
    issue_scoped_token_with_public_auth_limit_outcome_chirho(
        root_chirho,
        principal_chirho,
        credential_chirho,
        client_id_chirho,
        scopes_chirho,
        rate_limit_chirho,
        velocity_chirho,
    )
    .map_err(|refusal_chirho| refusal_chirho.error_chirho)
}

/// The same issue, saying whether a refusal RECORDED a failed attempt row, for the served road's per-source failure
/// limit (R12). Only a refused credential records one: the policy and client checks come before the sign-in, and the
/// issuance cap after a proved credential, so none of them does.
pub fn issue_scoped_token_with_public_auth_limit_outcome_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    client_id_chirho: &str,
    scopes_chirho: Vec<String>,
    rate_limit_chirho: Option<ScopedTokenRateLimitChirho>,
    velocity_chirho: &identity_chirho::SignInVelocityChirho,
) -> std::result::Result<ScopedTokenIssueChirho, identity_chirho::PublicAuthRefusalChirho> {
    use identity_chirho::PublicAuthRefusalChirho;
    // A public key always carries a policy: the default when the request names none (brick 4a-2b).
    let rate_limit_chirho =
        Some(rate_limit_chirho.unwrap_or_else(public_default_rate_limit_chirho));
    validate_requested_rate_limit_chirho(rate_limit_chirho.as_ref())
        .map_err(PublicAuthRefusalChirho::not_recorded_chirho)?;
    let client_chirho = find_client_chirho(root_chirho, client_id_chirho)
        .map_err(PublicAuthRefusalChirho::not_recorded_chirho)?
        .ok_or_else(|| {
            PublicAuthRefusalChirho::not_recorded_chirho(anyhow!(
                "unknown oauth client '{client_id_chirho}'"
            ))
        })?;
    refuse_legacy_key_for_limited_app_chirho(root_chirho, &client_chirho)
        .map_err(PublicAuthRefusalChirho::not_recorded_chirho)?;
    let login_chirho = identity_chirho::login_identity_with_public_auth_limit_outcome_chirho(
        root_chirho,
        principal_chirho,
        credential_chirho,
        identity_chirho::AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
        velocity_chirho,
    )?;
    issue_scoped_token_after_login_chirho(
        root_chirho,
        client_chirho,
        login_chirho,
        scopes_chirho,
        rate_limit_chirho,
    )
    .map_err(PublicAuthRefusalChirho::not_recorded_chirho)
}

fn issue_scoped_token_after_login_chirho(
    root_chirho: &Path,
    client_chirho: OauthClientRecordChirho,
    login_chirho: identity_chirho::IdentityLoginResultChirho,
    scopes_chirho: Vec<String>,
    rate_limit_chirho: Option<ScopedTokenRateLimitChirho>,
) -> Result<ScopedTokenIssueChirho> {
    issue_scoped_token_after_login_at_chirho(
        root_chirho,
        client_chirho,
        login_chirho,
        IssuedKeyKindChirho::LegacyChirho(scopes_chirho),
        rate_limit_chirho,
        now_ms_chirho,
    )
}

/// Append the token, refusing a rate-limited one when its principal already holds the cap of LIVE ones (unexpired, and
/// their session live: brick 4b-2). The count is read under the token log's append lock, and it runs after the
/// credential was proved (brick 4a-2b). `clock_chirho` says what "live" means: the expiry arm moves it past the tokens' lifetime.
/// K4: this road writes the legacy store only. A connection-store key has its own road, which decides before it creates
/// and gives the key's session the connection's 30 days (Part 2); the cap counts both stores under the root-wide lock
/// both roads take.
fn issue_scoped_token_after_login_at_chirho(
    root_chirho: &Path,
    client_chirho: OauthClientRecordChirho,
    login_chirho: identity_chirho::IdentityLoginResultChirho,
    kind_chirho: IssuedKeyKindChirho,
    rate_limit_chirho: Option<ScopedTokenRateLimitChirho>,
    clock_chirho: impl FnOnce() -> u64,
) -> Result<ScopedTokenIssueChirho> {
    let (draft_chirho, token_chirho) =
        key_row_chirho::draft_key_row_chirho(&client_chirho, kind_chirho, rate_limit_chirho)?;
    // K4: a connection client exists only for an app opened to limited keys, so a legacy key for it refuses as for any
    // limited app. A limited key for it is a connection, and only the connection's own road issues one.
    if draft_chirho.store_chirho() == KeyStoreChirho::ConnectionChirho {
        if !draft_chirho.is_limited_chirho() {
            return Err(LegacyKeyForLimitedAppChirho.into());
        }
        bail!(
            "ConnectionKeyRoadChirho: a connection-store key is issued only through the connection's own road, \
             which decides before it creates"
        );
    }
    let path_chirho = draft_chirho.store_chirho().tokens_path_chirho(root_chirho);
    let record_chirho =
        seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
            // K1: a legacy key re-checks the app's mode under the root-wide append lock, which the opt-in's one
            // locked section (its retirements, then its record) also holds. A legacy append that lands before the
            // section is retired inside it; one that lands after it meets the record here and refuses, whatever the
            // check before the sign-in saw.
            if !draft_chirho.is_limited_chirho() {
                refuse_legacy_key_for_limited_app_chirho(root_chirho, &client_chirho)?;
            }
            if draft_chirho.is_rate_limited_chirho()
                && key_listing_chirho::live_rate_limited_keys_chirho(
                    root_chirho,
                    &login_chirho.session_chirho.principal_chirho,
                    clock_chirho(),
                )? >= LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO
            {
                return Err(ScopedTokenCapReachedChirho.into());
            }
            connection_chirho::run_issuance_hold_chirho()?;
            draft_chirho.signed_at_chirho(root_chirho, seq_chirho, &login_chirho.session_chirho)
        })?;
    Ok(ScopedTokenIssueChirho {
        record_chirho,
        token_chirho,
    })
}

/// Record one use of a rate-limited token, or refuse it at its limit (brick 4a-2): the decision and the record are
/// one act through the use view's append door, which verifies only the uses appended since the last call. A token
/// without a policy records nothing, as before. A token whose policy is above today's ceiling is refused, with a
/// reason to reissue it: the use window keeps one ceiling of history (agy #25928 ruling (c)).
/// Workflow: the bearer-road DAG, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
/// (4a-2a, as built).
pub fn record_scoped_token_use_chirho(
    root_chirho: &Path,
    scoped_token_chirho: &ScopedTokenRecordChirho,
) -> Result<Option<ScopedTokenUseRecordChirho>> {
    let Some(rate_limit_chirho) = &scoped_token_chirho.rate_limit_chirho else {
        return Ok(None);
    };
    validate_rate_limit_policy_chirho(rate_limit_chirho)?;
    ensure_rate_limit_within_ceiling_chirho(rate_limit_chirho)?;
    token_use_view_chirho::decide_and_append_use_chirho(
        root_chirho,
        scoped_token_chirho,
        rate_limit_chirho,
        now_ms_chirho,
    )
    .map(Some)
}

pub fn validate_scoped_token_chirho(
    root_chirho: &Path,
    client_id_chirho: &str,
    token_chirho: &str,
) -> Result<Option<ScopedTokenRecordChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let Some(record_chirho) = token_view_chirho::latest_token_with_hash_chirho(
        root_chirho,
        &pubkey_chirho,
        &token_hash_chirho(token_chirho),
        |record_chirho| record_chirho.client_id_chirho == client_id_chirho,
    )?
    else {
        return Ok(None);
    };
    live_key_chirho(root_chirho, &pubkey_chirho, record_chirho, now_ms_chirho())
}

/// The latest token with this token's hash for `app_chirho`, read from the verified token view; `None` when there is
/// none, it has expired, or its session is not live.
/// Workflow: the bearer-road DAG, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
/// (4a-2a and 4b, as built).
pub fn validate_scoped_token_for_app_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    token_chirho: &str,
) -> Result<Option<ScopedTokenRecordChirho>> {
    validate_scoped_token_for_app_at_chirho(root_chirho, app_chirho, token_chirho, now_ms_chirho())
}

/// The app's bearer check at `now_ms_chirho`, as `validate_scoped_token_for_app_chirho` runs it with the real clock.
fn validate_scoped_token_for_app_at_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    token_chirho: &str,
    now_ms_chirho: u64,
) -> Result<Option<ScopedTokenRecordChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let Some(record_chirho) = token_view_chirho::latest_token_with_hash_chirho(
        root_chirho,
        &pubkey_chirho,
        &token_hash_chirho(token_chirho),
        |record_chirho| record_chirho.app_chirho == app_chirho,
    )?
    else {
        return Ok(None);
    };
    live_key_chirho(root_chirho, &pubkey_chirho, record_chirho, now_ms_chirho)
}

/// A key is accepted while it is unexpired AND its session is live (brick 4b): unexpired, its credential generation
/// current, not revoked. So revoking a key's session, or resetting its principal's credential, ends the key. A key
/// whose session is not live reads as no key, so it refuses exactly as an unknown key does (403).
/// Workflow: the bearer-road DAG, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
/// (4b, as built).
fn live_key_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    record_chirho: ScopedTokenRecordChirho,
    now_ms_chirho: u64,
) -> Result<Option<ScopedTokenRecordChirho>> {
    if record_chirho.expires_ms_chirho < now_ms_chirho
        || !identity_chirho::key_session_live_chirho(
            root_chirho,
            pubkey_chirho,
            &record_chirho.principal_chirho,
            record_chirho.session_seq_chirho,
            now_ms_chirho,
        )?
    {
        return Ok(None);
    }
    Ok(Some(record_chirho))
}

pub fn load_clients_chirho(root_chirho: &Path) -> Result<Vec<OauthClientRecordChirho>> {
    #[cfg(test)]
    token_view_metrics_chirho::note_client_read_chirho();
    let path_chirho = clients_path_chirho(root_chirho);
    let Some(text_chirho) = read_log_text_chirho(&path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: OauthClientRecordChirho = serde_json::from_str(line_chirho)?;
        verify_oauth_record_schema_chirho(
            &record_chirho.schema_chirho,
            OAUTH_CLIENT_RECORD_SCHEMA_CHIRHO,
            "oauth client record",
        )?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

pub fn load_scoped_tokens_chirho(root_chirho: &Path) -> Result<Vec<ScopedTokenRecordChirho>> {
    let path_chirho = scoped_tokens_path_chirho(root_chirho);
    let Some(text_chirho) = read_log_text_chirho(&path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(parse_scoped_token_line_chirho(line_chirho)?);
    }
    Ok(records_chirho)
}

pub fn load_scoped_token_uses_chirho(
    root_chirho: &Path,
) -> Result<Vec<ScopedTokenUseRecordChirho>> {
    let path_chirho = scoped_token_uses_path_chirho(root_chirho);
    let Some(text_chirho) = read_log_text_chirho(&path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(parse_scoped_token_use_line_chirho(line_chirho)?);
    }
    Ok(records_chirho)
}

/// The client `client_id_chirho`, from either store (K4). A client in both refuses.
pub fn find_client_chirho(
    root_chirho: &Path,
    client_id_chirho: &str,
) -> Result<Option<OauthClientRecordChirho>> {
    Ok(find_client_in_store_chirho(root_chirho, client_id_chirho)?
        .map(|(record_chirho, _store_chirho)| record_chirho))
}

pub fn verify_clients_chirho(root_chirho: &Path) -> Result<usize> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_clients_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "oauth client seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        let owner_chirho = identity_chirho::find_identity_chirho(
            root_chirho,
            &record_chirho.owner_principal_chirho,
        )?
        .ok_or_else(|| {
            anyhow!(
                "oauth client references unknown owner '{}'",
                record_chirho.owner_principal_chirho
            )
        })?;
        if owner_chirho.kind_chirho != identity_chirho::PrincipalKindChirho::OwnerChirho {
            bail!(
                "oauth client {} owner is not an owner principal",
                record_chirho.client_id_chirho
            );
        }
        let message_chirho = client_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "oauth client {} signature invalid",
                record_chirho.client_id_chirho
            );
        }
    }
    Ok(records_chirho.len())
}

pub fn verify_scoped_tokens_chirho(root_chirho: &Path) -> Result<usize> {
    identity_chirho::verify_sessions_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_scoped_tokens_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "scoped token seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        verify_scoped_token_record_chirho(root_chirho, &pubkey_chirho, record_chirho)?;
    }
    Ok(records_chirho.len())
}

pub fn verify_scoped_token_uses_chirho(root_chirho: &Path) -> Result<usize> {
    verify_scoped_tokens_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    token_use_view_chirho::verify_uses_in_namespace_chirho(
        &pubkey_chirho,
        &load_scoped_tokens_chirho(root_chirho)?,
        &load_scoped_token_uses_chirho(root_chirho)?,
    )
}

fn verify_scoped_token_record_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    record_chirho: &ScopedTokenRecordChirho,
) -> Result<()> {
    #[cfg(test)]
    token_view_metrics_chirho::note_token_check_chirho();
    let client_chirho = find_client_chirho(root_chirho, &record_chirho.client_id_chirho)?
        .ok_or_else(|| {
            anyhow!(
                "scoped token references unknown client '{}'",
                record_chirho.client_id_chirho
            )
        })?;
    if client_chirho.app_chirho != record_chirho.app_chirho {
        bail!(
            "scoped token {} app does not match client",
            record_chirho.seq_chirho
        );
    }
    connection_chirho::verify_key_store_chirho(&client_chirho, record_chirho)?;
    let identity_chirho =
        identity_chirho::find_identity_chirho(root_chirho, &record_chirho.principal_chirho)?
            .ok_or_else(|| {
                anyhow!(
                    "scoped token references unknown principal '{}'",
                    record_chirho.principal_chirho
                )
            })?;
    // The token's session, from the verified session index (brick 4b), where 4a-2 parsed the whole session log.
    let session_chirho = identity_chirho::verified_session_for_token_chirho(
        root_chirho,
        pubkey_chirho,
        &identity_chirho.principal_chirho,
        record_chirho.session_seq_chirho,
    )?
    .ok_or_else(|| {
        anyhow!(
            "scoped token {} references missing session",
            record_chirho.seq_chirho
        )
    })?;
    if record_chirho.issued_ms_chirho != session_chirho.issued_ms_chirho
        || record_chirho.expires_ms_chirho != session_chirho.expires_ms_chirho
    {
        bail!(
            "scoped token {} session time mismatch",
            record_chirho.seq_chirho
        );
    }
    if let Some(rate_limit_chirho) = &record_chirho.rate_limit_chirho {
        validate_rate_limit_policy_chirho(rate_limit_chirho)?;
    }
    let message_chirho = scoped_token_message_chirho(record_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        pubkey_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )? {
        bail!(
            "scoped token {} signature invalid",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

fn normalize_scopes_chirho(scopes_chirho: Vec<String>) -> Vec<String> {
    let mut scopes_chirho: Vec<String> = scopes_chirho
        .into_iter()
        .map(|scope_chirho| scope_chirho.trim().to_string())
        .filter(|scope_chirho| !scope_chirho.is_empty())
        .collect();
    if scopes_chirho.is_empty() {
        scopes_chirho.push("invoke_chirho".to_string());
    }
    scopes_chirho.sort();
    scopes_chirho.dedup();
    scopes_chirho
}

fn next_client_id_chirho(root_chirho: &Path) -> Result<String> {
    // Unique across both stores, so a client id never names two clients (K4).
    let mut existing_chirho = load_clients_chirho(root_chirho)?;
    existing_chirho.extend(load_connection_clients_chirho(root_chirho)?);
    for _ in 0..16 {
        let mut seed_chirho = [0_u8; 16];
        OsRng.fill_bytes(&mut seed_chirho);
        let id_chirho = cas_chirho::hash_chirho(&seed_chirho).0[..16].to_string();
        let client_id_chirho = format!("client/{id_chirho}");
        if !existing_chirho
            .iter()
            .any(|record_chirho| record_chirho.client_id_chirho == client_id_chirho)
        {
            return Ok(client_id_chirho);
        }
    }
    bail!("could not allocate unique oauth client id")
}

fn client_message_chirho(record_chirho: &OauthClientRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

/// The signed bytes of a key record: every field but the signature and a limited key's grant set. Leaving the grant set
/// out keeps the message exactly what engines before limited keys compute, so they verify every record, a limited key's
/// included, and their token log keeps working after a rollback. The grant set is bound by the digest in the scopes.
fn scoped_token_message_chirho(record_chirho: &ScopedTokenRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    signed_chirho.limited_grants_chirho = None;
    Ok(serde_json::to_vec(&signed_chirho)?)
}

fn scoped_token_use_message_chirho(record_chirho: &ScopedTokenUseRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

/// One line of the scoped-token log: the ONE parser the loader and the token view share.
fn parse_scoped_token_line_chirho(line_chirho: &str) -> Result<ScopedTokenRecordChirho> {
    let record_chirho: ScopedTokenRecordChirho = serde_json::from_str(line_chirho)?;
    verify_oauth_record_schema_chirho(
        &record_chirho.schema_chirho,
        SCOPED_TOKEN_RECORD_SCHEMA_CHIRHO,
        "scoped token record",
    )?;
    Ok(record_chirho)
}

/// One line of the scoped-token use log: the ONE parser the loader and the use view share.
fn parse_scoped_token_use_line_chirho(line_chirho: &str) -> Result<ScopedTokenUseRecordChirho> {
    let record_chirho: ScopedTokenUseRecordChirho = serde_json::from_str(line_chirho)?;
    verify_oauth_record_schema_chirho(
        &record_chirho.schema_chirho,
        SCOPED_TOKEN_USE_RECORD_SCHEMA_CHIRHO,
        "scoped token use record",
    )?;
    Ok(record_chirho)
}

/// A requested rate policy, checked BEFORE any credential work: valid by today's rule and within the ceiling, refused
/// and never clamped (PFE #25915).
fn validate_requested_rate_limit_chirho(
    rate_limit_chirho: Option<&ScopedTokenRateLimitChirho>,
) -> Result<()> {
    if let Some(rate_limit_chirho) = rate_limit_chirho {
        validate_rate_limit_policy_chirho(rate_limit_chirho)?;
        ensure_rate_limit_within_ceiling_chirho(rate_limit_chirho)?;
    }
    Ok(())
}

/// The policy a public token request without one gets: one hour, 600 invokes, no device.
fn public_default_rate_limit_chirho() -> ScopedTokenRateLimitChirho {
    ScopedTokenRateLimitChirho {
        window_ms_chirho: PUBLIC_TOKEN_DEFAULT_WINDOW_MS_CHIRHO,
        max_invokes_chirho: PUBLIC_TOKEN_DEFAULT_MAX_INVOKES_CHIRHO,
        device_id_chirho: None,
    }
}

/// A token whose rate policy is above today's ceiling is refused with a reason to reissue it (agy #25928 ruling (c);
/// PFE #25915). Today's verifier still accepts such a policy in HISTORY; only a new use or a new issue is refused.
fn ensure_rate_limit_within_ceiling_chirho(
    rate_limit_chirho: &ScopedTokenRateLimitChirho,
) -> Result<()> {
    if rate_limit_chirho.window_ms_chirho > TOKEN_RATE_WINDOW_CEILING_MS_CHIRHO
        || rate_limit_chirho.max_invokes_chirho > TOKEN_RATE_MAX_INVOKES_CEILING_CHIRHO
    {
        return Err(ScopedTokenPolicyAboveCeilingChirho.into());
    }
    Ok(())
}

fn verify_oauth_record_schema_chirho(
    schema_chirho: &str,
    expected_chirho: &str,
    label_chirho: &str,
) -> Result<()> {
    if !schema_chirho.is_empty() && schema_chirho != expected_chirho {
        bail!("unsupported {label_chirho} schema '{schema_chirho}'");
    }
    Ok(())
}

fn verify_scoped_token_use_matches_chirho(
    record_chirho: &ScopedTokenUseRecordChirho,
    token_chirho: &ScopedTokenRecordChirho,
) -> Result<()> {
    if record_chirho.principal_chirho != token_chirho.principal_chirho
        || record_chirho.client_id_chirho != token_chirho.client_id_chirho
        || record_chirho.app_chirho != token_chirho.app_chirho
        || !identity_chirho::constant_time_string_eq_chirho(
            &record_chirho.token_hash_chirho,
            &token_chirho.token_hash_chirho,
        )
    {
        bail!(
            "scoped token use {} does not match token record",
            record_chirho.seq_chirho
        );
    }
    if record_chirho.at_ms_chirho < token_chirho.issued_ms_chirho
        || record_chirho.at_ms_chirho > token_chirho.expires_ms_chirho
    {
        bail!(
            "scoped token use {} happened outside token lifetime",
            record_chirho.seq_chirho
        );
    }
    let rate_limit_chirho = token_chirho.rate_limit_chirho.as_ref().ok_or_else(|| {
        anyhow!(
            "scoped token use {} references an unlimited token",
            record_chirho.seq_chirho
        )
    })?;
    if record_chirho.window_ms_chirho != rate_limit_chirho.window_ms_chirho
        || record_chirho.max_invokes_chirho != rate_limit_chirho.max_invokes_chirho
        || record_chirho.device_id_chirho != rate_limit_chirho.device_id_chirho
    {
        bail!(
            "scoped token use {} rate policy mismatch",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

fn scoped_token_use_matches_rate_key_chirho(
    record_chirho: &ScopedTokenUseRecordChirho,
    token_chirho: &ScopedTokenRecordChirho,
    rate_limit_chirho: &ScopedTokenRateLimitChirho,
    now_ms_chirho: u64,
) -> bool {
    if record_chirho.app_chirho != token_chirho.app_chirho {
        return false;
    }
    let window_start_chirho = now_ms_chirho.saturating_sub(rate_limit_chirho.window_ms_chirho);
    if record_chirho.at_ms_chirho < window_start_chirho {
        return false;
    }
    let same_principal_chirho = record_chirho.principal_chirho == token_chirho.principal_chirho;
    let same_device_chirho =
        rate_limit_chirho
            .device_id_chirho
            .as_ref()
            .is_some_and(|device_id_chirho| {
                record_chirho.device_id_chirho.as_ref() == Some(device_id_chirho)
            });
    same_principal_chirho || same_device_chirho
}

fn validate_rate_limit_policy_chirho(rate_limit_chirho: &ScopedTokenRateLimitChirho) -> Result<()> {
    if rate_limit_chirho.window_ms_chirho == 0 {
        bail!("rate_limit_chirho.window_ms_chirho must be positive");
    }
    if rate_limit_chirho.max_invokes_chirho == 0 {
        bail!("rate_limit_chirho.max_invokes_chirho must be positive");
    }
    if let Some(device_id_chirho) = &rate_limit_chirho.device_id_chirho {
        if device_id_chirho.trim().is_empty() {
            bail!("rate_limit_chirho.device_id_chirho must not be empty");
        }
        if device_id_chirho.chars().any(char::is_whitespace) {
            bail!("rate_limit_chirho.device_id_chirho must not contain whitespace");
        }
    }
    Ok(())
}

fn random_token_chirho() -> String {
    let mut token_bytes_chirho = [0_u8; 32];
    OsRng.fill_bytes(&mut token_bytes_chirho);
    hex_encode_chirho(&token_bytes_chirho)
}

fn token_hash_chirho(token_chirho: &str) -> String {
    cas_chirho::hash_chirho(token_chirho.as_bytes()).0
}

fn hex_encode_chirho(bytes_chirho: &[u8]) -> String {
    const HEX_CHIRHO: &[u8; 16] = b"0123456789abcdef";
    let mut out_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for b_chirho in bytes_chirho {
        out_chirho.push(HEX_CHIRHO[(b_chirho >> 4) as usize] as char);
        out_chirho.push(HEX_CHIRHO[(b_chirho & 0x0f) as usize] as char);
    }
    out_chirho
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-oauth-test-{n_chirho}-{}", now_ms_chirho()))
    }

    fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, rows_chirho: &[T]) {
        if let Some(parent_chirho) = path_chirho.parent() {
            std::fs::create_dir_all(parent_chirho).unwrap();
        }
        let mut text_chirho = String::new();
        for row_chirho in rows_chirho {
            text_chirho.push_str(&serde_json::to_string(row_chirho).unwrap());
            text_chirho.push('\n');
        }
        std::fs::write(path_chirho, text_chirho).unwrap();
    }

    fn oauth_fixture_chirho(
        root_chirho: &Path,
    ) -> (
        OauthClientRecordChirho,
        ScopedTokenIssueChirho,
        ScopedTokenUseRecordChirho,
    ) {
        let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
            root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            "owner-secret-value",
        )
        .unwrap();
        let user_chirho = identity_chirho::register_identity_with_credential_chirho(
            root_chirho,
            identity_chirho::PrincipalKindChirho::UserChirho,
            "user-secret-value",
        )
        .unwrap();
        let client_chirho =
            register_client_chirho(root_chirho, "alpha", &owner_chirho.principal_chirho).unwrap();
        let token_chirho = issue_scoped_token_with_rate_limit_chirho(
            root_chirho,
            &user_chirho.principal_chirho,
            "user-secret-value",
            &client_chirho.client_id_chirho,
            vec!["invoke_chirho".to_string()],
            Some(ScopedTokenRateLimitChirho {
                window_ms_chirho: 60_000,
                max_invokes_chirho: 1,
                device_id_chirho: Some("device-a".to_string()),
            }),
        )
        .unwrap();
        let use_chirho = record_scoped_token_use_chirho(root_chirho, &token_chirho.record_chirho)
            .unwrap()
            .unwrap();
        (client_chirho, token_chirho, use_chirho)
    }

    fn resign_client_for_test_chirho(
        root_chirho: &Path,
        mut record_chirho: OauthClientRecordChirho,
    ) -> OauthClientRecordChirho {
        record_chirho.sig_chirho.clear();
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &client_message_chirho(&record_chirho).unwrap(),
        )
        .unwrap();
        record_chirho
    }

    fn resign_scoped_token_for_test_chirho(
        root_chirho: &Path,
        mut record_chirho: ScopedTokenRecordChirho,
    ) -> ScopedTokenRecordChirho {
        record_chirho.sig_chirho.clear();
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &scoped_token_message_chirho(&record_chirho).unwrap(),
        )
        .unwrap();
        record_chirho
    }

    fn resign_scoped_token_use_for_test_chirho(
        root_chirho: &Path,
        mut record_chirho: ScopedTokenUseRecordChirho,
    ) -> ScopedTokenUseRecordChirho {
        record_chirho.sig_chirho.clear();
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &scoped_token_use_message_chirho(&record_chirho).unwrap(),
        )
        .unwrap();
        record_chirho
    }

    #[test]
    fn scoped_tokens_are_per_client_for_one_identity_chirho() {
        let root_chirho = tmp_root_chirho();
        let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            "owner-secret-value",
        )
        .unwrap();
        let user_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::UserChirho,
            "user-secret-value",
        )
        .unwrap();
        let client_a_chirho =
            register_client_chirho(&root_chirho, "alpha", &owner_chirho.principal_chirho).unwrap();
        let client_b_chirho =
            register_client_chirho(&root_chirho, "beta", &owner_chirho.principal_chirho).unwrap();
        let token_a_chirho = issue_scoped_token_chirho(
            &root_chirho,
            &user_chirho.principal_chirho,
            "user-secret-value",
            &client_a_chirho.client_id_chirho,
            vec!["invoke_chirho".to_string()],
        )
        .unwrap();
        let token_b_chirho = issue_scoped_token_chirho(
            &root_chirho,
            &user_chirho.principal_chirho,
            "user-secret-value",
            &client_b_chirho.client_id_chirho,
            vec!["invoke_chirho".to_string()],
        )
        .unwrap();
        assert_ne!(token_a_chirho.token_chirho, token_b_chirho.token_chirho);
        assert_eq!(verify_clients_chirho(&root_chirho).unwrap(), 2);
        assert_eq!(verify_scoped_tokens_chirho(&root_chirho).unwrap(), 2);
        assert!(validate_scoped_token_chirho(
            &root_chirho,
            &client_a_chirho.client_id_chirho,
            &token_a_chirho.token_chirho
        )
        .unwrap()
        .is_some());
        assert!(validate_scoped_token_chirho(
            &root_chirho,
            &client_b_chirho.client_id_chirho,
            &token_a_chirho.token_chirho
        )
        .unwrap()
        .is_none());
        assert!(!root_chirho.join("ledger-chirho.jsonl").exists());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn oauth_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
        let root_chirho = tmp_root_chirho();
        let (client_chirho, token_chirho, use_chirho) = oauth_fixture_chirho(&root_chirho);

        assert_eq!(
            client_chirho.schema_chirho,
            OAUTH_CLIENT_RECORD_SCHEMA_CHIRHO
        );
        assert_eq!(
            token_chirho.record_chirho.schema_chirho,
            SCOPED_TOKEN_RECORD_SCHEMA_CHIRHO
        );
        assert_eq!(
            use_chirho.schema_chirho,
            SCOPED_TOKEN_USE_RECORD_SCHEMA_CHIRHO
        );
        assert_eq!(verify_clients_chirho(&root_chirho).unwrap(), 1);
        assert_eq!(verify_scoped_tokens_chirho(&root_chirho).unwrap(), 1);
        assert_eq!(verify_scoped_token_uses_chirho(&root_chirho).unwrap(), 1);

        let mut bad_client_chirho = client_chirho.clone();
        bad_client_chirho.schema_chirho = "oauth-client-record-v9-chirho".to_string();
        write_jsonl_chirho(&clients_path_chirho(&root_chirho), &[bad_client_chirho]);
        let error_chirho = verify_clients_chirho(&root_chirho).unwrap_err().to_string();
        assert!(error_chirho.contains("unsupported oauth client record schema"));
        write_jsonl_chirho(
            &clients_path_chirho(&root_chirho),
            std::slice::from_ref(&client_chirho),
        );

        let mut bad_token_chirho = token_chirho.record_chirho.clone();
        bad_token_chirho.schema_chirho = "scoped-token-record-v9-chirho".to_string();
        write_jsonl_chirho(
            &scoped_tokens_path_chirho(&root_chirho),
            &[bad_token_chirho],
        );
        let error_chirho = verify_scoped_tokens_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("unsupported scoped token record schema"));
        write_jsonl_chirho(
            &scoped_tokens_path_chirho(&root_chirho),
            std::slice::from_ref(&token_chirho.record_chirho),
        );

        let mut bad_use_chirho = use_chirho.clone();
        bad_use_chirho.schema_chirho = "scoped-token-use-record-v9-chirho".to_string();
        write_jsonl_chirho(
            &scoped_token_uses_path_chirho(&root_chirho),
            &[bad_use_chirho],
        );
        let error_chirho = verify_scoped_token_uses_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("unsupported scoped token use record schema"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn legacy_oauth_records_without_schema_still_verify_chirho() {
        let root_chirho = tmp_root_chirho();
        let (_client_chirho, token_chirho, _use_chirho) = oauth_fixture_chirho(&root_chirho);

        let mut clients_chirho = load_clients_chirho(&root_chirho).unwrap();
        for record_chirho in &mut clients_chirho {
            record_chirho.schema_chirho.clear();
            *record_chirho = resign_client_for_test_chirho(&root_chirho, record_chirho.clone());
        }
        write_jsonl_chirho(&clients_path_chirho(&root_chirho), &clients_chirho);

        let mut tokens_chirho = load_scoped_tokens_chirho(&root_chirho).unwrap();
        for record_chirho in &mut tokens_chirho {
            record_chirho.schema_chirho.clear();
            *record_chirho =
                resign_scoped_token_for_test_chirho(&root_chirho, record_chirho.clone());
        }
        write_jsonl_chirho(&scoped_tokens_path_chirho(&root_chirho), &tokens_chirho);

        let mut uses_chirho = load_scoped_token_uses_chirho(&root_chirho).unwrap();
        for record_chirho in &mut uses_chirho {
            record_chirho.schema_chirho.clear();
            *record_chirho =
                resign_scoped_token_use_for_test_chirho(&root_chirho, record_chirho.clone());
        }
        write_jsonl_chirho(&scoped_token_uses_path_chirho(&root_chirho), &uses_chirho);

        for path_chirho in [
            clients_path_chirho(&root_chirho),
            scoped_tokens_path_chirho(&root_chirho),
            scoped_token_uses_path_chirho(&root_chirho),
        ] {
            assert!(!std::fs::read_to_string(path_chirho)
                .unwrap()
                .contains("schema_chirho"));
        }
        assert_eq!(verify_clients_chirho(&root_chirho).unwrap(), 1);
        assert_eq!(verify_scoped_tokens_chirho(&root_chirho).unwrap(), 1);
        assert_eq!(verify_scoped_token_uses_chirho(&root_chirho).unwrap(), 1);
        assert!(validate_scoped_token_chirho(
            &root_chirho,
            &token_chirho.record_chirho.client_id_chirho,
            &token_chirho.token_chirho,
        )
        .unwrap()
        .is_some());
        assert!(load_clients_chirho(&root_chirho)
            .unwrap()
            .iter()
            .all(|record_chirho| record_chirho.schema_chirho.is_empty()));
        assert!(load_scoped_tokens_chirho(&root_chirho)
            .unwrap()
            .iter()
            .all(|record_chirho| record_chirho.schema_chirho.is_empty()));
        assert!(load_scoped_token_uses_chirho(&root_chirho)
            .unwrap()
            .iter()
            .all(|record_chirho| record_chirho.schema_chirho.is_empty()));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn oauth_client_requires_owner_principal_chirho() {
        let root_chirho = tmp_root_chirho();
        let user_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::UserChirho,
            "user-secret-value",
        )
        .unwrap();
        assert!(
            register_client_chirho(&root_chirho, "alpha", &user_chirho.principal_chirho).is_err()
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn scoped_token_rate_limit_counts_identity_and_device_chirho() {
        let root_chirho = tmp_root_chirho();
        let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            "owner-secret-value",
        )
        .unwrap();
        let user_a_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::UserChirho,
            "user-a-secret-value",
        )
        .unwrap();
        let user_b_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::UserChirho,
            "user-b-secret-value",
        )
        .unwrap();
        let client_chirho =
            register_client_chirho(&root_chirho, "guardedapp", &owner_chirho.principal_chirho)
                .unwrap();
        let policy_chirho = ScopedTokenRateLimitChirho {
            window_ms_chirho: 60_000,
            max_invokes_chirho: 1,
            device_id_chirho: Some("device-a".to_string()),
        };
        let token_a_chirho = issue_scoped_token_with_rate_limit_chirho(
            &root_chirho,
            &user_a_chirho.principal_chirho,
            "user-a-secret-value",
            &client_chirho.client_id_chirho,
            vec!["invoke_chirho".to_string()],
            Some(policy_chirho.clone()),
        )
        .unwrap();
        assert!(
            record_scoped_token_use_chirho(&root_chirho, &token_a_chirho.record_chirho)
                .unwrap()
                .is_some()
        );
        let same_identity_err_chirho =
            record_scoped_token_use_chirho(&root_chirho, &token_a_chirho.record_chirho)
                .unwrap_err();
        assert!(same_identity_err_chirho
            .downcast_ref::<RateLimitExceededChirho>()
            .is_some());

        let token_b_chirho = issue_scoped_token_with_rate_limit_chirho(
            &root_chirho,
            &user_b_chirho.principal_chirho,
            "user-b-secret-value",
            &client_chirho.client_id_chirho,
            vec!["invoke_chirho".to_string()],
            Some(policy_chirho),
        )
        .unwrap();
        let same_device_err_chirho =
            record_scoped_token_use_chirho(&root_chirho, &token_b_chirho.record_chirho)
                .unwrap_err();
        assert!(same_device_err_chirho
            .downcast_ref::<RateLimitExceededChirho>()
            .is_some());
        assert_eq!(verify_scoped_token_uses_chirho(&root_chirho).unwrap(), 1);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
