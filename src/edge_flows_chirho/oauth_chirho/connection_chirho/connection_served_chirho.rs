// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 Part 3's served issuance, the engine half: what the engine-rendered form offers for a client, and the one call its
//! POST makes, through Part 2's connection door, with the attempt rows the token road knows and an outcome the served
//! road's source meter settles.
//!
//! - **The attempt law.** A refused credential appends one failure row as `token-chirho`, and a created connection one
//!   success row; nothing else appends a row. The token road's own cap refusal follows a success row its sign-in already
//!   appended (PFE #26804); here the success row follows the key, so the cap and the daily limit append none.
//! - **The outcome.** A created connection whose success row is appended carries its bearer, to be shown once. A key
//!   that may exist without that (its append uncertain, or its success row not appended) is `UncertainChirho`: its
//!   bearer is dropped here and never shown. Both keep the source's success slot, and every refusal this call returns
//!   releases it. A task that panics never settles, so its slots stay charged until they expire (PFE #26814).
//! - **Selection by app** (Account Create brick 1, PFE #26824): the form may name its app instead of its client. The app
//!   resolves through the connection-client view to exactly one verified connection client, then follows the client's
//!   road unchanged. None or several is request-invalid, and a fault is an engine failure, never an absence.
//! - **The return path** is navigation data, never authority: exactly `/app-chirho/<the client's app>/<a route name>`,
//!   checked here against the verified client's app before anything is appended (PFE #26824, #26837).
//!
//! Workflow: `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md` (Part 3's
//! placement, as decided).

use super::super::limited_key_chirho::opened_key_routes_now_chirho;
use super::super::{
    find_client_chirho, now_ms_chirho, public_default_rate_limit_chirho, OauthClientRecordChirho,
    ScopedTokenCapReachedChirho, ScopedTokenIssueChirho,
};
use super::connection_client_view_chirho::{
    connection_client_for_app_chirho, AppConnectionClientChirho,
};
use super::{
    issue_connection_key_at_chirho, ConnectionDailyLimitReachedChirho, ConnectionIssueFaultChirho,
    KeyStoreChirho,
};
use crate::identity_chirho::{
    self, CredentialMismatchChirho, IdentityAuthAttemptOutcomeChirho, PublicAuthRefusalChirho,
    SignInVelocityChirho,
};
use anyhow::{anyhow, Result};
use cairn_capability_chirho::capability_key_grant_chirho::limited_key_grants_for_actions_chirho;
use cairn_model_app_chirho::{validate_app_name_chirho, validate_route_name_chirho};
use std::path::Path;

/// One served issuance's request: who asks and the credential she enters again, the client and the actions she chose,
/// and the return path her one-time page links back to, when there is one.
#[derive(Clone, Copy)]
pub struct ConnectionServedRequestChirho<'request_chirho> {
    pub principal_chirho: &'request_chirho str,
    pub credential_chirho: &'request_chirho str,
    pub client_id_chirho: &'request_chirho str,
    pub actions_chirho: &'request_chirho [String],
    pub return_chirho: Option<&'request_chirho str>,
}

/// How the form names its client (Account Create brick 1): by the client's id, as before, or by its app's name, which
/// must resolve to exactly one verified connection client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionSelectorChirho {
    ClientChirho(String),
    AppChirho(String),
}

/// The longest app name a selector carries.
pub const CONNECTION_APP_SELECTOR_MAX_BYTES_CHIRHO: usize = 128;
/// The longest return path a connection form carries.
pub const CONNECTION_RETURN_MAX_BYTES_CHIRHO: usize = 256;
/// Where an app's named routes are served.
const APP_ROUTE_PREFIX_CHIRHO: &str = "/app-chirho/";

/// An app name a selector may carry: the app grammar, at most 128 bytes.
pub fn connection_app_selector_well_formed_chirho(app_chirho: &str) -> bool {
    app_chirho.len() <= CONNECTION_APP_SELECTOR_MAX_BYTES_CHIRHO
        && validate_app_name_chirho(app_chirho).is_ok()
}

/// A return path's app and route: exactly `/app-chirho/<app>/<route>`, at most 256 bytes, each segment passing its model
/// grammar, made only of URL-unreserved characters, and not a dot segment (PFE #26837: `.` and `..` pass the grammars,
/// and a browser would resolve them away). So no query, fragment, percent-encoding, backslash, control character, extra
/// segment, trailing slash or dot segment survives, and the path means the same to every reader.
fn return_segments_chirho(path_chirho: &str) -> Option<(&str, &str)> {
    let segment_ok_chirho = |segment_chirho: &str| {
        !matches!(segment_chirho, "" | "." | "..")
            && segment_chirho.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_alphanumeric()
                    || matches!(byte_chirho, b'-' | b'.' | b'_' | b'~')
            })
    };
    if path_chirho.len() > CONNECTION_RETURN_MAX_BYTES_CHIRHO {
        return None;
    }
    let (app_chirho, route_chirho) = path_chirho
        .strip_prefix(APP_ROUTE_PREFIX_CHIRHO)?
        .split_once('/')?;
    (segment_ok_chirho(app_chirho)
        && segment_ok_chirho(route_chirho)
        && validate_app_name_chirho(app_chirho).is_ok()
        && validate_route_name_chirho(route_chirho).is_ok())
    .then_some((app_chirho, route_chirho))
}

/// A return path of the right shape, for some app: what a signed-out GET naming a client can check before it signs in.
pub fn connection_return_path_well_formed_chirho(path_chirho: &str) -> bool {
    return_segments_chirho(path_chirho).is_some()
}

/// A return path to one of `app_chirho`'s named routes: navigation data only, never authority (PFE #26824).
pub fn connection_return_path_for_app_chirho(app_chirho: &str, path_chirho: &str) -> bool {
    return_segments_chirho(path_chirho)
        .is_some_and(|(path_app_chirho, _route_chirho)| path_app_chirho == app_chirho)
}

/// What the form offers for one connection client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionFormChoicesChirho {
    pub client_id_chirho: String,
    pub app_chirho: String,
    /// The app's currently opened actions, in its key-authority record's order, each once.
    pub actions_chirho: Vec<String>,
}

/// The request names no connection client, or actions its app cannot grant now. It is refused before the sign-in, with
/// no attempt row, and nothing is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionRequestInvalidChirho {
    cause_chirho: String,
}

impl std::fmt::Display for ConnectionRequestInvalidChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter_chirho,
            "ConnectionRequestInvalidChirho: {}",
            self.cause_chirho
        )
    }
}

impl std::error::Error for ConnectionRequestInvalidChirho {}

fn request_invalid_chirho(cause_chirho: impl Into<String>) -> PublicAuthRefusalChirho {
    PublicAuthRefusalChirho::not_recorded_chirho(
        ConnectionRequestInvalidChirho {
            cause_chirho: cause_chirho.into(),
        }
        .into(),
    )
}

/// What a served issuance came to, when it was not refused. Its `Debug` never prints the bearer.
pub enum ConnectionServedOutcomeChirho {
    /// Created, with its success row appended: the bearer, for the one-time page.
    CreatedChirho(Box<ScopedTokenIssueChirho>),
    /// A connection may exist, or does, and its bearer will not be shown: the key's append was uncertain, or its
    /// success row could not be appended. Such a key holds a slot until it is ended or expires. The cause is for the
    /// server's log; it names no secret.
    UncertainChirho { cause_chirho: String },
}

impl std::fmt::Debug for ConnectionServedOutcomeChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreatedChirho(issue_chirho) => formatter_chirho
                .debug_struct("CreatedChirho")
                .field("seq_chirho", &issue_chirho.record_chirho.seq_chirho)
                .field("app_chirho", &issue_chirho.record_chirho.app_chirho)
                .field("bearer_chirho", &"<shown once, never printed>")
                .finish(),
            Self::UncertainChirho { cause_chirho } => formatter_chirho
                .debug_struct("UncertainChirho")
                .field("cause_chirho", cause_chirho)
                .finish(),
        }
    }
}

/// What a served issuance's refusal was, for the served road's fixed answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionServedRefusalChirho {
    /// No connection client by that id, or actions its app cannot grant now.
    RequestInvalidChirho,
    /// A refused credential, its failure row appended.
    CredentialMismatchChirho,
    /// The token road's pre-check, R12's source admission, or the daily limit: one answer for every rate limit.
    RateLimitedChirho,
    /// The cap of live keys.
    SlotsFullChirho,
    /// The session's append failed, so no key was written.
    NotCreatedChirho,
    /// A key that may exist. The road reports one as an outcome, never as a refusal; this keeps the reading conservative
    /// if one ever arrives as an error.
    UncertainChirho,
    /// Any other failure before an append: a log that fails verification, or a failure row that could not be appended.
    FailedChirho,
}

impl ConnectionServedRefusalChirho {
    /// The kind of `refusal_chirho`, read from its error's type. A refused credential counts as one only when its
    /// failure row was appended.
    pub fn of_chirho(refusal_chirho: &PublicAuthRefusalChirho) -> Self {
        let error_chirho = &refusal_chirho.error_chirho;
        if error_chirho
            .downcast_ref::<ConnectionRequestInvalidChirho>()
            .is_some()
        {
            Self::RequestInvalidChirho
        } else if refusal_chirho.failure_recorded_chirho
            && error_chirho
                .downcast_ref::<CredentialMismatchChirho>()
                .is_some()
        {
            Self::CredentialMismatchChirho
        } else if identity_chirho::is_auth_rate_limit_error_chirho(error_chirho)
            || error_chirho
                .downcast_ref::<ConnectionDailyLimitReachedChirho>()
                .is_some()
        {
            Self::RateLimitedChirho
        } else if error_chirho
            .downcast_ref::<ScopedTokenCapReachedChirho>()
            .is_some()
        {
            Self::SlotsFullChirho
        } else {
            match error_chirho.downcast_ref::<ConnectionIssueFaultChirho>() {
                Some(ConnectionIssueFaultChirho::SessionUncertainChirho { .. }) => {
                    Self::NotCreatedChirho
                }
                Some(ConnectionIssueFaultChirho::KeyUncertainChirho { .. }) => {
                    Self::UncertainChirho
                }
                None => Self::FailedChirho,
            }
        }
    }
}

/// `client_id_chirho`'s record when it names a connection client; `None` for an unknown client or a legacy one.
fn connection_client_chirho(
    root_chirho: &Path,
    client_id_chirho: &str,
) -> Result<Option<OauthClientRecordChirho>> {
    Ok(
        find_client_chirho(root_chirho, client_id_chirho)?.filter(|client_chirho| {
            KeyStoreChirho::of_client_chirho(client_chirho) == KeyStoreChirho::ConnectionChirho
        }),
    )
}

/// The form's choices for `selector_chirho`. An app selects its one verified connection client through the
/// connection-client view, then the client's choices follow as for an id. `None` for an unknown client or app, an app
/// with several connection clients, a client that is not a connection client, or one whose app opens nothing now. An
/// error is a read that failed: a fault never reads as an absence.
pub fn connection_form_choices_chirho(
    root_chirho: &Path,
    selector_chirho: &ConnectionSelectorChirho,
) -> Result<Option<ConnectionFormChoicesChirho>> {
    let (client_id_chirho, selected_app_chirho) = match selector_chirho {
        ConnectionSelectorChirho::ClientChirho(client_id_chirho) => {
            (client_id_chirho.clone(), None)
        }
        ConnectionSelectorChirho::AppChirho(app_chirho) => {
            match connection_client_for_app_chirho(root_chirho, app_chirho)? {
                AppConnectionClientChirho::OneChirho(client_id_chirho) => {
                    (client_id_chirho, Some(app_chirho))
                }
                AppConnectionClientChirho::NoneChirho
                | AppConnectionClientChirho::SeveralChirho => return Ok(None),
            }
        }
    };
    let Some(client_chirho) = connection_client_chirho(root_chirho, &client_id_chirho)? else {
        return Ok(None);
    };
    if let Some(selected_app_chirho) = selected_app_chirho {
        if &client_chirho.app_chirho != selected_app_chirho {
            return Err(anyhow!(
                "the connection client selected for '{selected_app_chirho}' belongs to another app"
            ));
        }
    }
    let Some(opened_chirho) = opened_key_routes_now_chirho(root_chirho, &client_chirho.app_chirho)?
    else {
        return Ok(None);
    };
    let mut actions_chirho: Vec<String> = Vec::new();
    for route_chirho in opened_chirho {
        if !actions_chirho.contains(&route_chirho.action_chirho) {
            actions_chirho.push(route_chirho.action_chirho);
        }
    }
    if actions_chirho.is_empty() {
        return Ok(None);
    }
    Ok(Some(ConnectionFormChoicesChirho {
        client_id_chirho: client_chirho.client_id_chirho,
        app_chirho: client_chirho.app_chirho,
        actions_chirho,
    }))
}

/// K4 Part 3's served issuance: a connection key for the signed-in `principal_chirho` through `client_id_chirho`,
/// holding `actions_chirho`, once her `credential_chirho` is proved again. In order:
/// 1. the client must be a connection client, a return path one of its app's named routes, and the actions a subset of
///    its app's current openings, or it refuses with no attempt row;
/// 2. the token road's pre-check, which refuses with no attempt row;
/// 3. Part 2's connection door: the proof under the credential lock, then one append-lock section that decides the daily
///    limit and the cap and appends the 30-day session and the key.
///
/// The attempt rows and the outcome follow the module's attempt law.
///
/// Workflow: the served issuance DAG in `connection-keys-k4-design-chirho.md` (Part 3's placement, as decided).
pub fn issue_connection_key_served_chirho(
    root_chirho: &Path,
    request_chirho: &ConnectionServedRequestChirho<'_>,
    velocity_chirho: &SignInVelocityChirho,
) -> std::result::Result<ConnectionServedOutcomeChirho, PublicAuthRefusalChirho> {
    issue_connection_key_served_at_chirho(
        root_chirho,
        request_chirho,
        velocity_chirho,
        now_ms_chirho,
    )
}

/// The served issuance at `clock_chirho()`, as `issue_connection_key_served_chirho` runs it with the real clock.
pub(in crate::oauth_chirho) fn issue_connection_key_served_at_chirho(
    root_chirho: &Path,
    request_chirho: &ConnectionServedRequestChirho<'_>,
    velocity_chirho: &SignInVelocityChirho,
    clock_chirho: impl FnOnce() -> u64,
) -> std::result::Result<ConnectionServedOutcomeChirho, PublicAuthRefusalChirho> {
    let ConnectionServedRequestChirho {
        principal_chirho,
        credential_chirho,
        client_id_chirho,
        actions_chirho,
        return_chirho,
    } = *request_chirho;
    let client_chirho = connection_client_chirho(root_chirho, client_id_chirho)
        .map_err(PublicAuthRefusalChirho::not_recorded_chirho)?
        .ok_or_else(|| request_invalid_chirho("no connection client has that id"))?;
    if return_chirho.is_some_and(|return_chirho| {
        !connection_return_path_for_app_chirho(&client_chirho.app_chirho, return_chirho)
    }) {
        return Err(request_invalid_chirho(
            "the return path is not a named route of the client's app",
        ));
    }
    let opened_chirho = opened_key_routes_now_chirho(root_chirho, &client_chirho.app_chirho)
        .map_err(PublicAuthRefusalChirho::not_recorded_chirho)?
        .ok_or_else(|| request_invalid_chirho("the client's app opens nothing to keys now"))?;
    let grants_chirho = limited_key_grants_for_actions_chirho(
        &client_chirho.app_chirho,
        actions_chirho,
        &opened_chirho,
    )
    .map_err(|error_chirho| request_invalid_chirho(format!("{error_chirho:#}")))?;
    identity_chirho::ensure_scoped_token_sign_in_allowed_chirho(
        root_chirho,
        principal_chirho,
        velocity_chirho,
    )
    .map_err(PublicAuthRefusalChirho::not_recorded_chirho)?;
    match issue_connection_key_at_chirho(
        root_chirho,
        &client_chirho,
        principal_chirho,
        credential_chirho,
        grants_chirho,
        public_default_rate_limit_chirho(),
        clock_chirho,
    ) {
        Ok(issue_chirho) => match identity_chirho::append_scoped_token_attempt_chirho(
            root_chirho,
            principal_chirho,
            IdentityAuthAttemptOutcomeChirho::SuccessChirho,
        ) {
            Ok(()) => Ok(ConnectionServedOutcomeChirho::CreatedChirho(Box::new(
                issue_chirho,
            ))),
            Err(error_chirho) => {
                // The connection exists and its bearer is in hand, but the success it is owed was not recorded: the
                // answer is uncertain, and the bearer is dropped here, never shown (PFE #26801).
                drop(issue_chirho);
                Ok(ConnectionServedOutcomeChirho::UncertainChirho {
                    cause_chirho: format!(
                        "the connection was created and its success row could not be appended ({error_chirho:#})"
                    ),
                })
            }
        },
        Err(error_chirho) => {
            if matches!(
                error_chirho.downcast_ref::<ConnectionIssueFaultChirho>(),
                Some(ConnectionIssueFaultChirho::KeyUncertainChirho { .. })
            ) {
                return Ok(ConnectionServedOutcomeChirho::UncertainChirho {
                    cause_chirho: format!("{error_chirho:#}"),
                });
            }
            if error_chirho
                .downcast_ref::<CredentialMismatchChirho>()
                .is_some()
            {
                identity_chirho::append_scoped_token_attempt_chirho(
                    root_chirho,
                    principal_chirho,
                    IdentityAuthAttemptOutcomeChirho::FailureChirho,
                )
                .map_err(PublicAuthRefusalChirho::not_recorded_chirho)?;
                return Err(PublicAuthRefusalChirho::recorded_chirho(error_chirho));
            }
            Err(PublicAuthRefusalChirho::not_recorded_chirho(error_chirho))
        }
    }
}
