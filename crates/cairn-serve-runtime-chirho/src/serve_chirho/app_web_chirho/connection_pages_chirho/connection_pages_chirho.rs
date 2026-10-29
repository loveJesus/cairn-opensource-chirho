// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 Part 3's trusted native pages: typed models filled into the authored templates beside this file, never HTML
//! assembled in Rust, and never rendered through a DAG (PFE #26804). Each value that comes from a request or a record is
//! escaped once, where it enters a model's fill; the templates and the shared style are trusted, authored text. Only
//! the one-time page's model holds a secret. An optional return path (Account Create brick 1) rides the form as a hidden
//! field and appears on the one-time page as an ordinary escaped link, never a redirect of that page. The connection
//! sign-in page (PFE unit 330) carries the form's accepted target as its hidden field, and shows each refusal that can
//! bring her back to it by CSS `:target` alone, with no script.

use anyhow::{bail, Result};
use axum::http::StatusCode;

const FORM_TEMPLATE_CHIRHO: &str = include_str!("connection_form_chirho.html");
const ACTION_TEMPLATE_CHIRHO: &str = include_str!("connection_action_chirho.html");
const CREATED_TEMPLATE_CHIRHO: &str = include_str!("connection_created_chirho.html");
const ANSWER_TEMPLATE_CHIRHO: &str = include_str!("connection_answer_chirho.html");
const STYLE_CHIRHO: &str = include_str!("connection_style_chirho.css");
const RETURN_FIELD_TEMPLATE_CHIRHO: &str = include_str!("connection_return_field_chirho.html");
const RETURN_LINK_TEMPLATE_CHIRHO: &str = include_str!("connection_return_link_chirho.html");
const SIGN_IN_TEMPLATE_CHIRHO: &str = include_str!("connection_sign_in_chirho.html");

/// Fill `template_chirho`'s `{{name}}` placeholders from `values_chirho` in one pass over the template, so text inside a
/// value is never read as a placeholder. An unknown or unclosed placeholder is an error that names the placeholder and
/// never a value.
fn fill_chirho(template_chirho: &str, values_chirho: &[(&str, &str)]) -> Result<String> {
    let mut filled_chirho = String::with_capacity(template_chirho.len());
    let mut rest_chirho = template_chirho;
    while let Some(start_chirho) = rest_chirho.find("{{") {
        filled_chirho.push_str(&rest_chirho[..start_chirho]);
        let after_chirho = &rest_chirho[start_chirho + 2..];
        let Some(end_chirho) = after_chirho.find("}}") else {
            bail!("a template has an unclosed placeholder");
        };
        let name_chirho = &after_chirho[..end_chirho];
        let Some((_name_chirho, value_chirho)) = values_chirho
            .iter()
            .find(|(candidate_chirho, _value_chirho)| *candidate_chirho == name_chirho)
        else {
            bail!("a template's placeholder '{name_chirho}' has no value");
        };
        filled_chirho.push_str(value_chirho);
        rest_chirho = &after_chirho[end_chirho + 2..];
    }
    filled_chirho.push_str(rest_chirho);
    Ok(filled_chirho)
}

/// A fragment template without its leading source-header comment, so a repeated fragment does not repeat it.
fn fragment_chirho(template_chirho: &str) -> &str {
    if template_chirho.starts_with("<!--") {
        template_chirho
            .split_once('\n')
            .map_or("", |(_header_chirho, rest_chirho)| rest_chirho)
    } else {
        template_chirho
    }
}

fn escaped_chirho(value_chirho: &str) -> String {
    super::super::escape_html_chirho(value_chirho)
}

/// The form, for one connection client of the signed-in owner: its app, the actions that app opens now, and the return
/// path the POST carries on, when there is one.
pub(super) struct ConnectionFormPageChirho<'page_chirho> {
    pub(super) client_id_chirho: &'page_chirho str,
    pub(super) app_chirho: &'page_chirho str,
    pub(super) actions_chirho: &'page_chirho [String],
    pub(super) return_chirho: Option<&'page_chirho str>,
}

impl ConnectionFormPageChirho<'_> {
    pub(super) fn render_chirho(&self) -> Result<String> {
        let mut actions_chirho = String::new();
        for action_chirho in self.actions_chirho {
            actions_chirho.push_str(&fill_chirho(
                fragment_chirho(ACTION_TEMPLATE_CHIRHO),
                &[("action_chirho", &escaped_chirho(action_chirho))],
            )?);
        }
        fill_chirho(
            FORM_TEMPLATE_CHIRHO,
            &[
                ("style_chirho", STYLE_CHIRHO),
                ("app_chirho", &escaped_chirho(self.app_chirho)),
                ("client_id_chirho", &escaped_chirho(self.client_id_chirho)),
                ("actions_chirho", &actions_chirho),
                (
                    "return_field_chirho",
                    &self
                        .return_chirho
                        .map_or(Ok(String::new()), |return_chirho| {
                            fill_chirho(
                                fragment_chirho(RETURN_FIELD_TEMPLATE_CHIRHO),
                                &[("return_chirho", &escaped_chirho(return_chirho))],
                            )
                        })?,
                ),
            ],
        )
    }
}

/// The one-time page: the only model that holds the secret, shown once in the originating POST's own answer, with an
/// ordinary link back to the app when the form carried a return path.
pub(super) struct ConnectionCreatedPageChirho<'page_chirho> {
    pub(super) app_chirho: &'page_chirho str,
    pub(super) actions_chirho: &'page_chirho [String],
    pub(super) bearer_chirho: &'page_chirho str,
    pub(super) return_chirho: Option<&'page_chirho str>,
}

impl ConnectionCreatedPageChirho<'_> {
    pub(super) fn render_chirho(&self) -> Result<String> {
        let actions_chirho = self
            .actions_chirho
            .iter()
            .map(|action_chirho| escaped_chirho(action_chirho))
            .collect::<Vec<_>>()
            .join(", ");
        fill_chirho(
            CREATED_TEMPLATE_CHIRHO,
            &[
                ("style_chirho", STYLE_CHIRHO),
                ("app_chirho", &escaped_chirho(self.app_chirho)),
                ("actions_chirho", &actions_chirho),
                ("bearer_chirho", &escaped_chirho(self.bearer_chirho)),
                (
                    "return_link_chirho",
                    &self
                        .return_chirho
                        .map_or(Ok(String::new()), |return_chirho| {
                            fill_chirho(
                                fragment_chirho(RETURN_LINK_TEMPLATE_CHIRHO),
                                &[
                                    ("return_chirho", &escaped_chirho(return_chirho)),
                                    ("app_chirho", &escaped_chirho(self.app_chirho)),
                                ],
                            )
                        })?,
                ),
            ],
        )
    }
}

/// The connection sign-in page (PFE unit 330): the sign-in form, posting to the login road with the connection form's
/// accepted target as its hidden field, and a notice for each refusal that can bring her back here. The caller has
/// accepted the target; it is escaped here.
pub(super) struct ConnectionSignInPageChirho<'page_chirho> {
    pub(super) target_chirho: &'page_chirho str,
}

impl ConnectionSignInPageChirho<'_> {
    pub(super) fn render_chirho(&self) -> Result<String> {
        fill_chirho(
            SIGN_IN_TEMPLATE_CHIRHO,
            &[
                ("style_chirho", STYLE_CHIRHO),
                ("target_chirho", &escaped_chirho(self.target_chirho)),
            ],
        )
    }
}

/// The fixed answers that are not a 303 back to the form: each a status, a token and fixed words, carrying no value
/// from the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConnectionAnswerPageChirho {
    /// The road's gate is closed (503).
    DisabledChirho,
    /// The form's GET names no client the signed-in owner can connect (400).
    RequestInvalidChirho,
    /// The session's append failed, so no key was written (500).
    NotCreatedChirho,
    /// A connection may exist, and its key was not shown (500).
    UncertainChirho,
    /// An engine failure before anything was appended (500).
    FailedChirho,
}

impl ConnectionAnswerPageChirho {
    pub(super) fn status_chirho(self) -> StatusCode {
        match self {
            Self::DisabledChirho => StatusCode::SERVICE_UNAVAILABLE,
            Self::RequestInvalidChirho => StatusCode::BAD_REQUEST,
            Self::NotCreatedChirho | Self::UncertainChirho | Self::FailedChirho => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    pub(super) fn token_chirho(self) -> &'static str {
        match self {
            Self::DisabledChirho => "connection-issuance-disabled-chirho",
            Self::RequestInvalidChirho => "request-invalid-chirho",
            Self::NotCreatedChirho => "connection-not-created-chirho",
            Self::UncertainChirho => "connection-uncertain-chirho",
            Self::FailedChirho => "connection-failed-chirho",
        }
    }

    fn words_chirho(self) -> (&'static str, &'static str) {
        match self {
            Self::DisabledChirho => (
                "Connections are not open",
                "Creating a connection is not available on this server.",
            ),
            Self::RequestInvalidChirho => (
                "This connection cannot be created",
                "This link does not name a tool you can connect here.",
            ),
            Self::NotCreatedChirho => (
                "The connection was not created",
                "No connection was created. You can try again.",
            ),
            Self::UncertainChirho => (
                "The connection may have been created",
                "Your connection may have been created, and its key was not shown. Open your connections and end any \
                 you did not receive before creating another.",
            ),
            Self::FailedChirho => (
                "The connection could not be created",
                "Nothing was created. Try again later.",
            ),
        }
    }

    /// The page. Should its fixed template ever fail to fill, the bare token, so the answer still says what it is.
    pub(super) fn render_chirho(self) -> String {
        let (title_chirho, message_chirho) = self.words_chirho();
        fill_chirho(
            ANSWER_TEMPLATE_CHIRHO,
            &[
                ("style_chirho", STYLE_CHIRHO),
                ("title_chirho", title_chirho),
                ("token_chirho", self.token_chirho()),
                ("message_chirho", message_chirho),
            ],
        )
        .unwrap_or_else(|_error_chirho| self.token_chirho().to_string())
    }
}

#[cfg(test)]
#[path = "connection_pages_tests_chirho.rs"]
mod connection_pages_tests_chirho;
