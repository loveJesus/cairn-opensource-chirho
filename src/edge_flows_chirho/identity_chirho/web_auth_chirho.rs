// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use anyhow::Result;
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A human-check refusal meant for the visitor, typed so a served answer can repeat its exact sentence
/// while any other failure (a malformed token, the signing key) stays out of the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthHumanCheckRefusalChirho {
    UnsupportedTokenSchemaChirho,
    TokenSignatureInvalidChirho,
    TokenExpiredChirho,
    AnswerInvalidChirho,
}

impl AuthHumanCheckRefusalChirho {
    /// The fixed sentence for this refusal.
    pub const fn message_chirho(self) -> &'static str {
        match self {
            Self::UnsupportedTokenSchemaChirho => "unsupported auth human-check token schema",
            Self::TokenSignatureInvalidChirho => "auth human-check token signature invalid",
            Self::TokenExpiredChirho => "auth human-check token expired",
            Self::AnswerInvalidChirho => "auth human-check answer invalid",
        }
    }
}

impl std::fmt::Display for AuthHumanCheckRefusalChirho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message_chirho())
    }
}

impl std::error::Error for AuthHumanCheckRefusalChirho {}

const AUTH_HUMAN_CHECK_SCHEMA_CHIRHO: &str = "auth-human-check-v1-chirho";
const AUTH_HUMAN_CHECK_TTL_MS_CHIRHO: u64 = 10 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthHumanCheckChallengeChirho {
    pub question_chirho: String,
    pub token_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AuthHumanCheckTokenChirho {
    schema_chirho: String,
    nonce_chirho: String,
    question_chirho: String,
    answer_hash_chirho: String,
    issued_ms_chirho: u64,
    expires_ms_chirho: u64,
    sig_chirho: String,
}

pub fn issue_auth_human_check_challenge_chirho(
    root_chirho: &Path,
) -> Result<AuthHumanCheckChallengeChirho> {
    let nonce_chirho = super::random_token_chirho();
    let digest_chirho = blake3::hash(nonce_chirho.as_bytes());
    let bytes_chirho = digest_chirho.as_bytes();
    let left_chirho = 2 + (bytes_chirho[0] % 17) as u32;
    let right_chirho = 2 + (bytes_chirho[1] % 17) as u32;
    let answer_chirho = (left_chirho + right_chirho).to_string();
    let question_chirho = format!("{left_chirho} + {right_chirho}");
    let issued_ms_chirho = super::now_ms_chirho();
    let mut token_chirho = AuthHumanCheckTokenChirho {
        schema_chirho: AUTH_HUMAN_CHECK_SCHEMA_CHIRHO.to_string(),
        nonce_chirho,
        question_chirho: question_chirho.clone(),
        answer_hash_chirho: auth_human_check_answer_hash_chirho(&question_chirho, &answer_chirho),
        issued_ms_chirho,
        expires_ms_chirho: issued_ms_chirho + AUTH_HUMAN_CHECK_TTL_MS_CHIRHO,
        sig_chirho: String::new(),
    };
    token_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &auth_human_check_message_chirho(&token_chirho)?,
    )?;
    Ok(AuthHumanCheckChallengeChirho {
        question_chirho,
        token_chirho: super::hex_encode_chirho(&serde_json::to_vec(&token_chirho)?),
    })
}

pub fn verify_auth_human_check_chirho(
    root_chirho: &Path,
    token_chirho: &str,
    answer_chirho: &str,
) -> Result<()> {
    let token_bytes_chirho = super::hex_decode_chirho(token_chirho.trim())?;
    let token_chirho: AuthHumanCheckTokenChirho = serde_json::from_slice(&token_bytes_chirho)?;
    if token_chirho.schema_chirho != AUTH_HUMAN_CHECK_SCHEMA_CHIRHO {
        return Err(AuthHumanCheckRefusalChirho::UnsupportedTokenSchemaChirho.into());
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        &pubkey_chirho,
        &auth_human_check_message_chirho(&token_chirho)?,
        &token_chirho.sig_chirho,
    )? {
        return Err(AuthHumanCheckRefusalChirho::TokenSignatureInvalidChirho.into());
    }
    if token_chirho.expires_ms_chirho < super::now_ms_chirho() {
        return Err(AuthHumanCheckRefusalChirho::TokenExpiredChirho.into());
    }
    let actual_hash_chirho =
        auth_human_check_answer_hash_chirho(&token_chirho.question_chirho, answer_chirho);
    if !super::constant_time_string_eq_chirho(&token_chirho.answer_hash_chirho, &actual_hash_chirho)
    {
        return Err(AuthHumanCheckRefusalChirho::AnswerInvalidChirho.into());
    }
    Ok(())
}

// Workflow: spec-chirho/workflows-chirho/identity-auth-chirho/public-registration-gate-chirho.md
pub fn public_registration_token_matches_chirho(
    configured_token_chirho: &str,
    request_token_chirho: &str,
) -> bool {
    super::constant_time_string_eq_chirho(configured_token_chirho, request_token_chirho)
}

pub fn auth_register_html_chirho(challenge_chirho: &AuthHumanCheckChallengeChirho) -> String {
    format!(
        "<!doctype html>\n<meta charset=\"utf-8\">\n<title>cairn-chirho registration</title>\n<body>\n<h1>register</h1>\n<form method=\"post\" action=\"/auth-chirho/register-chirho\"><input type=\"hidden\" name=\"kind_chirho\" value=\"user\"><input type=\"hidden\" name=\"human_check_token_chirho\" value=\"{}\"><label>registration token <input name=\"registration_token_chirho\" type=\"password\" autocomplete=\"off\"></label><label>password <input name=\"credential_chirho\" type=\"password\" autocomplete=\"new-password\"></label><label>{} = <input name=\"human_check_chirho\" inputmode=\"numeric\"></label><button type=\"submit\">register</button></form>\n<p>Already registered? <a href=\"/auth-chirho/login-chirho\">log in</a>.</p>\n<p>JSON APIs remain available on the same endpoints.</p>\n</body>\n",
        super::escape_html_chirho(&challenge_chirho.token_chirho),
        super::escape_html_chirho(&challenge_chirho.question_chirho)
    )
}

pub fn auth_login_html_chirho() -> String {
    "<!doctype html>\n<meta charset=\"utf-8\">\n<title>cairn-chirho login</title>\n<body>\n<h1>login</h1>\n<form method=\"post\" action=\"/auth-chirho/login-chirho\"><label>principal <input name=\"principal_chirho\" autocomplete=\"username\"></label><label>password <input name=\"credential_chirho\" type=\"password\" autocomplete=\"current-password\"></label><button type=\"submit\">login</button></form>\n<p>Need an account? <a href=\"/auth-chirho/register-chirho\">register</a>.</p>\n<p>The JSON API remains available on the same endpoint.</p>\n</body>\n".to_string()
}

fn auth_human_check_message_chirho(token_chirho: &AuthHumanCheckTokenChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = token_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

fn auth_human_check_answer_hash_chirho(question_chirho: &str, answer_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(b"cairn-chirho/auth-human-check-answer/v1");
    hasher_chirho.update(question_chirho.as_bytes());
    hasher_chirho.update(b"\0");
    hasher_chirho.update(answer_chirho.trim().as_bytes());
    super::hex_encode_chirho(hasher_chirho.finalize().as_bytes())
}
