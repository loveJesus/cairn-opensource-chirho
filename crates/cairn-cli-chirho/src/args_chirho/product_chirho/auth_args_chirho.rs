// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Grouped clap argument payloads for `auth_args_chirho`.

use std::path::PathBuf;

#[derive(clap::Args)]
pub struct IdentityRegisterArgsChirho {
    #[arg(long = "kind", default_value = "user")]
    pub kind_chirho: String,
    #[arg(long = "credential")]
    pub credential_chirho: Option<String>,
    #[arg(long = "credential-file")]
    pub credential_file_chirho: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct IdentityCredentialInventoryArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
    #[arg(long = "fail-on-legacy")]
    pub fail_on_legacy_chirho: bool,
}

#[derive(clap::Args)]
pub struct IdentityCredentialSetArgsChirho {
    pub principal_chirho: String,
    #[arg(long = "credential-file")]
    pub credential_file_chirho: PathBuf,
}

#[derive(clap::Args)]
pub struct IdentityCredentialResetArgsChirho {
    pub principal_chirho: String,
    #[arg(long = "credential-file")]
    pub credential_file_chirho: PathBuf,
    #[arg(long = "reason", default_value = "operator-credential-reset-chirho")]
    pub reason_chirho: String,
}

/// `identity-invite`: a new credentialless USER principal and its setup code, printed ONCE on stdout. `--kind` has no
/// default and one legal value, `user`; it stays so the operator's command line says what it makes (PFE #26061).
#[derive(clap::Args)]
pub struct IdentityInviteArgsChirho {
    #[arg(long = "kind")]
    pub kind_chirho: String,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct IdentityRecoveryCodeMintArgsChirho {
    #[arg(long = "principal")]
    pub principal_chirho: String,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct IdentityRecoveryCodeEventsArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct IdentitySessionRevokeArgsChirho {
    pub principal_chirho: String,
    #[arg(long = "token-file")]
    pub token_file_chirho: Option<PathBuf>,
    #[arg(long = "session-seq")]
    pub session_seq_chirho: Option<u64>,
    #[arg(long = "reason", default_value = "operator-revoke-chirho")]
    pub reason_chirho: String,
}

#[derive(clap::Args)]
pub struct OauthClientRegisterArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
}

/// `oauth-limited-key`: issue a limited key holding named actions over the app's current openings (K1).
#[derive(clap::Args)]
pub struct OauthLimitedKeyArgsChirho {
    #[arg(long = "principal")]
    pub principal_chirho: String,
    #[arg(long = "credential")]
    pub credential_chirho: Option<String>,
    #[arg(long = "credential-file")]
    pub credential_file_chirho: Option<PathBuf>,
    #[arg(long = "client")]
    pub client_chirho: String,
    /// One named action; repeat for more. Each must be declared by a route the app opens to limited keys.
    #[arg(long = "action", required = true)]
    pub actions_chirho: Vec<String>,
    #[arg(long = "rate-window-ms")]
    pub rate_window_ms_chirho: Option<u64>,
    #[arg(long = "rate-max-invokes")]
    pub rate_max_invokes_chirho: Option<u64>,
}

#[derive(clap::Args)]
pub struct OauthTokenArgsChirho {
    #[arg(long = "principal")]
    pub principal_chirho: String,
    #[arg(long = "credential")]
    pub credential_chirho: Option<String>,
    #[arg(long = "credential-file")]
    pub credential_file_chirho: Option<PathBuf>,
    #[arg(long = "client")]
    pub client_chirho: String,
    #[arg(long = "scope")]
    pub scopes_chirho: Vec<String>,
    #[arg(long = "rate-window-ms")]
    pub rate_window_ms_chirho: Option<u64>,
    #[arg(long = "rate-max-invokes")]
    pub rate_max_invokes_chirho: Option<u64>,
    #[arg(long = "device-id")]
    pub device_id_chirho: Option<String>,
}
