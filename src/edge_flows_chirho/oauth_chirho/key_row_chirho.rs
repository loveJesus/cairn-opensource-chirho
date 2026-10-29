// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A key's row: both issuance roads draft one before its log gives it a seq and before its session exists, then bind
//! it to that session and sign it, so a key in either store is written by one implementation (K4 Part 2).

use super::connection_chirho::KeyStoreChirho;
use super::{
    limited_key_chirho, normalize_scopes_chirho, random_token_chirho, scoped_token_message_chirho,
    token_hash_chirho, IssuedKeyKindChirho, OauthClientRecordChirho, ScopedTokenRateLimitChirho,
    ScopedTokenRecordChirho,
};
use crate::identity_chirho::IdentitySessionChirho;
use anyhow::Result;
use cairn_capability_chirho::capability_key_grant_chirho::{
    limited_key_scopes_chirho, LimitedKeyGrantsChirho,
};
use cairn_signer_chirho::signer_chirho;
use std::path::Path;

/// A key's row before it has a seq or a session: its store (its client's), its client and app, its scopes, the hash of
/// its new bearer, its rate policy, and a limited key's grant set.
pub(super) struct KeyRowDraftChirho {
    store_chirho: KeyStoreChirho,
    client_id_chirho: String,
    app_chirho: String,
    scopes_chirho: Vec<String>,
    token_hash_chirho: String,
    rate_limit_chirho: Option<ScopedTokenRateLimitChirho>,
    limited_grants_chirho: Option<LimitedKeyGrantsChirho>,
}

/// A new bearer for `client_chirho`, and its row's draft. A limited key is hashed under its own domain and signs its
/// grant set's digest into its scopes; a legacy key is exactly today's.
pub(super) fn draft_key_row_chirho(
    client_chirho: &OauthClientRecordChirho,
    kind_chirho: IssuedKeyKindChirho,
    rate_limit_chirho: Option<ScopedTokenRateLimitChirho>,
) -> Result<(KeyRowDraftChirho, String)> {
    let token_chirho = random_token_chirho();
    let (scopes_chirho, token_hash_chirho, limited_grants_chirho) = match kind_chirho {
        IssuedKeyKindChirho::LegacyChirho(scopes_chirho) => (
            normalize_scopes_chirho(scopes_chirho),
            token_hash_chirho(&token_chirho),
            None,
        ),
        IssuedKeyKindChirho::LimitedChirho(grants_chirho) => (
            limited_key_scopes_chirho(&grants_chirho)?,
            limited_key_chirho::limited_token_hash_chirho(&token_chirho),
            Some(grants_chirho),
        ),
    };
    let draft_chirho = KeyRowDraftChirho {
        store_chirho: KeyStoreChirho::of_client_chirho(client_chirho),
        client_id_chirho: client_chirho.client_id_chirho.clone(),
        app_chirho: client_chirho.app_chirho.clone(),
        scopes_chirho,
        token_hash_chirho,
        rate_limit_chirho,
        limited_grants_chirho,
    };
    Ok((draft_chirho, token_chirho))
}

impl KeyRowDraftChirho {
    /// The store the row goes to: its client's.
    pub(super) fn store_chirho(&self) -> KeyStoreChirho {
        self.store_chirho
    }

    /// Whether the row is a limited key's.
    pub(super) fn is_limited_chirho(&self) -> bool {
        self.limited_grants_chirho.is_some()
    }

    /// Whether the row carries a rate policy, and so counts toward its principal's cap.
    pub(super) fn is_rate_limited_chirho(&self) -> bool {
        self.rate_limit_chirho.is_some()
    }

    /// The row at `seq_chirho` in its store's log, bound to `session_chirho`: its principal, its seq, and both its
    /// instants, which the record check requires to be the session's own. Signed by the root.
    pub(super) fn signed_at_chirho(
        &self,
        root_chirho: &Path,
        seq_chirho: u64,
        session_chirho: &IdentitySessionChirho,
    ) -> Result<ScopedTokenRecordChirho> {
        let mut record_chirho = ScopedTokenRecordChirho {
            seq_chirho,
            schema_chirho: self.store_chirho.token_schema_chirho().to_string(),
            principal_chirho: session_chirho.principal_chirho.clone(),
            client_id_chirho: self.client_id_chirho.clone(),
            app_chirho: self.app_chirho.clone(),
            scopes_chirho: self.scopes_chirho.clone(),
            session_seq_chirho: session_chirho.seq_chirho,
            token_hash_chirho: self.token_hash_chirho.clone(),
            rate_limit_chirho: self.rate_limit_chirho.clone(),
            issued_ms_chirho: session_chirho.issued_ms_chirho,
            expires_ms_chirho: session_chirho.expires_ms_chirho,
            sig_chirho: String::new(),
            limited_grants_chirho: self.limited_grants_chirho.clone(),
        };
        let message_chirho = scoped_token_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    }
}
