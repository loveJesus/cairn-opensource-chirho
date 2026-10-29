// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! One account's private served-LLM evidence: a content ref's blob under that account's own subject and index, so two accounts never share one, and a frozen account's replay refuses.
//!
//! The content ref stays a content ref (the signed intent binds it); only where its private bytes rest is
//! per account (gpt #28874, #28880). The evidence is the requesting user's own data: their prompt and the
//! provider's account of their call. A replay checks the freeze inside the same attribution lock as its
//! lookup, so it cannot slip between a freeze and a read. Plaintext already returned is not recalled.

use crate::model_chirho::RequestContextChirho;
use crate::privacy_chirho::{
    load_private_blob_chirho, store_private_blob_chirho, verify_private_blob_ref_subject_chirho,
    PrivateBlobAttributionChirho, PrivateBlobRefChirho,
};
use anyhow::{Context, Result};
use cairn_account_attribution_chirho::{
    refuse_if_account_frozen_chirho, with_account_attribution_lock_chirho, AccountCoordinateChirho,
};
use std::fs;
use std::path::{Path, PathBuf};

/// The requesting user's own served-LLM evidence store.
pub(super) struct AccountEvidenceChirho {
    root_chirho: PathBuf,
    account_chirho: AccountCoordinateChirho,
    attribution_chirho: PrivateBlobAttributionChirho,
}

impl AccountEvidenceChirho {
    /// The store of the request's signed-in user, the account a close of theirs erases.
    pub(super) fn for_request_chirho(
        root_chirho: &Path,
        context_chirho: &RequestContextChirho,
    ) -> Result<Self> {
        Ok(Self {
            root_chirho: root_chirho.to_path_buf(),
            account_chirho: AccountCoordinateChirho::from_principal_chirho(
                &context_chirho.user_principal_chirho,
            )?,
            attribution_chirho: PrivateBlobAttributionChirho::account_owned_chirho(
                &context_chirho.user_principal_chirho,
            )?,
        })
    }

    /// This account's subject for one kind of evidence about one content ref.
    pub(super) fn subject_chirho(&self, kind_chirho: &str, content_ref_chirho: &str) -> String {
        format!(
            "llm-{kind_chirho}-chirho/{}/{content_ref_chirho}",
            &self.account_chirho.as_hex_chirho()[..32]
        )
    }

    /// This account's own index path in one evidence family.
    pub(super) fn index_path_chirho(
        &self,
        family_chirho: &str,
        content_ref_chirho: &str,
    ) -> Result<PathBuf> {
        super::llm_evidence_path_chirho(
            &self.root_chirho,
            &format!("{family_chirho}/{}", self.account_chirho.as_hex_chirho()),
            content_ref_chirho,
        )
    }

    /// Create or load this account's evidence bytes for one content ref.
    /// - Under the attribution lock, a frozen account refuses, a replay included, and an existing index
    ///   entry is read, bound to this account's subject, and loaded.
    /// - Otherwise the bytes go through the key chokepoint, which re-checks the freeze under the same
    ///   lock, and the index entry is published once. A concurrent first writer's entry wins, and that
    ///   entry is the one verified.
    pub(super) fn create_or_load_chirho(
        &self,
        index_path_chirho: &Path,
        kind_chirho: &str,
        content_ref_chirho: &str,
        bytes_chirho: &[u8],
        label_chirho: &str,
    ) -> Result<Vec<u8>> {
        let subject_chirho = self.subject_chirho(kind_chirho, content_ref_chirho);
        let replay_chirho = with_account_attribution_lock_chirho(&self.root_chirho, || {
            refuse_if_account_frozen_chirho(&self.root_chirho, &self.account_chirho)?;
            if !index_path_chirho.exists() {
                return Ok(None);
            }
            self.load_indexed_chirho(index_path_chirho, &subject_chirho, label_chirho)
                .map(Some)
        })?;
        if let Some(loaded_chirho) = replay_chirho {
            return Ok(loaded_chirho);
        }
        let blob_chirho = store_private_blob_chirho(
            &self.root_chirho,
            &self.attribution_chirho,
            &subject_chirho,
            bytes_chirho,
        )?;
        let proposed_chirho = serde_json::to_vec(&blob_chirho)?;
        let _ = super::create_or_load_bytes_chirho(index_path_chirho, &proposed_chirho)?;
        self.load_indexed_chirho(index_path_chirho, &subject_chirho, label_chirho)
    }

    fn load_indexed_chirho(
        &self,
        index_path_chirho: &Path,
        subject_chirho: &str,
        label_chirho: &str,
    ) -> Result<Vec<u8>> {
        let blob_chirho: PrivateBlobRefChirho =
            serde_json::from_slice(&fs::read(index_path_chirho)?)
                .context("decode served LLM private-blob ref")?;
        verify_private_blob_ref_subject_chirho(
            &self.root_chirho,
            label_chirho,
            &blob_chirho,
            subject_chirho,
        )?;
        load_private_blob_chirho(&self.root_chirho, &blob_chirho)
    }
}
