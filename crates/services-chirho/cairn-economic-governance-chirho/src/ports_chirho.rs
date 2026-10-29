// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Authority-bearing ports supplied by the root crate.

use anyhow::Result;
use std::path::Path;

pub trait EconomicGovernanceSigningPortChirho {
    fn sign_message_chirho(&self, root_chirho: &Path, message_chirho: &[u8]) -> Result<String>;

    fn pubkey_hex_chirho(&self, root_chirho: &Path) -> Result<String>;

    fn verify_with_pubkey_chirho(
        &self,
        pubkey_hex_chirho: &str,
        message_chirho: &[u8],
        sig_hex_chirho: &str,
    ) -> Result<bool>;
}

pub trait EconomicGovernanceAppOwnerPortChirho {
    fn ensure_app_owner_chirho(
        &self,
        root_chirho: &Path,
        app_chirho: &str,
        owner_principal_chirho: &str,
    ) -> Result<()>;

    fn verified_app_owner_chirho(
        &self,
        root_chirho: &Path,
        app_chirho: &str,
    ) -> Result<Option<String>>;
}

pub trait EconomicGovernanceIdentityPortChirho {
    fn ensure_owner_principal_chirho(
        &self,
        root_chirho: &Path,
        principal_chirho: &str,
    ) -> Result<()>;

    fn ensure_user_principal_chirho(
        &self,
        root_chirho: &Path,
        principal_chirho: &str,
    ) -> Result<()>;
}
