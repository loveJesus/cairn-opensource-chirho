// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Whose container a private blob's key joins, and which account initiated the write, both stated by every caller.
//!
//! Every caller of `store_private_blob_chirho` must choose, so the compiler finishes the census (gpt #28874).
//! The CONTAINER owns the key's subject: the account a later close erases it with, or no account at all for a
//! reason proven at the call site. The ACTOR is the signed-in account that caused the write, when there is one;
//! an actor who is not the container leaves a contribution row in its own inventory, and either account's
//! freeze refuses the write (gpt #28929). Both come from trusted context, never from a subject string. A path
//! that should carry an account and does not REFUSES: a blank or malformed principal is an error, never a
//! fallback to no account. The set of no-account reasons is closed and grows only when a caller proves one.

use anyhow::Result;
use cairn_account_attribution_chirho::{
    AccountCoordinateChirho, CoverageDebtChirho, SubjectOwnerChirho,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateBlobAttributionChirho {
    container_chirho: BlobContainerChirho,
    actor_chirho: Option<AccountCoordinateChirho>,
}

/// Who owns the subject a key joins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobContainerChirho {
    AccountChirho(AccountCoordinateChirho),
    NotAccountScopedChirho(NotAccountScopedReasonChirho),
}

/// Why a key belongs to no account. Each reason is proven where the store is called.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotAccountScopedReasonChirho {
    /// An operator's own run with no request context: no account is acting, and none owns the data.
    OperatorRunChirho,
    /// A trusted host integration's own provider call (a secret-injected net request), made on behalf
    /// of no account. A call made for an account passes that account instead.
    HostIntegrationChirho,
    /// INTERIM, not a lasting exemption: Descriptor-D PostgreSQL evidence (request, before-image,
    /// provider), which is not yet attributed per account. Its reconcile and compensation paths store
    /// evidence without knowing the intent's account, so per-account attribution waits on brick 2b-pg:
    /// an execute-time intent-to-account binding and evidence ports that know their intent. Until then,
    /// a close must treat this evidence as unresolved coverage, never as erased.
    PostgresEvidencePendingAttributionChirho,
}

impl NotAccountScopedReasonChirho {
    /// The coverage debt a key with this reason leaves, if any: data that some account's close may need
    /// but no account's inventory lists (gpt #29035). Its subject is then owned by the debt itself.
    pub fn coverage_debt_chirho(self) -> Option<CoverageDebtChirho> {
        match self {
            Self::PostgresEvidencePendingAttributionChirho => {
                Some(CoverageDebtChirho::PostgresEvidencePendingAttributionChirho)
            }
            Self::OperatorRunChirho | Self::HostIntegrationChirho => None,
        }
    }
}

impl PrivateBlobAttributionChirho {
    /// Data an account owns and writes itself: a request user's own input, viewer state, request evidence,
    /// or an owner's own payload. The principal must be a trusted one; a malformed principal refuses.
    pub fn account_owned_chirho(principal_chirho: &str) -> Result<Self> {
        let account_chirho = AccountCoordinateChirho::from_principal_chirho(principal_chirho)?;
        Ok(Self {
            container_chirho: BlobContainerChirho::AccountChirho(account_chirho.clone()),
            actor_chirho: Some(account_chirho),
        })
    }

    /// Data that joins an app owner's container: input under a subject the app declares and shares, its
    /// declared DAG outputs, its store state. The actor is the signed-in request user, or `None` for an
    /// anonymous request; when it is the owner itself, no contribution row is written.
    pub fn app_container_chirho(
        owner_principal_chirho: &str,
        actor_principal_chirho: Option<&str>,
    ) -> Result<Self> {
        Ok(Self {
            container_chirho: BlobContainerChirho::AccountChirho(
                AccountCoordinateChirho::from_principal_chirho(owner_principal_chirho)?,
            ),
            actor_chirho: actor_principal_chirho
                .map(AccountCoordinateChirho::from_principal_chirho)
                .transpose()?,
        })
    }

    /// Data no account owns or writes, for a reason proven at the caller.
    pub fn not_account_scoped_chirho(reason_chirho: NotAccountScopedReasonChirho) -> Self {
        Self {
            container_chirho: BlobContainerChirho::NotAccountScopedChirho(reason_chirho),
            actor_chirho: None,
        }
    }

    pub fn container_chirho(&self) -> &BlobContainerChirho {
        &self.container_chirho
    }

    pub fn actor_chirho(&self) -> Option<&AccountCoordinateChirho> {
        self.actor_chirho.as_ref()
    }

    /// The subject owner this attribution claims: its container's account, the coverage debt its reason
    /// leaves, or the no-account class. A subject holds keys of one owner only, so the debt is bound into
    /// the subject's signed owner record, not only into the root's marker (gpt #29054).
    pub(crate) fn subject_owner_chirho(&self) -> SubjectOwnerChirho {
        match &self.container_chirho {
            BlobContainerChirho::AccountChirho(account_chirho) => {
                SubjectOwnerChirho::AccountChirho(account_chirho.clone())
            }
            BlobContainerChirho::NotAccountScopedChirho(reason_chirho) => {
                reason_chirho.coverage_debt_chirho().map_or(
                    SubjectOwnerChirho::NoAccountChirho,
                    SubjectOwnerChirho::CoverageDebtChirho,
                )
            }
        }
    }
}

#[cfg(test)]
impl PrivateBlobAttributionChirho {
    /// TESTS ONLY, for fixtures written before attribution existed: a principal-namespace subject
    /// (`user/<id>` or `owner/<id>`, or a path below one) belongs to that principal's own account, the
    /// only owner the namespace rule allows; any other fixture subject is an operator's.
    pub(crate) fn for_test_subject_chirho(subject_chirho: &str) -> Self {
        for namespace_chirho in ["user/", "owner/"] {
            if let Some(rest_chirho) = subject_chirho.strip_prefix(namespace_chirho) {
                let id_chirho = rest_chirho.split('/').next().unwrap_or_default();
                return Self::account_owned_chirho(&format!("{namespace_chirho}{id_chirho}"))
                    .expect("a test fixture's principal is in form");
            }
        }
        Self::test_operator_chirho()
    }

    /// TESTS ONLY: an operator fixture that no account owns or writes.
    pub(crate) fn test_operator_chirho() -> Self {
        Self::not_account_scoped_chirho(NotAccountScopedReasonChirho::OperatorRunChirho)
    }
}
