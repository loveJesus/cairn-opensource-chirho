// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Whose container a private DAG value joins, carried beside its subject, and how a run turns that into the attribution its key is stored under.
//!
//! The owner source is set where the subject is resolved (a request-user edge, the viewer seal, an app's
//! declared or app-subject edge, a store seal) and travels with the subject through inheritance to the
//! store, so an owner is never read back out of a subject string (gpt #28935, agy #28931). A run resolves
//! it from its signed-in request: the actor's own data goes to the actor, the app's container to the app
//! owner with the actor recorded. A run with no request context has one attribution its caller declared
//! for the whole run (an anonymous app request's owner, or an operator run); with neither, a private
//! store refuses rather than guessing.

use crate::model_chirho::RequestContextChirho;
use crate::privacy_chirho::PrivateBlobAttributionChirho;
use anyhow::{anyhow, Result};

/// Whose container a private value's subject belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateValueOwnerChirho {
    /// The signed-in request user's own data: request-user input, viewer state, that user's request
    /// evidence, and whatever inherits from them.
    RequestActorChirho,
    /// The app owner's container: a subject the app declares (static or app-subject) or its store state.
    AppContainerChirho,
}

/// Where a run's private values get their attribution. It refuses, never defaults, when it has none.
#[derive(Clone, Copy, Debug)]
pub struct RunAttributionSourceChirho<'a> {
    request_context_chirho: Option<&'a RequestContextChirho>,
    declared_chirho: Option<&'a PrivateBlobAttributionChirho>,
}

impl<'a> RunAttributionSourceChirho<'a> {
    /// A run's source: its request context when it has one; otherwise the attribution its caller declared.
    pub fn new_chirho(
        request_context_chirho: Option<&'a RequestContextChirho>,
        declared_chirho: Option<&'a PrivateBlobAttributionChirho>,
    ) -> Self {
        Self {
            request_context_chirho,
            declared_chirho,
        }
    }

    pub fn request_context_chirho(&self) -> Option<&'a RequestContextChirho> {
        self.request_context_chirho
    }

    /// The attribution a key of this owner source is stored under in this run.
    pub fn resolve_chirho(
        &self,
        owner_chirho: PrivateValueOwnerChirho,
    ) -> Result<PrivateBlobAttributionChirho> {
        match (self.request_context_chirho, owner_chirho) {
            (Some(context_chirho), PrivateValueOwnerChirho::RequestActorChirho) => {
                PrivateBlobAttributionChirho::account_owned_chirho(
                    &context_chirho.user_principal_chirho,
                )
            }
            (Some(context_chirho), PrivateValueOwnerChirho::AppContainerChirho) => {
                PrivateBlobAttributionChirho::app_container_chirho(
                    &context_chirho.owner_principal_chirho,
                    Some(&context_chirho.user_principal_chirho),
                )
            }
            (None, _) => self.declared_chirho.cloned().ok_or_else(|| {
                anyhow!(
                    "MissingRunAttributionChirho: a run with no request context must declare whose \
                     container its private values join"
                )
            }),
        }
    }
}
