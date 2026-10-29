// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Private-mesh HTTP transport for the R2 served-write relay.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md`.
//! This adapter resolves one elected owner from a fixed private-IP directory, authenticates one
//! bounded request/response exchange, and owns no served entrypoint or mutation authority.

mod client_chirho;
mod directory_chirho;
mod dispatcher_chirho;
mod server_chirho;

pub use cairn_write_relay_chirho::{
    RelayDestinationExecutionFutureChirho, RelayDestinationExecutionPortChirho,
    RelayDestinationResponseChirho, ServedLocalReadAuthorityPortChirho,
    ServedLocalReadAuthorityWitnessChirho,
};
pub use client_chirho::{HttpServedWriteRelayPortChirho, RelayHttpTimeoutsChirho};
pub use directory_chirho::{
    FixedGroupLeadershipViewChirho, FixedRelayDirectoryChirho, ResolvedRelayOwnerChirho,
};
pub use dispatcher_chirho::{
    ExistingKeyRelayRequestSignerChirho, HttpServedWriteDispatchPortChirho,
    LocalRelayAuthorityReadinessChirho, LocalRelayDispatchPolicyChirho, RelayRequestSignerChirho,
};
pub use server_chirho::{
    relay_router_chirho, serve_relay_router_blocking_chirho, ExistingKeyRelayResponseSignerChirho,
    RelayResponseSignerChirho, RelayServerConfigChirho, RelayServerStateChirho,
};

pub const SERVED_WRITE_RELAY_PATH_CHIRHO: &str = "/served-write-relay-chirho/v1";

#[cfg(test)]
mod tests_chirho;
