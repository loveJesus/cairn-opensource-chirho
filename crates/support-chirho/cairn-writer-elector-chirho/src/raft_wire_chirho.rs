// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The wire format for Raft messages: prost encode/decode of `raft::eraftpb::Message`, plus a SIGNED
//! envelope so a transport can carry authenticated messages between hosts. This is what a transport moves
//! between nodes — bytes, not raft types — so a message transport (in-process, HTTP, or otherwise) never
//! needs to depend on the raft crate. Encode/decode must round-trip exactly, or a transported election
//! would silently corrupt; that invariant is tested against a real 3-node election.
//!
//! Authentication (the transport-auth BLOCKER fix): `encode_signed_message_chirho` signs a
//! domain-separated digest of the envelope schema, exact consistency-group digest, and encoded
//! message bytes with the SENDER's node key. `decode_and_verify_message_chirho` requires that exact
//! group, requires the message's `to` raft id to be this local recipient, and verifies the signature
//! against the pubkey the roster holds for the message's `from` raft id. It also rejects any `from`
//! that is not rostered. Because only the genuine peer holds its key, a reachable attacker cannot
//! forge a message that appears to come from a rostered peer (so it cannot "fake a leader"), a
//! rostered peer cannot impersonate another peer's `from`, and a valid message cannot be replayed
//! across consistency groups or delivered to another roster member. Node identity IS the ed25519
//! pubkey hex, so the roster doubles as the authentication authority. Replay to the same recipient
//! in the same group is bounded by Raft's term and index checks.

use crate::elector_port_chirho::NodeIdChirho;
use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::{consistency_group_digest_chirho, ConsistencyGroupIdChirho};
use cairn_signer_chirho::signer_chirho::{
    sign_message_with_existing_key_chirho, verify_with_pubkey_chirho,
};
use prost::Message as ProstMessageChirho;
use raft::eraftpb::Message;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const SIGNED_RAFT_MESSAGE_SCHEMA_V2_CHIRHO: &str = "signed-raft-message-v2-chirho";
const SIGNED_RAFT_MESSAGE_SIGNATURE_DOMAIN_V2_CHIRHO: &[u8] =
    b"cairn-signed-raft-message-v2-chirho";

/// A signed Raft message on the wire: an exact schema, consistency-group digest, prost-encoded
/// message bytes, and the sender's hex ed25519 signature over their domain-separated digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRaftMessageChirho {
    pub schema_chirho: String,
    pub group_digest_chirho: String,
    pub message_bytes_chirho: Vec<u8>,
    pub sig_hex_chirho: String,
}

/// Encode a Raft message to wire bytes.
pub fn encode_message_chirho(message_chirho: &Message) -> Vec<u8> {
    message_chirho.encode_to_vec()
}

/// Decode a Raft message from wire bytes.
pub fn decode_message_chirho(bytes_chirho: &[u8]) -> Result<Message> {
    Message::decode(bytes_chirho).map_err(|e_chirho| anyhow!("decode raft message: {e_chirho}"))
}

fn signed_raft_message_digest_chirho(
    schema_chirho: &str,
    group_digest_chirho: &str,
    message_bytes_chirho: &[u8],
) -> [u8; 32] {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(SIGNED_RAFT_MESSAGE_SIGNATURE_DOMAIN_V2_CHIRHO);
    hasher_chirho.update(&(schema_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(schema_chirho.as_bytes());
    hasher_chirho.update(&(group_digest_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(group_digest_chirho.as_bytes());
    hasher_chirho.update(&(message_bytes_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(message_bytes_chirho);
    *hasher_chirho.finalize().as_bytes()
}

/// Encode a Raft message into a SIGNED envelope: prost-encode it, bind it to the exact consistency
/// group, sign the fixed-size domain-separated digest with the sender's already-provisioned node key,
/// and serialize the envelope. Digesting streams over the message once without allocating a second
/// message-sized signing preimage.
pub fn encode_signed_message_chirho(
    message_chirho: &Message,
    group_chirho: &ConsistencyGroupIdChirho,
    sign_root_chirho: &Path,
) -> Result<Vec<u8>> {
    let message_bytes_chirho = encode_message_chirho(message_chirho);
    let group_digest_chirho = consistency_group_digest_chirho(group_chirho)?;
    let signing_digest_chirho = signed_raft_message_digest_chirho(
        SIGNED_RAFT_MESSAGE_SCHEMA_V2_CHIRHO,
        &group_digest_chirho,
        &message_bytes_chirho,
    );
    let sig_hex_chirho =
        sign_message_with_existing_key_chirho(sign_root_chirho, &signing_digest_chirho)?;
    let envelope_chirho = SignedRaftMessageChirho {
        schema_chirho: SIGNED_RAFT_MESSAGE_SCHEMA_V2_CHIRHO.to_owned(),
        group_digest_chirho,
        message_bytes_chirho,
        sig_hex_chirho,
    };
    serde_json::to_vec(&envelope_chirho)
        .map_err(|e_chirho| anyhow!("serialize signed raft envelope: {e_chirho}"))
}

/// Decode and AUTHENTICATE a signed Raft envelope against one exact group, local recipient, and
/// voter roster. Returns the verified message only if every binding and signature is valid.
pub fn decode_and_verify_message_chirho(
    envelope_bytes_chirho: &[u8],
    expected_group_chirho: &ConsistencyGroupIdChirho,
    expected_recipient_raft_id_chirho: u64,
    roster_chirho: &[(u64, NodeIdChirho)],
) -> Result<Message> {
    let envelope_chirho: SignedRaftMessageChirho = serde_json::from_slice(envelope_bytes_chirho)
        .map_err(|e_chirho| anyhow!("deserialize signed raft envelope: {e_chirho}"))?;
    if envelope_chirho.schema_chirho != SIGNED_RAFT_MESSAGE_SCHEMA_V2_CHIRHO {
        bail!("unsupported signed raft envelope schema");
    }
    let expected_group_digest_chirho = consistency_group_digest_chirho(expected_group_chirho)?;
    if envelope_chirho.group_digest_chirho != expected_group_digest_chirho {
        bail!("signed raft envelope consistency group does not match this elector");
    }
    let message_chirho = decode_message_chirho(&envelope_chirho.message_bytes_chirho)?;
    if message_chirho.to != expected_recipient_raft_id_chirho {
        bail!(
            "raft message recipient {} does not match local raft id {expected_recipient_raft_id_chirho}",
            message_chirho.to
        );
    }
    let from_raft_id_chirho = message_chirho.from;
    let sender_pubkey_chirho = roster_chirho
        .iter()
        .find(|(raft_id_chirho, _)| *raft_id_chirho == from_raft_id_chirho)
        .map(|(_, node_chirho)| node_chirho.0.as_str())
        .ok_or_else(|| {
            anyhow!("raft message claims a non-rostered sender id {from_raft_id_chirho}")
        })?;
    let signing_digest_chirho = signed_raft_message_digest_chirho(
        &envelope_chirho.schema_chirho,
        &envelope_chirho.group_digest_chirho,
        &envelope_chirho.message_bytes_chirho,
    );
    let verified_chirho = verify_with_pubkey_chirho(
        sender_pubkey_chirho,
        &signing_digest_chirho,
        &envelope_chirho.sig_hex_chirho,
    )?;
    if !verified_chirho {
        return Err(anyhow!(
            "raft message signature does not verify against rostered peer {from_raft_id_chirho}"
        ));
    }
    Ok(message_chirho)
}
