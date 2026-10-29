// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The leader's side of a holder's endpoints: post one frame, read a bounded answer, and accept only a receipt that verifies and answers that exact frame from that exact holder.

use crate::server_chirho::{KEY_CUSTODY_CUSTODY_PATH_CHIRHO, KEY_CUSTODY_ERASURE_PATH_CHIRHO};
use cairn_key_custody_chirho::{
    decode_and_verify_custody_receipt_chirho, decode_and_verify_erasure_receipt_chirho,
    verify_erasure_receipt_answers_frame_chirho, CustodyFrameV1Chirho, ErasureFrameV1Chirho,
    VerifiedCustodyReceiptChirho, VerifiedErasureReceiptChirho, ERASURE_WIRE_MAX_BYTES_CHIRHO,
    KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO,
};
use std::io::Read;
use std::time::Duration;

/// A refusal body is one fixed name; anything longer is not one.
const REFUSAL_BODY_MAX_BYTES_CHIRHO: u64 = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyCustodyClientErrorChirho {
    /// The leader's own frame did not encode, so nothing was sent.
    FrameNotEncodableChirho,
    /// The holder answered with this status and fixed refusal name (empty if it sent none).
    RefusedChirho {
        status_chirho: u16,
        identity_chirho: String,
    },
    /// No answer arrived, so the holder may or may not have acted. A custody frame is sent again as it is. An
    /// erasure is retried with a FRESH frame, signed under a fresh read of authority, because a resent erasure frame
    /// overstates the remaining lease by the time since it was signed (C5 B3-a3, item 14 D4).
    TransportChirho,
    /// The answer is not a receipt that verifies, or it answers another frame or another holder.
    ReceiptRejectedChirho,
}

pub struct KeyCustodyClientChirho {
    agent_chirho: ureq::Agent,
    base_url_chirho: String,
}

impl KeyCustodyClientChirho {
    /// `base_url_chirho` is the holder's private-mesh origin, such as `http://10.100.0.2:8301`.
    pub fn new_chirho(base_url_chirho: impl Into<String>, timeout_chirho: Duration) -> Self {
        Self {
            agent_chirho: ureq::AgentBuilder::new()
                .timeout(timeout_chirho)
                .redirects(0)
                .build(),
            base_url_chirho: base_url_chirho.into().trim_end_matches('/').to_string(),
        }
    }

    /// Send one custody frame; the receipt must answer this frame's digest and carry its exact binding,
    /// which names the holder.
    pub fn send_custody_chirho(
        &self,
        frame_chirho: &CustodyFrameV1Chirho,
    ) -> Result<VerifiedCustodyReceiptChirho, KeyCustodyClientErrorChirho> {
        let wire_chirho = frame_chirho
            .to_wire_bytes_chirho()
            .map_err(|_| KeyCustodyClientErrorChirho::FrameNotEncodableChirho)?;
        let answer_chirho = self.post_chirho(
            KEY_CUSTODY_CUSTODY_PATH_CHIRHO,
            &wire_chirho,
            KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO,
            None,
        )?;
        let receipt_chirho = decode_and_verify_custody_receipt_chirho(&answer_chirho)
            .map_err(|_| KeyCustodyClientErrorChirho::ReceiptRejectedChirho)?;
        if receipt_chirho.custody_frame_digest_chirho() != frame_chirho.frame_digest_chirho()
            || receipt_chirho.binding_chirho() != frame_chirho.binding_chirho()
        {
            return Err(KeyCustodyClientErrorChirho::ReceiptRejectedChirho);
        }
        Ok(receipt_chirho)
    }

    /// Send one erasure frame to the holder IT names, waiting at most `timeout_chirho` for the answer. The receipt
    /// must pass B1's one answer check, which derives the expected holder and every copied field from the frame
    /// itself (C5 B3-a3, item 14 D4; gpt #30156, agy #30163).
    pub fn send_erasure_chirho(
        &self,
        frame_chirho: &ErasureFrameV1Chirho,
        timeout_chirho: Duration,
    ) -> Result<VerifiedErasureReceiptChirho, KeyCustodyClientErrorChirho> {
        let wire_chirho = frame_chirho
            .to_wire_bytes_chirho()
            .map_err(|_| KeyCustodyClientErrorChirho::FrameNotEncodableChirho)?;
        let answer_chirho = self.post_chirho(
            KEY_CUSTODY_ERASURE_PATH_CHIRHO,
            &wire_chirho,
            ERASURE_WIRE_MAX_BYTES_CHIRHO,
            Some(timeout_chirho),
        )?;
        let receipt_chirho = decode_and_verify_erasure_receipt_chirho(&answer_chirho)
            .map_err(|_| KeyCustodyClientErrorChirho::ReceiptRejectedChirho)?;
        verify_erasure_receipt_answers_frame_chirho(frame_chirho, &receipt_chirho)
            .map_err(|_| KeyCustodyClientErrorChirho::ReceiptRejectedChirho)?;
        Ok(receipt_chirho)
    }

    /// Post one frame, with `timeout_chirho` overriding the agent's own when given.
    fn post_chirho(
        &self,
        path_chirho: &str,
        body_chirho: &[u8],
        answer_max_bytes_chirho: usize,
        timeout_chirho: Option<Duration>,
    ) -> Result<Vec<u8>, KeyCustodyClientErrorChirho> {
        let url_chirho = format!("{}{path_chirho}", self.base_url_chirho);
        let mut request_chirho = self
            .agent_chirho
            .post(&url_chirho)
            .set("content-type", "application/json");
        if let Some(timeout_chirho) = timeout_chirho {
            request_chirho = request_chirho.timeout(timeout_chirho);
        }
        match request_chirho.send_bytes(body_chirho) {
            Ok(response_chirho) => {
                read_bounded_chirho(response_chirho, answer_max_bytes_chirho as u64)
                    .ok_or(KeyCustodyClientErrorChirho::ReceiptRejectedChirho)
            }
            Err(ureq::Error::Status(status_chirho, response_chirho)) => {
                let identity_chirho =
                    read_bounded_chirho(response_chirho, REFUSAL_BODY_MAX_BYTES_CHIRHO)
                        .and_then(|bytes_chirho| String::from_utf8(bytes_chirho).ok())
                        .filter(|text_chirho| fixed_name_chirho(text_chirho))
                        .unwrap_or_default();
                Err(KeyCustodyClientErrorChirho::RefusedChirho {
                    status_chirho,
                    identity_chirho,
                })
            }
            Err(ureq::Error::Transport(_)) => Err(KeyCustodyClientErrorChirho::TransportChirho),
        }
    }
}

fn read_bounded_chirho(response_chirho: ureq::Response, max_bytes_chirho: u64) -> Option<Vec<u8>> {
    let mut bytes_chirho = Vec::new();
    response_chirho
        .into_reader()
        .take(max_bytes_chirho.saturating_add(1))
        .read_to_end(&mut bytes_chirho)
        .ok()?;
    (bytes_chirho.len() as u64 <= max_bytes_chirho).then_some(bytes_chirho)
}

/// A refusal name is letters, digits and colons; anything else is dropped rather than repeated.
fn fixed_name_chirho(text_chirho: &str) -> bool {
    !text_chirho.is_empty()
        && text_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_alphanumeric() || byte_chirho == b':')
}
