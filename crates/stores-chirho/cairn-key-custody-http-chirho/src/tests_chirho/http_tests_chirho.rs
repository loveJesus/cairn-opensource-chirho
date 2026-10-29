// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The endpoints over real HTTP: a leader's client gets receipts it can verify, a refusal crosses as its fixed name, and the client rejects a receipt that answers another frame or another holder.

use super::world_chirho::{key_id_chirho, world_chirho, SUBJECT_CHIRHO};
use crate::client_chirho::{KeyCustodyClientChirho, KeyCustodyClientErrorChirho};
use crate::server_chirho::{
    key_custody_router_chirho, KEY_CUSTODY_CUSTODY_PATH_CHIRHO, KEY_CUSTODY_ERASURE_PATH_CHIRHO,
};
use axum::routing::post;
use axum::Router;
use cairn_key_custody_chirho::KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO;
use std::sync::Arc;
use std::time::Duration;

/// Serve `router_chirho` on a loopback port; the runtime must outlive the requests.
fn serve_chirho(router_chirho: Router) -> (tokio::runtime::Runtime, String) {
    super::world_chirho::serve_router_chirho(router_chirho)
}

/// How long one erasure send waits for its answer here.
const SEND_TIMEOUT_CHIRHO: Duration = Duration::from_secs(10);

fn client_chirho(base_url_chirho: &str) -> KeyCustodyClientChirho {
    KeyCustodyClientChirho::new_chirho(base_url_chirho, Duration::from_secs(10))
}

#[test]
fn a_leaders_client_gets_receipts_it_can_verify_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = Arc::new(world_chirho.open_holder_chirho());
    let (_runtime_chirho, url_chirho) =
        serve_chirho(key_custody_router_chirho(holder_chirho.clone()));
    let client_chirho = client_chirho(&url_chirho);
    let frame_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        1,
        0x11,
        &world_chirho.leader_chirho,
    );
    let receipt_chirho = client_chirho
        .send_custody_chirho(&frame_chirho)
        .expect("a custody receipt");
    assert_eq!(
        receipt_chirho.binding_chirho(),
        frame_chirho.binding_chirho()
    );
    let erasure_chirho = world_chirho.erasure_frame_chirho(
        SUBJECT_CHIRHO,
        5,
        &[key_id_chirho(1)],
        &world_chirho.leader_chirho,
    );
    let erased_chirho = client_chirho
        .send_erasure_chirho(&erasure_chirho, SEND_TIMEOUT_CHIRHO)
        .expect("an erasure receipt");
    assert_eq!(
        erased_chirho
            .accounted_key_ids_chirho()
            .cloned()
            .collect::<Vec<_>>(),
        [key_id_chirho(1)]
    );
}

#[test]
fn a_refusal_crosses_http_as_its_fixed_name_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = Arc::new(world_chirho.open_holder_chirho());
    let (_runtime_chirho, url_chirho) =
        serve_chirho(key_custody_router_chirho(holder_chirho.clone()));
    let frame_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        1,
        0x11,
        &world_chirho.peer_chirho,
    );
    match client_chirho(&url_chirho).send_custody_chirho(&frame_chirho) {
        Err(KeyCustodyClientErrorChirho::RefusedChirho {
            status_chirho,
            identity_chirho,
        }) => {
            assert_eq!(status_chirho, 409);
            assert!(
                identity_chirho.starts_with("CustodyAuthorityRefusedChirho:"),
                "{identity_chirho}"
            );
        }
        other_chirho => panic!("expected a named refusal, got {other_chirho:?}"),
    }
    let oversized_chirho = vec![b'x'; KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO + 1];
    let status_chirho = match ureq::post(&format!("{url_chirho}{KEY_CUSTODY_CUSTODY_PATH_CHIRHO}"))
        .send_bytes(&oversized_chirho)
    {
        Err(ureq::Error::Status(status_chirho, _)) => status_chirho,
        other_chirho => panic!(
            "expected a status refusal, got {:?}",
            other_chirho.map(|_| ())
        ),
    };
    assert_eq!(
        status_chirho, 413,
        "a body over the custody wire limit is not read"
    );
}

/// The client binds a receipt to the exact frame and holder it sent to, so a replayed or misdirected
/// answer that verifies on its own is still rejected.
#[test]
fn the_client_rejects_a_receipt_for_another_frame_or_holder_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    let first_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        1,
        0x11,
        &world_chirho.leader_chirho,
    );
    let first_receipt_chirho = holder_chirho
        .admit_custody_chirho(&first_chirho.to_wire_bytes_chirho().unwrap())
        .unwrap();
    // The same binding sealed again: a different frame digest, the same key.
    let second_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        1,
        0x11,
        &world_chirho.leader_chirho,
    );
    assert_ne!(
        first_chirho.frame_digest_chirho(),
        second_chirho.frame_digest_chirho()
    );
    assert_eq!(
        first_chirho.binding_chirho(),
        second_chirho.binding_chirho()
    );
    let erasure_chirho = world_chirho.erasure_frame_chirho(
        SUBJECT_CHIRHO,
        5,
        &[key_id_chirho(2)],
        &world_chirho.leader_chirho,
    );
    let erasure_receipt_chirho = holder_chirho
        .admit_erasure_chirho(&erasure_chirho.to_wire_bytes_chirho().unwrap())
        .unwrap();
    // Each stub reads its request body. A handler that leaves the body unread makes hyper close the connection, and
    // the client's next pooled request, or its own pool return, then races that close: 7 and 11 failures in 300
    // runs were measured before the stubs read their bodies.
    let stale_chirho = Router::new()
        .route(
            KEY_CUSTODY_CUSTODY_PATH_CHIRHO,
            post(move |_body_chirho: axum::body::Bytes| {
                let answer_chirho = first_receipt_chirho.clone();
                async move { answer_chirho }
            }),
        )
        .route(
            KEY_CUSTODY_ERASURE_PATH_CHIRHO,
            post(move |_body_chirho: axum::body::Bytes| {
                let answer_chirho = erasure_receipt_chirho.clone();
                async move { answer_chirho }
            }),
        );
    let (_runtime_chirho, url_chirho) = serve_chirho(stale_chirho);
    let client_chirho = client_chirho(&url_chirho);
    client_chirho
        .send_custody_chirho(&first_chirho)
        .expect("control: the receipt for the frame that was sent");
    assert_eq!(
        client_chirho.send_custody_chirho(&second_chirho).err(),
        Some(KeyCustodyClientErrorChirho::ReceiptRejectedChirho),
        "a receipt for another frame of the same key"
    );
    client_chirho
        .send_erasure_chirho(&erasure_chirho, SEND_TIMEOUT_CHIRHO)
        .expect("control: the holder's receipt for this erasure");
    // The expected holder comes from the frame itself (gpt #30156): a frame addressed to the peer, answered with the
    // holder's receipt for another frame, is rejected.
    let to_peer_chirho = world_chirho.erasure_frame_to_chirho(
        world_chirho.peer_chirho.id_chirho(),
        SUBJECT_CHIRHO,
        5,
        &[key_id_chirho(2)],
        &world_chirho.leader_chirho,
    );
    assert_eq!(
        client_chirho
            .send_erasure_chirho(&to_peer_chirho, SEND_TIMEOUT_CHIRHO)
            .err(),
        Some(KeyCustodyClientErrorChirho::ReceiptRejectedChirho),
        "a receipt from a holder the frame did not address"
    );
}
