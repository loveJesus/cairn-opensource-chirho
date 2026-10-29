// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! S3 adapter object-plane over a REAL socket against an in-process fake S3 server that
//! re-derives SigV4 server-side (so sign-one-thing-send-another cannot pass): put/get roundtrip
//! with fs-address parity, remote verify-on-read (M142), pull-quarantine through the P3 receiver,
//! fail-closed pagination and foreign-key listing (R2), allowlist-before-HTTP on named logs, the
//! R1 corrupt-local-refusal mirror, and secret-free error exhaust (R4). Self-contained: no
//! head-mutation crate, so the P3 no-write-authority guard stays strict.

// The Chirho identifier convention necessarily shares a variant postfix (house-wide allow).
#![allow(clippy::enum_variant_names)]

use axum::body::Bytes;
use axum::extract::{Path as AxumPathChirho, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{ContentReadChirho, ContentStoreChirho};
use cairn_model_gate1_chirho::GATE1_LOG_ANCHORS_FILE_CHIRHO;
use cairn_replication_chirho::{receive_objects_chirho, ReplicationSourceChirho};
use cairn_replication_http_chirho::client_chirho::MAX_REPLICATION_BODY_BYTES_CHIRHO;
use cairn_replication_localfs_chirho::{FsReplicaQuarantineChirho, LocalFsReplicationSourceChirho};
use cairn_store_fs_chirho::FsContentStoreChirho;
use cairn_store_s3_chirho::http_chirho::MAX_S3_BODY_BYTES_CHIRHO;
use cairn_store_s3_chirho::sigv4_chirho::{
    sha256_hex_chirho, sign_request_chirho, SigV4CredsChirho, SigV4RequestChirho,
};
use cairn_store_s3_chirho::{
    mirror_source_to_s3_chirho, S3BlobStoreChirho, S3BlobStoreConfigChirho,
};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const TEST_BUCKET_CHIRHO: &str = "cairn-test-bucket-chirho";
const TEST_AKID_CHIRHO: &str = "GKTESTAKIDCHIRHO";
const TEST_SECRET_CHIRHO: &str = "TESTSECRETCHIRHO-never-in-errors";
const TEST_REGION_CHIRHO: &str = "garage";

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailModeChirho {
    Status500Chirho,
    Redirect301Chirho,
    TruncatedNoTokenChirho,
    /// One page that lists the same key twice (truncation honest, count honest).
    DuplicateKeyPageChirho,
    /// Truncated pages whose continuation token never changes (fresh keys, so only the stall
    /// guard can catch it).
    StuckContinuationTokenChirho,
    /// Truncated pages with ever-advancing tokens and fresh keys — only the page cap ends it.
    EndlessAdvancingTokensChirho,
    /// The bucket listing itself 404s (must surface as an error, never as an empty mirror).
    ListNotFoundChirho,
    /// A 200 listing body that is not UTF-8.
    NonUtf8ListBodyChirho,
}

struct FakeS3StateChirho {
    objects_chirho: Mutex<BTreeMap<String, Vec<u8>>>,
    /// Keys whose GET returns substituted bytes — the wire-tamper double.
    tamper_chirho: Mutex<HashMap<String, Vec<u8>>>,
    creds_chirho: SigV4CredsChirho,
    max_keys_chirho: usize,
    list_calls_chirho: AtomicU64,
    requests_chirho: AtomicU64,
    fail_mode_chirho: Mutex<Option<FailModeChirho>>,
}

impl FakeS3StateChirho {
    fn new_chirho(max_keys_chirho: usize) -> Arc<Self> {
        Arc::new(Self {
            objects_chirho: Mutex::new(BTreeMap::new()),
            tamper_chirho: Mutex::new(HashMap::new()),
            creds_chirho: SigV4CredsChirho {
                access_key_id_chirho: TEST_AKID_CHIRHO.to_string(),
                secret_access_key_chirho: TEST_SECRET_CHIRHO.to_string(),
                region_chirho: TEST_REGION_CHIRHO.to_string(),
            },
            max_keys_chirho,
            list_calls_chirho: AtomicU64::new(0),
            requests_chirho: AtomicU64::new(0),
            fail_mode_chirho: Mutex::new(None),
        })
    }
}

fn text_response_chirho(status_chirho: StatusCode, body_chirho: &str) -> Response {
    Response::builder()
        .status(status_chirho)
        .body(axum::body::Body::from(body_chirho.to_string()))
        .unwrap()
}

fn percent_decode_chirho(input_chirho: &str) -> Option<String> {
    let bytes_chirho = input_chirho.as_bytes();
    let mut out_chirho = Vec::with_capacity(bytes_chirho.len());
    let mut index_chirho = 0usize;
    while index_chirho < bytes_chirho.len() {
        if bytes_chirho[index_chirho] == b'%' {
            let hex_chirho = bytes_chirho.get(index_chirho + 1..index_chirho + 3)?;
            let value_chirho =
                u8::from_str_radix(std::str::from_utf8(hex_chirho).ok()?, 16).ok()?;
            out_chirho.push(value_chirho);
            index_chirho += 3;
        } else {
            out_chirho.push(bytes_chirho[index_chirho]);
            index_chirho += 1;
        }
    }
    String::from_utf8(out_chirho).ok()
}

/// Re-derive the SigV4 signature from the RECEIVED request and compare it to the received
/// `Authorization`. The signer algorithm itself is pinned by AWS/oracle vectors; this closes the
/// remaining gap (signing one thing while sending another).
fn verify_sigv4_chirho(
    state_chirho: &FakeS3StateChirho,
    method_chirho: &str,
    path_chirho: &str,
    raw_query_chirho: Option<&str>,
    headers_chirho: &HeaderMap,
) -> Result<(), Box<Response>> {
    let header_chirho = |name_chirho: &str| {
        headers_chirho
            .get(name_chirho)
            .and_then(|value_chirho| value_chirho.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let mut pairs_chirho: Vec<(String, String)> = Vec::new();
    if let Some(query_chirho) = raw_query_chirho {
        for part_chirho in query_chirho
            .split('&')
            .filter(|p_chirho| !p_chirho.is_empty())
        {
            let (key_chirho, value_chirho) =
                part_chirho.split_once('=').unwrap_or((part_chirho, ""));
            let (Some(key_chirho), Some(value_chirho)) = (
                percent_decode_chirho(key_chirho),
                percent_decode_chirho(value_chirho),
            ) else {
                return Err(Box::new(text_response_chirho(
                    StatusCode::BAD_REQUEST,
                    "bad query",
                )));
            };
            pairs_chirho.push((key_chirho, value_chirho));
        }
    }
    let payload_sha_chirho = header_chirho("x-amz-content-sha256");
    let timestamp_chirho = header_chirho("x-amz-date");
    let host_chirho = header_chirho(header::HOST.as_str());
    let expected_chirho = sign_request_chirho(
        &SigV4RequestChirho {
            method_chirho,
            path_chirho,
            query_chirho: &pairs_chirho,
            host_chirho: &host_chirho,
            payload_sha256_hex_chirho: &payload_sha_chirho,
            amz_timestamp_chirho: &timestamp_chirho,
        },
        &state_chirho.creds_chirho,
    );
    if header_chirho(header::AUTHORIZATION.as_str()) != expected_chirho.authorization_chirho {
        return Err(Box::new(text_response_chirho(
            StatusCode::FORBIDDEN,
            "sigv4 signature mismatch",
        )));
    }
    Ok(())
}

fn apply_fail_mode_chirho(state_chirho: &FakeS3StateChirho) -> Option<Response> {
    match *state_chirho.fail_mode_chirho.lock().unwrap() {
        Some(FailModeChirho::Status500Chirho) => Some(text_response_chirho(
            StatusCode::INTERNAL_SERVER_ERROR,
            "injected 500",
        )),
        Some(FailModeChirho::Redirect301Chirho) => Some(
            Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(header::LOCATION, "http://127.0.0.1:9/elsewhere")
                .body(axum::body::Body::empty())
                .unwrap(),
        ),
        _ => None,
    }
}

async fn list_handler_chirho(
    State(state_chirho): State<Arc<FakeS3StateChirho>>,
    AxumPathChirho(bucket_chirho): AxumPathChirho<String>,
    RawQuery(raw_query_chirho): RawQuery,
    headers_chirho: HeaderMap,
) -> Response {
    state_chirho.requests_chirho.fetch_add(1, Ordering::Relaxed);
    if let Some(response_chirho) = apply_fail_mode_chirho(&state_chirho) {
        return response_chirho;
    }
    if bucket_chirho != TEST_BUCKET_CHIRHO {
        return text_response_chirho(StatusCode::NOT_FOUND, "no such bucket");
    }
    let path_chirho = format!("/{bucket_chirho}");
    if let Err(response_chirho) = verify_sigv4_chirho(
        &state_chirho,
        "GET",
        &path_chirho,
        raw_query_chirho.as_deref(),
        &headers_chirho,
    ) {
        return *response_chirho;
    }
    let call_index_chirho = state_chirho
        .list_calls_chirho
        .fetch_add(1, Ordering::Relaxed);
    // Handcrafted fail-mode listings (all behind a VALID signature, like a lying-but-authorized
    // endpoint would be). Keys stay well-formed and unique per page unless the mode is the
    // duplicate itself, so each response defeats exactly ONE client-side guard.
    let unique_key_chirho = format!("objects-chirho/aa/{call_index_chirho:062x}");
    let list_fail_chirho = *state_chirho.fail_mode_chirho.lock().unwrap();
    match list_fail_chirho {
        Some(FailModeChirho::ListNotFoundChirho) => {
            return text_response_chirho(StatusCode::NOT_FOUND, "no listing for you");
        }
        Some(FailModeChirho::NonUtf8ListBodyChirho) => {
            return Response::builder()
                .status(StatusCode::OK)
                .body(axum::body::Body::from(vec![0xffu8, 0xfe, b'<']))
                .unwrap();
        }
        Some(FailModeChirho::DuplicateKeyPageChirho) => {
            let dup_key_chirho = format!("objects-chirho/ab/{}", "c".repeat(62));
            return text_response_chirho(
                StatusCode::OK,
                &format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult>\
                     <KeyCount>2</KeyCount>\
                     <Contents><Key>{dup_key_chirho}</Key></Contents>\
                     <Contents><Key>{dup_key_chirho}</Key></Contents>\
                     <IsTruncated>false</IsTruncated></ListBucketResult>"
                ),
            );
        }
        Some(FailModeChirho::StuckContinuationTokenChirho) => {
            return text_response_chirho(
                StatusCode::OK,
                &format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult>\
                     <KeyCount>1</KeyCount>\
                     <Contents><Key>{unique_key_chirho}</Key></Contents>\
                     <IsTruncated>true</IsTruncated>\
                     <NextContinuationToken>stuck-token-chirho</NextContinuationToken>\
                     </ListBucketResult>"
                ),
            );
        }
        Some(FailModeChirho::EndlessAdvancingTokensChirho) => {
            return text_response_chirho(
                StatusCode::OK,
                &format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult>\
                     <KeyCount>1</KeyCount>\
                     <Contents><Key>{unique_key_chirho}</Key></Contents>\
                     <IsTruncated>true</IsTruncated>\
                     <NextContinuationToken>tok-{call_index_chirho}-chirho</NextContinuationToken>\
                     </ListBucketResult>"
                ),
            );
        }
        _ => {}
    }
    let mut prefix_chirho = String::new();
    let mut token_chirho = String::new();
    if let Some(query_chirho) = raw_query_chirho.as_deref() {
        for part_chirho in query_chirho.split('&') {
            let (key_chirho, value_chirho) =
                part_chirho.split_once('=').unwrap_or((part_chirho, ""));
            let value_chirho = percent_decode_chirho(value_chirho).unwrap_or_default();
            match key_chirho {
                "prefix" => prefix_chirho = value_chirho,
                "continuation-token" => token_chirho = value_chirho,
                _ => {}
            }
        }
    }
    let objects_chirho = state_chirho.objects_chirho.lock().unwrap();
    let matching_chirho: Vec<&String> = objects_chirho
        .keys()
        .filter(|key_chirho| {
            key_chirho.starts_with(&prefix_chirho)
                && (token_chirho.is_empty() || key_chirho.as_str() > token_chirho.as_str())
        })
        .collect();
    let page_chirho = &matching_chirho[..state_chirho.max_keys_chirho.min(matching_chirho.len())];
    let truncated_chirho = matching_chirho.len() > page_chirho.len();
    let mut xml_chirho = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult><Name>b</Name>",
    );
    xml_chirho.push_str(&format!("<KeyCount>{}</KeyCount>", page_chirho.len()));
    for key_chirho in page_chirho {
        xml_chirho.push_str(&format!("<Contents><Key>{key_chirho}</Key></Contents>"));
    }
    xml_chirho.push_str(&format!(
        "<IsTruncated>{}</IsTruncated>",
        if truncated_chirho { "true" } else { "false" }
    ));
    let omit_token_chirho = *state_chirho.fail_mode_chirho.lock().unwrap()
        == Some(FailModeChirho::TruncatedNoTokenChirho);
    if truncated_chirho && !omit_token_chirho {
        xml_chirho.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            page_chirho.last().expect("truncated page is non-empty")
        ));
    }
    xml_chirho.push_str("</ListBucketResult>");
    text_response_chirho(StatusCode::OK, &xml_chirho)
}

async fn object_get_handler_chirho(
    State(state_chirho): State<Arc<FakeS3StateChirho>>,
    AxumPathChirho((bucket_chirho, key_chirho)): AxumPathChirho<(String, String)>,
    RawQuery(raw_query_chirho): RawQuery,
    headers_chirho: HeaderMap,
) -> Response {
    state_chirho.requests_chirho.fetch_add(1, Ordering::Relaxed);
    if let Some(response_chirho) = apply_fail_mode_chirho(&state_chirho) {
        return response_chirho;
    }
    if bucket_chirho != TEST_BUCKET_CHIRHO {
        return text_response_chirho(StatusCode::NOT_FOUND, "no such bucket");
    }
    let path_chirho = format!("/{bucket_chirho}/{key_chirho}");
    if let Err(response_chirho) = verify_sigv4_chirho(
        &state_chirho,
        "GET",
        &path_chirho,
        raw_query_chirho.as_deref(),
        &headers_chirho,
    ) {
        return *response_chirho;
    }
    if let Some(bytes_chirho) = state_chirho.tamper_chirho.lock().unwrap().get(&key_chirho) {
        return Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::Body::from(bytes_chirho.clone()))
            .unwrap();
    }
    match state_chirho.objects_chirho.lock().unwrap().get(&key_chirho) {
        Some(bytes_chirho) => Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::Body::from(bytes_chirho.clone()))
            .unwrap(),
        None => text_response_chirho(StatusCode::NOT_FOUND, "no such key"),
    }
}

async fn object_put_handler_chirho(
    State(state_chirho): State<Arc<FakeS3StateChirho>>,
    AxumPathChirho((bucket_chirho, key_chirho)): AxumPathChirho<(String, String)>,
    RawQuery(raw_query_chirho): RawQuery,
    headers_chirho: HeaderMap,
    body_chirho: Bytes,
) -> Response {
    state_chirho.requests_chirho.fetch_add(1, Ordering::Relaxed);
    if let Some(response_chirho) = apply_fail_mode_chirho(&state_chirho) {
        return response_chirho;
    }
    if bucket_chirho != TEST_BUCKET_CHIRHO {
        return text_response_chirho(StatusCode::NOT_FOUND, "no such bucket");
    }
    let path_chirho = format!("/{bucket_chirho}/{key_chirho}");
    if let Err(response_chirho) = verify_sigv4_chirho(
        &state_chirho,
        "PUT",
        &path_chirho,
        raw_query_chirho.as_deref(),
        &headers_chirho,
    ) {
        return *response_chirho;
    }
    let declared_sha_chirho = headers_chirho
        .get("x-amz-content-sha256")
        .and_then(|value_chirho| value_chirho.to_str().ok())
        .unwrap_or("");
    if sha256_hex_chirho(&body_chirho) != declared_sha_chirho {
        return text_response_chirho(StatusCode::BAD_REQUEST, "payload hash mismatch");
    }
    state_chirho
        .objects_chirho
        .lock()
        .unwrap()
        .insert(key_chirho, body_chirho.to_vec());
    text_response_chirho(StatusCode::OK, "")
}

/// Bind an ephemeral loopback port and serve the fake S3 router on a detached thread; the socket
/// is bound before the thread starts so a client connect queues in the listen backlog.
fn start_fake_s3_chirho(state_chirho: Arc<FakeS3StateChirho>) -> String {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
    let router_chirho = Router::new()
        .route("/:bucket", get(list_handler_chirho))
        .route(
            "/:bucket/*key",
            get(object_get_handler_chirho).put(object_put_handler_chirho),
        )
        .with_state(state_chirho);
    std::thread::spawn(move || {
        let runtime_chirho = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime_chirho.block_on(async move {
            listener_chirho.set_nonblocking(true).unwrap();
            let tokio_listener_chirho = tokio::net::TcpListener::from_std(listener_chirho).unwrap();
            let _ = axum::serve(tokio_listener_chirho, router_chirho).await;
        });
    });
    base_url_chirho
}

fn s3_store_chirho(base_url_chirho: &str) -> S3BlobStoreChirho {
    S3BlobStoreChirho::new_chirho(S3BlobStoreConfigChirho {
        endpoint_chirho: base_url_chirho.to_string(),
        bucket_chirho: TEST_BUCKET_CHIRHO.to_string(),
        region_chirho: TEST_REGION_CHIRHO.to_string(),
        access_key_id_chirho: TEST_AKID_CHIRHO.to_string(),
        secret_access_key_chirho: TEST_SECRET_CHIRHO.to_string(),
    })
    .unwrap()
}

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-s3-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn object_disk_path_chirho(root_chirho: &std::path::Path, addr_chirho: &HashChirho) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&addr_chirho.0[..2])
        .join(&addr_chirho.0[2..])
}

#[test]
fn put_get_roundtrip_matches_fs_addresses_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho));
    let bytes_chirho = b"the jordan stones chirho";
    let addr_chirho = store_chirho.put_chirho(bytes_chirho).unwrap();
    let fs_store_chirho = FsContentStoreChirho::new_chirho(tmp_root_chirho("parity"));
    assert_eq!(
        fs_store_chirho.put_chirho(bytes_chirho).unwrap(),
        addr_chirho
    );
    assert_eq!(
        store_chirho.get_chirho(&addr_chirho).unwrap().as_deref(),
        Some(bytes_chirho.as_slice())
    );
    let absent_chirho = hash_chirho(b"never stored");
    assert_eq!(store_chirho.get_chirho(&absent_chirho).unwrap(), None);
}

/// M142 on remote reads: a tampered bucket object fails the content get closed.
#[test]
fn get_tampered_object_fails_closed_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    let addr_chirho = store_chirho.put_chirho(b"honest bytes").unwrap();
    let key_chirho = S3BlobStoreChirho::object_key_for_addr_chirho(&addr_chirho).unwrap();
    state_chirho
        .tamper_chirho
        .lock()
        .unwrap()
        .insert(key_chirho, b"substituted bytes".to_vec());
    let message_chirho = store_chirho
        .get_chirho(&addr_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        message_chirho.contains("content address mismatch"),
        "{message_chirho}"
    );
}

/// The P3 receiver over the S3 source: a corrupt pull is quarantined and never served.
#[test]
fn pull_quarantines_corrupt_never_serves_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    let good_addr_chirho = store_chirho.put_chirho(b"good stone").unwrap();
    let bad_addr_chirho = store_chirho.put_chirho(b"stone to corrupt").unwrap();
    let bad_key_chirho = S3BlobStoreChirho::object_key_for_addr_chirho(&bad_addr_chirho).unwrap();
    state_chirho
        .tamper_chirho
        .lock()
        .unwrap()
        .insert(bad_key_chirho, b"evil replacement".to_vec());
    let replica_root_chirho = tmp_root_chirho("replica");
    let served_chirho = FsContentStoreChirho::new_chirho(&replica_root_chirho);
    let quarantine_chirho = FsReplicaQuarantineChirho::new_chirho(&replica_root_chirho);
    let (report_chirho, _receipts_chirho) =
        receive_objects_chirho(&store_chirho, &served_chirho, &quarantine_chirho).unwrap();
    assert_eq!(report_chirho.listed_chirho, 2);
    assert_eq!(report_chirho.stored_chirho, 1);
    assert_eq!(report_chirho.quarantined_chirho, 1);
    assert!(served_chirho
        .get_chirho(&good_addr_chirho)
        .unwrap()
        .is_some());
    assert!(served_chirho
        .get_chirho(&bad_addr_chirho)
        .unwrap()
        .is_none());
    let quarantined_addr_chirho = hash_chirho(b"evil replacement");
    assert!(quarantine_chirho
        .quarantine_dir_chirho()
        .join(&quarantined_addr_chirho.0)
        .is_file());
}

#[test]
fn listing_paginates_with_continuation_tokens_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(2);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    let mut expected_chirho: Vec<HashChirho> = (0..5u8)
        .map(|n_chirho| store_chirho.put_chirho(&[n_chirho; 9]).unwrap())
        .collect();
    expected_chirho.sort_by(|a_chirho, b_chirho| a_chirho.0.cmp(&b_chirho.0));
    let listed_chirho = store_chirho.list_object_addrs_chirho().unwrap();
    assert_eq!(listed_chirho, expected_chirho);
    assert!(state_chirho.list_calls_chirho.load(Ordering::Relaxed) >= 3);
}

/// R2: the bucket is exclusively a cairn root mirror — one foreign key fails the WHOLE listing.
#[test]
fn listing_fails_closed_on_foreign_key_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    store_chirho.put_chirho(b"legit stone").unwrap();
    state_chirho
        .objects_chirho
        .lock()
        .unwrap()
        .insert("objects-chirho/evil.txt".to_string(), b"foreign".to_vec());
    let message_chirho = store_chirho
        .list_object_addrs_chirho()
        .unwrap_err()
        .to_string();
    assert!(
        message_chirho.contains("non-mirror key"),
        "{message_chirho}"
    );
}

/// R2: a truncated page without a continuation token is an error, never a silent partial.
#[test]
fn listing_fails_closed_on_truncated_without_token_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    store_chirho.put_chirho(b"stone one").unwrap();
    store_chirho.put_chirho(b"stone two").unwrap();
    *state_chirho.fail_mode_chirho.lock().unwrap() = Some(FailModeChirho::TruncatedNoTokenChirho);
    let message_chirho = store_chirho
        .list_object_addrs_chirho()
        .unwrap_err()
        .to_string();
    assert!(
        message_chirho.contains("silent partial"),
        "{message_chirho}"
    );
}

/// R2 loop teeth: a page listing the same well-formed key twice fails the whole listing.
#[test]
fn listing_fails_closed_on_duplicate_key_page_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    *state_chirho.fail_mode_chirho.lock().unwrap() = Some(FailModeChirho::DuplicateKeyPageChirho);
    let message_chirho = store_chirho
        .list_object_addrs_chirho()
        .unwrap_err()
        .to_string();
    assert!(message_chirho.contains("duplicate key"), "{message_chirho}");
}

/// R2 loop teeth: truncated pages whose continuation token never advances are a stall, not
/// progress — fresh keys per page mean only the stall guard can catch this shape.
#[test]
fn listing_fails_closed_on_stuck_continuation_token_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    *state_chirho.fail_mode_chirho.lock().unwrap() =
        Some(FailModeChirho::StuckContinuationTokenChirho);
    let message_chirho = store_chirho
        .list_object_addrs_with_page_cap_chirho(10)
        .unwrap_err()
        .to_string();
    assert!(
        message_chirho.contains("did not advance"),
        "{message_chirho}"
    );
    assert_eq!(
        state_chirho.list_calls_chirho.load(Ordering::Relaxed),
        2,
        "the stall must be caught on the second page, not ridden to the cap"
    );
}

/// R2 loop teeth: ever-advancing tokens with fresh keys run into the page-cap backstop.
#[test]
fn listing_fails_closed_at_the_page_cap_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    *state_chirho.fail_mode_chirho.lock().unwrap() =
        Some(FailModeChirho::EndlessAdvancingTokensChirho);
    let message_chirho = store_chirho
        .list_object_addrs_with_page_cap_chirho(3)
        .unwrap_err()
        .to_string();
    assert!(
        message_chirho.contains("page-count backstop"),
        "{message_chirho}"
    );
    assert_eq!(
        state_chirho.list_calls_chirho.load(Ordering::Relaxed),
        3,
        "the cap must stop the loop after exactly the capped page count"
    );
}

/// R2 loop teeth: a 404 on the bucket listing is an error — never an empty mirror.
#[test]
fn listing_404_is_an_error_not_absence_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    *state_chirho.fail_mode_chirho.lock().unwrap() = Some(FailModeChirho::ListNotFoundChirho);
    let message_chirho = store_chirho
        .list_object_addrs_chirho()
        .unwrap_err()
        .to_string();
    assert!(message_chirho.contains("returned 404"), "{message_chirho}");
}

/// R2 loop teeth: a 200 listing body that is not UTF-8 fails closed.
#[test]
fn listing_fails_closed_on_non_utf8_body_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    *state_chirho.fail_mode_chirho.lock().unwrap() = Some(FailModeChirho::NonUtf8ListBodyChirho);
    let message_chirho = store_chirho
        .list_object_addrs_chirho()
        .unwrap_err()
        .to_string();
    assert!(message_chirho.contains("not UTF-8"), "{message_chirho}");
}

/// The S3 transport's body cap must not silently drift from the replication transport's cap —
/// pinning the constant keeps both remote planes under one reviewed ceiling.
#[test]
fn body_cap_stays_in_parity_with_the_replication_transport_chirho() {
    assert_eq!(MAX_S3_BODY_BYTES_CHIRHO, MAX_REPLICATION_BODY_BYTES_CHIRHO);
}

/// The named-log allowlist is enforced adapter-side BEFORE any HTTP leaves the process.
#[test]
fn named_log_allowlist_enforced_before_http_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    let requests_before_chirho = state_chirho.requests_chirho.load(Ordering::Relaxed);
    let message_chirho = store_chirho
        .fetch_named_log_chirho("signing-key-chirho.bin")
        .unwrap_err()
        .to_string();
    assert!(
        message_chirho.contains("not an allowlisted"),
        "{message_chirho}"
    );
    assert_eq!(
        state_chirho.requests_chirho.load(Ordering::Relaxed),
        requests_before_chirho,
        "the refused name must never reach the wire"
    );
    state_chirho.objects_chirho.lock().unwrap().insert(
        GATE1_LOG_ANCHORS_FILE_CHIRHO.to_string(),
        b"{\"anchor\":1}\n".to_vec(),
    );
    assert_eq!(
        store_chirho
            .fetch_named_log_chirho(GATE1_LOG_ANCHORS_FILE_CHIRHO)
            .unwrap()
            .as_deref(),
        Some(b"{\"anchor\":1}\n".as_slice())
    );
}

/// R1 push-side M142: a corrupt local object is refused loudly (verified siblings still upload),
/// and after repair the mirror completes; the bucket then round-trips through the P3 receiver.
#[test]
fn mirror_refuses_corrupt_local_object_then_roundtrips_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    let source_root_chirho = tmp_root_chirho("mirror-src");
    let source_store_chirho = FsContentStoreChirho::new_chirho(&source_root_chirho);
    let good_bytes_chirho = b"upright stone".to_vec();
    let bad_bytes_chirho = b"stone corrupted on disk".to_vec();
    let good_addr_chirho = source_store_chirho.put_chirho(&good_bytes_chirho).unwrap();
    let bad_addr_chirho = source_store_chirho.put_chirho(&bad_bytes_chirho).unwrap();
    std::fs::write(
        object_disk_path_chirho(&source_root_chirho, &bad_addr_chirho),
        b"bit-rotted body",
    )
    .unwrap();
    std::fs::write(
        source_root_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO),
        b"{\"anchor\":1}\n",
    )
    .unwrap();
    let source_chirho = LocalFsReplicationSourceChirho::new_chirho(&source_root_chirho);
    let message_chirho = mirror_source_to_s3_chirho(&source_chirho, &store_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        message_chirho.contains("mirror refused 1 corrupt local object"),
        "{message_chirho}"
    );
    assert!(
        message_chirho.contains(&bad_addr_chirho.0[..8]),
        "{message_chirho}"
    );
    // The corrupt address never reached the bucket; the verified sibling and the log did.
    assert_eq!(store_chirho.get_chirho(&bad_addr_chirho).unwrap(), None);
    assert_eq!(
        store_chirho.get_chirho(&good_addr_chirho).unwrap(),
        Some(good_bytes_chirho.clone())
    );
    assert_eq!(
        store_chirho
            .fetch_named_log_chirho(GATE1_LOG_ANCHORS_FILE_CHIRHO)
            .unwrap()
            .as_deref(),
        Some(b"{\"anchor\":1}\n".as_slice())
    );
    // Repair the source object and re-run: the mirror completes and reports honestly.
    std::fs::write(
        object_disk_path_chirho(&source_root_chirho, &bad_addr_chirho),
        &bad_bytes_chirho,
    )
    .unwrap();
    let report_chirho = mirror_source_to_s3_chirho(&source_chirho, &store_chirho).unwrap();
    assert_eq!(report_chirho.listed_chirho, 2);
    assert_eq!(report_chirho.uploaded_chirho, 1);
    assert_eq!(report_chirho.already_present_chirho, 1);
    assert!(report_chirho.corrupt_refused_chirho.is_empty());
    assert_eq!(report_chirho.logs_uploaded_chirho, 1);
    // Full path home: pull the bucket into a fresh replica root through the verifying receiver.
    let replica_root_chirho = tmp_root_chirho("mirror-replica");
    let served_chirho = FsContentStoreChirho::new_chirho(&replica_root_chirho);
    let quarantine_chirho = FsReplicaQuarantineChirho::new_chirho(&replica_root_chirho);
    let (pull_chirho, _receipts_chirho) =
        receive_objects_chirho(&store_chirho, &served_chirho, &quarantine_chirho).unwrap();
    assert_eq!(pull_chirho.stored_chirho, 2);
    assert_eq!(pull_chirho.quarantined_chirho, 0);
    assert_eq!(
        served_chirho.get_chirho(&bad_addr_chirho).unwrap(),
        Some(bad_bytes_chirho)
    );
}

#[test]
fn wrong_credentials_are_refused_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let base_url_chirho = start_fake_s3_chirho(state_chirho);
    let honest_chirho = s3_store_chirho(&base_url_chirho);
    let addr_chirho = honest_chirho.put_chirho(b"guarded stone").unwrap();
    let impostor_chirho = S3BlobStoreChirho::new_chirho(S3BlobStoreConfigChirho {
        endpoint_chirho: base_url_chirho,
        bucket_chirho: TEST_BUCKET_CHIRHO.to_string(),
        region_chirho: TEST_REGION_CHIRHO.to_string(),
        access_key_id_chirho: TEST_AKID_CHIRHO.to_string(),
        secret_access_key_chirho: "WRONGSECRETCHIRHO".to_string(),
    })
    .unwrap();
    let message_chirho = impostor_chirho
        .get_chirho(&addr_chirho)
        .unwrap_err()
        .to_string();
    assert!(message_chirho.contains("403"), "{message_chirho}");
}

/// R4: no error path may carry the secret, the access key id, or any signature material.
#[test]
fn errors_never_carry_secret_material_chirho() {
    let assert_secret_free_chirho = |message_chirho: &str| {
        for needle_chirho in [
            TEST_SECRET_CHIRHO,
            "WRONGSECRETCHIRHO",
            TEST_AKID_CHIRHO,
            "Signature=",
            "AWS4-HMAC-SHA256",
        ] {
            assert!(
                !message_chirho.contains(needle_chirho),
                "error leaked {needle_chirho:?}: {message_chirho}"
            );
        }
    };
    // Transport failure (connection refused).
    let unroutable_chirho = S3BlobStoreChirho::new_chirho(S3BlobStoreConfigChirho {
        endpoint_chirho: "http://127.0.0.1:1".to_string(),
        bucket_chirho: TEST_BUCKET_CHIRHO.to_string(),
        region_chirho: TEST_REGION_CHIRHO.to_string(),
        access_key_id_chirho: TEST_AKID_CHIRHO.to_string(),
        secret_access_key_chirho: TEST_SECRET_CHIRHO.to_string(),
    })
    .unwrap();
    let addr_chirho = hash_chirho(b"any stone");
    assert_secret_free_chirho(
        &unroutable_chirho
            .get_chirho(&addr_chirho)
            .unwrap_err()
            .to_string(),
    );
    // Server-status failure (injected 500) and auth refusal (403).
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let base_url_chirho = start_fake_s3_chirho(state_chirho.clone());
    let store_chirho = s3_store_chirho(&base_url_chirho);
    *state_chirho.fail_mode_chirho.lock().unwrap() = Some(FailModeChirho::Status500Chirho);
    assert_secret_free_chirho(
        &store_chirho
            .get_chirho(&addr_chirho)
            .unwrap_err()
            .to_string(),
    );
    *state_chirho.fail_mode_chirho.lock().unwrap() = None;
    // Auth refusal (403): a wrong-secret store's error must be as needle-clean as the rest.
    let impostor_chirho = S3BlobStoreChirho::new_chirho(S3BlobStoreConfigChirho {
        endpoint_chirho: base_url_chirho,
        bucket_chirho: TEST_BUCKET_CHIRHO.to_string(),
        region_chirho: TEST_REGION_CHIRHO.to_string(),
        access_key_id_chirho: TEST_AKID_CHIRHO.to_string(),
        secret_access_key_chirho: "WRONGSECRETCHIRHO".to_string(),
    })
    .unwrap();
    assert_secret_free_chirho(
        &impostor_chirho
            .get_chirho(&addr_chirho)
            .unwrap_err()
            .to_string(),
    );
}

/// A redirect is refused, never followed — and a 500 is an error, never absence.
#[test]
fn redirect_and_server_error_fail_closed_chirho() {
    let state_chirho = FakeS3StateChirho::new_chirho(1_000);
    let store_chirho = s3_store_chirho(&start_fake_s3_chirho(state_chirho.clone()));
    let addr_chirho = hash_chirho(b"unfollowed stone");
    *state_chirho.fail_mode_chirho.lock().unwrap() = Some(FailModeChirho::Redirect301Chirho);
    let message_chirho = store_chirho
        .get_chirho(&addr_chirho)
        .unwrap_err()
        .to_string();
    assert!(message_chirho.contains("301"), "{message_chirho}");
    *state_chirho.fail_mode_chirho.lock().unwrap() = Some(FailModeChirho::Status500Chirho);
    assert!(store_chirho.get_chirho(&addr_chirho).is_err());
}
