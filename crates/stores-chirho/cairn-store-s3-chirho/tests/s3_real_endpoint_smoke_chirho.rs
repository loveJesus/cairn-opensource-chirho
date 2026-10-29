// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Opt-in operator smoke against a REAL S3-compatible endpoint (local Garage / MinIO / Ceph RGW):
//! `#[ignore]`d so CI stays hermetic on the in-process fake server. Run deliberately with the env
//! below; it proves the SigV4 dialect and the verify-on-read path against a live implementation.
//!
//! ```sh
//! CAIRN_S3_SMOKE_ENDPOINT_CHIRHO=http://127.0.0.1:3900 \
//! CAIRN_S3_SMOKE_BUCKET_CHIRHO=cairn-smoke-chirho \
//! CAIRN_S3_SMOKE_REGION_CHIRHO=garage \
//! CAIRN_S3_SMOKE_ACCESS_KEY_ID_CHIRHO=… \
//! CAIRN_S3_SMOKE_SECRET_CHIRHO=… \
//! cargo test -p cairn-store-s3-chirho --test s3_real_endpoint_smoke_chirho -- --ignored
//! ```
//!
//! First-real-run checklist (flagged in the 29a744a post-commit audit): (1) **x-amz-date
//! freshness** — a live server enforces a clock-skew window the fake server cannot, so a skewed
//! host clock surfaces here first; (2) **default-port Host parity** — prefer an explicit
//! non-default-port endpoint (e.g. `:3900`): if the signer ever saw `host:80` while the transport
//! sent a bare `Host: host`, a real endpoint 403s (functional risk, not a security one); (3) this
//! run is also the designed falsifier for the SigV4 vector/oracle pairing (a shared misreading of
//! the AWS canonical format would only be caught by a live implementation).

use cairn_core_chirho::ports_chirho::{ContentReadChirho, ContentStoreChirho};
use cairn_replication_chirho::ReplicationSourceChirho;
use cairn_store_s3_chirho::{S3BlobStoreChirho, S3BlobStoreConfigChirho};

fn smoke_env_chirho(name_chirho: &str) -> String {
    std::env::var(name_chirho).unwrap_or_else(|_| {
        panic!("real-endpoint smoke needs {name_chirho} (see the module doc for the full env set)")
    })
}

#[test]
#[ignore = "opt-in operator smoke: needs a live S3-compatible endpoint via CAIRN_S3_SMOKE_* env"]
fn real_endpoint_put_get_list_roundtrip_chirho() {
    let store_chirho = S3BlobStoreChirho::new_chirho(S3BlobStoreConfigChirho {
        endpoint_chirho: smoke_env_chirho("CAIRN_S3_SMOKE_ENDPOINT_CHIRHO"),
        bucket_chirho: smoke_env_chirho("CAIRN_S3_SMOKE_BUCKET_CHIRHO"),
        region_chirho: smoke_env_chirho("CAIRN_S3_SMOKE_REGION_CHIRHO"),
        access_key_id_chirho: smoke_env_chirho("CAIRN_S3_SMOKE_ACCESS_KEY_ID_CHIRHO"),
        secret_access_key_chirho: smoke_env_chirho("CAIRN_S3_SMOKE_SECRET_CHIRHO"),
    })
    .expect("smoke config must validate");
    // Unique-per-invocation bytes so reruns exercise a fresh PUT (the object stays: content-
    // addressed debris is idempotent and harmless in a dedicated smoke bucket).
    let bytes_chirho = format!(
        "cairn s3 smoke stone pid={} time={:?}",
        std::process::id(),
        std::time::SystemTime::now()
    )
    .into_bytes();
    let addr_chirho = store_chirho
        .put_chirho(&bytes_chirho)
        .expect("live PUT must succeed");
    let fetched_chirho = store_chirho
        .get_chirho(&addr_chirho)
        .expect("live GET must succeed")
        .expect("just-stored object must exist");
    assert_eq!(fetched_chirho, bytes_chirho, "verify-on-read round-trip");
    let listed_chirho = store_chirho
        .list_object_addrs_chirho()
        .expect("live ListObjectsV2 must parse fail-closed");
    assert!(
        listed_chirho.contains(&addr_chirho),
        "listing must include the stone just stored"
    );
    println!(
        "real-endpoint smoke OK: stored {}, listed {} object(s)",
        addr_chirho.0,
        listed_chirho.len()
    );
}
