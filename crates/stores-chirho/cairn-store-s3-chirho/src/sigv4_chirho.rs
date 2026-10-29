// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pure AWS Signature Version 4 request signing (no I/O, no clock) — the auth dialect Ceph RGW,
//! Garage, and MinIO all speak; pinned against AWS-published vectors plus oracle-minted cairn vectors.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// The service name S3-compatible stores sign for.
pub const S3_SERVICE_CHIRHO: &str = "s3";

/// hex(sha256("")) — the payload hash of every body-less (GET) request.
pub const EMPTY_PAYLOAD_SHA256_CHIRHO: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The fixed header set every request signs, in canonical (lexicographic) order.
pub const SIGNED_HEADERS_CHIRHO: &str = "host;x-amz-content-sha256;x-amz-date";

/// Static credentials for one S3-compatible endpoint. Deliberately NO `Debug` derive: the secret
/// must never reach logs, error strings, or evidence (R4) — there is no accidental way to render it.
pub struct SigV4CredsChirho {
    pub access_key_id_chirho: String,
    pub secret_access_key_chirho: String,
    pub region_chirho: String,
}

/// One request to sign. `query_chirho` holds RAW (unencoded) pairs; signing encodes them, and the
/// transport must send the byte-identical canonical encoding it was handed back.
pub struct SigV4RequestChirho<'a> {
    pub method_chirho: &'a str,
    /// Absolute path (`/bucket` or `/bucket/key`), URI-encoded by the signer (slashes preserved).
    pub path_chirho: &'a str,
    pub query_chirho: &'a [(String, String)],
    /// The `Host` header value — authority incl. any port, e.g. `127.0.0.1:3900`.
    pub host_chirho: &'a str,
    /// hex(sha256(body)); [`EMPTY_PAYLOAD_SHA256_CHIRHO`] for GET.
    pub payload_sha256_hex_chirho: &'a str,
    /// `yyyymmddThhmmssZ` — supplied by the caller so signing stays pure and vector-testable.
    pub amz_timestamp_chirho: &'a str,
}

/// The three headers a signed request carries. No `Debug` derive: the signature is auth material.
pub struct SigV4SignedHeadersChirho {
    pub authorization_chirho: String,
    pub x_amz_date_chirho: String,
    pub x_amz_content_sha256_chirho: String,
}

pub fn sha256_hex_chirho(bytes_chirho: &[u8]) -> String {
    hex_encode_chirho(&Sha256::digest(bytes_chirho))
}

fn hex_encode_chirho(bytes_chirho: &[u8]) -> String {
    let mut out_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        out_chirho.push_str(&format!("{byte_chirho:02x}"));
    }
    out_chirho
}

/// AWS URI-encode: unreserved bytes (`A-Za-z0-9 - _ . ~`) pass through; `/` passes only when
/// `encode_slash_chirho` is false (paths); every other byte becomes uppercase `%XX`. This exact
/// rule on the query side is what the continuation-token vector (R3) pins — `+ / =` MUST encode.
pub fn uri_encode_chirho(input_chirho: &str, encode_slash_chirho: bool) -> String {
    let mut out_chirho = String::with_capacity(input_chirho.len());
    for byte_chirho in input_chirho.as_bytes() {
        match byte_chirho {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out_chirho.push(*byte_chirho as char);
            }
            b'/' if !encode_slash_chirho => out_chirho.push('/'),
            _ => out_chirho.push_str(&format!("%{byte_chirho:02X}")),
        }
    }
    out_chirho
}

/// Canonical query string: encode each key and value (slash-encoding ON), sort by encoded key then
/// encoded value, join `k=v` with `&`. The transport sends this exact string, so what is signed is
/// byte-identical to what goes on the wire.
pub fn canonical_query_string_chirho(pairs_chirho: &[(String, String)]) -> String {
    let mut encoded_chirho: Vec<(String, String)> = pairs_chirho
        .iter()
        .map(|(key_chirho, value_chirho)| {
            (
                uri_encode_chirho(key_chirho, true),
                uri_encode_chirho(value_chirho, true),
            )
        })
        .collect();
    encoded_chirho.sort();
    let parts_chirho: Vec<String> = encoded_chirho
        .into_iter()
        .map(|(key_chirho, value_chirho)| format!("{key_chirho}={value_chirho}"))
        .collect();
    parts_chirho.join("&")
}

fn hmac_sha256_chirho(key_chirho: &[u8], message_chirho: &[u8]) -> Vec<u8> {
    let mut mac_chirho =
        Hmac::<Sha256>::new_from_slice(key_chirho).expect("HMAC-SHA256 accepts any key length");
    mac_chirho.update(message_chirho);
    mac_chirho.finalize().into_bytes().to_vec()
}

/// The SigV4 key-derivation chain: `AWS4<secret>` → date → region → service → `aws4_request`.
pub fn derive_signing_key_chirho(
    secret_chirho: &str,
    date_chirho: &str,
    region_chirho: &str,
    service_chirho: &str,
) -> Vec<u8> {
    let key_date_chirho = hmac_sha256_chirho(
        format!("AWS4{secret_chirho}").as_bytes(),
        date_chirho.as_bytes(),
    );
    let key_region_chirho = hmac_sha256_chirho(&key_date_chirho, region_chirho.as_bytes());
    let key_service_chirho = hmac_sha256_chirho(&key_region_chirho, service_chirho.as_bytes());
    hmac_sha256_chirho(&key_service_chirho, b"aws4_request")
}

/// Sign one request: canonical request → string-to-sign → derived key → `Authorization` header.
pub fn sign_request_chirho(
    request_chirho: &SigV4RequestChirho<'_>,
    creds_chirho: &SigV4CredsChirho,
) -> SigV4SignedHeadersChirho {
    let canonical_headers_chirho = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        request_chirho.host_chirho,
        request_chirho.payload_sha256_hex_chirho,
        request_chirho.amz_timestamp_chirho
    );
    let canonical_request_chirho = [
        request_chirho.method_chirho,
        &uri_encode_chirho(request_chirho.path_chirho, false),
        &canonical_query_string_chirho(request_chirho.query_chirho),
        &canonical_headers_chirho,
        SIGNED_HEADERS_CHIRHO,
        request_chirho.payload_sha256_hex_chirho,
    ]
    .join("\n");
    let date_chirho =
        &request_chirho.amz_timestamp_chirho[..8.min(request_chirho.amz_timestamp_chirho.len())];
    let scope_chirho = format!(
        "{date_chirho}/{}/{}/aws4_request",
        creds_chirho.region_chirho, S3_SERVICE_CHIRHO
    );
    let string_to_sign_chirho = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope_chirho}\n{}",
        request_chirho.amz_timestamp_chirho,
        sha256_hex_chirho(canonical_request_chirho.as_bytes())
    );
    let signing_key_chirho = derive_signing_key_chirho(
        &creds_chirho.secret_access_key_chirho,
        date_chirho,
        &creds_chirho.region_chirho,
        S3_SERVICE_CHIRHO,
    );
    let signature_chirho = hex_encode_chirho(&hmac_sha256_chirho(
        &signing_key_chirho,
        string_to_sign_chirho.as_bytes(),
    ));
    SigV4SignedHeadersChirho {
        authorization_chirho: format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope_chirho}, SignedHeaders={SIGNED_HEADERS_CHIRHO}, Signature={signature_chirho}",
            creds_chirho.access_key_id_chirho
        ),
        x_amz_date_chirho: request_chirho.amz_timestamp_chirho.to_string(),
        x_amz_content_sha256_chirho: request_chirho.payload_sha256_hex_chirho.to_string(),
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    /// AWS-published derived-signing-key vector (SigV4 docs, "Deriving the signing key").
    #[test]
    fn derives_the_aws_documented_signing_key_chirho() {
        let key_chirho = derive_signing_key_chirho(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex_encode_chirho(&key_chirho),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    /// `get-vanilla` from the AWS SigV4 test suite: full canonical-request → signature chain.
    /// (Suite signs only host;x-amz-date, so this reproduces the chain with that header set.)
    #[test]
    fn reproduces_the_aws_get_vanilla_signature_chirho() {
        let canonical_chirho = format!(
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n{EMPTY_PAYLOAD_SHA256_CHIRHO}"
        );
        let string_to_sign_chirho = format!(
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n{}",
            sha256_hex_chirho(canonical_chirho.as_bytes())
        );
        let key_chirho = derive_signing_key_chirho(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "service",
        );
        let signature_chirho = hex_encode_chirho(&hmac_sha256_chirho(
            &key_chirho,
            string_to_sign_chirho.as_bytes(),
        ));
        assert_eq!(
            signature_chirho,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    fn cairn_test_creds_chirho() -> SigV4CredsChirho {
        SigV4CredsChirho {
            access_key_id_chirho: "GKTESTAKIDCHIRHO".to_string(),
            secret_access_key_chirho: "testsecretkeychirho/with+specials".to_string(),
            region_chirho: "garage".to_string(),
        }
    }

    /// Cairn V1 vector (python-oracle-minted; oracle itself validated against the two AWS vectors
    /// above): path-style listing with an encoded-slash prefix value.
    #[test]
    fn signs_the_list_prefix_request_vector_chirho() {
        let query_chirho = vec![
            ("list-type".to_string(), "2".to_string()),
            ("prefix".to_string(), "objects-chirho/".to_string()),
        ];
        let signed_chirho = sign_request_chirho(
            &SigV4RequestChirho {
                method_chirho: "GET",
                path_chirho: "/cairn-test-bucket-chirho",
                query_chirho: &query_chirho,
                host_chirho: "127.0.0.1:19000",
                payload_sha256_hex_chirho: EMPTY_PAYLOAD_SHA256_CHIRHO,
                amz_timestamp_chirho: "20260713T120000Z",
            },
            &cairn_test_creds_chirho(),
        );
        assert_eq!(
            signed_chirho.authorization_chirho,
            "AWS4-HMAC-SHA256 Credential=GKTESTAKIDCHIRHO/20260713/garage/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=2b1cba4ce420580e94ca37a21c854fe108e2bfc048db3437838522dca5d2a715"
        );
    }

    /// Cairn V2 vector — R3: continuation-token carrying `+ / =` must canonical-encode to
    /// `%2B %2F %3D` (the classic SigV4 listing bug), proven at both the query and signature level.
    #[test]
    fn signs_the_continuation_token_request_vector_chirho() {
        let query_chirho = vec![
            ("continuation-token".to_string(), "abc+def/ghi=".to_string()),
            ("list-type".to_string(), "2".to_string()),
            ("max-keys".to_string(), "1".to_string()),
            ("prefix".to_string(), "objects-chirho/".to_string()),
        ];
        assert_eq!(
            canonical_query_string_chirho(&query_chirho),
            "continuation-token=abc%2Bdef%2Fghi%3D&list-type=2&max-keys=1&prefix=objects-chirho%2F"
        );
        let signed_chirho = sign_request_chirho(
            &SigV4RequestChirho {
                method_chirho: "GET",
                path_chirho: "/cairn-test-bucket-chirho",
                query_chirho: &query_chirho,
                host_chirho: "127.0.0.1:19000",
                payload_sha256_hex_chirho: EMPTY_PAYLOAD_SHA256_CHIRHO,
                amz_timestamp_chirho: "20260713T120000Z",
            },
            &cairn_test_creds_chirho(),
        );
        assert_eq!(
            signed_chirho.authorization_chirho,
            "AWS4-HMAC-SHA256 Credential=GKTESTAKIDCHIRHO/20260713/garage/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=c7fc3f9debc3e461850d50762a4bd3029441bb0e16a595d49627209148d1739f"
        );
    }

    /// Cairn V3 vector: PUT with a real payload hash on a byte-mirror object key.
    #[test]
    fn signs_the_put_object_request_vector_chirho() {
        let body_sha_chirho = sha256_hex_chirho(b"hello cairn stone");
        assert_eq!(
            body_sha_chirho,
            "a555f2566aa29374262652523b072500626a82821ddf4253a6ef9d3c4faa620a"
        );
        let path_chirho = format!(
            "/cairn-test-bucket-chirho/objects-chirho/ab/{}",
            "c".repeat(62)
        );
        let signed_chirho = sign_request_chirho(
            &SigV4RequestChirho {
                method_chirho: "PUT",
                path_chirho: &path_chirho,
                query_chirho: &[],
                host_chirho: "127.0.0.1:19000",
                payload_sha256_hex_chirho: &body_sha_chirho,
                amz_timestamp_chirho: "20260713T120000Z",
            },
            &cairn_test_creds_chirho(),
        );
        assert!(signed_chirho.authorization_chirho.ends_with(
            "Signature=ae6ccee3c644c77dc3495cea784923a6ffcb4e663b51dc5e47c59d5689fa1184"
        ));
    }

    /// Cairn V4 vector: GET of the same object key (empty payload hash).
    #[test]
    fn signs_the_get_object_request_vector_chirho() {
        let path_chirho = format!(
            "/cairn-test-bucket-chirho/objects-chirho/ab/{}",
            "c".repeat(62)
        );
        let signed_chirho = sign_request_chirho(
            &SigV4RequestChirho {
                method_chirho: "GET",
                path_chirho: &path_chirho,
                query_chirho: &[],
                host_chirho: "127.0.0.1:19000",
                payload_sha256_hex_chirho: EMPTY_PAYLOAD_SHA256_CHIRHO,
                amz_timestamp_chirho: "20260713T120000Z",
            },
            &cairn_test_creds_chirho(),
        );
        assert!(signed_chirho.authorization_chirho.ends_with(
            "Signature=2a393c081b64164b06dccaa044190dc03f2d09680e4a52f2ecc6ba04f28672e5"
        ));
    }
}
