// For God so loved the world, that He gave His only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use cairn_chirho::{app_chirho, identity_chirho, model_chirho, store_chirho};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;

struct HttpAssetResponseChirho {
    status_chirho: u16,
    headers_chirho: BTreeMap<String, String>,
    body_chirho: Vec<u8>,
}

fn temp_root_chirho() -> PathBuf {
    let nanos_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("cairn-app-asset-serve-{nanos_chirho}"))
}

fn unused_port_chirho() -> u16 {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener_chirho.local_addr().unwrap().port()
}

fn http_get_chirho(addr_chirho: &str, path_chirho: &str) -> HttpAssetResponseChirho {
    let mut stream_chirho = std::net::TcpStream::connect(addr_chirho).unwrap();
    let request_chirho =
        format!("GET {path_chirho} HTTP/1.1\r\nhost: {addr_chirho}\r\nconnection: close\r\n\r\n");
    stream_chirho.write_all(request_chirho.as_bytes()).unwrap();
    let mut response_chirho = Vec::new();
    stream_chirho.read_to_end(&mut response_chirho).unwrap();
    let header_end_chirho = response_chirho
        .windows(4)
        .position(|window_chirho| window_chirho == b"\r\n\r\n")
        .unwrap();
    let header_text_chirho = String::from_utf8_lossy(&response_chirho[..header_end_chirho]);
    let mut lines_chirho = header_text_chirho.lines();
    let status_chirho = lines_chirho
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let mut headers_chirho = BTreeMap::new();
    for line_chirho in lines_chirho {
        if let Some((name_chirho, value_chirho)) = line_chirho.split_once(':') {
            headers_chirho.insert(
                name_chirho.trim().to_ascii_lowercase(),
                value_chirho.trim().to_string(),
            );
        }
    }
    HttpAssetResponseChirho {
        status_chirho,
        headers_chirho,
        body_chirho: response_chirho[header_end_chirho + 4..].to_vec(),
    }
}

fn wait_for_health_chirho(addr_chirho: &str) {
    for _attempt_chirho in 0..100 {
        if let Ok(mut stream_chirho) = std::net::TcpStream::connect(addr_chirho) {
            let request_chirho = format!(
                "GET /healthz-chirho HTTP/1.1\r\nhost: {addr_chirho}\r\nconnection: close\r\n\r\n"
            );
            if stream_chirho.write_all(request_chirho.as_bytes()).is_ok() {
                let mut response_chirho = String::new();
                if stream_chirho.read_to_string(&mut response_chirho).is_ok()
                    && response_chirho.contains("200 OK")
                {
                    return;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("serve_chirho did not become healthy at {addr_chirho}");
}

#[test]
fn app_static_asset_routes_redirect_and_serve_from_cas_chirho() {
    let root_chirho = temp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let dag_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &model_chirho::DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(&root_chirho, "assetapp-chirho", dag_chirho, &owner_chirho)
        .unwrap();
    let record_chirho = app_chirho::set_app_static_asset_bytes_chirho(
        &root_chirho,
        "assetapp-chirho",
        &owner_chirho,
        "site-chirho.css",
        "text/css",
        b".proof-chirho { color: rgb(36, 92, 75); }\n",
    )
    .unwrap();
    let png_bytes_chirho = b"\x89PNG\r\n\x1a\nserve-proof-chirho";
    let png_record_chirho = app_chirho::set_app_static_asset_bytes_chirho(
        &root_chirho,
        "assetapp-chirho",
        &owner_chirho,
        "logo-chirho.png",
        "image/png",
        png_bytes_chirho,
    )
    .unwrap();
    let pdf_bytes_chirho = b"%PDF-1.7\n% serve-proof-chirho\n";
    let pdf_record_chirho = app_chirho::set_app_static_asset_bytes_chirho(
        &root_chirho,
        "assetapp-chirho",
        &owner_chirho,
        "bulletin-chirho.pdf",
        "application/pdf",
        pdf_bytes_chirho,
    )
    .unwrap();
    let font_bytes_chirho = b"wOF2 serve font proof chirho";
    let font_record_chirho = app_chirho::set_app_static_asset_bytes_chirho(
        &root_chirho,
        "assetapp-chirho",
        &owner_chirho,
        "brand-chirho.woff2",
        "font/woff2",
        font_bytes_chirho,
    )
    .unwrap();

    let port_chirho = unused_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            cairn_serve_runtime_chirho::serve_chirho(
                &root_for_server_chirho,
                port_chirho,
                8,
                String::new(),
            )
            .await
        });
        wait_for_health_chirho(&addr_chirho);

        let by_name_chirho = http_get_chirho(
            &addr_chirho,
            "/app-assets-chirho/assetapp-chirho/by-name-chirho/site-chirho.css",
        );
        assert_eq!(by_name_chirho.status_chirho, 302);
        assert_eq!(
            by_name_chirho.headers_chirho.get("cache-control").unwrap(),
            "no-store, max-age=0"
        );
        let location_chirho = by_name_chirho.headers_chirho.get("location").unwrap();
        assert_eq!(
            location_chirho,
            &format!(
                "/app-assets-chirho/assetapp-chirho/by-hash-chirho/{}/site-chirho.css",
                record_chirho.asset_chirho.0
            )
        );

        let by_hash_chirho = http_get_chirho(&addr_chirho, location_chirho);
        assert_eq!(by_hash_chirho.status_chirho, 200);
        assert_eq!(
            by_hash_chirho.headers_chirho.get("content-type").unwrap(),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            by_hash_chirho
                .headers_chirho
                .get("x-content-type-options")
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            by_hash_chirho.headers_chirho.get("cache-control").unwrap(),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            by_hash_chirho.body_chirho,
            b".proof-chirho { color: rgb(36, 92, 75); }\n"
        );

        let png_by_name_chirho = http_get_chirho(
            &addr_chirho,
            "/app-assets-chirho/assetapp-chirho/by-name-chirho/logo-chirho.png",
        );
        assert_eq!(png_by_name_chirho.status_chirho, 302);
        assert_eq!(
            png_by_name_chirho
                .headers_chirho
                .get("cache-control")
                .unwrap(),
            "no-store, max-age=0"
        );
        let png_location_chirho = png_by_name_chirho.headers_chirho.get("location").unwrap();
        assert_eq!(
            png_location_chirho,
            &format!(
                "/app-assets-chirho/assetapp-chirho/by-hash-chirho/{}/logo-chirho.png",
                png_record_chirho.asset_chirho.0
            )
        );
        let png_by_hash_chirho = http_get_chirho(&addr_chirho, png_location_chirho);
        assert_eq!(png_by_hash_chirho.status_chirho, 200);
        assert_eq!(
            png_by_hash_chirho
                .headers_chirho
                .get("content-type")
                .unwrap(),
            "image/png"
        );
        assert_eq!(
            png_by_hash_chirho
                .headers_chirho
                .get("x-content-type-options")
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            png_by_hash_chirho
                .headers_chirho
                .get("cache-control")
                .unwrap(),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(png_by_hash_chirho.body_chirho, png_bytes_chirho);

        let pdf_by_hash_chirho = http_get_chirho(
            &addr_chirho,
            &format!(
                "/app-assets-chirho/assetapp-chirho/by-hash-chirho/{}/bulletin-chirho.pdf",
                pdf_record_chirho.asset_chirho.0
            ),
        );
        assert_eq!(pdf_by_hash_chirho.status_chirho, 200);
        assert_eq!(
            pdf_by_hash_chirho
                .headers_chirho
                .get("content-type")
                .unwrap(),
            "application/pdf"
        );
        assert_eq!(
            pdf_by_hash_chirho
                .headers_chirho
                .get("content-disposition")
                .unwrap(),
            "attachment; filename=\"bulletin-chirho.pdf\""
        );
        assert_eq!(
            pdf_by_hash_chirho
                .headers_chirho
                .get("x-content-type-options")
                .unwrap(),
            "nosniff"
        );
        assert_eq!(pdf_by_hash_chirho.body_chirho, pdf_bytes_chirho);

        let font_by_name_chirho = http_get_chirho(
            &addr_chirho,
            "/app-assets-chirho/assetapp-chirho/by-name-chirho/brand-chirho.woff2",
        );
        assert_eq!(font_by_name_chirho.status_chirho, 302);
        let font_location_chirho = font_by_name_chirho.headers_chirho.get("location").unwrap();
        assert_eq!(
            font_location_chirho,
            &format!(
                "/app-assets-chirho/assetapp-chirho/by-hash-chirho/{}/brand-chirho.woff2",
                font_record_chirho.asset_chirho.0
            )
        );
        let font_by_hash_chirho = http_get_chirho(&addr_chirho, font_location_chirho);
        assert_eq!(font_by_hash_chirho.status_chirho, 200);
        assert_eq!(
            font_by_hash_chirho
                .headers_chirho
                .get("content-type")
                .unwrap(),
            "font/woff2"
        );
        assert_eq!(
            font_by_hash_chirho
                .headers_chirho
                .get("x-content-type-options")
                .unwrap(),
            "nosniff"
        );
        assert_eq!(font_by_hash_chirho.body_chirho, font_bytes_chirho);

        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}
