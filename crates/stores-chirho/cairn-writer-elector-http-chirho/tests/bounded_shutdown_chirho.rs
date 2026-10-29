// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::State,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use cairn_writer_elector_http_chirho::{
    serve_router_blocking_with_shutdown_chirho, GRACEFUL_SHUTDOWN_DRAIN_TIMEOUT_CHIRHO,
};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const INCOMPLETE_BODY_PATH_CHIRHO: &str = "/incomplete-body-chirho";
const SHORT_REQUEST_PATH_CHIRHO: &str = "/short-request-chirho";

type ServerStartChirho = (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    mpsc::Receiver<Result<(), String>>,
    JoinHandle<()>,
);

async fn hold_incomplete_body_chirho(
    State(request_entered_chirho): State<Arc<AtomicBool>>,
    request_chirho: Request<Body>,
) -> StatusCode {
    request_entered_chirho.store(true, Ordering::SeqCst);
    let _body_result_chirho = to_bytes(request_chirho.into_body(), 64).await;
    StatusCode::OK
}

async fn finish_short_request_chirho(
    State(request_entered_chirho): State<Arc<AtomicBool>>,
    _body_chirho: Bytes,
) -> StatusCode {
    request_entered_chirho.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    StatusCode::OK
}

fn start_server_chirho(router_chirho: Router) -> ServerStartChirho {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address_chirho = listener_chirho.local_addr().unwrap();
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let server_stop_chirho = stop_chirho.clone();
    let (completion_tx_chirho, completion_rx_chirho) = mpsc::sync_channel(1);
    let server_handle_chirho = std::thread::spawn(move || {
        let result_chirho = serve_router_blocking_with_shutdown_chirho(
            listener_chirho,
            router_chirho,
            server_stop_chirho,
        )
        .map_err(|error_chirho| error_chirho.to_string());
        completion_tx_chirho.send(result_chirho).unwrap();
    });
    (
        address_chirho,
        stop_chirho,
        completion_rx_chirho,
        server_handle_chirho,
    )
}

fn wait_for_handler_chirho(request_entered_chirho: &AtomicBool) {
    let deadline_chirho = Instant::now() + Duration::from_secs(2);
    while !request_entered_chirho.load(Ordering::SeqCst) {
        assert!(
            Instant::now() < deadline_chirho,
            "the real-socket request must enter its handler before shutdown"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn incomplete_request_body_cannot_hold_rolling_restart_chirho() {
    let request_entered_chirho = Arc::new(AtomicBool::new(false));
    let router_chirho = Router::new()
        .route(
            INCOMPLETE_BODY_PATH_CHIRHO,
            post(hold_incomplete_body_chirho),
        )
        .with_state(request_entered_chirho.clone());
    let (address_chirho, stop_chirho, completion_rx_chirho, server_handle_chirho) =
        start_server_chirho(router_chirho);

    let mut stream_chirho = TcpStream::connect(address_chirho).unwrap();
    stream_chirho
        .write_all(
            format!(
                "POST {INCOMPLETE_BODY_PATH_CHIRHO} HTTP/1.1\r\nHost: {address_chirho}\r\nContent-Length: 32\r\nConnection: keep-alive\r\n\r\nx"
            )
            .as_bytes(),
        )
        .unwrap();
    stream_chirho.flush().unwrap();
    wait_for_handler_chirho(&request_entered_chirho);

    let shutdown_started_chirho = Instant::now();
    stop_chirho.store(true, Ordering::SeqCst);
    let bounded_return_chirho = GRACEFUL_SHUTDOWN_DRAIN_TIMEOUT_CHIRHO + Duration::from_secs(2);
    completion_rx_chirho
        .recv_timeout(bounded_return_chirho)
        .expect("the stalled body must be canceled after the bounded graceful drain")
        .expect("forced connection cancellation is a successful server shutdown");
    assert!(
        shutdown_started_chirho.elapsed() < bounded_return_chirho,
        "the shared HTTP transport must return within its bounded shutdown interval"
    );
    server_handle_chirho.join().unwrap();

    stream_chirho
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut response_chirho = Vec::new();
    match stream_chirho.read_to_end(&mut response_chirho) {
        Ok(_) => {}
        Err(error_chirho)
            if matches!(
                error_chirho.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) => {}
        Err(error_chirho) => {
            panic!("the canceled connection must close after shutdown: {error_chirho}")
        }
    }
}

#[test]
fn short_inflight_request_still_completes_during_graceful_drain_chirho() {
    let request_entered_chirho = Arc::new(AtomicBool::new(false));
    let router_chirho = Router::new()
        .route(SHORT_REQUEST_PATH_CHIRHO, post(finish_short_request_chirho))
        .with_state(request_entered_chirho.clone());
    let (address_chirho, stop_chirho, completion_rx_chirho, server_handle_chirho) =
        start_server_chirho(router_chirho);
    let (response_tx_chirho, response_rx_chirho) = mpsc::sync_channel(1);

    let client_handle_chirho = std::thread::spawn(move || {
        let mut stream_chirho = TcpStream::connect(address_chirho).unwrap();
        stream_chirho
            .write_all(
                format!(
                    "POST {SHORT_REQUEST_PATH_CHIRHO} HTTP/1.1\r\nHost: {address_chirho}\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx"
                )
                .as_bytes(),
            )
            .unwrap();
        stream_chirho.flush().unwrap();
        let mut response_chirho = String::new();
        stream_chirho.read_to_string(&mut response_chirho).unwrap();
        response_tx_chirho.send(response_chirho).unwrap();
    });

    wait_for_handler_chirho(&request_entered_chirho);
    stop_chirho.store(true, Ordering::SeqCst);
    let response_chirho = response_rx_chirho
        .recv_timeout(Duration::from_secs(2))
        .expect("the short in-flight request must complete during the graceful drain");
    assert!(
        response_chirho.starts_with("HTTP/1.1 200 OK"),
        "normal in-flight work must retain its successful response"
    );
    completion_rx_chirho
        .recv_timeout(Duration::from_secs(2))
        .expect("the server returns after the completed graceful drain")
        .expect("normal graceful shutdown succeeds");
    client_handle_chirho.join().unwrap();
    server_handle_chirho.join().unwrap();
}
