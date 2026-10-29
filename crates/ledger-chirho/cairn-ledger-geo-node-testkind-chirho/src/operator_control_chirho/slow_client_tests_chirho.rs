// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A client slow to write is served, not refused: the operator server reads each accepted stream with its read timeout,
//! because macOS hands an accepted stream the listener's non-blocking flag and Linux does not.

use super::*;

/// The server's accept loop polls every 10 ms, so a client that waits 100 ms after connecting is accepted before it
/// writes a byte. Before the fix the server's read returned at once, the server refused and closed, and this client's
/// set_read_timeout failed with EINVAL on macOS: the flake a Mac gate under load met in
/// `unix_custody_and_all_six_verbs_are_one_live_control_path_chirho`.
///
/// MIGRATION PATH: EINVAL here, or a refused outcome, means accepted streams are non-blocking again on macOS.
#[test]
fn a_client_slow_to_write_is_served_not_refused_chirho() {
    let root_chirho = root_fixture_chirho("slow-client");
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let thread_chirho = start_testkind_cf7_operator_control_with_authority_chirho(
        &root_chirho,
        fake_authority_chirho(),
        Arc::clone(&stop_chirho),
    )
    .unwrap();
    let mut stream_chirho =
        UnixStream::connect(testkind_cf7_operator_socket_path_chirho(&root_chirho)).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    stream_chirho
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("the server keeps the connection open until its client writes");
    let mut request_bytes_chirho =
        serde_json::to_vec(&TestkindCf7OperatorRequestChirho::preview_chirho(
            "credits-demo-chirho".to_owned(),
            "user/0123456789abcdef".to_owned(),
        ))
        .unwrap();
    request_bytes_chirho.push(b'\n');
    stream_chirho.write_all(&request_bytes_chirho).unwrap();
    stream_chirho.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response_bytes_chirho = Vec::new();
    stream_chirho
        .read_to_end(&mut response_bytes_chirho)
        .unwrap();
    let response_chirho: TestkindCf7OperatorResponseChirho = serde_json::from_slice(
        response_bytes_chirho
            .strip_suffix(b"\n")
            .expect("one line of response"),
    )
    .unwrap();
    assert!(
        matches!(
            response_chirho.outcome_chirho,
            TestkindCf7OperatorOutcomeChirho::PreviewChirho { .. }
        ),
        "a slow client gets its preview, not a refusal: {:?}",
        response_chirho.outcome_chirho
    );
    stop_chirho.store(true, Ordering::Release);
    thread_chirho.join().unwrap().unwrap();
    fs::remove_dir_all(root_chirho).unwrap();
}
