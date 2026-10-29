// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Serves prebuilt review WASM on one exclusively owned component fixture, never a geo topology.

#[path = "transient_review_fixture_chirho/mod_chirho.rs"]
mod fixture_chirho;

#[tokio::main]
async fn main() {
    let args_chirho: Vec<_> = std::env::args_os().skip(1).collect();
    if args_chirho == [std::ffi::OsStr::new("--version")] {
        println!(
            "{}",
            cairn_build_identity_chirho::version_line_chirho!(
                "transient_review_testkind_serve_chirho"
            )
        );
        return;
    }
    if std::env::var("CAIRN_TESTKIND_TRANSIENT_REVIEW_CHIRHO").as_deref() != Ok("1") {
        eprintln!("TransientReviewOptInRequiredChirho");
        std::process::exit(2);
    }
    std::panic::set_hook(Box::new(|_panic_chirho| {
        eprintln!("TransientReviewPanicChirho");
        std::process::exit(1);
    }));
    if fixture_chirho::run_chirho(args_chirho).await.is_err() {
        eprintln!("TransientReviewBridgeRefusedChirho");
        std::process::exit(1);
    }
}
