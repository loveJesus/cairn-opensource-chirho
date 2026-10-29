// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Grouped clap argument payloads for `realtime_args_chirho`.

use std::path::PathBuf;

#[derive(clap::Args)]
pub struct RealtimeOpenArgsChirho {
    #[arg(long = "session")]
    pub session_chirho: String,
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "caller")]
    pub caller_chirho: String,
    #[arg(long = "payer")]
    pub payer_chirho: String,
    #[arg(long = "provider", default_value = "provider/realtime-llm")]
    pub provider_chirho: String,
    #[arg(long = "max-seconds")]
    pub max_seconds_chirho: u64,
    #[arg(long = "token-per-second")]
    pub token_per_second_chirho: i64,
}

#[derive(clap::Args)]
pub struct RealtimeEventArgsChirho {
    #[arg(long = "session")]
    pub session_chirho: String,
    #[arg(long = "kind")]
    pub kind_chirho: String,
    #[arg(long = "payload")]
    pub payload_chirho: String,
}

#[derive(clap::Args)]
pub struct RealtimeTickArgsChirho {
    #[arg(long = "session")]
    pub session_chirho: String,
}

#[derive(clap::Args)]
pub struct RealtimeProviderUsageArgsChirho {
    #[arg(long = "session")]
    pub session_chirho: String,
    #[arg(long = "seconds")]
    pub seconds_chirho: u64,
    #[arg(long = "token")]
    pub token_chirho: i64,
    #[arg(long = "payload")]
    pub payload_chirho: String,
}

#[derive(clap::Args)]
pub struct RealtimeOpenAiUsageImportArgsChirho {
    #[arg(long = "session")]
    pub session_chirho: String,
    #[arg(long = "provider-session")]
    pub provider_session_chirho: String,
    #[arg(long = "receipt-file")]
    pub receipt_file_chirho: PathBuf,
}

#[derive(clap::Args)]
pub struct RealtimeCloseArgsChirho {
    #[arg(long = "session")]
    pub session_chirho: String,
    #[arg(long = "transcript")]
    pub transcript_chirho: String,
    #[arg(long = "reason", default_value = "closed")]
    pub reason_chirho: String,
}

#[derive(clap::Args)]
pub struct RealtimeTranscriptRevealArgsChirho {
    #[arg(long = "session")]
    pub session_chirho: String,
    #[arg(long = "accessed-by")]
    pub accessed_by_chirho: String,
    #[arg(long = "purpose", default_value = "realtime-transcript-reveal-chirho")]
    pub purpose_chirho: String,
}

#[derive(clap::Args)]
pub struct RealtimeSweepArgsChirho {
    #[arg(long = "stale-after-ms")]
    pub stale_after_ms_chirho: u64,
}

#[derive(clap::Args)]
pub struct RealtimeEpilogueArgsChirho {
    #[arg(long = "session")]
    pub session_chirho: String,
    #[arg(long = "dag")]
    pub dag_chirho: Option<String>,
}
