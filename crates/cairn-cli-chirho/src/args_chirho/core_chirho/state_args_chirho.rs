// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Grouped clap argument payloads for `state_args_chirho`.

#[derive(clap::Args)]
pub struct RollbackArgsChirho {
    pub branch_chirho: String,
    pub to_chirho: String,
}

#[derive(clap::Args)]
pub struct BranchArgsChirho {
    pub name_chirho: String,
    pub to_chirho: String,
}

#[derive(clap::Args)]
pub struct KvPutArgsChirho {
    pub key_chirho: String,
    pub value_chirho: String,
}

#[derive(clap::Args)]
pub struct KvGetArgsChirho {
    pub key_chirho: String,
    #[arg(long = "at")]
    pub at_chirho: Option<u64>,
}

#[derive(clap::Args)]
pub struct QueryEffectArgsChirho {
    #[arg(long = "caller")]
    pub caller_chirho: String,
    #[arg(long = "prefix")]
    pub prefix_chirho: String,
    #[arg(long = "request-prefix")]
    pub request_prefix_chirho: String,
    #[arg(long = "limit")]
    pub limit_chirho: Option<u64>,
    #[arg(long = "max-rows", default_value_t = 100)]
    pub max_rows_chirho: u64,
}

#[derive(clap::Args)]
pub struct IndexProjectArgsChirho {
    #[arg(long = "at")]
    pub at_chirho: Option<u64>,
}

#[derive(clap::Args)]
pub struct IndexGetArgsChirho {
    pub root_chirho: String,
    pub key_chirho: String,
}

#[derive(clap::Args)]
pub struct IndexProvenanceFindArgsChirho {
    pub root_chirho: String,
    pub state_chirho: String,
}
