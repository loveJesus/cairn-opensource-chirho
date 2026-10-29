// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//! Grouped clap argument payloads for `core_args_chirho`.
use std::path::PathBuf;
#[derive(clap::Args)]
pub struct RunNodeArgsChirho {
    /// Input to double.
    #[arg(default_value_t = 21)]
    pub input_chirho: i64,
}
#[derive(clap::Args)]
pub struct NodeBuildArgsChirho {
    pub wasm_chirho: PathBuf,
    #[arg(long = "name")]
    pub name_chirho: Option<String>,
    #[arg(long = "entry")]
    pub entry_chirho: Option<String>,
    #[arg(long = "fuel", default_value_t = 1_000_000)]
    pub fuel_chirho: u64,
}
#[derive(clap::Args)]
pub struct NodeCheckArgsChirho {
    pub node_chirho: String,
    #[arg(long = "input")]
    pub input_chirho: Option<String>,
}
#[derive(clap::Args)]
pub struct NativeBuildArgsChirho {
    pub executable_chirho: PathBuf,
    #[arg(long = "name")]
    pub name_chirho: Option<String>,
    #[arg(long = "arg")]
    pub argv_chirho: Vec<String>,
    #[arg(long = "abi", default_value = "bytes-stdio-once/v1-chirho")]
    pub abi_chirho: String,
    #[arg(long = "syscall")]
    pub syscalls_chirho: Vec<String>,
    #[arg(long = "cap")]
    pub capabilities_chirho: Vec<String>,
    #[arg(long = "timeout-ms", default_value_t = 1000)]
    pub timeout_ms_chirho: u64,
    #[arg(long = "max-memory-bytes", default_value_t = 268_435_456)]
    pub max_memory_bytes_chirho: u64,
    #[arg(long = "max-input-bytes", default_value_t = 1_048_576)]
    pub max_input_bytes_chirho: usize,
    #[arg(long = "max-output-bytes", default_value_t = 1_048_576)]
    pub max_output_bytes_chirho: usize,
    #[arg(long = "warm-pool-size", default_value_t = 1)]
    pub warm_pool_size_chirho: usize,
    #[arg(long = "allow-unsupported-sandbox")]
    pub allow_unsupported_sandbox_chirho: bool,
}
#[derive(clap::Args)]
pub struct NativeNodeBuildArgsChirho {
    pub spec_chirho: String,
    #[arg(long = "name")]
    pub name_chirho: Option<String>,
}
#[derive(clap::Args)]
pub struct NativeRunArgsChirho {
    pub spec_chirho: String,
    #[arg(long = "input")]
    pub input_chirho: String,
}
#[derive(clap::Args)]
pub struct NativeStatelessAttestArgsChirho {
    pub spec_chirho: String,
    #[arg(long = "probe", default_value = "cairn-stateless-probe-chirho")]
    pub probe_chirho: String,
}
#[derive(clap::Args)]
pub struct NativeBenchArgsChirho {
    #[arg(long = "iterations", default_value_t = 1_000_000)]
    pub iterations_chirho: u64,
    #[arg(long = "samples", default_value_t = 3)]
    pub samples_chirho: usize,
    #[arg(long = "timeout-ms", default_value_t = 30_000)]
    pub timeout_ms_chirho: u64,
    #[arg(long = "allow-unsupported-sandbox")]
    pub allow_unsupported_sandbox_chirho: bool,
    #[arg(long = "assert-native-faster")]
    pub assert_native_faster_chirho: bool,
}
#[derive(clap::Args)]
pub struct DagGraphArgsChirho {
    pub dag_chirho: String,
    #[arg(long = "format")]
    pub format_chirho: Option<String>,
}
#[derive(clap::Args)]
pub struct DagModuleBuildArgsChirho {
    pub dag_chirho: String,
    #[arg(long = "name")]
    pub name_chirho: String,
    #[arg(long = "version", default_value = "v1")]
    pub version_chirho: String,
    #[arg(long = "previous")]
    pub previous_chirho: Option<String>,
    #[arg(long = "input")]
    pub inputs_chirho: Vec<String>,
    #[arg(long = "output")]
    pub outputs_chirho: Vec<String>,
    #[arg(long = "route")]
    pub routes_chirho: Vec<String>,
    #[arg(long = "meta")]
    pub metadata_chirho: Vec<String>,
}
#[derive(clap::Args)]
pub struct DagModuleComposeArgsChirho {
    #[arg(long = "name")]
    pub name_chirho: String,
    #[arg(long = "version", default_value = "v1")]
    pub version_chirho: String,
    #[arg(long = "instance")]
    pub instances_chirho: Vec<String>,
    #[arg(long = "wire")]
    pub wires_chirho: Vec<String>,
    #[arg(long = "input")]
    pub inputs_chirho: Vec<String>,
    #[arg(long = "output")]
    pub outputs_chirho: Vec<String>,
    #[arg(long = "meta")]
    pub metadata_chirho: Vec<String>,
}
#[derive(clap::Args)]
pub struct DagModuleRunArgsChirho {
    pub composition_chirho: String,
    #[arg(long = "input")]
    pub input_chirho: String,
}
#[derive(clap::Args)]
pub struct RuntimePackageBuildArgsChirho {
    pub module_chirho: String,
    #[arg(long = "profile")]
    pub profile_chirho: String,
}
#[derive(clap::Args)]
pub struct RuntimePackageSmokeArgsChirho {
    pub package_chirho: String,
    #[arg(long = "server")]
    pub server_chirho: String,
    #[arg(long = "json")]
    pub json_chirho: bool,
    #[arg(long = "input")]
    pub input_chirho: Option<String>,
    #[arg(long = "expect-output")]
    pub expect_output_chirho: Option<String>,
}
#[derive(clap::Args)]
pub struct DagRunArgsChirho {
    pub dag_chirho: String,
    pub input_chirho: String,
}
#[derive(clap::Args)]
pub struct DagBuildArgsChirho {
    #[arg(long = "node", required = true)]
    pub nodes_chirho: Vec<String>,
    #[arg(long = "edge")]
    pub edges_chirho: Vec<String>,
}
#[derive(clap::Args)]
pub struct RunCacheVerifyArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
}
