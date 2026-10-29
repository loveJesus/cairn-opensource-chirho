// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Std-only dev watch loop for tree-authored apps: poll source metadata, rerun check/build/emit,
//! and report an unreviewed candidate digest without moving refs or touching runtime state.

use cairn_tree_build_chirho::check_chirho::{check_app_tree_with_descriptor_chirho, FindingChirho};
use cairn_tree_build_chirho::emit_chirho::{emit_manifest_chirho, load_app_descriptor_chirho};
use cairn_tree_build_chirho::tree_chirho::walk_app_tree_chirho;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant, UNIX_EPOCH};

const WATCH_CYCLE_SCHEMA_CHIRHO: &str = "tree-build-watch-cycle-v2-chirho";
const DEFAULT_INTERVAL_MS_CHIRHO: u64 = 500;
const MAX_GUEST_BUILD_STDERR_BYTES_CHIRHO: usize = 16_384;

#[derive(Clone, Debug)]
struct WatchOptionsChirho {
    root_chirho: PathBuf,
    interval_chirho: Duration,
    cycles_chirho: Option<usize>,
    json_chirho: bool,
    guest_build_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WatchFingerprintChirho {
    change_fingerprint_chirho: String,
    content_hash_chirho: String,
    entry_count_chirho: usize,
}

#[derive(Clone, Debug, Serialize)]
struct WatchCycleReportChirho {
    schema_chirho: &'static str,
    cycle_chirho: usize,
    changed_chirho: bool,
    clean_chirho: bool,
    status_chirho: String,
    latency_ms_chirho: u128,
    watched_entry_count_chirho: usize,
    check_finding_count_chirho: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    check_findings_chirho: Vec<FindingChirho>,
    guest_build_chirho: GuestBuildReportChirho,
    emitted_manifest_blake3_chirho: Option<String>,
    source_tree_blake3_chirho: String,
    watch_change_fingerprint_chirho: String,
    watch_cycle_fingerprint_chirho: Option<String>,
    preview_chirho: PreviewReportChirho,
}

#[derive(Clone, Debug, Serialize)]
struct GuestBuildReportChirho {
    ran_chirho: bool,
    success_chirho: bool,
    exit_code_chirho: Option<i32>,
    stderr_preview_chirho: String,
}

#[derive(Clone, Debug, Serialize)]
struct PreviewReportChirho {
    label_chirho: &'static str,
    unreviewed_chirho: bool,
    moved_refs_chirho: bool,
    granted_capabilities_chirho: bool,
    source_chirho: &'static str,
}

pub(crate) fn cmd_watch_chirho(args_chirho: &[String]) -> ExitCode {
    let options_chirho = match parse_watch_options_chirho(args_chirho) {
        Ok(options_chirho) => options_chirho,
        Err(error_chirho) => {
            eprintln!("{error_chirho}");
            return ExitCode::from(2);
        }
    };
    let mut stdout_chirho = std::io::stdout();
    match run_watch_loop_chirho(&options_chirho, &mut stdout_chirho) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error_chirho) => {
            eprintln!("tree-build watch: {error_chirho}");
            ExitCode::FAILURE
        }
    }
}

fn parse_watch_options_chirho(args_chirho: &[String]) -> Result<WatchOptionsChirho, String> {
    let mut root_chirho: Option<PathBuf> = None;
    let mut interval_chirho = Duration::from_millis(DEFAULT_INTERVAL_MS_CHIRHO);
    let mut cycles_chirho = None;
    let mut json_chirho = false;
    let mut guest_build_chirho = true;

    let mut i_chirho = 2;
    while i_chirho < args_chirho.len() {
        let arg_chirho = &args_chirho[i_chirho];
        match arg_chirho.as_str() {
            "--json" => {
                json_chirho = true;
                i_chirho += 1;
            }
            "--skip-guest-build" => {
                guest_build_chirho = false;
                i_chirho += 1;
            }
            "--interval-ms" => {
                let value_chirho = args_chirho
                    .get(i_chirho + 1)
                    .ok_or_else(|| "error: --interval-ms requires a value".to_string())?;
                let ms_chirho = value_chirho
                    .parse::<u64>()
                    .map_err(|_e_chirho| "error: --interval-ms must be a u64".to_string())?;
                if ms_chirho == 0 {
                    return Err("error: --interval-ms must be positive".to_string());
                }
                interval_chirho = Duration::from_millis(ms_chirho);
                i_chirho += 2;
            }
            "--cycles" => {
                let value_chirho = args_chirho
                    .get(i_chirho + 1)
                    .ok_or_else(|| "error: --cycles requires a value".to_string())?;
                let cycles_value_chirho = value_chirho.parse::<usize>().map_err(|_e_chirho| {
                    "error: --cycles must be a positive integer".to_string()
                })?;
                if cycles_value_chirho == 0 {
                    return Err("error: --cycles must be positive".to_string());
                }
                cycles_chirho = Some(cycles_value_chirho);
                i_chirho += 2;
            }
            _ if arg_chirho.starts_with('-') => {
                return Err(format!("error: unknown watch flag '{arg_chirho}'"));
            }
            _ if root_chirho.is_none() => {
                root_chirho = Some(PathBuf::from(arg_chirho));
                i_chirho += 1;
            }
            _ => return Err(format!("error: unexpected watch argument '{arg_chirho}'")),
        }
    }

    let root_chirho = root_chirho.ok_or_else(|| {
        "usage: tree-build-chirho watch <app_root> [--interval-ms <ms>] [--cycles <n>] [--json] [--skip-guest-build]"
            .to_string()
    })?;
    Ok(WatchOptionsChirho {
        root_chirho,
        interval_chirho,
        cycles_chirho,
        json_chirho,
        guest_build_chirho,
    })
}

fn run_watch_loop_chirho(
    options_chirho: &WatchOptionsChirho,
    writer_chirho: &mut impl Write,
) -> Result<(), String> {
    let mut fingerprint_chirho = watch_fingerprint_chirho(&options_chirho.root_chirho)?;
    let mut cycle_chirho = 0usize;

    loop {
        cycle_chirho += 1;
        let report_chirho =
            run_watch_cycle_chirho(options_chirho, cycle_chirho, true, &fingerprint_chirho)?;
        write_report_chirho(writer_chirho, options_chirho.json_chirho, &report_chirho)?;
        if options_chirho
            .cycles_chirho
            .is_some_and(|max_chirho| cycle_chirho >= max_chirho)
        {
            return Ok(());
        }
        loop {
            std::thread::sleep(options_chirho.interval_chirho);
            let next_chirho = watch_fingerprint_chirho(&options_chirho.root_chirho)?;
            if next_chirho != fingerprint_chirho {
                fingerprint_chirho = next_chirho;
                break;
            }
        }
    }
}

fn run_watch_cycle_chirho(
    options_chirho: &WatchOptionsChirho,
    cycle_chirho: usize,
    changed_chirho: bool,
    fingerprint_chirho: &WatchFingerprintChirho,
) -> Result<WatchCycleReportChirho, String> {
    let started_chirho = Instant::now();
    let tree_chirho = walk_app_tree_chirho(&options_chirho.root_chirho);
    let descriptor_result_chirho = load_app_descriptor_chirho(&options_chirho.root_chirho);
    let findings_chirho =
        check_app_tree_with_descriptor_chirho(&tree_chirho, descriptor_result_chirho.as_ref().ok());
    let mut guest_build_report_chirho = GuestBuildReportChirho {
        ran_chirho: false,
        success_chirho: true,
        exit_code_chirho: None,
        stderr_preview_chirho: String::new(),
    };
    let mut manifest_hash_chirho = None;
    let mut watch_cycle_fingerprint_chirho = None;
    let mut status_chirho = "clean".to_string();

    if !findings_chirho.is_empty() {
        status_chirho = "check-failed-chirho".to_string();
    } else {
        if options_chirho.guest_build_chirho {
            guest_build_report_chirho = run_guest_build_chirho(&options_chirho.root_chirho)?;
            if !guest_build_report_chirho.success_chirho {
                status_chirho = "guest-build-failed-chirho".to_string();
            }
        }
        if status_chirho == "clean" {
            let descriptor_chirho = descriptor_result_chirho?;
            let manifest_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho)?;
            let manifest_bytes_chirho = serde_json::to_vec_pretty(&manifest_chirho)
                .map_err(|e_chirho| e_chirho.to_string())?;
            let manifest_hash_value_chirho =
                blake3::hash(&manifest_bytes_chirho).to_hex().to_string();
            let mut cycle_hasher_chirho = blake3::Hasher::new();
            cycle_hasher_chirho.update(b"tree-build-watch-cycle-v2-chirho\n");
            cycle_hasher_chirho.update(manifest_hash_value_chirho.as_bytes());
            cycle_hasher_chirho.update(b"\n");
            cycle_hasher_chirho.update(fingerprint_chirho.change_fingerprint_chirho.as_bytes());
            manifest_hash_chirho = Some(manifest_hash_value_chirho);
            watch_cycle_fingerprint_chirho =
                Some(cycle_hasher_chirho.finalize().to_hex().to_string());
        }
    }

    Ok(WatchCycleReportChirho {
        schema_chirho: WATCH_CYCLE_SCHEMA_CHIRHO,
        cycle_chirho,
        changed_chirho,
        clean_chirho: status_chirho == "clean",
        status_chirho,
        latency_ms_chirho: started_chirho.elapsed().as_millis(),
        watched_entry_count_chirho: fingerprint_chirho.entry_count_chirho,
        check_finding_count_chirho: findings_chirho.len(),
        check_findings_chirho: findings_chirho,
        guest_build_chirho: guest_build_report_chirho,
        emitted_manifest_blake3_chirho: manifest_hash_chirho,
        source_tree_blake3_chirho: fingerprint_chirho.content_hash_chirho.clone(),
        watch_change_fingerprint_chirho: fingerprint_chirho.change_fingerprint_chirho.clone(),
        watch_cycle_fingerprint_chirho,
        preview_chirho: PreviewReportChirho {
            label_chirho: "unreviewed-candidate-preview-chirho",
            unreviewed_chirho: true,
            moved_refs_chirho: false,
            granted_capabilities_chirho: false,
            source_chirho: "emitted-manifest-plus-source-tree-digest-chirho",
        },
    })
}

fn run_guest_build_chirho(root_chirho: &Path) -> Result<GuestBuildReportChirho, String> {
    let output_chirho = Command::new("cargo")
        .arg("build")
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--examples")
        .arg("--message-format")
        .arg("short")
        .current_dir(root_chirho)
        .output()
        .map_err(|error_chirho| format!("run guest cargo build: {error_chirho}"))?;
    Ok(GuestBuildReportChirho {
        ran_chirho: true,
        success_chirho: output_chirho.status.success(),
        exit_code_chirho: output_chirho.status.code(),
        stderr_preview_chirho: bounded_stderr_chirho(&output_chirho.stderr),
    })
}

fn bounded_stderr_chirho(stderr_chirho: &[u8]) -> String {
    let text_chirho = String::from_utf8_lossy(stderr_chirho);
    text_chirho
        .chars()
        .take(MAX_GUEST_BUILD_STDERR_BYTES_CHIRHO)
        .collect()
}

fn write_report_chirho(
    writer_chirho: &mut impl Write,
    json_chirho: bool,
    report_chirho: &WatchCycleReportChirho,
) -> Result<(), String> {
    if json_chirho {
        serde_json::to_writer(&mut *writer_chirho, report_chirho)
            .map_err(|e_chirho| e_chirho.to_string())?;
        writeln!(writer_chirho).map_err(|e_chirho| e_chirho.to_string())?;
        return Ok(());
    }
    writeln!(
        writer_chirho,
        "watch-cycle {} status={} changed={} latency_ms={} watch_cycle={} manifest={} source_tree={} preview={}",
        report_chirho.cycle_chirho,
        report_chirho.status_chirho,
        report_chirho.changed_chirho,
        report_chirho.latency_ms_chirho,
        report_chirho
            .watch_cycle_fingerprint_chirho
            .as_deref()
            .unwrap_or("(none)"),
        report_chirho
            .emitted_manifest_blake3_chirho
            .as_deref()
            .unwrap_or("(none)"),
        report_chirho.source_tree_blake3_chirho,
        report_chirho.preview_chirho.label_chirho,
    )
    .map_err(|e_chirho| e_chirho.to_string())
}

fn watch_fingerprint_chirho(root_chirho: &Path) -> Result<WatchFingerprintChirho, String> {
    let mut entries_chirho = Vec::new();
    collect_watch_entries_chirho(root_chirho, root_chirho, &mut entries_chirho)?;
    entries_chirho.sort();
    let mut change_hasher_chirho = blake3::Hasher::new();
    let mut content_hasher_chirho = blake3::Hasher::new();
    for entry_chirho in &entries_chirho {
        change_hasher_chirho.update(entry_chirho.change_line_chirho.as_bytes());
        change_hasher_chirho.update(b"\n");
        content_hasher_chirho.update(entry_chirho.content_line_chirho.as_bytes());
        content_hasher_chirho.update(b"\n");
    }
    Ok(WatchFingerprintChirho {
        change_fingerprint_chirho: change_hasher_chirho.finalize().to_hex().to_string(),
        content_hash_chirho: content_hasher_chirho.finalize().to_hex().to_string(),
        entry_count_chirho: entries_chirho.len(),
    })
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct WatchEntryChirho {
    change_line_chirho: String,
    content_line_chirho: String,
}

fn collect_watch_entries_chirho(
    root_chirho: &Path,
    dir_chirho: &Path,
    entries_chirho: &mut Vec<WatchEntryChirho>,
) -> Result<(), String> {
    let read_dir_chirho = std::fs::read_dir(dir_chirho)
        .map_err(|error_chirho| format!("read {}: {error_chirho}", dir_chirho.display()))?;
    for entry_chirho in read_dir_chirho {
        let entry_chirho =
            entry_chirho.map_err(|error_chirho| format!("read dir entry: {error_chirho}"))?;
        let path_chirho = entry_chirho.path();
        let name_chirho = path_chirho
            .file_name()
            .and_then(|name_chirho| name_chirho.to_str())
            .unwrap_or("");
        if should_skip_watch_entry_chirho(name_chirho) {
            continue;
        }
        let metadata_chirho = std::fs::symlink_metadata(&path_chirho).map_err(|error_chirho| {
            format!("metadata {}: {error_chirho}", path_chirho.display())
        })?;
        let relative_chirho = path_chirho
            .strip_prefix(root_chirho)
            .unwrap_or(&path_chirho)
            .to_string_lossy()
            .replace('\\', "/");
        let modified_ns_chirho = metadata_chirho
            .modified()
            .ok()
            .and_then(|time_chirho| time_chirho.duration_since(UNIX_EPOCH).ok())
            .map(|duration_chirho| duration_chirho.as_nanos())
            .unwrap_or(0);
        let file_kind_chirho = file_kind_chirho(&metadata_chirho);
        let mut change_line_chirho = format!(
            "{}\t{}\t{}\t{}",
            relative_chirho,
            metadata_chirho.len(),
            modified_ns_chirho,
            file_kind_chirho
        );
        let mut content_line_chirho = format!("{}\t{}", relative_chirho, file_kind_chirho);
        if metadata_chirho.file_type().is_symlink() {
            if let Ok(target_chirho) = std::fs::read_link(&path_chirho) {
                let target_text_chirho = target_chirho.to_string_lossy();
                change_line_chirho.push('\t');
                change_line_chirho.push_str(&target_text_chirho);
                content_line_chirho.push('\t');
                content_line_chirho.push_str(&target_text_chirho);
            }
        } else if metadata_chirho.is_file() {
            let bytes_chirho = std::fs::read(&path_chirho).map_err(|error_chirho| {
                format!("read {}: {error_chirho}", path_chirho.display())
            })?;
            let bytes_hash_chirho = blake3::hash(&bytes_chirho).to_hex().to_string();
            change_line_chirho.push('\t');
            change_line_chirho.push_str(&bytes_hash_chirho);
            content_line_chirho.push('\t');
            content_line_chirho.push_str(&bytes_hash_chirho);
        }
        entries_chirho.push(WatchEntryChirho {
            change_line_chirho,
            content_line_chirho,
        });
        if metadata_chirho.is_dir() {
            collect_watch_entries_chirho(root_chirho, &path_chirho, entries_chirho)?;
        }
    }
    Ok(())
}

fn should_skip_watch_entry_chirho(name_chirho: &str) -> bool {
    matches!(
        name_chirho,
        ".git" | "target" | "node_modules" | ".cairn-chirho" | ".DS_Store"
    )
}

fn file_kind_chirho(metadata_chirho: &std::fs::Metadata) -> &'static str {
    if metadata_chirho.file_type().is_symlink() {
        "symlink-chirho"
    } else if metadata_chirho.is_dir() {
        "dir-chirho"
    } else if metadata_chirho.is_file() {
        "file-chirho"
    } else {
        "other-chirho"
    }
}
