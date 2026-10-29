// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//! CLI for the page assembler: `render --layout F --vars V.json [--partials-dir D] --out F`, writing deterministic HTML or failing closed.
//!
//! Vars JSON is one object; each value is either a string or `{"file_chirho": "path"}` read
//! relative to the vars file's directory. Partials are loaded from `--partials-dir`, keyed by
//! file name. Trusted developer input only; no escaping is performed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cairn_pages_chirho::render_chirho;

fn usage_chirho() -> String {
    "usage: cairn-pages-chirho render --layout <file> --vars <vars.json> [--partials-dir <dir>] --out <file>"
        .to_string()
}

fn arg_value_chirho(args_chirho: &[String], flag_chirho: &str) -> Option<String> {
    args_chirho
        .iter()
        .position(|a_chirho| a_chirho == flag_chirho)
        .and_then(|i_chirho| args_chirho.get(i_chirho + 1).cloned())
}

fn load_vars_chirho(vars_path_chirho: &Path) -> Result<BTreeMap<String, String>, String> {
    let raw_chirho = std::fs::read_to_string(vars_path_chirho)
        .map_err(|e_chirho| format!("read vars {}: {e_chirho}", vars_path_chirho.display()))?;
    let parsed_chirho: serde_json::Value = serde_json::from_str(&raw_chirho)
        .map_err(|e_chirho| format!("parse vars {}: {e_chirho}", vars_path_chirho.display()))?;
    let object_chirho = parsed_chirho
        .as_object()
        .ok_or_else(|| "vars JSON must be one object".to_string())?;
    let base_chirho = vars_path_chirho.parent().unwrap_or(Path::new("."));
    let mut vars_chirho = BTreeMap::new();
    for (key_chirho, value_chirho) in object_chirho {
        let rendered_chirho = match value_chirho {
            serde_json::Value::String(s_chirho) => s_chirho.clone(),
            serde_json::Value::Object(map_chirho) => {
                let file_chirho = map_chirho
                    .get("file_chirho")
                    .and_then(|v_chirho| v_chirho.as_str())
                    .ok_or_else(|| {
                        format!("var {key_chirho}: object values need a string file_chirho")
                    })?;
                let path_chirho = base_chirho.join(file_chirho);
                std::fs::read_to_string(&path_chirho).map_err(|e_chirho| {
                    format!("read var file {}: {e_chirho}", path_chirho.display())
                })?
            }
            other_chirho => {
                return Err(format!(
                    "var {key_chirho}: unsupported value type {other_chirho}"
                ))
            }
        };
        vars_chirho.insert(key_chirho.clone(), rendered_chirho);
    }
    Ok(vars_chirho)
}

fn load_partials_chirho(dir_chirho: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut partials_chirho = BTreeMap::new();
    let entries_chirho = std::fs::read_dir(dir_chirho)
        .map_err(|e_chirho| format!("read partials dir {}: {e_chirho}", dir_chirho.display()))?;
    for entry_chirho in entries_chirho {
        let entry_chirho =
            entry_chirho.map_err(|e_chirho| format!("read partials entry: {e_chirho}"))?;
        let path_chirho = entry_chirho.path();
        if !path_chirho.is_file() {
            continue;
        }
        let name_chirho = path_chirho
            .file_name()
            .and_then(|n_chirho| n_chirho.to_str())
            .ok_or_else(|| format!("non-utf8 partial name: {}", path_chirho.display()))?
            .to_string();
        let body_chirho = std::fs::read_to_string(&path_chirho)
            .map_err(|e_chirho| format!("read partial {}: {e_chirho}", path_chirho.display()))?;
        partials_chirho.insert(name_chirho, body_chirho);
    }
    Ok(partials_chirho)
}

fn run_chirho() -> Result<(), String> {
    let args_chirho: Vec<String> = std::env::args().skip(1).collect();
    if args_chirho.first().map(String::as_str) != Some("render") {
        return Err(usage_chirho());
    }
    let layout_chirho =
        PathBuf::from(arg_value_chirho(&args_chirho, "--layout").ok_or_else(usage_chirho)?);
    let vars_path_chirho =
        PathBuf::from(arg_value_chirho(&args_chirho, "--vars").ok_or_else(usage_chirho)?);
    let out_chirho =
        PathBuf::from(arg_value_chirho(&args_chirho, "--out").ok_or_else(usage_chirho)?);
    let template_chirho = std::fs::read_to_string(&layout_chirho)
        .map_err(|e_chirho| format!("read layout {}: {e_chirho}", layout_chirho.display()))?;
    let vars_chirho = load_vars_chirho(&vars_path_chirho)?;
    let partials_chirho = match arg_value_chirho(&args_chirho, "--partials-dir") {
        Some(dir_chirho) => load_partials_chirho(Path::new(&dir_chirho))?,
        None => BTreeMap::new(),
    };
    let rendered_chirho = render_chirho(&template_chirho, &vars_chirho, &partials_chirho)
        .map_err(|e_chirho| format!("render: {e_chirho}"))?;
    std::fs::write(&out_chirho, rendered_chirho)
        .map_err(|e_chirho| format!("write out {}: {e_chirho}", out_chirho.display()))?;
    Ok(())
}

fn main() -> ExitCode {
    match run_chirho() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message_chirho) => {
            eprintln!("cairn-pages-chirho: {message_chirho}");
            ExitCode::FAILURE
        }
    }
}
