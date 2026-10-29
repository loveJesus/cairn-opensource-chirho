// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! `tree-build-chirho` — the porcelain CLI over the directory-structure-IS-DAG toolchain:
//! ```text
//!   check    [--json] <app_root>                                   # fail-closed checker
//!   test     [--json] <app_root>                                   # run pure node fixtures
//!   emit     <app_root>                                            # emit the app-source manifest
//!   watch    <app_root> [--interval-ms <ms>] [--cycles <n>] [--json] [--skip-guest-build]
//!   authoring-context --json --output <json>                       # emit advisory generation context
//!   source-platform-smoke --json [--cairn-cli <path>]              # SP13 guide-as-golden smoke
//!   copy-lint <html_file> --policy <toml> --route-kind <kind>       # lint rendered HTML copy
//!   source-dictionary <app_root> --json <json> --value-type <type> --const <CONST> --function <fn> --output <rs>
//!   template-render <app_root> --template <html> --model-type <type> --template-struct <Name> --function <fn> --output <rs>
//!   template-guest  <app_root> --model-type <type> --render-function <path> --entry <fn> --output <rs>
//!   style-compile <app_root> --style <scss/css> ... --output <css>
//!   new      <template> <app_root> [--sdk-dep-mode <path|git>] [--sdk-git-rev <rev>] # scaffold a starter app tree
//!   dag-new  <app_root> <dag> --in name:type ... --out name:type ...
//!   node-add <app_root> <dag> <role> --in name:type ... --out name:type ... [--impl module]
//!   blessed-add <app_root> <dag> <role> <contract> --scope value --intent text --in name:type ... --out name:type ...
//!   wire     <app_root> <dag> <from owner:port> <to owner:port>    # owner is `surface` or a role
//! ```

use std::io::Write;

use cairn_tree_build_chirho::authoring_context_chirho::write_authoring_context_chirho;
use cairn_tree_build_chirho::check_chirho::{
    check_app_tree_with_descriptor_chirho, check_report_chirho,
};
use cairn_tree_build_chirho::copy_lint_chirho::{
    lint_rendered_html_copy_chirho, load_rendered_copy_lint_policy_chirho,
    route_kind_disposition_chirho, RenderedCopyLintRouteDispositionChirho,
};
use cairn_tree_build_chirho::emit_chirho::{
    emit_manifest_bytes_chirho, load_app_descriptor_chirho,
};
use cairn_tree_build_chirho::node_test_chirho::node_test_report_chirho;
use cairn_tree_build_chirho::scaffold_chirho::{
    blessed_add_chirho, dag_new_chirho, new_app_chirho, node_add_chirho, parse_port_spec_chirho,
    wire_chirho, BlessedNodeSpecChirho, PortSpecChirho,
};
use cairn_tree_build_chirho::source_dictionary_chirho::{
    write_source_dictionary_source_chirho, SourceDictionarySpecChirho,
};
use cairn_tree_build_chirho::style_compile_chirho::compile_style_sources_chirho;
use cairn_tree_build_chirho::template_codegen_chirho::{
    write_askama_render_source_chirho, write_template_guest_source_chirho, TemplateGuestSpecChirho,
    TemplateRenderSpecChirho,
};
use cairn_tree_build_chirho::tree_chirho::walk_app_tree_chirho;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

#[path = "tree_build_chirho/source_platform_smoke_chirho.rs"]
mod source_platform_smoke_chirho;
#[path = "tree_build_chirho/watch_chirho.rs"]
mod watch_chirho;

const HELP_TEXT_CHIRHO: &str = "\
usage: tree-build-chirho <command> ...

Commands:
  check [--json] <app_root>
  test [--json] <app_root>
  emit <app_root>
  watch <app_root> [--interval-ms <ms>] [--cycles <n>] [--json] [--skip-guest-build]
  authoring-context --json --output <json>
  source-platform-smoke --json [--cairn-cli <path>]
  copy-lint <html_file> --policy <toml> --route-kind <kind>
  source-dictionary <app_root> --json <json> --value-type <type> --const <CONST> --function <fn> --output <rs>
  template-render <app_root> --template <html> --model-type <type> --template-struct <Name> --function <fn> --output <rs>
  template-guest <app_root> --model-type <type> --render-function <path> --entry <fn> --output <rs>
  style-compile <app_root> --style <scss/css> ... --output <css>
  new <template> <app_root> [--sdk-dep-mode <path|git>] [--sdk-git-rev <rev>]
  dag-new <app_root> <dag> --in name:type ... --out name:type ...
  node-add <app_root> <dag> <role> --in name:type ... --out name:type ... [--impl module]
  blessed-add <app_root> <dag> <role> <contract> --scope value --intent text --in name:type ... --out name:type ... [--caller value] [--max-rows n] [--max-tokens n] [--max-price-per-token n]
  wire <app_root> <dag> <from owner:port> <to owner:port>
";

fn main() -> ExitCode {
    let args_chirho: Vec<String> = std::env::args().collect();
    match args_chirho.get(1).map(String::as_str) {
        Some("--help") | Some("-h") | Some("help") => {
            println!("{HELP_TEXT_CHIRHO}");
            ExitCode::SUCCESS
        }
        Some("check") => cmd_check_chirho(&args_chirho),
        Some("test") => cmd_test_chirho(&args_chirho),
        Some("emit") => cmd_emit_chirho(&args_chirho),
        Some("watch") => watch_chirho::cmd_watch_chirho(&args_chirho),
        Some("authoring-context") => cmd_authoring_context_chirho(&args_chirho),
        Some("source-platform-smoke") => {
            source_platform_smoke_chirho::cmd_source_platform_smoke_chirho(&args_chirho)
        }
        Some("copy-lint") => cmd_copy_lint_chirho(&args_chirho),
        Some("source-dictionary") => cmd_source_dictionary_chirho(&args_chirho),
        Some("template-render") => cmd_template_render_chirho(&args_chirho),
        Some("template-guest") => cmd_template_guest_chirho(&args_chirho),
        Some("style-compile") => cmd_style_compile_chirho(&args_chirho),
        Some("new") => cmd_new_chirho(&args_chirho),
        Some("dag-new") => cmd_dag_new_chirho(&args_chirho),
        Some("node-add") => cmd_node_add_chirho(&args_chirho),
        Some("blessed-add") => cmd_blessed_add_chirho(&args_chirho),
        Some("wire") => cmd_wire_chirho(&args_chirho),
        _ => {
            eprintln!("{}", HELP_TEXT_CHIRHO.trim_end());
            ExitCode::from(2)
        }
    }
}

fn cmd_new_chirho(args_chirho: &[String]) -> ExitCode {
    let mut template_chirho = None;
    let mut root_chirho = None;
    let mut sdk_dep_mode_chirho = "path".to_string();
    let mut sdk_git_rev_chirho = None;

    let mut i_chirho = 2;
    while i_chirho < args_chirho.len() {
        let arg_chirho = &args_chirho[i_chirho];
        if arg_chirho == "--sdk-dep-mode" {
            if let Some(val_chirho) = args_chirho.get(i_chirho + 1) {
                sdk_dep_mode_chirho = val_chirho.clone();
                i_chirho += 2;
            } else {
                eprintln!("error: --sdk-dep-mode requires a value (path or git)");
                return ExitCode::from(2);
            }
        } else if arg_chirho == "--sdk-git-rev" {
            if let Some(val_chirho) = args_chirho.get(i_chirho + 1) {
                sdk_git_rev_chirho = Some(val_chirho.clone());
                i_chirho += 2;
            } else {
                eprintln!("error: --sdk-git-rev requires a value");
                return ExitCode::from(2);
            }
        } else if arg_chirho.starts_with('-') {
            eprintln!("error: unknown flag '{arg_chirho}'");
            return ExitCode::from(2);
        } else if template_chirho.is_none() {
            template_chirho = Some(arg_chirho.clone());
            i_chirho += 1;
        } else if root_chirho.is_none() {
            root_chirho = Some(arg_chirho.clone());
            i_chirho += 1;
        } else {
            eprintln!("error: unexpected argument '{arg_chirho}'");
            return ExitCode::from(2);
        }
    }

    let (Some(template_chirho), Some(root_chirho)) = (template_chirho, root_chirho) else {
        eprintln!("usage: tree-build-chirho new <template> <app_root> [--sdk-dep-mode <path|git>] [--sdk-git-rev <rev>]");
        return ExitCode::from(2);
    };

    if sdk_dep_mode_chirho != "path" && sdk_dep_mode_chirho != "git" {
        eprintln!("error: --sdk-dep-mode must be 'path' or 'git'");
        return ExitCode::from(2);
    }
    if sdk_dep_mode_chirho == "git" && sdk_git_rev_chirho.is_none() {
        eprintln!("error: --sdk-dep-mode git requires --sdk-git-rev <rev>");
        return ExitCode::from(2);
    }

    let result_chirho = new_app_chirho(
        Path::new(&root_chirho),
        &template_chirho,
        &sdk_dep_mode_chirho,
        sdk_git_rev_chirho.as_deref(),
    );
    report_chirho(result_chirho)
}

/// Collect every value following each occurrence of `flag` (so `--in a --in b` -> [a, b]).
fn collect_flag_chirho(args_chirho: &[String], flag_chirho: &str) -> Vec<String> {
    let mut out_chirho = Vec::new();
    let mut i_chirho = 0;
    while i_chirho < args_chirho.len() {
        if args_chirho[i_chirho] == flag_chirho {
            if let Some(value_chirho) = args_chirho.get(i_chirho + 1) {
                out_chirho.push(value_chirho.clone());
            }
            i_chirho += 2;
        } else {
            i_chirho += 1;
        }
    }
    out_chirho
}

fn one_flag_chirho(args_chirho: &[String], flag_chirho: &str) -> Option<String> {
    collect_flag_chirho(args_chirho, flag_chirho)
        .into_iter()
        .next()
}

fn parse_ports_chirho(specs_chirho: &[String]) -> Result<Vec<PortSpecChirho>, String> {
    specs_chirho
        .iter()
        .map(|s_chirho| parse_port_spec_chirho(s_chirho))
        .collect()
}

fn report_chirho(result_chirho: Result<String, String>) -> ExitCode {
    match result_chirho {
        Ok(message_chirho) => {
            println!("{message_chirho}");
            ExitCode::SUCCESS
        }
        Err(error_chirho) => {
            eprintln!("error: {error_chirho}");
            ExitCode::FAILURE
        }
    }
}

fn command_root_and_json_chirho<'a>(
    args_chirho: &'a [String],
    command_chirho: &str,
) -> Result<(&'a str, bool), String> {
    let mut root_chirho: Option<&str> = None;
    let mut json_chirho = false;
    for arg_chirho in args_chirho.iter().skip(2) {
        if arg_chirho == "--json" {
            json_chirho = true;
        } else if root_chirho.is_none() {
            root_chirho = Some(arg_chirho.as_str());
        } else {
            return Err(format!(
                "unexpected extra {command_chirho} argument: {arg_chirho}"
            ));
        }
    }
    root_chirho
        .map(|root_chirho| (root_chirho, json_chirho))
        .ok_or_else(|| format!("usage: tree-build-chirho {command_chirho} [--json] <app_root>"))
}

fn cmd_check_chirho(args_chirho: &[String]) -> ExitCode {
    let (root_chirho, json_chirho) = match command_root_and_json_chirho(args_chirho, "check") {
        Ok(parsed_chirho) => parsed_chirho,
        Err(error_chirho) => {
            eprintln!("{error_chirho}");
            return ExitCode::from(2);
        }
    };
    let app_root_chirho = Path::new(root_chirho);
    let tree_chirho = walk_app_tree_chirho(app_root_chirho);
    let descriptor_chirho = load_app_descriptor_chirho(app_root_chirho).ok();
    let findings_chirho =
        check_app_tree_with_descriptor_chirho(&tree_chirho, descriptor_chirho.as_ref());
    if json_chirho {
        let clean_chirho = findings_chirho.is_empty();
        println!(
            "{}",
            serde_json::to_string_pretty(&check_report_chirho(findings_chirho)).unwrap()
        );
        return if clean_chirho {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    if findings_chirho.is_empty() {
        println!("dag-check: clean");
        ExitCode::SUCCESS
    } else {
        for finding_chirho in &findings_chirho {
            eprintln!(
                "[{}] {}\n  where: {}\n  expected: {}\n  found: {}\n  hint: {}",
                finding_chirho.code_chirho,
                finding_chirho.message_chirho,
                finding_chirho.where_chirho,
                finding_chirho.expected_chirho,
                finding_chirho.found_chirho,
                finding_chirho.hint_chirho
            );
        }
        eprintln!("dag-check: {} finding(s)", findings_chirho.len());
        ExitCode::FAILURE
    }
}

fn cmd_test_chirho(args_chirho: &[String]) -> ExitCode {
    let (root_chirho, json_chirho) = match command_root_and_json_chirho(args_chirho, "test") {
        Ok(parsed_chirho) => parsed_chirho,
        Err(error_chirho) => {
            eprintln!("{error_chirho}");
            return ExitCode::from(2);
        }
    };
    let report_chirho = node_test_report_chirho(Path::new(root_chirho));
    if json_chirho {
        let clean_chirho = report_chirho.clean_chirho;
        println!("{}", serde_json::to_string_pretty(&report_chirho).unwrap());
        return if clean_chirho {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    if report_chirho.clean_chirho {
        println!(
            "node-test: clean ({} fixture(s))",
            report_chirho.fixture_count_chirho
        );
        ExitCode::SUCCESS
    } else {
        for failure_chirho in &report_chirho.failures_chirho {
            eprintln!(
                "[{}] {}\n  node: {}\n  fixture: {}\n  path: {}\n  expected-hash: {}\n  actual-hash: {}\n  first-diff: {}",
                failure_chirho.code_chirho,
                failure_chirho.message_chirho,
                failure_chirho.node_chirho,
                failure_chirho.fixture_chirho,
                failure_chirho.fixture_path_chirho,
                failure_chirho
                    .expected_hash_chirho
                    .as_deref()
                    .unwrap_or("(none)"),
                failure_chirho
                    .actual_hash_chirho
                    .as_deref()
                    .unwrap_or("(none)"),
                failure_chirho
                    .first_diff_chirho
                    .as_deref()
                    .unwrap_or("(none)")
            );
        }
        eprintln!(
            "node-test: {} failure(s)",
            report_chirho.failures_chirho.len()
        );
        ExitCode::FAILURE
    }
}

fn cmd_emit_chirho(args_chirho: &[String]) -> ExitCode {
    let Some(root_chirho) = args_chirho.get(2) else {
        eprintln!("usage: tree-build-chirho emit <app_root>");
        return ExitCode::from(2);
    };
    let app_root_chirho = Path::new(root_chirho);
    let tree_chirho = walk_app_tree_chirho(app_root_chirho);
    let descriptor_chirho = match load_app_descriptor_chirho(app_root_chirho) {
        Ok(descriptor_chirho) => descriptor_chirho,
        Err(error_chirho) => {
            eprintln!("tree-build emit: {error_chirho}");
            return ExitCode::FAILURE;
        }
    };
    match emit_manifest_bytes_chirho(&tree_chirho, &descriptor_chirho) {
        Ok(manifest_bytes_chirho) => {
            // Byte-exact stdout: the helper already appends the terminal newline, so write the
            // bytes directly (no extra println newline) to keep the RAW emit hash reproducible.
            match std::io::stdout().write_all(&manifest_bytes_chirho) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error_chirho) => {
                    eprintln!("tree-build emit: {error_chirho}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(error_chirho) => {
            eprintln!("tree-build emit: {error_chirho}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_authoring_context_chirho(args_chirho: &[String]) -> ExitCode {
    let mut json_chirho = false;
    let mut output_chirho: Option<String> = None;
    let mut i_chirho = 2;
    while i_chirho < args_chirho.len() {
        match args_chirho[i_chirho].as_str() {
            "--json" => {
                json_chirho = true;
                i_chirho += 1;
            }
            "--output" => {
                let Some(value_chirho) = args_chirho.get(i_chirho + 1) else {
                    eprintln!("error: authoring-context requires --output <json>");
                    return ExitCode::from(2);
                };
                output_chirho = Some(value_chirho.clone());
                i_chirho += 2;
            }
            other_chirho => {
                eprintln!("error: unexpected authoring-context argument '{other_chirho}'");
                return ExitCode::from(2);
            }
        }
    }
    if !json_chirho {
        eprintln!("error: authoring-context requires --json");
        return ExitCode::from(2);
    }
    let Some(output_chirho) = output_chirho else {
        eprintln!("usage: tree-build-chirho authoring-context --json --output <json>");
        return ExitCode::from(2);
    };
    match write_authoring_context_chirho(Path::new(&output_chirho)) {
        Ok(report_chirho) => {
            println!("{}", serde_json::to_string_pretty(&report_chirho).unwrap());
            ExitCode::SUCCESS
        }
        Err(error_chirho) => {
            eprintln!("tree-build authoring-context: {error_chirho}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_copy_lint_chirho(args_chirho: &[String]) -> ExitCode {
    let Some(html_file_chirho) = args_chirho.get(2) else {
        eprintln!(
            "usage: tree-build-chirho copy-lint <html_file> --policy <policy_toml> --route-kind <kind>"
        );
        return ExitCode::from(2);
    };
    let Some(policy_chirho) = one_flag_chirho(args_chirho, "--policy") else {
        eprintln!("error: copy-lint requires --policy <policy_toml>");
        return ExitCode::from(2);
    };
    let Some(route_kind_chirho) = one_flag_chirho(args_chirho, "--route-kind") else {
        eprintln!("error: copy-lint requires --route-kind <kind>");
        return ExitCode::from(2);
    };
    let html_chirho = match std::fs::read_to_string(html_file_chirho) {
        Ok(html_chirho) => html_chirho,
        Err(error_chirho) => {
            eprintln!("tree-build copy-lint: read rendered HTML: {error_chirho}");
            return ExitCode::FAILURE;
        }
    };
    let policy_chirho = match load_rendered_copy_lint_policy_chirho(Path::new(&policy_chirho)) {
        Ok(policy_chirho) => policy_chirho,
        Err(error_chirho) => {
            eprintln!("tree-build copy-lint: {error_chirho}");
            return ExitCode::FAILURE;
        }
    };
    match route_kind_disposition_chirho(&policy_chirho, &route_kind_chirho) {
        RenderedCopyLintRouteDispositionChirho::LintChirho => {}
        RenderedCopyLintRouteDispositionChirho::SkipChirho => {
            println!("rendered-copy-lint: clean");
            return ExitCode::SUCCESS;
        }
        RenderedCopyLintRouteDispositionChirho::UnknownChirho => {
            eprintln!(
                "tree-build copy-lint: unknown route kind '{route_kind_chirho}'; add it to public_route_kinds_chirho, technical_route_kinds_chirho, or unlinted_route_kinds_chirho"
            );
            return ExitCode::FAILURE;
        }
    }
    let findings_chirho =
        lint_rendered_html_copy_chirho(&html_chirho, &route_kind_chirho, &policy_chirho);
    if findings_chirho.is_empty() {
        println!("rendered-copy-lint: clean");
        return ExitCode::SUCCESS;
    }
    for finding_chirho in &findings_chirho {
        eprintln!(
            "[{}] {}\n  route-kind: {}\n  term: {}\n  category: {}\n  visible: {}\n  hint: {}",
            finding_chirho.code_chirho,
            finding_chirho.message_chirho,
            finding_chirho.route_kind_chirho,
            finding_chirho.term_chirho,
            finding_chirho
                .category_chirho
                .as_deref()
                .unwrap_or("(uncategorized)"),
            finding_chirho.snippet_chirho,
            finding_chirho.hint_chirho
        );
    }
    eprintln!("rendered-copy-lint: {} finding(s)", findings_chirho.len());
    ExitCode::FAILURE
}

fn cmd_source_dictionary_chirho(args_chirho: &[String]) -> ExitCode {
    let Some(root_chirho) = args_chirho.get(2) else {
        eprintln!(
            "usage: tree-build-chirho source-dictionary <app_root> --json <dictionary_json> --value-type <type> --const <CONST_CHIRHO> --function <fn_chirho> --output <generated_rs>"
        );
        return ExitCode::from(2);
    };
    let Some(dictionary_chirho) = one_flag_chirho(args_chirho, "--json") else {
        eprintln!("error: source-dictionary requires --json <dictionary_json>");
        return ExitCode::from(2);
    };
    let Some(value_type_chirho) = one_flag_chirho(args_chirho, "--value-type") else {
        eprintln!("error: source-dictionary requires --value-type <type>");
        return ExitCode::from(2);
    };
    let Some(const_name_chirho) = one_flag_chirho(args_chirho, "--const") else {
        eprintln!("error: source-dictionary requires --const <CONST_CHIRHO>");
        return ExitCode::from(2);
    };
    let Some(function_name_chirho) = one_flag_chirho(args_chirho, "--function") else {
        eprintln!("error: source-dictionary requires --function <fn_chirho>");
        return ExitCode::from(2);
    };
    let Some(output_chirho) = one_flag_chirho(args_chirho, "--output") else {
        eprintln!("error: source-dictionary requires --output <generated_rs>");
        return ExitCode::from(2);
    };
    let result_chirho = write_source_dictionary_source_chirho(
        Path::new(root_chirho),
        &SourceDictionarySpecChirho {
            dictionary_path_chirho: PathBuf::from(dictionary_chirho),
            value_type_chirho,
            const_name_chirho,
            function_name_chirho,
        },
        Path::new(&output_chirho),
    )
    .map(|()| format!("source-dictionary: wrote {output_chirho}"));
    report_chirho(result_chirho)
}

fn cmd_template_render_chirho(args_chirho: &[String]) -> ExitCode {
    let Some(root_chirho) = args_chirho.get(2) else {
        eprintln!(
            "usage: tree-build-chirho template-render <app_root> --template <html> --model-type <type> --template-struct <NameChirho> --function <render_fn_chirho> --output <generated_rs>"
        );
        return ExitCode::from(2);
    };
    let Some(template_chirho) = one_flag_chirho(args_chirho, "--template") else {
        eprintln!("error: template-render requires --template <html>");
        return ExitCode::from(2);
    };
    let Some(model_type_chirho) = one_flag_chirho(args_chirho, "--model-type") else {
        eprintln!("error: template-render requires --model-type <type>");
        return ExitCode::from(2);
    };
    let Some(template_struct_chirho) = one_flag_chirho(args_chirho, "--template-struct") else {
        eprintln!("error: template-render requires --template-struct <NameChirho>");
        return ExitCode::from(2);
    };
    let Some(render_function_chirho) = one_flag_chirho(args_chirho, "--function") else {
        eprintln!("error: template-render requires --function <render_fn_chirho>");
        return ExitCode::from(2);
    };
    let Some(output_chirho) = one_flag_chirho(args_chirho, "--output") else {
        eprintln!("error: template-render requires --output <generated_rs>");
        return ExitCode::from(2);
    };
    let result_chirho = write_askama_render_source_chirho(
        Path::new(root_chirho),
        &TemplateRenderSpecChirho {
            template_path_chirho: PathBuf::from(template_chirho),
            model_type_chirho,
            template_struct_chirho,
            render_function_chirho,
        },
        Path::new(&output_chirho),
    )
    .map(|()| format!("template-render: wrote {output_chirho}"));
    report_chirho(result_chirho)
}

fn cmd_style_compile_chirho(args_chirho: &[String]) -> ExitCode {
    let Some(root_chirho) = args_chirho.get(2) else {
        eprintln!("usage: tree-build-chirho style-compile <app_root> --style <scss/css> ... --output <css>");
        return ExitCode::from(2);
    };
    let styles_chirho: Vec<PathBuf> = collect_flag_chirho(args_chirho, "--style")
        .into_iter()
        .map(PathBuf::from)
        .collect();
    let Some(output_chirho) = one_flag_chirho(args_chirho, "--output") else {
        eprintln!("error: style-compile requires --output <css>");
        return ExitCode::from(2);
    };
    let result_chirho = compile_style_sources_chirho(
        Path::new(root_chirho),
        &styles_chirho,
        Path::new(&output_chirho),
    )
    .map(|report_chirho| {
        format!(
            "style-compile: wrote {} from {} source(s), {} byte(s)",
            report_chirho.output_path_chirho.display(),
            report_chirho.input_count_chirho,
            report_chirho.css_bytes_chirho
        )
    });
    report_chirho(result_chirho)
}

fn cmd_template_guest_chirho(args_chirho: &[String]) -> ExitCode {
    let Some(root_chirho) = args_chirho.get(2) else {
        eprintln!(
            "usage: tree-build-chirho template-guest <app_root> --model-type <type> --render-function <path> --entry <entry_fn_chirho> --output <guest_rs>"
        );
        return ExitCode::from(2);
    };
    let Some(model_type_chirho) = one_flag_chirho(args_chirho, "--model-type") else {
        eprintln!("error: template-guest requires --model-type <type>");
        return ExitCode::from(2);
    };
    let Some(render_function_path_chirho) = one_flag_chirho(args_chirho, "--render-function")
    else {
        eprintln!("error: template-guest requires --render-function <path>");
        return ExitCode::from(2);
    };
    let Some(entry_function_chirho) = one_flag_chirho(args_chirho, "--entry") else {
        eprintln!("error: template-guest requires --entry <entry_fn_chirho>");
        return ExitCode::from(2);
    };
    let Some(output_chirho) = one_flag_chirho(args_chirho, "--output") else {
        eprintln!("error: template-guest requires --output <guest_rs>");
        return ExitCode::from(2);
    };
    let result_chirho = write_template_guest_source_chirho(
        Path::new(root_chirho),
        &TemplateGuestSpecChirho {
            model_type_chirho,
            render_function_path_chirho,
            entry_function_chirho,
        },
        Path::new(&output_chirho),
    )
    .map(|()| format!("template-guest: wrote {output_chirho}"));
    report_chirho(result_chirho)
}

fn cmd_dag_new_chirho(args_chirho: &[String]) -> ExitCode {
    let (Some(root_chirho), Some(dag_chirho)) = (args_chirho.get(2), args_chirho.get(3)) else {
        eprintln!(
            "usage: tree-build-chirho dag-new <app_root> <dag> --in name:type ... --out name:type ..."
        );
        return ExitCode::from(2);
    };
    let ins_chirho = match parse_ports_chirho(&collect_flag_chirho(args_chirho, "--in")) {
        Ok(ins_chirho) => ins_chirho,
        Err(error_chirho) => {
            eprintln!("error: {error_chirho}");
            return ExitCode::FAILURE;
        }
    };
    let outs_chirho = match parse_ports_chirho(&collect_flag_chirho(args_chirho, "--out")) {
        Ok(outs_chirho) => outs_chirho,
        Err(error_chirho) => {
            eprintln!("error: {error_chirho}");
            return ExitCode::FAILURE;
        }
    };
    report_chirho(dag_new_chirho(
        Path::new(root_chirho),
        dag_chirho,
        &ins_chirho,
        &outs_chirho,
    ))
}

fn cmd_node_add_chirho(args_chirho: &[String]) -> ExitCode {
    let (Some(root_chirho), Some(dag_chirho), Some(role_chirho)) =
        (args_chirho.get(2), args_chirho.get(3), args_chirho.get(4))
    else {
        eprintln!(
            "usage: tree-build-chirho node-add <app_root> <dag> <role> --in name:type ... --out name:type ... [--impl module]"
        );
        return ExitCode::from(2);
    };
    let ins_chirho = match parse_ports_chirho(&collect_flag_chirho(args_chirho, "--in")) {
        Ok(ins_chirho) => ins_chirho,
        Err(error_chirho) => {
            eprintln!("error: {error_chirho}");
            return ExitCode::FAILURE;
        }
    };
    let outs_chirho = match parse_ports_chirho(&collect_flag_chirho(args_chirho, "--out")) {
        Ok(outs_chirho) => outs_chirho,
        Err(error_chirho) => {
            eprintln!("error: {error_chirho}");
            return ExitCode::FAILURE;
        }
    };
    let impl_chirho = one_flag_chirho(args_chirho, "--impl").unwrap_or_else(|| role_chirho.clone());
    report_chirho(node_add_chirho(
        Path::new(root_chirho),
        dag_chirho,
        role_chirho,
        &ins_chirho,
        &outs_chirho,
        &impl_chirho,
    ))
}

fn parse_u64_flag_chirho(args_chirho: &[String], flag_chirho: &str) -> Result<Option<u64>, String> {
    one_flag_chirho(args_chirho, flag_chirho)
        .map(|value_chirho| {
            value_chirho.parse::<u64>().map_err(|error_chirho| {
                format!("{flag_chirho} needs an unsigned integer: {error_chirho}")
            })
        })
        .transpose()
}

fn parse_i64_flag_chirho(args_chirho: &[String], flag_chirho: &str) -> Result<Option<i64>, String> {
    one_flag_chirho(args_chirho, flag_chirho)
        .map(|value_chirho| {
            value_chirho
                .parse::<i64>()
                .map_err(|error_chirho| format!("{flag_chirho} needs an integer: {error_chirho}"))
        })
        .transpose()
}

fn cmd_blessed_add_chirho(args_chirho: &[String]) -> ExitCode {
    let (Some(root_chirho), Some(dag_chirho), Some(role_chirho), Some(contract_chirho)) = (
        args_chirho.get(2),
        args_chirho.get(3),
        args_chirho.get(4),
        args_chirho.get(5),
    ) else {
        eprintln!(
            "usage: tree-build-chirho blessed-add <app_root> <dag> <role> <contract> --scope value --intent text --in name:type ... --out name:type ..."
        );
        return ExitCode::from(2);
    };
    let Some(scope_chirho) = one_flag_chirho(args_chirho, "--scope") else {
        eprintln!("error: blessed-add requires --scope <value>");
        return ExitCode::from(2);
    };
    let Some(intent_chirho) = one_flag_chirho(args_chirho, "--intent") else {
        eprintln!("error: blessed-add requires --intent <text>");
        return ExitCode::from(2);
    };
    let ins_chirho = match parse_ports_chirho(&collect_flag_chirho(args_chirho, "--in")) {
        Ok(ins_chirho) => ins_chirho,
        Err(error_chirho) => {
            eprintln!("error: {error_chirho}");
            return ExitCode::FAILURE;
        }
    };
    let outs_chirho = match parse_ports_chirho(&collect_flag_chirho(args_chirho, "--out")) {
        Ok(outs_chirho) => outs_chirho,
        Err(error_chirho) => {
            eprintln!("error: {error_chirho}");
            return ExitCode::FAILURE;
        }
    };
    let max_rows_chirho = match parse_u64_flag_chirho(args_chirho, "--max-rows") {
        Ok(value_chirho) => value_chirho,
        Err(error_chirho) => {
            eprintln!("error: {error_chirho}");
            return ExitCode::FAILURE;
        }
    };
    let max_tokens_chirho = match parse_u64_flag_chirho(args_chirho, "--max-tokens") {
        Ok(value_chirho) => value_chirho,
        Err(error_chirho) => {
            eprintln!("error: {error_chirho}");
            return ExitCode::FAILURE;
        }
    };
    let max_price_per_token_chirho =
        match parse_i64_flag_chirho(args_chirho, "--max-price-per-token") {
            Ok(value_chirho) => value_chirho,
            Err(error_chirho) => {
                eprintln!("error: {error_chirho}");
                return ExitCode::FAILURE;
            }
        };
    let caller_chirho = one_flag_chirho(args_chirho, "--caller");
    report_chirho(blessed_add_chirho(
        Path::new(root_chirho),
        dag_chirho,
        role_chirho,
        &ins_chirho,
        &outs_chirho,
        &BlessedNodeSpecChirho {
            contract_chirho,
            scope_chirho: &scope_chirho,
            caller_chirho: caller_chirho.as_deref(),
            max_rows_chirho,
            max_tokens_chirho,
            max_price_per_token_chirho,
            intent_chirho: &intent_chirho,
        },
    ))
}

fn cmd_wire_chirho(args_chirho: &[String]) -> ExitCode {
    let (Some(root_chirho), Some(dag_chirho), Some(from_chirho), Some(to_chirho)) = (
        args_chirho.get(2),
        args_chirho.get(3),
        args_chirho.get(4),
        args_chirho.get(5),
    ) else {
        eprintln!(
            "usage: tree-build-chirho wire <app_root> <dag> <from owner:port> <to owner:port>"
        );
        return ExitCode::from(2);
    };
    report_chirho(wire_chirho(
        Path::new(root_chirho),
        dag_chirho,
        from_chirho,
        to_chirho,
    ))
}
