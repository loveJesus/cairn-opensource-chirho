// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Every CLI command a LIVING doc or deploy artifact claims you can INVOKE must still be declared.
//!
//! The doc corpus and the command set are wired in PARALLEL: deleting a command silently decouples
//! them, so a retired command keeps being promised by an artifact an operator may follow. This guard
//! puts them in SERIES. CF6 retired roughly 126 commands across its waves; D1 alone removed ten.
//!
//! THE CORPUS IS THE CLAIM, NOT A DETAIL. This guard does not prove "no artifact names a dead
//! command". It proves "no artifact IN THE CORPUS BELOW names a dead command in an invocation
//! position". Every miss in the CF6 wave came from an instrument whose scope was narrower than its
//! author believed while it reported success, so the scope is stated here rather than implied:
//!   INCLUDED  deploy-chirho/**, docs-chirho/** (md/sh/py) and the named living root docs
//!   EXCLUDED  spec-chirho/** entirely - historical evidence, correct to leave stale
//!   EXCLUDED  any artifact carrying the retirement marker - a historical record, correct to preserve
//!
//! Ambiguity fails toward EXCLUSION, not toward RED: only hyphenated kebab tokens in an invocation
//! position count. A false RED on prose is how a guard gets disabled, and a disabled guard covers
//! nothing. That is a different axis from failing closed toward the harm, and conflating them kills
//! guards.

use super::super::workspace_root_chirho;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Binaries whose next non-flag argument is a cairn command.
const CLI_BINARIES_CHIRHO: &[&str] = &["cairn-chirho", "cairn-chirho-smoke"];

/// Both halves must appear for a file to count as retired. Matched as two INDEPENDENT substrings so
/// an em-dash / hyphen / wording drift in the banner cannot silently un-exempt a retired artifact.
const RETIREMENT_MARKER_PARTS_CHIRHO: &[&str] = &["RETIRED", "NOT EXECUTABLE"];

const LIVING_ROOT_DOCS_CHIRHO: &[&str] = &[
    "CLAUDE.md",
    "AGENTS.md",
    "MAP-chirho.md",
    "STATE-AND-PATH-chirho.md",
    "WHITEPAPER-chirho.md",
    "DESIGN-chirho.md",
];

fn declared_commands_chirho() -> BTreeSet<String> {
    let args_chirho = std::fs::read_to_string(
        workspace_root_chirho().join("crates/cairn-cli-chirho/src/args_chirho.rs"),
    )
    .expect("read the CLI argument surface");
    let mut declared_chirho = BTreeSet::new();
    for line_chirho in args_chirho.lines() {
        if let Some((_, rest_chirho)) = line_chirho.split_once("command(name = \"") {
            if let Some((name_chirho, _)) = rest_chirho.split_once('"') {
                declared_chirho.insert(name_chirho.to_owned());
            }
        }
    }
    assert!(
        declared_chirho.len() > 50,
        "the declared-command extractor found only {} names - that is the EXTRACTOR breaking, not the \
         CLI shrinking; a silently-empty declared set would make this whole guard vacuously green",
        declared_chirho.len()
    );
    declared_chirho
}

fn is_retirement_marked_chirho(text_chirho: &str) -> bool {
    RETIREMENT_MARKER_PARTS_CHIRHO
        .iter()
        .all(|part_chirho| text_chirho.contains(part_chirho))
}

/// Commands a text CLAIMS are invocable: the first non-flag token after a cairn binary.
/// `--flag value` pairs are skipped so `cairn-chirho --root R --tenant T some-command` resolves to
/// `some-command` and never to `R` or `T`.
pub(crate) fn invoked_commands_in_text_chirho(text_chirho: &str) -> BTreeSet<String> {
    let mut invoked_chirho = BTreeSet::new();
    for raw_line_chirho in text_chirho.lines() {
        let tokens_chirho: Vec<&str> = raw_line_chirho.split_whitespace().collect();
        for (index_chirho, raw_token_chirho) in tokens_chirho.iter().enumerate() {
            let token_chirho =
                raw_token_chirho.trim_matches(|c_chirho: char| "`'\"\\".contains(c_chirho));
            // The binary must occupy a COMMAND POSITION: the whole token is the binary, or an absolute
            // path ending in it. A bare substring match also fires on `tar -C /var/lib/cairn-chirho`
            // and on `install -o cairn-chirho` where the name is a PATH ARGUMENT or a UNIX USER.
            let is_binary_chirho = CLI_BINARIES_CHIRHO.iter().any(|binary_chirho| {
                token_chirho == *binary_chirho
                    || token_chirho.ends_with(&format!("/{binary_chirho}"))
            });
            if !is_binary_chirho {
                continue;
            }
            // ...and it must not itself be the VALUE of a preceding flag (`-o cairn-chirho`).
            if index_chirho > 0 && tokens_chirho[index_chirho - 1].starts_with('-') {
                continue;
            }
            // A BARE `cairn-chirho` is ambiguous - it is also the unix user/group name, and appears
            // inside quoted match patterns (`grep -F "600 cairn-chirho cairn-chirho"`). Only a PATH
            // form, a line-leading token, or a token after a shell operator is an invocation claim.
            // Ambiguity fails toward EXCLUSION.
            let path_form_chirho = token_chirho.contains('/');
            let leading_chirho = index_chirho == 0;
            // A BACKTICKED token is explicit code context - `cairn-chirho ledger-verify` in prose IS
            // an invocation claim, and it is the commonest doc form. A double-quoted token is not.
            let backticked_chirho = raw_token_chirho.starts_with('`');
            let after_operator_chirho = index_chirho > 0
                && matches!(
                    tokens_chirho[index_chirho - 1],
                    "|" | "&&" | ";" | "sudo" | "$("
                );
            if !(path_form_chirho || leading_chirho || after_operator_chirho || backticked_chirho) {
                continue;
            }
            let mut rest_chirho = tokens_chirho[index_chirho + 1..].iter().peekable();
            while let Some(raw_next_chirho) = rest_chirho.next() {
                let next_chirho =
                    raw_next_chirho.trim_matches(|c_chirho: char| "`'\"\\".contains(c_chirho));
                if next_chirho.is_empty() {
                    continue;
                }
                if next_chirho.starts_with('-') {
                    if rest_chirho
                        .peek()
                        .is_some_and(|peeked_chirho| !peeked_chirho.starts_with('-'))
                    {
                        let _flag_value_chirho = rest_chirho.next();
                    }
                    continue;
                }
                let kebab_chirho = next_chirho.contains('-')
                    && next_chirho.chars().all(|c_chirho| {
                        c_chirho.is_ascii_lowercase()
                            || c_chirho == '-'
                            || c_chirho.is_ascii_digit()
                    });
                if kebab_chirho {
                    invoked_chirho.insert(next_chirho.to_owned());
                }
                break;
            }
        }
    }
    invoked_chirho
}

fn collect_corpus_files_chirho(dir_chirho: &Path, out_chirho: &mut Vec<PathBuf>) {
    let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) else {
        return;
    };
    for entry_chirho in entries_chirho.flatten() {
        let path_chirho = entry_chirho.path();
        if path_chirho.is_dir() {
            collect_corpus_files_chirho(&path_chirho, out_chirho);
        } else if path_chirho.extension().is_some_and(|ext_chirho| {
            ext_chirho == "md" || ext_chirho == "sh" || ext_chirho == "py"
        }) {
            out_chirho.push(path_chirho);
        }
    }
}

fn corpus_files_chirho() -> Vec<PathBuf> {
    let root_chirho = workspace_root_chirho();
    let mut files_chirho = Vec::new();
    for dir_chirho in ["deploy-chirho", "docs-chirho"] {
        collect_corpus_files_chirho(&root_chirho.join(dir_chirho), &mut files_chirho);
    }
    for doc_chirho in LIVING_ROOT_DOCS_CHIRHO {
        let path_chirho = root_chirho.join(doc_chirho);
        if path_chirho.is_file() {
            files_chirho.push(path_chirho);
        }
    }
    files_chirho
}

#[test]
fn living_docs_never_claim_an_undeclared_cli_command_chirho() {
    let declared_chirho = declared_commands_chirho();
    let root_chirho = workspace_root_chirho();
    let mut findings_chirho: Vec<String> = Vec::new();
    for file_chirho in corpus_files_chirho() {
        let Ok(text_chirho) = std::fs::read_to_string(&file_chirho) else {
            continue;
        };
        if is_retirement_marked_chirho(&text_chirho) {
            continue;
        }
        for invoked_chirho in invoked_commands_in_text_chirho(&text_chirho) {
            if !declared_chirho.contains(&invoked_chirho) {
                let shown_chirho = file_chirho
                    .strip_prefix(&root_chirho)
                    .unwrap_or(&file_chirho)
                    .display();
                findings_chirho.push(format!("{shown_chirho}: `{invoked_chirho}`"));
            }
        }
    }
    assert!(
        findings_chirho.is_empty(),
        "living docs / deploy artifacts claim CLI commands that are no longer declared. Restore the \
         command, correct the artifact, or - if it is a historical record - mark it RETIRED — NOT \
         EXECUTABLE:\n  {}",
        findings_chirho.join("\n  ")
    );
}

#[test]
fn guard_fixture_catches_a_live_artifact_naming_a_retired_command_chirho() {
    // ARM A. Without a known-true input a green result means nothing: the guard could be passing
    // because it detects nothing at all.
    let live_chirho = "Run `cairn-chirho gate1-authority-soak --json` to soak the authority log.";
    let invoked_chirho = invoked_commands_in_text_chirho(live_chirho);
    assert!(
        invoked_chirho.contains("gate1-authority-soak"),
        "the detector must SEE an invocation in a live artifact; saw {invoked_chirho:?}"
    );
    assert!(
        !is_retirement_marked_chirho(live_chirho),
        "an unmarked artifact must never be treated as retired"
    );
}

#[test]
fn guard_fixture_exempts_a_retirement_marked_artifact_naming_the_same_command_chirho() {
    // ARM B. Without this the guard cannot distinguish the two cases it exists to distinguish, and
    // would fire forever on legitimate history until someone disabled it.
    let retired_chirho =
        "**RETIRED — NOT EXECUTABLE.**\nRun `cairn-chirho gate1-authority-soak --json`.";
    assert!(
        is_retirement_marked_chirho(retired_chirho),
        "a retirement-marked artifact must be exempt"
    );
    assert!(
        invoked_commands_in_text_chirho(retired_chirho).contains("gate1-authority-soak"),
        "the detector still SEES the command - exemption is a file-level decision, never blindness"
    );
}

#[test]
fn flag_values_are_never_mistaken_for_commands_chirho() {
    let line_chirho = "sudo -u cairn /usr/local/bin/cairn-chirho-smoke --root \"$root\" \
                       --tenant prod-chirho app-verify --json";
    let invoked_chirho = invoked_commands_in_text_chirho(line_chirho);
    assert!(
        invoked_chirho.contains("app-verify"),
        "the command after flag/value pairs must resolve; saw {invoked_chirho:?}"
    );
    assert!(
        !invoked_chirho.contains("prod-chirho"),
        "a flag VALUE must never be reported as a command; saw {invoked_chirho:?}"
    );
}

#[test]
fn prose_mentioning_a_command_name_is_not_an_invocation_chirho() {
    // The false-RED direction. Discussing a concept is not claiming an invocation, and firing here is
    // how this guard would get disabled.
    let prose_chirho = "The gate1-authority-soak rung compared old and new road digests.";
    assert!(
        invoked_commands_in_text_chirho(prose_chirho).is_empty(),
        "prose without a binary must yield no invocation claims"
    );
}

#[test]
fn a_binary_name_inside_a_path_is_not_an_invocation_chirho() {
    // Found by this guard's own first run: `/var/lib/cairn-chirho/current-root-chirho` contains the
    // binary name as a PATH COMPONENT. Without the whitespace requirement the next path segment was
    // reported as a command - a false RED on an artifact that claims nothing.
    let path_chirho = "root_chirho=\"/var/lib/cairn-chirho/current-root-chirho\"";
    assert!(
        invoked_commands_in_text_chirho(path_chirho).is_empty(),
        "a binary name embedded in a path must yield no invocation claims"
    );
}

#[test]
fn the_binary_name_as_a_flag_value_or_path_argument_is_not_an_invocation_chirho() {
    // Both found by this guard's own runs against the real corpus. `tar -C /var/lib/cairn-chirho`
    // makes the name a PATH ARGUMENT to tar; `install -o cairn-chirho` makes it a UNIX USER. Neither
    // claims a cairn invocation, and firing on them is how this guard would get disabled.
    let tar_chirho =
        "sudo tar -C /var/lib/cairn-chirho -czf \"$backup/current-root-before.tgz\" current-root-chirho";
    let install_chirho =
        "sudo install -d -o cairn-chirho -g cairn-chirho -m 700 \"$evidence_chirho\"";
    assert!(
        invoked_commands_in_text_chirho(tar_chirho).is_empty(),
        "a path argument to another command must not be read as a cairn invocation"
    );
    assert!(
        invoked_commands_in_text_chirho(install_chirho).is_empty(),
        "a unix user named after the binary must not be read as a cairn invocation"
    );
}

#[test]
fn a_bare_binary_name_inside_a_quoted_pattern_is_not_an_invocation_chirho() {
    // Found by this guard's third run against the real corpus: an ownership check
    // `grep -F "600 cairn-chirho cairn-chirho"` names the unix USER, not a command. Only path-form,
    // line-leading, or post-operator occurrences are invocation claims.
    let ownership_chirho =
        "sudo stat -c \"%a %U %G\" /etc/cairn-chirho/x.env | grep -F \"600 cairn-chirho cairn-chirho\"";
    assert!(
        invoked_commands_in_text_chirho(ownership_chirho).is_empty(),
        "a bare binary name inside a quoted match pattern must not be read as an invocation"
    );
    // and the positive control still resolves, so the exclusion did not blind the detector
    assert!(
        invoked_commands_in_text_chirho("/usr/local/bin/cairn-chirho app-verify --json")
            .contains("app-verify"),
        "path-form invocations must still resolve"
    );
}
