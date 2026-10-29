// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;

fn panic_text_chirho(payload_chirho: &(dyn std::any::Any + Send)) -> String {
    payload_chirho
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload_chirho
                .downcast_ref::<&'static str>()
                .map(|text_chirho| (*text_chirho).to_string())
        })
        .unwrap_or_else(|| "non-string panic payload chirho".to_string())
}

fn has_visible_production_after_chirho(lines_chirho: &[&str], start_chirho: usize) -> bool {
    lines_chirho.iter().skip(start_chirho).any(|line_chirho| {
        let trimmed_chirho = line_chirho.trim();
        !(trimmed_chirho.is_empty()
            || trimmed_chirho.starts_with("//")
            || trimmed_chirho.starts_with("#["))
    })
}

fn braced_cfg_test_before_production_starts_chirho(lines_chirho: &[&str]) -> Vec<usize> {
    let mut starts_chirho = Vec::new();
    let mut index_chirho = 0usize;
    while index_chirho < lines_chirho.len() {
        if !is_cfg_test_attribute_line_chirho(lines_chirho[index_chirho]) {
            index_chirho += 1;
            continue;
        }
        if let Some(skip_len_chirho) =
            cfg_test_declaration_skip_len_chirho(lines_chirho, index_chirho)
                .or_else(|| cfg_test_block_skip_len_chirho(lines_chirho, index_chirho))
        {
            index_chirho += skip_len_chirho;
            continue;
        }
        if has_visible_production_after_chirho(lines_chirho, index_chirho + 1) {
            starts_chirho.push(index_chirho);
        }
        index_chirho += 1;
    }
    starts_chirho
}

fn braced_cfg_test_before_production_files_chirho() -> Vec<String> {
    let mut files_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let lines_chirho: Vec<&str> = text_chirho.split_inclusive('\n').collect();
        if !braced_cfg_test_before_production_starts_chirho(&lines_chirho).is_empty() {
            files_chirho.push(workspace_relative_chirho(&path_chirho));
        }
    }
    files_chirho.sort();
    files_chirho
}

#[test]
fn braced_cfg_test_before_production_inventory_stays_named_chirho() {
    let files_chirho = braced_cfg_test_before_production_files_chirho();
    assert_eq!(
        files_chirho,
        Vec::<String>::new(),
        "line-leading cfg-test blocks before later production code must be skippable so source guards scan every production region"
    );
}

#[test]
fn production_text_keeps_code_after_cfg_test_declarations_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
mod tests_chirho;
#[cfg(test)]
use crate::tests_chirho::helper_chirho;
#[cfg(test)]
#[path = \"tests_chirho.rs\"]
mod split_tests_chirho;
#[cfg(test)]
use crate::{
    hidden_one_chirho,
    hidden_two_chirho,
};
#[cfg(test)]
static TEST_COUNTER_CHIRHO: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
pub fn after_chirho() {
    seqlog_chirho::append_jsonl_unlocked_chirho();
}
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(production_chirho.contains("pub fn before_chirho()"));
    assert!(production_chirho.contains("pub fn after_chirho()"));
    assert!(production_chirho.contains("seqlog_chirho::append_jsonl_unlocked_chirho"));
    assert!(
        !production_chirho.contains("mod tests_chirho;"),
        "split test module declarations are skipped, not treated as production"
    );
    assert!(
        !production_chirho.contains("helper_chirho"),
        "cfg-test import declarations are skipped, not treated as production"
    );
    assert!(
        !production_chirho.contains("split_tests_chirho"),
        "stacked cfg-test path/module declarations are skipped"
    );
    assert!(
        !production_chirho.contains("hidden_one_chirho"),
        "multiline cfg-test use declarations are skipped"
    );
    assert!(
        !production_chirho.contains("TEST_COUNTER_CHIRHO"),
        "multiline cfg-test static declarations are skipped"
    );
    let line_chirho = production_chirho
        .lines()
        .position(|line_chirho| line_chirho.contains("pub fn after_chirho()"))
        .expect("after function stays visible")
        + 1;
    assert_eq!(
        line_chirho, 17,
        "skipped declaration lines are preserved as blank lines so guard line numbers stay honest"
    );
}

#[test]
fn production_text_handles_trailing_comments_on_cfg_test_declarations_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
use crate::tests_chirho::helper_chirho; // trailing comment is not declaration text
#[cfg(test)]
static TEST_URL_CHIRHO: &str = \"https://example.test/chirho\";
pub fn after_chirho() {
    seqlog_chirho::append_jsonl_unlocked_chirho();
}
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(production_chirho.contains("pub fn before_chirho()"));
    assert!(production_chirho.contains("pub fn after_chirho()"));
    assert!(!production_chirho.contains("helper_chirho"));
    assert!(!production_chirho.contains("TEST_URL_CHIRHO"));
    assert!(
        production_chirho.contains("seqlog_chirho::append_jsonl_unlocked_chirho"),
        "production after comment-bearing cfg-test declarations remains visible"
    );
}

#[test]
fn production_text_does_not_treat_comment_semicolon_as_declaration_end_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
pub fn helper_for_test_chirho() {} // ;
pub const MUST_NOT_BE_SWALLOWED_CHIRHO: &str = \"visible\";
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(
        production_chirho.contains("MUST_NOT_BE_SWALLOWED_CHIRHO"),
        "a semicolon inside a trailing comment must not prevent scanning production after a cfg-test block"
    );
}

#[test]
fn braced_cfg_test_inventory_skips_conventional_tests_module_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
mod tests_chirho {
    fn test_body_chirho() {}
}
#[cfg(test)]
fn helper_after_tests_mod_chirho() {
}
pub fn production_after_helper_chirho() {}
";
    let lines_chirho: Vec<&str> = text_chirho.split_inclusive('\n').collect();
    assert_eq!(
        braced_cfg_test_before_production_starts_chirho(&lines_chirho),
        Vec::<usize>::new(),
        "inventory skips balanced tests modules and later cfg-test helpers so production after them is scanned"
    );
}

#[test]
fn braced_cfg_test_inventory_skips_after_split_tests_module_declaration_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
mod tests_chirho;
#[cfg(test)]
fn helper_after_split_tests_mod_chirho() {
}
pub fn production_after_helper_chirho() {}
";
    let lines_chirho: Vec<&str> = text_chirho.split_inclusive('\n').collect();
    assert_eq!(
        braced_cfg_test_before_production_starts_chirho(&lines_chirho),
        Vec::<usize>::new(),
        "inventory skips split cfg-test declarations and balanced helpers before scanning later production"
    );
}

#[test]
fn braced_cfg_test_inventory_skips_string_braces_inside_tests_module_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
mod tests_chirho {
    fn string_braces_chirho() {
        let open_chirho = format!(\"{{\");
        let close_chirho = \"}}\";
    }
}
#[cfg(test)]
fn helper_after_tests_mod_chirho() {
}
pub fn production_after_helper_chirho() {}
";
    let lines_chirho: Vec<&str> = text_chirho.split_inclusive('\n').collect();
    assert_eq!(
        braced_cfg_test_before_production_starts_chirho(&lines_chirho),
        Vec::<usize>::new(),
        "string literal braces inside tests modules do not prevent scanning later production"
    );
}

#[test]
fn braced_cfg_test_inventory_does_not_resume_inside_tests_module_strings_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
mod tests_chirho {
    fn fixture_text_chirho() {
        let fake_chirho = \"#[cfg(test)] fn fake_chirho() { }}\";
    }
}
pub fn production_after_tests_mod_chirho() {}
";
    let lines_chirho: Vec<&str> = text_chirho.split_inclusive('\n').collect();
    assert_eq!(
        braced_cfg_test_before_production_starts_chirho(&lines_chirho),
        Vec::<usize>::new(),
        "closing braces inside strings cannot make inventory resume inside a tests module"
    );
}

#[test]
fn braced_cfg_test_inventory_sees_one_line_braced_forms_chirho() {
    let text_chirho = "\
#[cfg(test)] pub fn helper_for_test_chirho() {}
pub fn production_after_one_line_helper_chirho() {}
";
    let lines_chirho: Vec<&str> = text_chirho.split_inclusive('\n').collect();
    assert_eq!(
        braced_cfg_test_before_production_starts_chirho(&lines_chirho),
        Vec::<usize>::new(),
        "one-line cfg-test braced forms are skipped so later production remains scanned"
    );
}

#[test]
fn production_text_skips_cfg_test_blocks_and_resumes_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
mod tests_chirho {
    fn hidden_chirho() {
        seqlog_chirho::append_jsonl_unlocked_chirho();
    }
}
pub fn after_test_block_chirho() {}
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(production_chirho.contains("pub fn before_chirho()"));
    assert!(!production_chirho.contains("hidden_chirho"));
    assert!(production_chirho.contains("after_test_block_chirho"));
}

#[test]
fn production_text_scans_between_and_after_multiple_cfg_test_blocks_chirho() {
    let text_chirho = "\
#[cfg(test)]
fn first_helper_chirho() {
    let hidden_first_chirho = true;
}
pub fn production_between_helpers_chirho() {
    refs_chirho::remove_branch_chirho(root_chirho, \"app/between\")?;
}
#[cfg(test)]
fn second_helper_chirho() {
    let hidden_second_chirho = true;
}
pub fn production_after_helpers_chirho() {
    use cairn_chirho::effect_chirho;
}
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(!production_chirho.contains("hidden_first_chirho"));
    assert!(!production_chirho.contains("hidden_second_chirho"));
    assert!(
        production_chirho.contains("refs_chirho::remove_branch_chirho"),
        "production between cfg-test blocks must be visible to guards"
    );
    assert!(
        production_chirho.contains("use cairn_chirho::effect_chirho"),
        "production after the last cfg-test block must be visible to guards"
    );
}

#[test]
fn production_text_cfg_test_block_skip_ignores_literal_and_comment_braces_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
fn tricky_helper_chirho() {
    let string_close_chirho = \"}\";
    let char_close_chirho = '}';
    let raw_close_chirho = r#\"}\"#;
    let open_string_chirho = \"{\";
    // } a comment brace must not close the block
    if true {
        let nested_chirho = \"still test-only\";
    }
}
pub fn after_tricky_helper_chirho() {
    refs_chirho::remove_branch_chirho(root_chirho, \"app/after\")?;
}
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(production_chirho.contains("pub fn before_chirho()"));
    assert!(production_chirho.contains("after_tricky_helper_chirho"));
    assert!(production_chirho.contains("refs_chirho::remove_branch_chirho"));
    assert!(!production_chirho.contains("fn tricky_helper_chirho"));
    assert!(!production_chirho.contains("nested_chirho"));
}

#[test]
fn production_text_cfg_test_block_skip_ignores_raw_and_multiline_string_braces_chirho() {
    let text_chirho = r##"
pub fn before_chirho() {}
#[cfg(test)]
mod tests_chirho {
    fn fixture_text_chirho() {
        let raw_json_chirho = r#"{"close_chirho":"}","open_chirho":"{"}"#;
        let multiline_chirho = "a misleading open brace {
and a misleading close brace }";
    }
}
pub fn production_after_strings_chirho() {
    refs_chirho::remove_branch_chirho(root_chirho, "app/after-strings")?;
}
"##;
    let production_chirho = production_text_chirho(text_chirho);
    assert!(!production_chirho.contains("raw_json_chirho"));
    assert!(!production_chirho.contains("multiline_chirho"));
    assert!(production_chirho.contains("production_after_strings_chirho"));
    assert!(production_chirho.contains("refs_chirho::remove_branch_chirho"));
    syn::parse_file(&production_chirho)
        .expect("raw and multiline test strings must not corrupt production Rust");
}

#[test]
fn production_text_skips_attached_outer_docs_and_attributes_with_cfg_test_item_chirho() {
    let text_chirho = "\
pub fn production_before_docs_chirho() {}
/// Test-only documentation must not dangle after the item is blanked.
#[doc = \"More test-only documentation.\"]
#[allow(dead_code)]
#[cfg(test)]
mod documented_tests_chirho;
pub fn production_after_docs_chirho() {}
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(!production_chirho.contains("Test-only documentation"));
    assert!(!production_chirho.contains("More test-only documentation"));
    assert!(!production_chirho.contains("documented_tests_chirho"));
    assert!(production_chirho.contains("production_before_docs_chirho"));
    assert!(production_chirho.contains("production_after_docs_chirho"));
    assert_eq!(
        production_chirho.lines().count(),
        text_chirho.lines().count(),
        "blank padding must preserve source coordinates"
    );
    syn::parse_file(&production_chirho)
        .expect("skipping a documented cfg-test item must leave parseable production Rust");
}

#[test]
fn production_text_cfg_test_block_skip_ignores_nested_multiline_comment_braces_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
fn block_comment_helper_chirho() {
    /*
    {
    /* nested misleading open brace: { */
    }
    */
    let hidden_after_comment_chirho = true;
}
pub fn production_after_block_comment_chirho() {
    refs_chirho::remove_branch_chirho(root_chirho, \"app/block-comment\")?;
}
/* } */
pub fn final_production_chirho() {}
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(
        production_chirho.contains("production_after_block_comment_chirho"),
        "braces in nested multiline block comments must not swallow following production"
    );
    assert!(
        production_chirho.contains("refs_chirho::remove_branch_chirho"),
        "the safety-relevant production call after the cfg-test item stays visible"
    );
    assert!(production_chirho.contains("final_production_chirho"));
    assert!(!production_chirho.contains("block_comment_helper_chirho"));
    assert!(!production_chirho.contains("hidden_after_comment_chirho"));
}

#[test]
fn production_text_cfg_test_declaration_ignores_nested_block_comment_semicolons_chirho() {
    let text_chirho = "\
#[cfg(test)]
use crate::{
    hidden_before_comment_chirho,
    /*
    ;
    /* nested misleading semicolon: ; */
    */
    hidden_after_comment_chirho,
};
pub const PRODUCTION_AFTER_COMMENTED_USE_CHIRHO: &str = \"visible\";
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(
        production_chirho.contains("PRODUCTION_AFTER_COMMENTED_USE_CHIRHO"),
        "production after a comment-bearing cfg-test declaration stays visible"
    );
    assert!(!production_chirho.contains("hidden_before_comment_chirho"));
    assert!(
        !production_chirho.contains("hidden_after_comment_chirho"),
        "semicolons in nested block comments cannot end a cfg-test declaration early"
    );
}

#[test]
fn production_text_keeps_forbidden_token_line_numbers_honest_after_cfg_test_block_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
fn helper_chirho() {
    let hidden_chirho = true;
}
pub fn after_chirho() {
    refs_chirho::remove_branch_chirho(root_chirho, \"app/after\")?;
}
";
    let production_chirho = production_text_chirho(text_chirho);
    let line_chirho = production_chirho
        .lines()
        .position(|line_chirho| line_chirho.contains("refs_chirho::remove_branch_chirho"))
        .expect("forbidden-token-shaped production line stays visible")
        + 1;
    assert_eq!(
        line_chirho, 7,
        "skipped cfg-test block padding must preserve the original file line number"
    );
}

#[test]
fn production_text_hides_forbidden_tokens_inside_cfg_test_blocks_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
fn helper_chirho() {
    use cairn_chirho::effect_chirho;
    refs_chirho::remove_branch_chirho(root_chirho, \"app/test-only\")?;
}
pub fn after_chirho() {}
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(production_chirho.contains("pub fn before_chirho()"));
    assert!(production_chirho.contains("pub fn after_chirho()"));
    assert!(
        !production_chirho.contains("use cairn_chirho::effect_chirho"),
        "root imports inside cfg-test helpers remain hidden"
    );
    assert!(
        !production_chirho.contains("refs_chirho::remove_branch_chirho"),
        "raw remove calls inside cfg-test helpers remain hidden"
    );
}

#[test]
fn production_text_ignores_indented_cfg_test_attributes_chirho() {
    let text_chirho = "\
enum DurableInjectionChirho {
    None,
    #[cfg(test)]
    BeforeRenameChirho,
}
pub fn after_enum_chirho() {}
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(
        production_chirho.contains("pub fn after_enum_chirho()"),
        "indented cfg-test enum variant attributes are not line-leading module boundaries"
    );
}

#[test]
fn production_text_does_not_swallow_production_after_cfg_test_block_chirho() {
    let text_chirho = "\
#[cfg(test)]
pub fn helper_for_test_chirho() {
}
pub const MUST_NOT_BE_SWALLOWED_CHIRHO: &str = \"visible\";
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(
        production_chirho.contains("MUST_NOT_BE_SWALLOWED_CHIRHO"),
        "braced cfg-test blocks are skipped so later semicolon production remains visible"
    );
}

#[test]
fn production_text_unrecognized_cfg_test_retained_and_scanned_chirho() {
    let text_chirho = "\
pub fn before_chirho() {}
#[cfg(test)]
extern crate some_test_crate_chirho;
pub fn after_chirho() {}
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(production_chirho.contains("pub fn before_chirho()"));
    assert!(
        production_chirho.contains("extern crate some_test_crate_chirho"),
        "unrecognized cfg(test) line must be retained-and-scanned"
    );
    assert!(
        production_chirho.contains("pub fn after_chirho()"),
        "code after unrecognized cfg(test) must not be truncated"
    );
}

#[test]
fn production_text_unbalanced_cfg_test_block_comment_retained_and_scanned_chirho() {
    let text_chirho = "\
#[cfg(test)]
fn uncertain_helper_chirho() {
    /* unbalanced comment with misleading { ; tokens
}
pub const POSSIBLE_PRODUCTION_AFTER_UNBALANCED_COMMENT_CHIRHO: &str = \"scan me\";
";
    let production_chirho = production_text_chirho(text_chirho);
    assert!(
        production_chirho.contains("uncertain_helper_chirho"),
        "an unbalanced cfg-test region must stay scanned rather than being trusted as test-only"
    );
    assert!(
        production_chirho.contains("POSSIBLE_PRODUCTION_AFTER_UNBALANCED_COMMENT_CHIRHO"),
        "possible production after an unbalanced comment must remain visible fail-safe"
    );
}

#[test]
fn cfg_test_whole_file_module_excluded_but_inline_test_file_scanned_chirho() {
    // End-to-end over a temp crate tree: prove claude2's precision (#4688) — a whole-file cfg-test
    // module is excluded via its PARENT's `#[cfg(test)] mod <name>;`, while a production file that
    // merely CONTAINS an inline `#[cfg(test)] mod tests` stays scanned.
    let root_chirho = std::env::temp_dir().join("cairn-source-scan-cfgtest-fixture-chirho");
    let src_chirho = root_chirho.join("src");
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&src_chirho).unwrap();
    std::fs::write(
        root_chirho.join("Cargo.toml"),
        "[package]\nname = \"source-guard-fixture-chirho\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"custom-root-chirho\"\npath = \"src/main_chirho.rs\"\n",
    )
    .unwrap();
    std::fs::write(
        src_chirho.join("lib.rs"),
        "#[cfg(test)]\nmod whole_test_chirho;\n#[cfg(test)]\nmod grouped_test_chirho;\n#[cfg(test)]\n#[path = \"nested_chirho/lib.rs\"]\nmod nested_lib_test_chirho;\nmod grouped_prod_chirho;\nmod deceptive_tests_chirho;\n#[cfg(test)]\n#[path = \"deceptive_tests_chirho.rs\"]\nmod deceptive_test_alias_chirho;\n#[cfg_attr(feature = \"alternate-chirho\", path = \"alternate_chirho/conditional_test_alias_chirho.rs\")]\nmod conditional_test_alias_chirho;\n#[cfg(test)]\n#[path = \"alternate_chirho/conditional_test_alias_chirho.rs\"]\nmod direct_conditional_target_test_chirho;\n#[cfg(test)]\nmod ambiguous_test_chirho;\n#[path = \"relocated_chirho/logical_container_chirho.rs\"]\nmod logical_container_chirho;\n#[cfg(test)]\nmod inline_include_test_chirho {\n    include!(\"inline_include_test_chirho.rs\");\n}\nmod inline_include_prod_chirho {\n    include!(\"production_include_tests_chirho.rs\");\n}\nmod mixed_chirho;\n",
    )
    .unwrap();
    std::fs::write(
        src_chirho.join("whole_test_chirho.rs"),
        "include!(\"whole_test_include_child_chirho.rs\");\n",
    )
    .unwrap();
    let whole_test_include_child_chirho = src_chirho.join("whole_test_include_child_chirho.rs");
    std::fs::write(
        &whole_test_include_child_chirho,
        "fn nested_include_test_only_chirho() {}\n",
    )
    .unwrap();
    let grouped_chirho = src_chirho.join("grouped_test_chirho");
    std::fs::create_dir_all(&grouped_chirho).unwrap();
    std::fs::write(
        grouped_chirho.join("mod.rs"),
        "// cfg-test-only directory module\n",
    )
    .unwrap();
    let nested_lib_test_chirho = src_chirho.join("nested_chirho").join("lib.rs");
    std::fs::create_dir_all(nested_lib_test_chirho.parent().unwrap()).unwrap();
    std::fs::write(
        &nested_lib_test_chirho,
        "// nested lib filename is a module leaf, not a Cargo root\n",
    )
    .unwrap();
    let grouped_prod_chirho = src_chirho.join("grouped_prod_chirho");
    std::fs::create_dir_all(&grouped_prod_chirho).unwrap();
    std::fs::write(
        grouped_prod_chirho.join("mod.rs"),
        "pub fn production_chirho() {}\n",
    )
    .unwrap();
    std::fs::write(
        src_chirho.join("mixed_chirho.rs"),
        "pub fn prod_chirho() {}\n#[cfg(test)]\n#[path = \"renamed_test_module_chirho\"]\nmod tests_chirho {\n    #[path = \"mixed_test_child_chirho.rs\"]\n    mod mixed_test_child_chirho;\n}\n",
    )
    .unwrap();
    let mixed_test_dir_chirho = src_chirho.join("renamed_test_module_chirho");
    std::fs::create_dir_all(&mixed_test_dir_chirho).unwrap();
    let mixed_test_child_chirho = mixed_test_dir_chirho.join("mixed_test_child_chirho.rs");
    std::fs::write(
        &mixed_test_child_chirho,
        "fn nested_test_only_chirho() {}\n",
    )
    .unwrap();
    let inline_include_test_chirho = src_chirho.join("inline_include_test_chirho.rs");
    std::fs::write(
        &inline_include_test_chirho,
        "fn inline_include_test_only_chirho() {}\n",
    )
    .unwrap();
    let production_include_tests_chirho = src_chirho.join("production_include_tests_chirho.rs");
    std::fs::write(
        &production_include_tests_chirho,
        "pub fn production_despite_include_filename_chirho() {}\n",
    )
    .unwrap();
    let deceptive_tests_chirho = src_chirho.join("deceptive_tests_chirho.rs");
    std::fs::write(
        &deceptive_tests_chirho,
        "pub fn production_despite_filename_chirho() {}\n",
    )
    .unwrap();
    let conditional_conventional_chirho = src_chirho.join("conditional_test_alias_chirho.rs");
    std::fs::write(
        &conditional_conventional_chirho,
        "pub fn conventional_candidate_chirho() {}\n",
    )
    .unwrap();
    let conditional_target_chirho = src_chirho
        .join("alternate_chirho")
        .join("conditional_test_alias_chirho.rs");
    std::fs::create_dir_all(conditional_target_chirho.parent().unwrap()).unwrap();
    std::fs::write(
        &conditional_target_chirho,
        "fn conditional_test_target_chirho() {}\n",
    )
    .unwrap();
    let ambiguous_file_chirho = src_chirho.join("ambiguous_test_chirho.rs");
    std::fs::write(&ambiguous_file_chirho, "fn ambiguous_file_chirho() {}\n").unwrap();
    let ambiguous_dir_chirho = src_chirho.join("ambiguous_test_chirho");
    std::fs::create_dir_all(&ambiguous_dir_chirho).unwrap();
    let ambiguous_mod_chirho = ambiguous_dir_chirho.join("mod.rs");
    std::fs::write(&ambiguous_mod_chirho, "fn ambiguous_mod_chirho() {}\n").unwrap();
    let relocated_container_chirho = src_chirho
        .join("relocated_chirho")
        .join("logical_container_chirho.rs");
    std::fs::create_dir_all(relocated_container_chirho.parent().unwrap()).unwrap();
    std::fs::write(
        &relocated_container_chirho,
        "#[cfg(test)]\nmod nested_alias_test_chirho;\nmod inline_chirho {\n    #[cfg(test)]\n    #[path = \"nested_inline_test_chirho.rs\"]\n    mod nested_inline_test_chirho;\n}\n",
    )
    .unwrap();
    let logical_container_dir_chirho = src_chirho.join("relocated_chirho");
    std::fs::create_dir_all(logical_container_dir_chirho.join("inline_chirho")).unwrap();
    let nested_alias_test_chirho = logical_container_dir_chirho.join("nested_alias_test_chirho.rs");
    std::fs::write(
        &nested_alias_test_chirho,
        "fn nested_alias_test_chirho() {}\n",
    )
    .unwrap();
    let nested_inline_test_chirho = logical_container_dir_chirho
        .join("inline_chirho")
        .join("nested_inline_test_chirho.rs");
    std::fs::write(
        &nested_inline_test_chirho,
        "fn nested_inline_test_chirho() {}\n",
    )
    .unwrap();
    let custom_root_chirho = src_chirho.join("main_chirho.rs");
    std::fs::write(
        &custom_root_chirho,
        "#[cfg(test)]\nmod custom_root_test_chirho;\nfn main() {}\n",
    )
    .unwrap();
    let custom_root_test_chirho = src_chirho.join("custom_root_test_chirho.rs");
    std::fs::write(
        &custom_root_test_chirho,
        "fn custom_root_test_chirho() {}\n",
    )
    .unwrap();
    std::fs::write(
        src_chirho.join("orphan_poison_chirho.rs"),
        "#[cfg(test)]\n#[path = \"lib.rs\"]\nmod hidden_lib_chirho;\n#[cfg(test)]\n#[path = \"main_chirho.rs\"]\nmod hidden_custom_root_chirho;\n",
    )
    .unwrap();

    // Whole-file cfg-test module: parent declares `#[cfg(test)] mod whole_test_chirho;` -> excluded.
    assert!(is_cfg_test_declared_module_file_chirho(
        &src_chirho.join("whole_test_chirho.rs")
    ));
    // Directory-module layout has the same cfg(test) meaning: `grouped/mod.rs` is the leaf named
    // `grouped`, not an unconditional parent module merely because its filename is `mod.rs`.
    assert!(is_cfg_test_declared_module_file_chirho(
        &grouped_chirho.join("mod.rs")
    ));
    // The directory layout alone is not an exemption: an ordinary parent declaration remains in
    // the production set.
    assert!(!is_cfg_test_declared_module_file_chirho(
        &grouped_prod_chirho.join("mod.rs")
    ));
    // Mixed production file: parent declares plain `mod mixed_chirho;` (the inline cfg-test block
    // inside the file is irrelevant to the parent's declaration) -> stays scanned.
    assert!(!is_cfg_test_declared_module_file_chirho(
        &src_chirho.join("mixed_chirho.rs")
    ));
    // A crate root file is a parent module file, never itself a declared leaf.
    assert!(!is_cfg_test_declared_module_file_chirho(
        &src_chirho.join("lib.rs")
    ));

    let mut candidates_chirho = Vec::new();
    collect_rs_files_chirho(&src_chirho, &mut candidates_chirho);
    let production_chirho = production_rs_files_from_candidates_chirho(candidates_chirho)
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert!(
        production_chirho.contains(&deceptive_tests_chirho),
        "a production declaration must win even when the filename looks test-only and a cfg-test alias names the same target"
    );
    assert!(
        production_chirho.contains(&production_include_tests_chirho),
        "a literal production include must remain scanned even when its filename looks test-only"
    );
    assert!(
        production_chirho.contains(&src_chirho.join("lib.rs")),
        "an orphan cfg-test alias must not suppress a conventional Cargo root"
    );
    assert!(
        production_chirho.contains(&custom_root_chirho),
        "an orphan cfg-test alias must not suppress an explicit Cargo target root"
    );
    assert!(
        production_chirho.contains(&conditional_conventional_chirho)
            && production_chirho.contains(&conditional_target_chirho),
        "a conditional production module path must keep every possible target scanned even when another cfg-test edge names one"
    );
    assert!(
        production_chirho.contains(&ambiguous_file_chirho)
            && production_chirho.contains(&ambiguous_mod_chirho),
        "ambiguous conventional module ownership must keep every candidate scanned"
    );
    assert!(
        !production_chirho.contains(&custom_root_test_chirho),
        "an explicit Cargo target root must resolve child modules from its containing directory"
    );
    assert!(
        !production_chirho.contains(&src_chirho.join("whole_test_chirho.rs")),
        "a uniquely resolved parent cfg-test declaration must exclude its whole-file module"
    );
    assert!(
        !production_chirho.contains(&grouped_chirho.join("mod.rs")),
        "a uniquely resolved parent cfg-test declaration must exclude its directory module"
    );
    assert!(
        !production_chirho.contains(&nested_lib_test_chirho),
        "only package src/lib.rs is a conventional Cargo root; a nested lib.rs must honor its cfg-test declaration"
    );
    assert!(
        !production_chirho.contains(&mixed_test_child_chirho),
        "an external child declared inside an inline cfg-test module must inherit exclusion"
    );
    assert!(
        !production_chirho.contains(&whole_test_include_child_chirho)
            && !production_chirho.contains(&inline_include_test_chirho),
        "literal include! sources must inherit the exact cfg-test context that compiles them"
    );
    assert!(
        !production_chirho.contains(&nested_alias_test_chirho)
            && !production_chirho.contains(&nested_inline_test_chirho),
        "rustc treats an external #[path] file like mod.rs, so its nested modules resolve beside the target file"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn unparseable_module_graph_keeps_every_candidate_scanned_chirho() {
    let root_chirho = std::env::temp_dir().join("cairn-source-scan-unparseable-fixture-chirho");
    let src_chirho = root_chirho.join("src");
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&src_chirho).unwrap();
    std::fs::write(
        root_chirho.join("Cargo.toml"),
        "[package]\nname = \"source-guard-unparseable-fixture-chirho\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        src_chirho.join("lib.rs"),
        "#[cfg(test)]\n#[path = \"shared_target_chirho.rs\"]\nmod shared_test_alias_chirho;\nmod broken_parent_chirho;\n",
    )
    .unwrap();
    let shared_target_chirho = src_chirho.join("shared_target_chirho.rs");
    std::fs::write(
        &shared_target_chirho,
        "pub fn production_candidate_chirho() {}\n",
    )
    .unwrap();
    std::fs::write(
        src_chirho.join("broken_parent_chirho.rs"),
        "mod missing_brace_chirho {\n",
    )
    .unwrap();

    let mut candidates_chirho = Vec::new();
    collect_rs_files_chirho(&src_chirho, &mut candidates_chirho);
    let production_chirho = production_rs_files_from_candidates_chirho(candidates_chirho)
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert!(
        production_chirho.contains(&shared_target_chirho),
        "an unparseable declaring file must disable exclusions instead of letting a cfg-test alias hide a possible production target"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn unresolved_include_keeps_every_candidate_scanned_chirho() {
    let root_chirho = std::env::temp_dir().join("cairn-source-scan-include-failsafe-chirho");
    let src_chirho = root_chirho.join("src");
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&src_chirho).unwrap();
    std::fs::write(
        root_chirho.join("Cargo.toml"),
        "[package]\nname = \"source-guard-include-failsafe-chirho\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        src_chirho.join("lib.rs"),
        "#[cfg(test)]\n#[path = \"shared_target_chirho.rs\"]\nmod shared_test_alias_chirho;\ninclude!(concat!(\"generated_chirho\", \".rs\"));\n",
    )
    .unwrap();
    let shared_target_chirho = src_chirho.join("shared_target_chirho.rs");
    std::fs::write(
        &shared_target_chirho,
        "pub fn possible_production_candidate_chirho() {}\n",
    )
    .unwrap();
    std::fs::write(
        src_chirho.join("generated_chirho.rs"),
        "pub fn generated_production_chirho() {}\n",
    )
    .unwrap();

    let mut candidates_chirho = Vec::new();
    collect_rs_files_chirho(&src_chirho, &mut candidates_chirho);
    let production_chirho = production_rs_files_from_candidates_chirho(candidates_chirho)
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert!(
        production_chirho.contains(&shared_target_chirho),
        "a non-literal include must disable exclusions instead of letting another cfg-test edge hide a possible production target"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn explicit_non_mod_rs_path_uses_rustc_sibling_module_base_chirho() {
    let root_chirho = std::env::temp_dir().join("cairn-source-scan-renamed-path-fixture-chirho");
    let src_chirho = root_chirho.join("src");
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&src_chirho).unwrap();
    std::fs::write(
        root_chirho.join("Cargo.toml"),
        "[package]\nname = \"source-guard-renamed-path-fixture-chirho\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        src_chirho.join("lib.rs"),
        "#[cfg(test)]\nmod whole_test_chirho;\n#[path = \"renamed_source_chirho.rs\"]\nmod logical_name_chirho;\n",
    )
    .unwrap();
    let whole_test_chirho = src_chirho.join("whole_test_chirho.rs");
    std::fs::write(&whole_test_chirho, "fn test_only_chirho() {}\n").unwrap();
    std::fs::write(
        src_chirho.join("renamed_source_chirho.rs"),
        "pub fn production_chirho() {}\n#[cfg(test)]\nmod nested_test_chirho;\n",
    )
    .unwrap();
    let nested_test_chirho = src_chirho.join("nested_test_chirho.rs");
    std::fs::write(&nested_test_chirho, "fn nested_test_chirho() {}\n").unwrap();

    let mut candidates_chirho = Vec::new();
    collect_rs_files_chirho(&src_chirho, &mut candidates_chirho);
    let production_chirho = production_rs_files_from_candidates_chirho(candidates_chirho)
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert!(
        !production_chirho.contains(&whole_test_chirho),
        "a renamed explicit path must not erase an independently proven cfg-test exclusion"
    );
    assert!(
        production_chirho.contains(&src_chirho.join("renamed_source_chirho.rs")),
        "the production #[path] target must remain scanned"
    );
    assert!(
        !production_chirho.contains(&nested_test_chirho),
        "rustc treats every external #[path] target like mod.rs, so nested modules resolve beside the target file"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resolved_module_target_outside_inventory_is_red_chirho() {
    let root_chirho = std::env::temp_dir().join("cairn-source-scan-module-escape-fixture-chirho");
    let src_chirho = root_chirho.join("src");
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&src_chirho).unwrap();
    std::fs::write(
        root_chirho.join("Cargo.toml"),
        "[package]\nname = \"source-guard-module-escape-fixture-chirho\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        src_chirho.join("lib.rs"),
        "#[path = \"hidden_source_chirho.inc\"]\nmod hidden_source_chirho;\n",
    )
    .unwrap();
    std::fs::write(
        src_chirho.join("hidden_source_chirho.inc"),
        "pub fn hidden_production_chirho() {}\n",
    )
    .unwrap();

    let mut candidates_chirho = Vec::new();
    collect_rs_files_chirho(&src_chirho, &mut candidates_chirho);
    let panic_chirho =
        std::panic::catch_unwind(|| production_rs_files_from_candidates_chirho(candidates_chirho))
            .expect_err("a resolved non-rs module target must be RED rather than silently omitted");
    let module_panic_text_chirho = panic_text_chirho(panic_chirho.as_ref());
    assert!(module_panic_text_chirho.contains("resolved Rust module target escaped"));

    std::fs::write(
        src_chirho.join("lib.rs"),
        "include!(\"hidden_source_chirho.inc\");\n",
    )
    .unwrap();
    let mut include_candidates_chirho = Vec::new();
    collect_rs_files_chirho(&src_chirho, &mut include_candidates_chirho);
    let include_panic_chirho = std::panic::catch_unwind(|| {
        production_rs_files_from_candidates_chirho(include_candidates_chirho)
    })
    .expect_err("a resolved non-rs include target must be RED rather than silently omitted");
    let include_panic_text_chirho = panic_text_chirho(include_panic_chirho.as_ref());
    let _ = std::fs::remove_dir_all(&root_chirho);
    assert!(include_panic_text_chirho.contains("resolved Rust module target escaped"));
}

#[test]
fn declared_cargo_target_outside_inventory_is_red_chirho() {
    let root_chirho = std::env::temp_dir().join("cairn-source-scan-cargo-escape-fixture-chirho");
    let src_chirho = root_chirho.join("src");
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&src_chirho).unwrap();
    std::fs::write(
        root_chirho.join("Cargo.toml"),
        "[package]\nname = \"source-guard-cargo-escape-fixture-chirho\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"outside-target-chirho\"\npath = \"outside_target_chirho.rs\"\n",
    )
    .unwrap();
    std::fs::write(src_chirho.join("lib.rs"), "pub fn visible_chirho() {}\n").unwrap();
    std::fs::write(
        root_chirho.join("outside_target_chirho.rs"),
        "fn main() {}\n",
    )
    .unwrap();

    let mut candidates_chirho = Vec::new();
    collect_rs_files_chirho(&src_chirho, &mut candidates_chirho);
    let panic_chirho =
        std::panic::catch_unwind(|| production_rs_files_from_candidates_chirho(candidates_chirho))
            .expect_err(
                "a declared Cargo target outside src must be RED rather than silently omitted",
            );
    let panic_text_chirho = panic_text_chirho(panic_chirho.as_ref());
    let _ = std::fs::remove_dir_all(&root_chirho);
    assert!(panic_text_chirho.contains("declared Cargo target escaped"));
}

#[test]
fn workspace_directory_modules_keep_exact_production_boundary_chirho() {
    let root_chirho = workspace_root_chirho();
    let production_chirho = workspace_production_rs_files_chirho()
        .into_iter()
        .collect::<BTreeSet<_>>();
    // THREE ROWS REMOVED 2026-07-26 at CF6 wave-1, and the two lists were treated differently
    // because their POLARITY differs. The `included_chirho` row
    // (`economic_flows_chirho/holds_chirho/mod.rs`) asserted a file IS in production and went red the
    // moment the spine was deleted -- a positive assertion over a deleted subject, which must be
    // removed. The two `excluded_chirho` rows asserted a file is NOT in production; those passed
    // VACUOUSLY after deletion and would have passed forever, asserting nothing about a path that
    // cannot return now that the tree is archived. Removed as dead weight, not as a relaxation: an
    // absence guard over a deleted subject is not evidence, it is a row that can never fire.
    for excluded_chirho in [
        "crates/ledger-chirho/cairn-ledger-sim-chirho/src/journal_crash_tests_chirho/mod.rs",
        "crates/ledger-chirho/cairn-ledger-transfer-chirho/src/coordinator_tests_chirho/mod.rs",
        "crates/support-chirho/cairn-source-scan-chirho/src/source_scan_chirho/tests_chirho/ha2_writer_head_chirho/elector_no_mint_guard_tests_chirho.rs",
        "crates/support-chirho/cairn-source-scan-chirho/src/source_scan_chirho/tests_chirho/ha2_writer_head_chirho/elector_no_mint_guard_tests_chirho/callable_tables_chirho.rs",
        "crates/cairn-projection-chirho/src/typed_ingestion_tests_chirho.rs",
        "src/app_runtime_chirho/effect_pricing_chirho/ha2_head_commit_tests_chirho.rs",
        "src/edge_flows_chirho/onboarding_chirho/ha2_head_commit_tests_chirho.rs",
    ] {
        assert!(
            !production_chirho.contains(&root_chirho.join(excluded_chirho)),
            "parent-declared cfg-test directory module leaked into production: {excluded_chirho}"
        );
    }
    for included_chirho in [
        "crates/authoring-chirho/cairn-tree-build-chirho/src/copy_lint_chirho/mod.rs",
        "crates/authoring-chirho/cairn-tree-build-chirho/src/input_projection_chirho/mod.rs",
        "crates/authoring-chirho/cairn-tree-build-chirho/src/tree_chirho/mod.rs",
        "crates/cairn-node-sdk-chirho/src/exact_json_chirho/mod.rs",
        "crates/runtime-chirho/cairn-input-projection-chirho/src/attestation_chirho/mod.rs",
        "crates/runtime-chirho/cairn-model-app-chirho/src/app_source_manifest_v2_chirho/mod.rs",
        "crates/runtime-chirho/cairn-wasmtime-runner-chirho/src/input_attestation_chirho/mod.rs",
        "src/governance_flows_chirho/agent_authority_chirho/mod.rs",
        "src/governance_flows_chirho/review_chirho/mod.rs",
    ] {
        assert!(
            production_chirho.contains(&root_chirho.join(included_chirho)),
            "production directory module was excluded without a resolved cfg-test declaration: {included_chirho}"
        );
    }
}
