// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Compile ordered SCSS/CSS source files into one deployable CSS app asset. v1 deliberately avoids
//! filesystem imports: authors pass the source list explicitly, so provenance stays visible and the
//! compiler never reaches outside the app tree.

use crate::template_codegen_chirho::{
    checked_relative_output_path_chirho, checked_relative_source_path_chirho,
};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StyleCompileReportChirho {
    pub input_count_chirho: usize,
    pub output_path_chirho: PathBuf,
    pub css_bytes_chirho: usize,
}

pub fn compile_style_sources_chirho(
    app_root_chirho: &Path,
    input_paths_chirho: &[PathBuf],
    output_path_chirho: &Path,
) -> Result<StyleCompileReportChirho, String> {
    if input_paths_chirho.is_empty() {
        return Err("style compile requires at least one --style input".to_string());
    }
    let output_path_chirho =
        checked_relative_output_path_chirho(app_root_chirho, output_path_chirho, "css")?;
    let mut combined_chirho = String::new();
    for input_path_chirho in input_paths_chirho {
        let source_path_chirho = checked_relative_source_path_chirho(
            app_root_chirho,
            input_path_chirho,
            &["scss", "css"],
        )?;
        let source_chirho = std::fs::read_to_string(&source_path_chirho).map_err(|e_chirho| {
            format!(
                "read style source '{}': {e_chirho}",
                input_path_chirho.display()
            )
        })?;
        reject_filesystem_imports_chirho(input_path_chirho, &source_chirho)?;
        combined_chirho.push_str("\n/* source: ");
        combined_chirho.push_str(&input_path_chirho.display().to_string());
        combined_chirho.push_str(" */\n");
        combined_chirho.push_str(&source_chirho);
        combined_chirho.push('\n');
    }

    let css_chirho = grass::from_string(
        combined_chirho,
        &grass::Options::default().style(grass::OutputStyle::Expanded),
    )
    .map_err(|e_chirho| format!("compile SCSS/CSS: {e_chirho}"))?;
    if css_chirho.to_ascii_lowercase().contains("@import") {
        return Err("compiled CSS must not contain @import in v1".to_string());
    }

    if let Some(parent_chirho) = output_path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho)
            .map_err(|e_chirho| format!("create style output dir: {e_chirho}"))?;
    }
    std::fs::write(&output_path_chirho, css_chirho.as_bytes())
        .map_err(|e_chirho| format!("write compiled CSS: {e_chirho}"))?;

    Ok(StyleCompileReportChirho {
        input_count_chirho: input_paths_chirho.len(),
        css_bytes_chirho: css_chirho.len(),
        output_path_chirho,
    })
}

fn reject_filesystem_imports_chirho(path_chirho: &Path, source_chirho: &str) -> Result<(), String> {
    for (index_chirho, line_chirho) in source_chirho.lines().enumerate() {
        let lower_chirho = line_chirho.to_ascii_lowercase();
        if lower_chirho.contains("@use")
            || lower_chirho.contains("@forward")
            || lower_chirho.contains("@import")
        {
            return Err(format!(
                "style source '{}' line {} uses filesystem imports; pass every source file explicitly with --style in v1",
                path_chirho.display(),
                index_chirho + 1
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn temp_root_chirho(suffix_chirho: &str) -> PathBuf {
        let mut path_chirho = std::env::temp_dir();
        path_chirho.push(format!(
            "cairn-style-compile-test-{}-{}-chirho",
            std::process::id(),
            suffix_chirho
        ));
        let _ = std::fs::remove_dir_all(&path_chirho);
        std::fs::create_dir_all(path_chirho.join("styles_chirho")).unwrap();
        path_chirho
    }

    #[test]
    fn compiles_ordered_scss_sources_to_css_chirho() {
        let root_chirho = temp_root_chirho("compile");
        std::fs::write(
            root_chirho.join("styles_chirho/tokens_chirho.scss"),
            "$brand-chirho: #24594f;",
        )
        .unwrap();
        std::fs::write(
            root_chirho.join("styles_chirho/home_chirho.scss"),
            ".hero-chirho { color: $brand-chirho; }",
        )
        .unwrap();
        let report_chirho = compile_style_sources_chirho(
            &root_chirho,
            &[
                PathBuf::from("styles_chirho/tokens_chirho.scss"),
                PathBuf::from("styles_chirho/home_chirho.scss"),
            ],
            Path::new("assets_chirho/home-chirho.css"),
        )
        .unwrap();
        let css_chirho = std::fs::read_to_string(&report_chirho.output_path_chirho).unwrap();
        assert_eq!(report_chirho.input_count_chirho, 2);
        assert!(css_chirho.contains(".hero-chirho"));
        assert!(css_chirho.contains("#24594f"));
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn scss_edit_changes_compiled_css_hash_chirho() {
        let root_chirho = temp_root_chirho("hash-change");
        let source_chirho = root_chirho.join("styles_chirho/home_chirho.scss");
        std::fs::write(&source_chirho, ".hero-chirho { color: #24594f; }").unwrap();
        let output_chirho = Path::new("assets_chirho/home-chirho.css");
        let first_chirho = compile_style_sources_chirho(
            &root_chirho,
            &[PathBuf::from("styles_chirho/home_chirho.scss")],
            output_chirho,
        )
        .unwrap();
        let first_bytes_chirho = std::fs::read(&first_chirho.output_path_chirho).unwrap();
        std::fs::write(&source_chirho, ".hero-chirho { color: #7c3aed; }").unwrap();
        let second_chirho = compile_style_sources_chirho(
            &root_chirho,
            &[PathBuf::from("styles_chirho/home_chirho.scss")],
            output_chirho,
        )
        .unwrap();
        let second_bytes_chirho = std::fs::read(&second_chirho.output_path_chirho).unwrap();

        assert_ne!(
            blake3::hash(&first_bytes_chirho),
            blake3::hash(&second_bytes_chirho),
            "editing SCSS must change the compiled CSS content address"
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn rejects_scss_imports_until_import_policy_exists_chirho() {
        let root_chirho = temp_root_chirho("reject");
        std::fs::write(
            root_chirho.join("styles_chirho/home_chirho.scss"),
            "@use '../tokens_chirho';\n.hero-chirho { color: red; }",
        )
        .unwrap();
        let error_chirho = compile_style_sources_chirho(
            &root_chirho,
            &[PathBuf::from("styles_chirho/home_chirho.scss")],
            Path::new("assets_chirho/home-chirho.css"),
        )
        .unwrap_err();
        assert!(error_chirho.contains("pass every source file explicitly"));
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn rejects_mid_line_css_imports_chirho() {
        let root_chirho = temp_root_chirho("mid-import");
        std::fs::write(
            root_chirho.join("styles_chirho/home_chirho.css"),
            "body { color: red; } @import url('https://example.invalid/style.css');",
        )
        .unwrap();
        let error_chirho = compile_style_sources_chirho(
            &root_chirho,
            &[PathBuf::from("styles_chirho/home_chirho.css")],
            Path::new("assets_chirho/home-chirho.css"),
        )
        .unwrap_err();
        assert!(error_chirho.contains("pass every source file explicitly"));
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn rejects_empty_style_input_list_chirho() {
        let root_chirho = temp_root_chirho("empty");
        let error_chirho =
            compile_style_sources_chirho(&root_chirho, &[], Path::new("assets_chirho/home.css"))
                .unwrap_err();
        assert!(error_chirho.contains("at least one"));
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}
