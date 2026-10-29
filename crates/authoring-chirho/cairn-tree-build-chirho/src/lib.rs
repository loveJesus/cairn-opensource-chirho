// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Compiles a directory-structure-IS-DAG app tree into cairn app-source manifests: walk, parse
//! the segment grammar, check wiring fail-closed with friendly diagnostics, emit the manifest.

// Every identifier this workspace owns carries the `Chirho` suffix, enum variants included.
#![allow(clippy::enum_variant_names)]

#[path = "tree_chirho/authoring_context_chirho.rs"]
pub mod authoring_context_chirho;
pub mod blessed_catalog_chirho;
pub mod check_chirho;
pub mod copy_lint_chirho;
#[path = "codegen_chirho/emit_chirho.rs"]
pub mod emit_chirho;
pub mod grammar_chirho;
pub mod input_projection_chirho;
pub mod node_test_chirho;
#[path = "codegen_chirho/scaffold_chirho.rs"]
pub mod scaffold_chirho;
pub mod source_dictionary_chirho;
#[path = "codegen_chirho/style_compile_chirho.rs"]
pub mod style_compile_chirho;
#[path = "codegen_chirho/template_codegen_chirho.rs"]
pub mod template_codegen_chirho;
pub mod tree_chirho;
