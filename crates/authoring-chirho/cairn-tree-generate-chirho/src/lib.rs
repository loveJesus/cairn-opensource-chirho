// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Operator-run brief-to-source generation upstream of tree-build and app-source-review.

pub mod model_chirho;
pub mod provider_chirho;
pub mod runner_chirho;
pub mod source_plan_chirho;

pub use model_chirho::{
    GenerateOptionsChirho, ProviderModeChirho, StubScenarioChirho, TreeGenerateReportChirho,
};
pub use runner_chirho::run_tree_generation_chirho;

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;
