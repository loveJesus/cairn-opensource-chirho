// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The configured ledger namespace has two deliberately different migration coordinates.
//!
//! Eligibility observes root-level surfaces, so it needs the FIRST path component. Opening the
//! target ledger needs the complete relative namespace. Keeping both in one validated value makes
//! it impossible for a nested namespace to accidentally reuse its last component for both jobs.

use cairn_tenant_chirho::surface_disposition_chirho::configured_namespace_root_surface_chirho;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ConfiguredMigrationNamespaceChirho {
    full_relative_path_chirho: PathBuf,
    root_surface_chirho: String,
}

impl ConfiguredMigrationNamespaceChirho {
    pub(super) fn parse_chirho(configured_namespace_chirho: &str) -> Option<Self> {
        let full_relative_path_chirho = PathBuf::from(configured_namespace_chirho);
        if full_relative_path_chirho.is_absolute()
            || full_relative_path_chirho
                .components()
                .any(|component_chirho| !matches!(component_chirho, Component::Normal(_)))
        {
            return None;
        }
        let root_surface_chirho =
            configured_namespace_root_surface_chirho(configured_namespace_chirho)?;
        Some(Self {
            full_relative_path_chirho,
            root_surface_chirho,
        })
    }

    pub(super) fn root_surface_chirho(&self) -> &str {
        &self.root_surface_chirho
    }

    pub(super) fn full_relative_key_chirho(&self) -> &str {
        self.full_relative_path_chirho
            .to_str()
            .expect("a path parsed from UTF-8 config remains UTF-8")
    }

    pub(super) fn target_namespace_path_chirho(&self, target_root_chirho: &Path) -> PathBuf {
        target_root_chirho.join(&self.full_relative_path_chirho)
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_tenant_chirho::migration_completeness_chirho::{
        verify_migration_completeness_chirho, RootSurfaceEnumeratorChirho,
    };
    use cairn_tenant_chirho::surface_disposition_chirho::verify_surface_dispositions_chirho;
    use std::collections::BTreeSet;

    struct OneSurfaceChirho(String);

    impl RootSurfaceEnumeratorChirho for OneSurfaceChirho {
        fn observed_surfaces_chirho(&self) -> Vec<String> {
            vec![self.0.clone()]
        }
    }

    fn assert_namespace_coordinates_chirho(
        configured_namespace_chirho: &str,
        expected_root_surface_chirho: &str,
        expected_full_path_chirho: &str,
    ) {
        let namespace_chirho =
            ConfiguredMigrationNamespaceChirho::parse_chirho(configured_namespace_chirho)
                .expect("a validated configured namespace must parse");
        assert_eq!(
            namespace_chirho.root_surface_chirho(),
            expected_root_surface_chirho
        );
        assert_eq!(
            namespace_chirho.target_namespace_path_chirho(Path::new("target-root-chirho")),
            Path::new("target-root-chirho").join(expected_full_path_chirho)
        );

        let declared_chirho = BTreeSet::from([expected_root_surface_chirho.to_owned()]);
        let completeness_chirho = verify_migration_completeness_chirho(
            &declared_chirho,
            &OneSurfaceChirho(expected_root_surface_chirho.to_owned()),
        );
        let disposition_chirho = verify_surface_dispositions_chirho(
            &[expected_root_surface_chirho.to_owned()],
            Some(namespace_chirho.root_surface_chirho()),
        );
        assert!(completeness_chirho.is_complete_over_evidence_chirho());
        assert!(disposition_chirho.is_disposed_over_evidence_chirho());
    }

    #[test]
    fn nested_and_flat_namespaces_keep_surface_and_open_coordinates_distinct_chirho() {
        assert_namespace_coordinates_chirho(
            "item6-drill-parent-chirho/ledger-chirho",
            "item6-drill-parent-chirho",
            "item6-drill-parent-chirho/ledger-chirho",
        );
        assert_namespace_coordinates_chirho("ledger-chirho", "ledger-chirho", "ledger-chirho");

        let nested_chirho = ConfiguredMigrationNamespaceChirho::parse_chirho(
            "item6-drill-parent-chirho/ledger-chirho",
        )
        .unwrap();
        assert_ne!(
            nested_chirho.target_namespace_path_chirho(Path::new("target-root-chirho")),
            Path::new("target-root-chirho").join(nested_chirho.root_surface_chirho()),
            "a nested namespace must fail if the two coordinates collapse back into one accessor"
        );
    }
}
