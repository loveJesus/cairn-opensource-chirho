// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Module-graph and concrete-port boundary for the test-only elected bridge.

use super::*;

#[test]
fn elected_bridge_module_is_private_unreferenced_and_host_local_chirho() {
    let root_chirho = workspace_root_chirho();
    let owner_path_chirho =
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/elected_authority_chirho.rs";
    let host_lib_chirho =
        root_chirho.join("crates/ledger-chirho/cairn-ledger-host-chirho/src/lib.rs");
    let host_lib_source_chirho = std::fs::read_to_string(&host_lib_chirho).unwrap();
    let host_lib_ast_chirho = syn::parse_file(&host_lib_source_chirho).unwrap();
    let declarations_chirho = host_lib_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Mod(module_chirho) if module_chirho.ident == "elected_authority_chirho" => {
                Some((
                    &module_chirho.vis,
                    has_exact_cfg_test_chirho(&module_chirho.attrs),
                ))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(declarations_chirho.len(), 1);
    assert!(matches!(declarations_chirho[0].0, Visibility::Inherited));
    assert!(declarations_chirho[0].1);

    let production_files_chirho = workspace_production_rs_files_chirho();
    let production_paths_chirho = production_files_chirho
        .iter()
        .map(|path_chirho| workspace_relative_chirho(path_chirho))
        .collect::<BTreeSet<_>>();
    assert!(
        !production_paths_chirho.contains(owner_path_chirho),
        "the executable A6 bridge source entered the production module graph through a path/include alias"
    );

    let mut references_chirho = BTreeSet::new();
    for path_chirho in production_files_chirho {
        let raw_source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_source_chirho);
        if !source_chirho.contains("elected_authority_chirho") {
            continue;
        }
        let ast_chirho = syn::parse_file(&source_chirho).unwrap_or_else(|error_chirho| {
            panic!(
                "elected bridge module-reference inventory must parse {}: {error_chirho}",
                workspace_relative_chirho(&path_chirho)
            )
        });
        let mut visitor_chirho = ModuleReferenceVisitorChirho::default();
        visitor_chirho.visit_file(&ast_chirho);
        if visitor_chirho.found_chirho {
            references_chirho.insert(workspace_relative_chirho(&path_chirho));
        }
    }
    assert!(
        references_chirho.is_empty(),
        "private A6 bridge module gained production references {references_chirho:?}; activation requires a separately reviewed canary and authority flip"
    );

    let owner_source_chirho = std::fs::read_to_string(root_chirho.join(owner_path_chirho)).unwrap();
    let owner_ast_chirho = syn::parse_file(&owner_source_chirho).unwrap();
    let local_port_types_chirho = owner_ast_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Struct(struct_chirho)
                if struct_chirho.ident == "ElectedLedgerLocalPortsChirho" =>
            {
                assert!(visibility_is_crate_chirho(&struct_chirho.vis));
                Some(
                    struct_chirho
                        .fields
                        .iter()
                        .map(|field_chirho| {
                            assert!(matches!(field_chirho.vis, Visibility::Public(_)));
                            (
                                field_chirho
                                    .ident
                                    .as_ref()
                                    .expect("elected local port field must be named")
                                    .to_string(),
                                canonical_type_path_chirho(&field_chirho.ty),
                            )
                        })
                        .collect::<BTreeSet<_>>(),
                )
            }
            _ => None,
        })
        .expect("elected host-local ports struct must exist");
    assert_eq!(
        local_port_types_chirho,
        BTreeSet::from([
            (
                "authority_chirho".to_owned(),
                "crate::authority_chirho::PlatformPolicyMintAuthorityChirho".to_owned(),
            ),
            (
                "clock_chirho".to_owned(),
                "crate::clock_chirho::SystemLedgerClockChirho".to_owned(),
            ),
            (
                "kind_registry_chirho".to_owned(),
                "cairn_kind_registry_chirho::chain_chirho::VerifiedRegistryChirho".to_owned(),
            ),
            (
                "membership_chirho".to_owned(),
                "crate::authority_chirho::ElectedClusterMembershipChirho".to_owned(),
            ),
            (
                "signer_chirho".to_owned(),
                "crate::signer_chirho::RoleBoundLedgerSignerChirho".to_owned(),
            ),
            (
                "storage_chirho".to_owned(),
                "crate::storage_chirho::FsLedgerStorageChirho".to_owned(),
            ),
        ]),
        "the elected lock scope must contain only exact reviewed concrete local port targets"
    );
}
