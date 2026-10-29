// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::exact_target_reference_resolver_chirho::{
    h3_target_inventory_chirho, H3_ADOPTION_BIRTH_PERMIT_TARGET_CHIRHO,
    H3_BIRTH_PERMIT_TARGET_CHIRHO, H3_BIRTH_TARGET_CHIRHO,
};
use super::*;

const RESIDENT_BIRTH_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/birth_chirho.rs";
const RESIDENT_OWNER_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs";
const RESIDENT_OPEN_VIEW_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/resident_mutation_chirho/authority_open_view_chirho.rs";
const RESIDENT_ACTIVATION_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/activation_chirho.rs";
const RESIDENT_RUNTIME_ACTOR_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho.rs";
const WRITER_ADOPTION_STORE_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/migration_chirho/writer_adoption_chirho/store_chirho.rs";
const WRITER_ADOPTION_MODULE_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/migration_chirho/writer_adoption_chirho/mod.rs";
const HOST_LIB_PATH_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/lib.rs";
const STORAGE_PATH_CHIRHO: &str =
    "crates/ledger-chirho/host-chirho/cairn-ledger-host-storage-chirho/src/lib.rs";
const DESCRIPTOR_PATH_CHIRHO: &str = "crates/ledger-chirho/host-chirho/cairn-ledger-host-storage-chirho/src/descriptor_namespace_chirho.rs";

#[test]
fn sealed_resident_birth_surface_has_exact_reviewed_caller_and_ordering_chirho() {
    let root_chirho = workspace_root_chirho();
    let birth_source_chirho =
        std::fs::read_to_string(root_chirho.join(RESIDENT_BIRTH_PATH_CHIRHO)).unwrap();
    let birth_ast_chirho = syn::parse_file(&birth_source_chirho).unwrap();

    let birth_chirho = birth_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho)
                if canonical_type_path_chirho(&implementation_chirho.self_ty)
                    == "ResidentLedgerAuthorityChirho" =>
            {
                Some(&implementation_chirho.items)
            }
            _ => None,
        })
        .flatten()
        .filter_map(|item_chirho| match item_chirho {
            syn::ImplItem::Fn(function_chirho)
                if function_chirho.sig.ident == "create_bound_preactivation_chirho" =>
            {
                Some(function_chirho)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(birth_chirho.len(), 1);
    let birth_chirho = birth_chirho[0];
    assert!(matches!(birth_chirho.vis, Visibility::Public(_)));
    assert!(
        birth_chirho.sig.asyncness.is_none()
            && birth_chirho.sig.constness.is_none()
            && birth_chirho.sig.unsafety.is_none()
            && birth_chirho.sig.abi.is_none()
            && birth_chirho.sig.variadic.is_none()
            && birth_chirho.sig.generics.params.is_empty()
            && birth_chirho.sig.generics.where_clause.is_none(),
        "sealed resident birth must remain synchronous, nongeneric, and callback-free"
    );
    let birth_parameters_chirho = birth_chirho
        .sig
        .inputs
        .iter()
        .filter_map(|argument_chirho| match argument_chirho {
            syn::FnArg::Typed(argument_chirho) => {
                let syn::Pat::Ident(name_chirho) = argument_chirho.pat.as_ref() else {
                    panic!("sealed resident birth input must use one named binding");
                };
                Some((
                    name_chirho.ident.to_string(),
                    canonical_type_path_chirho(&argument_chirho.ty),
                ))
            }
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        birth_parameters_chirho,
        vec![
            (
                "permit_chirho".to_owned(),
                "ResidentLedgerBirthPermitChirho".to_owned(),
            ),
            (
                "ports_chirho".to_owned(),
                "ResidentLedgerLocalPortsChirho".to_owned(),
            ),
            (
                "local_authority_chirho".to_owned(),
                "LocalAppendAuthorityHandleChirho".to_owned(),
            ),
        ],
        "sealed resident birth must consume only its coordinate permit, concrete ports, and local authority handle"
    );

    let birth_permit_fields_chirho = birth_ast_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Struct(struct_chirho)
                if struct_chirho.ident == "ResidentLedgerBirthPermitChirho" =>
            {
                assert!(matches!(struct_chirho.vis, Visibility::Public(_)));
                Some(
                    struct_chirho
                        .fields
                        .iter()
                        .map(|field_chirho| {
                            assert!(matches!(field_chirho.vis, Visibility::Inherited));
                            (
                                field_chirho
                                    .ident
                                    .as_ref()
                                    .expect("birth permit field must be named")
                                    .to_string(),
                                canonical_type_path_chirho(&field_chirho.ty),
                            )
                        })
                        .collect::<BTreeSet<_>>(),
                )
            }
            _ => None,
        })
        .expect("sealed resident birth permit must exist");
    assert_eq!(
        birth_permit_fields_chirho,
        BTreeSet::from([
            ("adopt_existing_journal_chirho".to_owned(), "bool".to_owned()),
            ("canonical_root_chirho".to_owned(), "PathBuf".to_owned()),
            ("cluster_id_chirho".to_owned(), "ClusterIdChirho".to_owned()),
            (
                "journal_path_chirho".to_owned(),
                "StoragePathChirho".to_owned(),
            ),
            (
                "identity_storage_namespace_chirho".to_owned(),
                "Option<PathBuf>".to_owned(),
            ),
            ("opening_epoch_chirho".to_owned(), "u64".to_owned()),
        ]),
        "the consumed birth permit must bind the exact root, final logical storage namespace, journal, cluster, and opening epoch"
    );
    let birth_permit_constructors_chirho = birth_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho)
                if canonical_type_path_chirho(&implementation_chirho.self_ty)
                    == "ResidentLedgerBirthPermitChirho" =>
            {
                Some(&implementation_chirho.items)
            }
            _ => None,
        })
        .flatten()
        .filter_map(|item_chirho| match item_chirho {
            syn::ImplItem::Fn(function_chirho) => Some((
                function_chirho.sig.ident.to_string(),
                visibility_is_crate_chirho(&function_chirho.vis),
                visibility_is_super_chirho(&function_chirho.vis),
                has_exact_cfg_test_chirho(&function_chirho.attrs),
            )),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        birth_permit_constructors_chirho,
        BTreeSet::from([
            (
                "for_reviewed_activation_chirho".to_owned(),
                false,
                true,
                false,
            ),
            (
                "for_reviewed_adoption_chirho".to_owned(),
                false,
                true,
                false,
            ),
            ("for_test_adoption_chirho".to_owned(), true, false, true),
            ("for_test_chirho".to_owned(), true, false, true),
            (
                "for_test_with_identity_storage_chirho".to_owned(),
                true,
                false,
                true,
            ),
        ]),
        "the sealed birth permit must have one parent-private production constructor and exact test constructors"
    );

    #[derive(Default)]
    struct BirthPermitStructVisitorChirho {
        birth_permit_struct_expressions_chirho: usize,
    }
    impl<'ast_chirho> Visit<'ast_chirho> for BirthPermitStructVisitorChirho {
        fn visit_expr_struct(&mut self, expression_chirho: &'ast_chirho syn::ExprStruct) {
            if expression_chirho
                .path
                .segments
                .last()
                .is_some_and(|segment_chirho| {
                    segment_chirho.ident == "ResidentLedgerBirthPermitChirho"
                })
            {
                self.birth_permit_struct_expressions_chirho += 1;
            }
            syn::visit::visit_expr_struct(self, expression_chirho);
        }
    }

    let mut birth_reference_paths_chirho = BTreeSet::new();
    let mut permit_reference_paths_chirho = BTreeSet::new();
    let mut production_birth_permit_structs_chirho = BirthPermitStructVisitorChirho::default();
    for path_chirho in workspace_production_rs_files_chirho() {
        let raw_source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_source_chirho);
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let has_birth_reference_chirho =
            source_chirho.contains("create_bound_preactivation_chirho");
        let has_permit_reference_chirho = source_chirho.contains("ResidentLedgerBirthPermitChirho");
        if has_birth_reference_chirho {
            birth_reference_paths_chirho.insert(relative_chirho.clone());
        }
        if has_permit_reference_chirho {
            permit_reference_paths_chirho.insert(relative_chirho);
        }
        if !has_birth_reference_chirho && !has_permit_reference_chirho {
            continue;
        }
        let ast_chirho = syn::parse_file(&source_chirho).unwrap_or_else(|error_chirho| {
            panic!("failed to parse {}: {error_chirho}", path_chirho.display())
        });
        production_birth_permit_structs_chirho.visit_file(&ast_chirho);
    }
    assert_eq!(
        birth_reference_paths_chirho,
        BTreeSet::from([
            RESIDENT_ACTIVATION_PATH_CHIRHO.to_owned(),
            RESIDENT_BIRTH_PATH_CHIRHO.to_owned(),
            WRITER_ADOPTION_STORE_PATH_CHIRHO.to_owned(),
        ]),
        "sealed resident birth must have exactly the reviewed activation and migration-adoption callers"
    );
    assert_eq!(
        permit_reference_paths_chirho,
        BTreeSet::from([
            HOST_LIB_PATH_CHIRHO.to_owned(),
            RESIDENT_ACTIVATION_PATH_CHIRHO.to_owned(),
            RESIDENT_BIRTH_PATH_CHIRHO.to_owned(),
            RESIDENT_OWNER_PATH_CHIRHO.to_owned(),
            WRITER_ADOPTION_STORE_PATH_CHIRHO.to_owned(),
        ]),
        "birth-permit references must remain confined to its owner, reviewed activation/adoption capsules, and public type exports"
    );
    let h3_inventory_chirho = h3_target_inventory_chirho();
    assert!(
        h3_inventory_chirho.unresolved_chirho.is_empty(),
        "H3 capability references must resolve to reviewed target symbols; unresolved forms fail closed: {:?}",
        h3_inventory_chirho.unresolved_chirho
    );
    let birth_coordinates_chirho = h3_inventory_chirho
        .coordinates_chirho
        .iter()
        .filter(|entry_chirho| entry_chirho.0 .2 == H3_BIRTH_TARGET_CHIRHO)
        .map(
            |((file_chirho, owner_chirho, _target_chirho), count_chirho)| {
                (file_chirho.clone(), owner_chirho.clone(), *count_chirho)
            },
        )
        .collect::<BTreeSet<_>>();
    assert_eq!(
        birth_coordinates_chirho,
        BTreeSet::from([
            (
                RESIDENT_ACTIVATION_PATH_CHIRHO.to_owned(),
                "activate_reviewed_h3_chirho".to_owned(),
                1,
            ),
            (
                WRITER_ADOPTION_STORE_PATH_CHIRHO.to_owned(),
                "mint_adopted_identity_chirho".to_owned(),
                1,
            ),
        ]),
        "sealed resident birth must resolve to the reviewed activation and warrant-consumption callers"
    );
    let permit_constructor_coordinates_chirho = h3_inventory_chirho
        .coordinates_chirho
        .iter()
        .filter(|entry_chirho| {
            matches!(
                entry_chirho.0 .2.as_str(),
                H3_BIRTH_PERMIT_TARGET_CHIRHO | H3_ADOPTION_BIRTH_PERMIT_TARGET_CHIRHO
            )
        })
        .map(
            |((file_chirho, owner_chirho, _target_chirho), count_chirho)| {
                (file_chirho.clone(), owner_chirho.clone(), *count_chirho)
            },
        )
        .collect::<BTreeSet<_>>();
    assert_eq!(
        permit_constructor_coordinates_chirho,
        BTreeSet::from([
            (
                RESIDENT_ACTIVATION_PATH_CHIRHO.to_owned(),
                "activate_reviewed_h3_chirho".to_owned(),
                1,
            ),
            (
                WRITER_ADOPTION_STORE_PATH_CHIRHO.to_owned(),
                "mint_adopted_identity_chirho".to_owned(),
                1,
            ),
        ]),
        "one reviewed constructor must feed each reviewed resident-birth call"
    );
    assert_eq!(
        production_birth_permit_structs_chirho.birth_permit_struct_expressions_chirho, 0,
        "production source must use the reviewed parent-private constructor, never a birth-permit struct literal"
    );
    let activation_source_chirho =
        std::fs::read_to_string(root_chirho.join(RESIDENT_ACTIVATION_PATH_CHIRHO)).unwrap();
    let activation_ast_chirho = syn::parse_file(&activation_source_chirho).unwrap();
    let activation_function_chirho = activation_ast_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Fn(function_chirho)
                if function_chirho.sig.ident == "activate_reviewed_h3_chirho" =>
            {
                Some(function_chirho)
            }
            _ => None,
        })
        .expect("reviewed H3 activation capsule must exist");
    let mut activation_birth_permit_structs_chirho = BirthPermitStructVisitorChirho::default();
    activation_birth_permit_structs_chirho.visit_block(&activation_function_chirho.block);
    assert_eq!(
        activation_birth_permit_structs_chirho.birth_permit_struct_expressions_chirho,
        0
    );

    let birth_method_source_chirho = source_span_chirho(
        &birth_source_chirho,
        "    pub fn create_bound_preactivation_chirho(",
        "\n}\n\nfn require_opening_membership_chirho(",
    );
    assert_ordered_anchors_chirho(
        birth_method_source_chirho,
        &[
            "try_acquire_chirho()",
            "require_opening_membership_chirho",
            "FsLedgerStorageChirho::open_existing_chirho",
            "ResidentWriterRootCustodyChirho::from_retained_directory_chirho",
            "clone_namespace_root_descriptor_chirho",
            "provision_exclusive_lock_handle_chirho",
            "writer_lock_chirho\n            .try_acquire_chirho()",
            "try_inspect_resident_writer_identity_in_custody_chirho",
            "reserve_resident_writer_in_custody_chirho",
            "create_prepared_chirho",
            "exact_resident_genesis_bytes_chirho",
            "open_read_only_chirho",
            "authority_root_snapshot_chirho\n            .verify_current_path_chirho",
            "create_or_recover_resident_sink_term_cell_at_birth_chirho",
            "canonical_bound_identity_chirho",
            "bind_resident_writer_chirho",
            "resident_lease_chirho\n            .inspect_identity_chirho",
            "verify_bound_identity_chirho",
            "verify_custody_chirho",
            "validate_epoch_posture_chirho",
            "drop(writer_lock_guard_chirho)",
            "let resident_chirho = Self",
            "drop(generation_guard_chirho)",
        ],
    );

    let runtime_actor_source_chirho =
        std::fs::read_to_string(root_chirho.join(RESIDENT_RUNTIME_ACTOR_PATH_CHIRHO)).unwrap();
    assert_ordered_anchors_chirho(
        &runtime_actor_source_chirho,
        &[
            "if config_chirho.adopt_migrated_root_chirho",
            "consume_writer_adoption_warrant_chirho(",
            "ResidentLedgerAuthorityChirho::open_bound_serving_chirho(",
        ],
    );
    let writer_adoption_source_chirho =
        std::fs::read_to_string(root_chirho.join(WRITER_ADOPTION_STORE_PATH_CHIRHO)).unwrap();
    let adoption_birth_source_chirho = source_span_chirho(
        &writer_adoption_source_chirho,
        "fn mint_adopted_identity_chirho<'ports_chirho>(",
        "\nfn verify_existing_adopted_identity_chirho<'ports_chirho>(",
    );
    assert_ordered_anchors_chirho(
        adoption_birth_source_chirho,
        &[
            "ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(",
            "ResidentLedgerBirthPermitChirho::for_reviewed_adoption_chirho(",
            "inspect_target_adoption_posture_chirho(canonical_root_chirho)",
        ],
    );

    let mut warrant_consumer_reference_paths_chirho = BTreeSet::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let raw_source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        if production_text_chirho(&raw_source_chirho)
            .contains("consume_writer_adoption_warrant_chirho")
        {
            warrant_consumer_reference_paths_chirho.insert(workspace_relative_chirho(&path_chirho));
        }
    }
    assert_eq!(
        warrant_consumer_reference_paths_chirho,
        BTreeSet::from([
            RESIDENT_RUNTIME_ACTOR_PATH_CHIRHO.to_owned(),
            WRITER_ADOPTION_MODULE_PATH_CHIRHO.to_owned(),
            WRITER_ADOPTION_STORE_PATH_CHIRHO.to_owned(),
        ]),
        "the target warrant consumer must have one definition, one owner-module export, and one resident-startup caller"
    );
}

#[test]
fn sealed_resident_birth_lock_provisioning_remains_descriptor_owned_chirho() {
    let root_chirho = workspace_root_chirho();
    let storage_source_chirho =
        std::fs::read_to_string(root_chirho.join(STORAGE_PATH_CHIRHO)).unwrap();
    let provision_source_chirho = source_span_chirho(
        &storage_source_chirho,
        "    pub fn provision_exclusive_lock_handle_chirho(",
        "\n    pub fn read_bounded_object_chirho(",
    );
    assert_ordered_anchors_chirho(
        provision_source_chirho,
        &[
            "validate_logical_path_chirho",
            "#[cfg(all(unix, not(target_os = \"solaris\")))]",
            "LedgerStoragePortChirho::create_durable_chirho",
            "open_existing_exclusive_lock_handle_chirho",
            "#[cfg(any(not(unix), target_os = \"solaris\"))]",
            "UnsupportedAuthorityPlatformChirho",
        ],
    );

    let descriptor_source_chirho =
        std::fs::read_to_string(root_chirho.join(DESCRIPTOR_PATH_CHIRHO)).unwrap();
    let lock_open_source_chirho = source_span_chirho(
        &descriptor_source_chirho,
        "    pub(super) fn open_existing_exclusive_lock_handle_chirho(",
        "\n    pub(super) fn read_bounded_object_chirho(",
    );
    assert_ordered_anchors_chirho(
        lock_open_source_chirho,
        &[
            "open_parent_target_chirho",
            "open_existing_file_chirho",
            "inspect_open_file_chirho",
            "len_chirho != 0",
            "ObjectExceedsBoundChirho",
            "verify_open_file_entry_chirho",
        ],
    );

    let mut provision_reference_paths_chirho = BTreeSet::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let raw_source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_source_chirho);
        if source_chirho.contains("provision_exclusive_lock_handle_chirho") {
            provision_reference_paths_chirho.insert(workspace_relative_chirho(&path_chirho));
        }
    }
    assert_eq!(
        provision_reference_paths_chirho,
        BTreeSet::from([
            RESIDENT_BIRTH_PATH_CHIRHO.to_owned(),
            STORAGE_PATH_CHIRHO.to_owned(),
        ]),
        "descriptor-relative lock provisioning must remain private to storage and sealed birth"
    );
}

#[test]
fn resident_host_uses_retained_control_custody_without_pathname_reopen_chirho() {
    let root_chirho = workspace_root_chirho();
    let owner_source_chirho =
        std::fs::read_to_string(root_chirho.join(RESIDENT_OWNER_PATH_CHIRHO)).unwrap();
    let birth_source_chirho =
        std::fs::read_to_string(root_chirho.join(RESIDENT_BIRTH_PATH_CHIRHO)).unwrap();
    let open_view_source_chirho =
        std::fs::read_to_string(root_chirho.join(RESIDENT_OPEN_VIEW_PATH_CHIRHO)).unwrap();
    let combined_source_chirho =
        format!("{owner_source_chirho}\n{birth_source_chirho}\n{open_view_source_chirho}");
    for forbidden_chirho in [
        "reserve_resident_writer_chirho(",
        "inspect_resident_writer_identity_chirho(",
        "open_resident_writer_chirho(",
        "resident_writer_identity_path_chirho(",
    ] {
        assert!(
            !combined_source_chirho.contains(forbidden_chirho),
            "production resident host regained a pathname control call {forbidden_chirho}"
        );
    }
    for required_chirho in [
        "clone_namespace_root_descriptor_chirho",
        "ResidentWriterRootCustodyChirho::from_retained_directory_chirho",
        "try_inspect_resident_writer_identity_in_custody_chirho",
        "reserve_resident_writer_in_custody_chirho",
        "open_exact_chirho",
        "inspect_identity_chirho",
    ] {
        assert!(
            combined_source_chirho.contains(required_chirho),
            "production resident host lost retained control custody {required_chirho}"
        );
    }
}

fn source_span_chirho<'a>(source_chirho: &'a str, start_chirho: &str, end_chirho: &str) -> &'a str {
    let start_index_chirho = source_chirho
        .find(start_chirho)
        .unwrap_or_else(|| panic!("missing source-span start anchor {start_chirho}"));
    let end_index_chirho = source_chirho[start_index_chirho..]
        .find(end_chirho)
        .map(|offset_chirho| start_index_chirho + offset_chirho)
        .unwrap_or_else(|| panic!("missing source-span end anchor {end_chirho}"));
    &source_chirho[start_index_chirho..end_index_chirho]
}

fn assert_ordered_anchors_chirho(source_chirho: &str, anchors_chirho: &[&str]) {
    let mut cursor_chirho = 0;
    for anchor_chirho in anchors_chirho {
        let relative_anchor_chirho = source_chirho[cursor_chirho..]
            .find(anchor_chirho)
            .unwrap_or_else(|| panic!("ordered source span lost safety anchor {anchor_chirho}"));
        cursor_chirho += relative_anchor_chirho + anchor_chirho.len();
    }
}

fn visibility_is_super_chirho(visibility_chirho: &Visibility) -> bool {
    matches!(
        visibility_chirho,
        Visibility::Restricted(restricted_chirho)
            if restricted_chirho.path.segments.len() == 1
                && restricted_chirho.path.segments[0].ident == "super"
    )
}
