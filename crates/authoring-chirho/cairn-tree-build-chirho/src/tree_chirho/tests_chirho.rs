// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The walker reads the real checked-in demo tree (tree-contact-chirho) into the expected model.

use super::*;

fn demo_app_root_chirho() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples-chirho/tree-contact-chirho")
}

fn role_chirho<'a>(dag_chirho: &'a DagChirho, name_chirho: &str) -> &'a RoleChirho {
    dag_chirho
        .roles_chirho
        .iter()
        .find(|role_chirho| role_chirho.name_chirho == name_chirho)
        .unwrap_or_else(|| panic!("missing role {name_chirho}"))
}

#[test]
fn walks_the_demo_tree_into_one_two_role_dag_chirho() {
    let tree_chirho = walk_app_tree_chirho(&demo_app_root_chirho());
    assert_eq!(tree_chirho.dags_chirho.len(), 1, "exactly one dag");
    let dag_chirho = &tree_chirho.dags_chirho[0];
    assert_eq!(dag_chirho.name_chirho, "receive_message_chirho");
    assert!(dag_chirho.has_spec_chirho, "dag has a spec-chirho.toml");
    assert_eq!(dag_chirho.roles_chirho.len(), 2);

    // Surface: one in (a real dir), one out (a link to the producing role).
    assert_eq!(dag_chirho.surface_chirho.in_ports_chirho.len(), 1);
    assert_eq!(dag_chirho.surface_chirho.out_ports_chirho.len(), 1);
    assert_eq!(
        dag_chirho.surface_chirho.in_ports_chirho[0]
            .parsed_chirho
            .name_chirho,
        "request"
    );
}

#[test]
fn validate_role_has_one_wire_and_one_pin_chirho() {
    let tree_chirho = walk_app_tree_chirho(&demo_app_root_chirho());
    let dag_chirho = &tree_chirho.dags_chirho[0];
    let validate_chirho = role_chirho(dag_chirho, "validate_message_chirho");

    // It is bound to a pure implementation symlink.
    assert!(matches!(
        validate_chirho.binding_chirho,
        RoleBindingChirho::ImplementationChirho { .. }
    ));
    assert!(validate_chirho.has_spec_chirho);

    // Two input ports: a wire (raw_form) and a pin (max_length).
    assert_eq!(validate_chirho.in_ports_chirho.len(), 2);
    let wire_count_chirho = validate_chirho
        .in_ports_chirho
        .iter()
        .filter(|port_chirho| {
            matches!(
                port_chirho.source_chirho,
                Some(PortSourceChirho::WireChirho { .. })
            )
        })
        .count();
    let pin_count_chirho = validate_chirho
        .in_ports_chirho
        .iter()
        .filter(|port_chirho| {
            matches!(
                port_chirho.source_chirho,
                Some(PortSourceChirho::PinChirho { .. })
            )
        })
        .count();
    assert_eq!(wire_count_chirho, 1, "one live wire (raw_form)");
    assert_eq!(pin_count_chirho, 1, "one pin (max_length)");

    // One output binding: clean_message.
    assert_eq!(validate_chirho.out_ports_chirho.len(), 1);
    assert_eq!(
        validate_chirho.out_ports_chirho[0]
            .parsed_chirho
            .name_chirho,
        "clean_message"
    );
}

#[test]
fn render_role_wires_from_validate_chirho() {
    let tree_chirho = walk_app_tree_chirho(&demo_app_root_chirho());
    let dag_chirho = &tree_chirho.dags_chirho[0];
    let render_chirho = role_chirho(dag_chirho, "render_thanks_chirho");
    assert_eq!(render_chirho.in_ports_chirho.len(), 1);
    let source_chirho = render_chirho.in_ports_chirho[0]
        .source_chirho
        .as_ref()
        .expect("render input is fed");
    match source_chirho {
        PortSourceChirho::WireChirho { target_chirho } => {
            assert!(
                target_chirho
                    .to_string_lossy()
                    .contains("validate_message_chirho"),
                "render wires from validate's output: {target_chirho:?}"
            );
        }
        PortSourceChirho::PinChirho { .. } => panic!("render input should be a wire, not a pin"),
    }
}
