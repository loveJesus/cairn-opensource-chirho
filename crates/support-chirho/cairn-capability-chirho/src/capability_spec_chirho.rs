// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Parses compact capability specs shared by CLI and app manifests.

use anyhow::Result;
use cairn_core_chirho::model_chirho::{CapabilityChirho, HashChirho};

use crate::capability_dictionary_chirho::capability_form_for_spec_chirho;

pub fn parse_capabilities_chirho(specs_chirho: &[String]) -> Result<Vec<CapabilityChirho>> {
    specs_chirho
        .iter()
        .map(|spec_chirho| parse_capability_chirho(spec_chirho))
        .collect()
}

pub fn parse_capability_chirho(spec_chirho: &str) -> Result<CapabilityChirho> {
    let Some(form_chirho) = capability_form_for_spec_chirho(spec_chirho) else {
        anyhow::bail!(
            "unknown capability '{spec_chirho}' (supported forms: {})",
            supported_shapes_chirho()
        );
    };
    match form_chirho.id_chirho {
        "clock_chirho" => return Ok(CapabilityChirho::ClockChirho),
        "random_chirho" => return Ok(CapabilityChirho::RandomChirho),
        _ => {}
    }
    if form_chirho.id_chirho == "read_store_chirho" {
        let prefix_chirho = suffix_after_known_form_chirho(spec_chirho, form_chirho)?;
        return Ok(CapabilityChirho::ReadStoreChirho {
            prefix_chirho: nonempty_part_chirho(spec_chirho, prefix_chirho)?,
        });
    }
    if form_chirho.id_chirho == "write_store_chirho" {
        let prefix_chirho = suffix_after_known_form_chirho(spec_chirho, form_chirho)?;
        return Ok(CapabilityChirho::WriteStoreChirho {
            prefix_chirho: nonempty_part_chirho(spec_chirho, prefix_chirho)?,
        });
    }
    if form_chirho.id_chirho == "paid_effect_chirho" {
        let rest_chirho = suffix_after_known_form_chirho(spec_chirho, form_chirho)?;
        let parts_chirho =
            exact_parts_chirho(spec_chirho, rest_chirho, "paid:<effect>:<caller>", 2)?;
        return Ok(CapabilityChirho::PaidEffectChirho {
            effect_chirho: parts_chirho[0].clone(),
            caller_chirho: parts_chirho[1].clone(),
        });
    }
    if form_chirho.id_chirho == "identity_chirho" {
        let rest_chirho = suffix_after_known_form_chirho(spec_chirho, form_chirho)?;
        let parts_chirho = exact_parts_chirho(
            spec_chirho,
            rest_chirho,
            "identity:<principal>:<client>:<token_hash>",
            3,
        )?;
        return Ok(CapabilityChirho::UserIdentityChirho {
            principal_chirho: parts_chirho[0].clone(),
            client_id_chirho: parts_chirho[1].clone(),
            token_hash_chirho: parts_chirho[2].clone(),
        });
    }
    if form_chirho.id_chirho == "app_context_chirho" {
        let rest_chirho = suffix_after_known_form_chirho(spec_chirho, form_chirho)?;
        let parts_chirho = exact_parts_chirho(spec_chirho, rest_chirho, "app:<app>:<owner>", 2)?;
        return Ok(CapabilityChirho::AppContextChirho {
            app_chirho: parts_chirho[0].clone(),
            owner_principal_chirho: parts_chirho[1].clone(),
            price_book_chirho: None,
            billing_policy_chirho: None,
        });
    }
    if form_chirho.id_chirho == "secret_ref_chirho" {
        let name_chirho = suffix_after_known_form_chirho(spec_chirho, form_chirho)?;
        return Ok(CapabilityChirho::SecretRefChirho {
            name_chirho: nonempty_part_chirho(spec_chirho, name_chirho)?,
        });
    }
    if form_chirho.id_chirho == "query_chirho" {
        let rest_chirho = suffix_after_known_form_chirho(spec_chirho, form_chirho)?;
        let parts_chirho = exact_parts_chirho(
            spec_chirho,
            rest_chirho,
            "query:<prefix>:<caller>:<max_rows>",
            3,
        )?;
        let max_rows_chirho: u64 = parts_chirho[2].parse()?;
        if max_rows_chirho == 0 {
            anyhow::bail!("capability '{spec_chirho}' query max_rows must be positive");
        }
        return Ok(CapabilityChirho::QueryChirho {
            prefix_chirho: parts_chirho[0].to_string(),
            caller_chirho: parts_chirho[1].to_string(),
            max_rows_chirho,
        });
    }
    if form_chirho.id_chirho == "net_chirho" {
        let rest_chirho = suffix_after_known_form_chirho(spec_chirho, form_chirho)?;
        let allowlist_chirho = rest_chirho
            .split('|')
            .map(str::trim)
            .filter(|part_chirho| !part_chirho.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if allowlist_chirho.is_empty() {
            anyhow::bail!(
                "capability '{spec_chirho}' must include at least one NetChirho allowlist URL"
            );
        }
        for host_chirho in &allowlist_chirho {
            if host_chirho.contains(',') || host_chirho.contains('=') {
                anyhow::bail!(
                    "capability '{spec_chirho}' NetChirho host '{host_chirho}' contains forbidden ',' or '='"
                );
            }
        }
        return Ok(CapabilityChirho::NetChirho { allowlist_chirho });
    }
    if form_chirho.id_chirho == "invoke_chirho" {
        let node_chirho = suffix_after_known_form_chirho(spec_chirho, form_chirho)?;
        return Ok(CapabilityChirho::InvokeChirho {
            node_chirho: HashChirho(nonempty_part_chirho(spec_chirho, node_chirho)?),
        });
    }
    if form_chirho.id_chirho == "template_app_deploy_chirho" {
        let template_id_chirho = suffix_after_known_form_chirho(spec_chirho, form_chirho)?;
        return Ok(CapabilityChirho::TemplateAppDeployChirho {
            template_id_chirho: nonempty_part_chirho(spec_chirho, template_id_chirho)?,
        });
    }
    anyhow::bail!("capability '{spec_chirho}' resolved to an unhandled dictionary form")
}

fn suffix_after_known_form_chirho<'a>(
    spec_chirho: &'a str,
    form_chirho: &crate::capability_dictionary_chirho::CapabilityFormChirho,
) -> Result<&'a str> {
    for prefix_chirho in std::iter::once(form_chirho.primary_prefix_chirho)
        .chain(form_chirho.aliases_chirho.iter().copied())
    {
        if let Some(rest_chirho) = spec_chirho.strip_prefix(prefix_chirho) {
            return rest_chirho.strip_prefix(':').ok_or_else(|| {
                anyhow::anyhow!(
                    "capability '{spec_chirho}' must be {}",
                    form_chirho.shape_chirho
                )
            });
        }
    }
    anyhow::bail!(
        "capability '{spec_chirho}' did not match {}",
        form_chirho.shape_chirho
    )
}

fn supported_shapes_chirho() -> String {
    crate::capability_dictionary_chirho::capability_forms_chirho()
        .iter()
        .map(|form_chirho| form_chirho.shape_chirho)
        .collect::<Vec<_>>()
        .join(", ")
}

fn exact_parts_chirho(
    spec_chirho: &str,
    rest_chirho: &str,
    shape_chirho: &str,
    expected_chirho: usize,
) -> Result<Vec<String>> {
    let parts_chirho = rest_chirho.split(':').collect::<Vec<_>>();
    if parts_chirho.len() != expected_chirho {
        anyhow::bail!("capability '{spec_chirho}' must be {shape_chirho}");
    }
    parts_chirho
        .into_iter()
        .map(|part_chirho| nonempty_part_chirho(spec_chirho, part_chirho))
        .collect()
}

fn nonempty_part_chirho(spec_chirho: &str, part_chirho: &str) -> Result<String> {
    if part_chirho.trim().is_empty() {
        anyhow::bail!("capability '{spec_chirho}' has an empty component");
    }
    let trimmed_chirho = part_chirho.trim().to_string();
    if trimmed_chirho.contains(',') || trimmed_chirho.contains('=') {
        anyhow::bail!(
            "capability '{spec_chirho}' has component '{trimmed_chirho}' containing forbidden ',' or '='"
        );
    }
    Ok(trimmed_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn parses_store_and_query_capabilities_chirho() {
        let caps_chirho = parse_capabilities_chirho(&[
            "write-store:contacts-chirho/latest".to_string(),
            "read:contacts-chirho/latest".to_string(),
            "query:user/alice:owner/alice:10".to_string(),
            "template-app-deploy:tree-template-landing-chirho".to_string(),
        ])
        .unwrap();
        assert!(matches!(
            caps_chirho[0],
            CapabilityChirho::WriteStoreChirho { .. }
        ));
        assert!(matches!(
            caps_chirho[1],
            CapabilityChirho::ReadStoreChirho { .. }
        ));
        assert!(matches!(
            caps_chirho[2],
            CapabilityChirho::QueryChirho { .. }
        ));
        assert!(matches!(
            caps_chirho[3],
            CapabilityChirho::TemplateAppDeployChirho { .. }
        ));
    }

    #[test]
    fn rejects_empty_parts_chirho() {
        assert!(parse_capability_chirho("write-store:").is_err());
        assert!(parse_capability_chirho("query:user:alice:0").is_err());
        assert!(parse_capability_chirho("query:user:al:ice:10").is_err());
        assert!(parse_capability_chirho("template-app-deploy:").is_err());
        assert!(parse_capability_chirho("unknown").is_err());
    }

    #[test]
    fn rejects_injection_characters_chirho() {
        assert!(parse_capability_chirho("write-store:contacts,x=victim-secrets").is_err());
        assert!(parse_capability_chirho("write-store:contacts=victim").is_err());
        assert!(parse_capability_chirho("paid:innocent,caller=owner:attacker").is_err());
        assert!(parse_capability_chirho("net:https://api.example.com,x=1").is_err());
    }

    #[test]
    fn blessed_catalog_lowered_strings_roundtrip_chirho() {
        let spec_write = "write-store:orders-chirho";
        let cap_write = parse_capability_chirho(spec_write).unwrap();
        assert_eq!(
            cap_write,
            CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "orders-chirho".to_string()
            }
        );

        let spec_query = "query:orders-chirho:caller-chirho:10";
        let cap_query = parse_capability_chirho(spec_query).unwrap();
        assert_eq!(
            cap_query,
            CapabilityChirho::QueryChirho {
                prefix_chirho: "orders-chirho".to_string(),
                caller_chirho: "caller-chirho".to_string(),
                max_rows_chirho: 10,
            }
        );

        let spec_ident = "identity:caller-chirho:client-chirho:token-chirho";
        let cap_ident = parse_capability_chirho(spec_ident).unwrap();
        assert_eq!(
            cap_ident,
            CapabilityChirho::UserIdentityChirho {
                principal_chirho: "caller-chirho".to_string(),
                client_id_chirho: "client-chirho".to_string(),
                token_hash_chirho: "token-chirho".to_string(),
            }
        );

        let spec_deploy = "template-app-deploy:some-template-chirho";
        let cap_deploy = parse_capability_chirho(spec_deploy).unwrap();
        assert_eq!(
            cap_deploy,
            CapabilityChirho::TemplateAppDeployChirho {
                template_id_chirho: "some-template-chirho".to_string()
            }
        );

        let spec_llm = "paid:llm_chirho:some-caller-chirho";
        let cap_llm = parse_capability_chirho(spec_llm).unwrap();
        assert_eq!(
            cap_llm,
            CapabilityChirho::PaidEffectChirho {
                effect_chirho: "llm_chirho".to_string(),
                caller_chirho: "some-caller-chirho".to_string(),
            }
        );
    }

    #[test]
    fn parser_forms_are_documented_by_dictionary_chirho() {
        for spec_chirho in [
            "clock",
            "clock-chirho",
            "random",
            "random-chirho",
            "read-store:contacts-chirho",
            "read:contacts-chirho",
            "write-store:contacts-chirho",
            "write:contacts-chirho",
            "paid:llm_chirho:owner-chirho",
            "identity:owner-chirho:client-chirho:token-chirho",
            "app:demo-chirho:owner-chirho",
            "secret:openrouter-chirho",
            "query:contacts-chirho:caller-chirho:10",
            "net:https://api.example-chirho.test|https://other.example-chirho.test",
            "invoke:abc123-chirho",
            "template-app-deploy:tree-template-landing-chirho",
        ] {
            assert!(
                crate::capability_dictionary_chirho::capability_form_for_spec_chirho(spec_chirho)
                    .is_some(),
                "{spec_chirho} should be documented by the dictionary"
            );
            parse_capability_chirho(spec_chirho).unwrap();
        }
    }

    #[test]
    fn checked_in_example_manifest_capabilities_are_dictionary_known_chirho() {
        let root_chirho = workspace_root_chirho();
        let manifests_chirho = checked_in_example_manifest_paths_chirho(&root_chirho);
        assert!(
            !manifests_chirho.is_empty(),
            "example manifest guard went blind"
        );

        let mut capability_count_chirho = 0usize;
        for path_chirho in manifests_chirho {
            let content_chirho = std::fs::read_to_string(&path_chirho).unwrap();
            let value_chirho: serde_json::Value = serde_json::from_str(&content_chirho)
                .unwrap_or_else(|error_chirho| {
                    panic!(
                        "{} is not valid JSON: {error_chirho}",
                        path_chirho.display()
                    )
                });
            capability_count_chirho += assert_manifest_capabilities_are_dictionary_known_chirho(
                &path_chirho,
                &value_chirho,
            )
            .unwrap();
        }
        assert!(
            capability_count_chirho > 0,
            "example manifest guard found no capability strings"
        );
    }

    #[test]
    fn undocumented_manifest_capability_would_fail_guard_chirho() {
        let value_chirho = serde_json::json!({
            "nodes_chirho": [
                { "capabilities_chirho": ["future-unknown:thing-chirho"] }
            ]
        });
        let error_chirho = assert_manifest_capabilities_are_dictionary_known_chirho(
            std::path::Path::new("synthetic-chirho.json"),
            &value_chirho,
        )
        .unwrap_err();
        assert!(error_chirho.contains("undictionaried capability"));
    }

    fn workspace_root_chirho() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("capability crate should live three levels below workspace root")
            .to_path_buf()
    }

    fn checked_in_example_manifest_paths_chirho(
        root_chirho: &std::path::Path,
    ) -> Vec<std::path::PathBuf> {
        let mut stack_chirho = vec![
            root_chirho.join("examples-chirho"),
            root_chirho.join("deploy-chirho"),
        ];
        let mut manifests_chirho = Vec::new();
        while let Some(dir_chirho) = stack_chirho.pop() {
            for entry_chirho in std::fs::read_dir(&dir_chirho).unwrap() {
                let entry_chirho = entry_chirho.unwrap();
                let path_chirho = entry_chirho.path();
                let file_name_chirho = path_chirho
                    .file_name()
                    .and_then(|name_chirho| name_chirho.to_str())
                    .unwrap_or("");
                if path_chirho.is_dir() {
                    if file_name_chirho != "target" {
                        stack_chirho.push(path_chirho);
                    }
                    continue;
                }
                if file_name_chirho.contains("manifest")
                    && file_name_chirho.ends_with(".json")
                    && path_chirho.is_file()
                {
                    manifests_chirho.push(path_chirho);
                }
            }
        }
        manifests_chirho.sort();
        manifests_chirho
    }

    fn assert_manifest_capabilities_are_dictionary_known_chirho(
        path_chirho: &std::path::Path,
        value_chirho: &serde_json::Value,
    ) -> Result<usize, String> {
        let mut found_chirho = 0usize;
        visit_manifest_capabilities_chirho(path_chirho, value_chirho, &mut found_chirho)?;
        Ok(found_chirho)
    }

    fn visit_manifest_capabilities_chirho(
        path_chirho: &std::path::Path,
        value_chirho: &serde_json::Value,
        found_chirho: &mut usize,
    ) -> Result<(), String> {
        match value_chirho {
            serde_json::Value::Object(map_chirho) => {
                for (key_chirho, child_chirho) in map_chirho {
                    if key_chirho == "capabilities_chirho" {
                        let capabilities_chirho = child_chirho.as_array().ok_or_else(|| {
                            format!(
                                "{} has non-array capabilities_chirho",
                                path_chirho.display()
                            )
                        })?;
                        for capability_chirho in capabilities_chirho {
                            let spec_chirho = capability_chirho.as_str().ok_or_else(|| {
                                format!("{} has non-string capability entry", path_chirho.display())
                            })?;
                            *found_chirho += 1;
                            if crate::capability_dictionary_chirho::capability_form_for_spec_chirho(
                                spec_chirho,
                            )
                            .is_none()
                            {
                                return Err(format!(
                                    "{} contains undictionaried capability '{}'",
                                    path_chirho.display(),
                                    spec_chirho
                                ));
                            }
                            parse_capability_chirho(spec_chirho).map_err(|error_chirho| {
                                format!(
                                    "{} capability '{}' failed parser: {error_chirho}",
                                    path_chirho.display(),
                                    spec_chirho
                                )
                            })?;
                        }
                    }
                    visit_manifest_capabilities_chirho(path_chirho, child_chirho, found_chirho)?;
                }
            }
            serde_json::Value::Array(children_chirho) => {
                for child_chirho in children_chirho {
                    visit_manifest_capabilities_chirho(path_chirho, child_chirho, found_chirho)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}
