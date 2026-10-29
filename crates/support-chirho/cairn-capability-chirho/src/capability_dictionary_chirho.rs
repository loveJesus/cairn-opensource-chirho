// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Machine-readable compact capability grammar for app manifests and authoring review.

/// One field inside a compact capability form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityFieldChirho {
    pub name_chirho: &'static str,
    pub description_chirho: &'static str,
    pub required_chirho: bool,
    pub bounds_chirho: &'static str,
}

/// One compact capability form such as `write-store:<prefix>` or
/// `query:<prefix>:<caller>:<max_rows>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityFormChirho {
    pub id_chirho: &'static str,
    pub primary_prefix_chirho: &'static str,
    pub aliases_chirho: &'static [&'static str],
    pub shape_chirho: &'static str,
    pub fields_chirho: &'static [CapabilityFieldChirho],
    pub category_chirho: &'static str,
    pub plain_template_chirho: &'static str,
    pub bounds_chirho: &'static [&'static str],
}

const NO_FIELDS_CHIRHO: &[CapabilityFieldChirho] = &[];

const PREFIX_FIELD_CHIRHO: &[CapabilityFieldChirho] = &[CapabilityFieldChirho {
    name_chirho: "prefix_chirho",
    description_chirho: "Scoped store key prefix.",
    required_chirho: true,
    bounds_chirho: "non-empty string; caller must keep tenant/private-data policy boundaries",
}];

const PAID_FIELDS_CHIRHO: &[CapabilityFieldChirho] = &[
    CapabilityFieldChirho {
        name_chirho: "effect_chirho",
        description_chirho: "Registered paid effect name.",
        required_chirho: true,
        bounds_chirho: "non-empty string; runtime price book decides actual cost",
    },
    CapabilityFieldChirho {
        name_chirho: "caller_chirho",
        description_chirho: "Caller principal or source-manifest caller label.",
        required_chirho: true,
        bounds_chirho: "non-empty string",
    },
];

const IDENTITY_FIELDS_CHIRHO: &[CapabilityFieldChirho] = &[
    CapabilityFieldChirho {
        name_chirho: "principal_chirho",
        description_chirho: "Principal the app acts as.",
        required_chirho: true,
        bounds_chirho: "non-empty string",
    },
    CapabilityFieldChirho {
        name_chirho: "client_id_chirho",
        description_chirho: "Client/session id binding.",
        required_chirho: true,
        bounds_chirho: "non-empty string",
    },
    CapabilityFieldChirho {
        name_chirho: "token_hash_chirho",
        description_chirho: "Token hash or source-manifest token label.",
        required_chirho: true,
        bounds_chirho: "non-empty string",
    },
];

const APP_FIELDS_CHIRHO: &[CapabilityFieldChirho] = &[
    CapabilityFieldChirho {
        name_chirho: "app_chirho",
        description_chirho: "App id.",
        required_chirho: true,
        bounds_chirho: "non-empty string",
    },
    CapabilityFieldChirho {
        name_chirho: "owner_principal_chirho",
        description_chirho: "Owner principal bound to the app context.",
        required_chirho: true,
        bounds_chirho: "non-empty string",
    },
];

const SECRET_FIELDS_CHIRHO: &[CapabilityFieldChirho] = &[CapabilityFieldChirho {
    name_chirho: "name_chirho",
    description_chirho: "Stored secret name.",
    required_chirho: true,
    bounds_chirho: "non-empty string; value never appears in CAS or review output",
}];

const QUERY_FIELDS_CHIRHO: &[CapabilityFieldChirho] = &[
    CapabilityFieldChirho {
        name_chirho: "prefix_chirho",
        description_chirho: "Projection/store prefix to query.",
        required_chirho: true,
        bounds_chirho: "non-empty string",
    },
    CapabilityFieldChirho {
        name_chirho: "caller_chirho",
        description_chirho: "Caller label used for query audit and billing context.",
        required_chirho: true,
        bounds_chirho: "non-empty string",
    },
    CapabilityFieldChirho {
        name_chirho: "max_rows_chirho",
        description_chirho: "Maximum rows returned by the query effect.",
        required_chirho: true,
        bounds_chirho: "positive u64",
    },
];

const NET_FIELDS_CHIRHO: &[CapabilityFieldChirho] = &[CapabilityFieldChirho {
    name_chirho: "allowlist_chirho",
    description_chirho: "Pipe-separated allowlist of URL origins or prefixes.",
    required_chirho: true,
    bounds_chirho: "one or more non-empty entries separated by |",
}];

const INVOKE_FIELDS_CHIRHO: &[CapabilityFieldChirho] = &[CapabilityFieldChirho {
    name_chirho: "node_chirho",
    description_chirho: "Exact target node hash.",
    required_chirho: true,
    bounds_chirho: "non-empty content hash string",
}];

const TEMPLATE_FIELDS_CHIRHO: &[CapabilityFieldChirho] = &[CapabilityFieldChirho {
    name_chirho: "template_id_chirho",
    description_chirho: "Reviewed template id the app may deploy.",
    required_chirho: true,
    bounds_chirho: "non-empty string",
}];

const CAPABILITY_FORMS_CHIRHO: &[CapabilityFormChirho] = &[
    CapabilityFormChirho {
        id_chirho: "clock_chirho",
        primary_prefix_chirho: "clock",
        aliases_chirho: &["clock-chirho"],
        shape_chirho: "clock",
        fields_chirho: NO_FIELDS_CHIRHO,
        category_chirho: "environment",
        plain_template_chirho: "Read the current time.",
        bounds_chirho: &["no fields"],
    },
    CapabilityFormChirho {
        id_chirho: "random_chirho",
        primary_prefix_chirho: "random",
        aliases_chirho: &["random-chirho"],
        shape_chirho: "random",
        fields_chirho: NO_FIELDS_CHIRHO,
        category_chirho: "environment",
        plain_template_chirho: "Use runtime randomness.",
        bounds_chirho: &["no fields"],
    },
    CapabilityFormChirho {
        id_chirho: "read_store_chirho",
        primary_prefix_chirho: "read-store",
        aliases_chirho: &["read"],
        shape_chirho: "read-store:<prefix_chirho>",
        fields_chirho: PREFIX_FIELD_CHIRHO,
        category_chirho: "data",
        plain_template_chirho: "Read saved data under {prefix_chirho}.",
        bounds_chirho: &["prefix_chirho must be non-empty"],
    },
    CapabilityFormChirho {
        id_chirho: "write_store_chirho",
        primary_prefix_chirho: "write-store",
        aliases_chirho: &["write"],
        shape_chirho: "write-store:<prefix_chirho>",
        fields_chirho: PREFIX_FIELD_CHIRHO,
        category_chirho: "data",
        plain_template_chirho: "Save data under {prefix_chirho}.",
        bounds_chirho: &["prefix_chirho must be non-empty"],
    },
    CapabilityFormChirho {
        id_chirho: "paid_effect_chirho",
        primary_prefix_chirho: "paid",
        aliases_chirho: &[],
        shape_chirho: "paid:<effect_chirho>:<caller_chirho>",
        fields_chirho: PAID_FIELDS_CHIRHO,
        category_chirho: "money",
        plain_template_chirho: "Use paid effect {effect_chirho} for {caller_chirho}.",
        bounds_chirho: &["effect_chirho and caller_chirho must be non-empty"],
    },
    CapabilityFormChirho {
        id_chirho: "identity_chirho",
        primary_prefix_chirho: "identity",
        aliases_chirho: &[],
        shape_chirho: "identity:<principal_chirho>:<client_id_chirho>:<token_hash_chirho>",
        fields_chirho: IDENTITY_FIELDS_CHIRHO,
        category_chirho: "identity",
        plain_template_chirho: "Act as {principal_chirho} for the named client/token binding.",
        bounds_chirho: &["all identity components must be non-empty"],
    },
    CapabilityFormChirho {
        id_chirho: "app_context_chirho",
        primary_prefix_chirho: "app",
        aliases_chirho: &[],
        shape_chirho: "app:<app_chirho>:<owner_principal_chirho>",
        fields_chirho: APP_FIELDS_CHIRHO,
        category_chirho: "identity",
        plain_template_chirho: "Run in app {app_chirho} for owner {owner_principal_chirho}.",
        bounds_chirho: &["app_chirho and owner_principal_chirho must be non-empty"],
    },
    CapabilityFormChirho {
        id_chirho: "secret_ref_chirho",
        primary_prefix_chirho: "secret",
        aliases_chirho: &[],
        shape_chirho: "secret:<name_chirho>",
        fields_chirho: SECRET_FIELDS_CHIRHO,
        category_chirho: "secret",
        plain_template_chirho: "Use stored secret {name_chirho} without revealing its value.",
        bounds_chirho: &["name_chirho must be non-empty"],
    },
    CapabilityFormChirho {
        id_chirho: "query_chirho",
        primary_prefix_chirho: "query",
        aliases_chirho: &[],
        shape_chirho: "query:<prefix_chirho>:<caller_chirho>:<max_rows_chirho>",
        fields_chirho: QUERY_FIELDS_CHIRHO,
        category_chirho: "data",
        plain_template_chirho:
            "Query data under {prefix_chirho} as {caller_chirho}, capped at {max_rows_chirho} rows.",
        bounds_chirho: &["max_rows_chirho must parse as positive u64"],
    },
    CapabilityFormChirho {
        id_chirho: "net_chirho",
        primary_prefix_chirho: "net",
        aliases_chirho: &[],
        shape_chirho: "net:<allowlist_chirho>|...",
        fields_chirho: NET_FIELDS_CHIRHO,
        category_chirho: "network",
        plain_template_chirho: "Reach only the listed network endpoints.",
        bounds_chirho: &["allowlist_chirho must contain at least one non-empty entry"],
    },
    CapabilityFormChirho {
        id_chirho: "invoke_chirho",
        primary_prefix_chirho: "invoke",
        aliases_chirho: &[],
        shape_chirho: "invoke:<node_chirho>",
        fields_chirho: INVOKE_FIELDS_CHIRHO,
        category_chirho: "internal",
        plain_template_chirho: "Invoke exactly the named node.",
        bounds_chirho: &["node_chirho must be non-empty"],
    },
    CapabilityFormChirho {
        id_chirho: "template_app_deploy_chirho",
        primary_prefix_chirho: "template-app-deploy",
        aliases_chirho: &[],
        shape_chirho: "template-app-deploy:<template_id_chirho>",
        fields_chirho: TEMPLATE_FIELDS_CHIRHO,
        category_chirho: "app-deploy",
        plain_template_chirho: "Deploy the reviewed template {template_id_chirho}.",
        bounds_chirho: &["template_id_chirho must be non-empty"],
    },
];

/// All compact capability forms currently accepted by app manifests and CLI parsing.
pub fn capability_forms_chirho() -> &'static [CapabilityFormChirho] {
    CAPABILITY_FORMS_CHIRHO
}

/// Resolve a compact capability string to its grammar form.
pub fn capability_form_for_spec_chirho(spec_chirho: &str) -> Option<&'static CapabilityFormChirho> {
    CAPABILITY_FORMS_CHIRHO
        .iter()
        .find(|form_chirho| form_matches_spec_chirho(form_chirho, spec_chirho))
}

fn form_matches_spec_chirho(form_chirho: &CapabilityFormChirho, spec_chirho: &str) -> bool {
    if spec_chirho == form_chirho.primary_prefix_chirho
        || form_chirho.aliases_chirho.contains(&spec_chirho)
    {
        return form_chirho.fields_chirho.is_empty();
    }
    if form_chirho.fields_chirho.is_empty() {
        return false;
    }
    spec_chirho
        .strip_prefix(form_chirho.primary_prefix_chirho)
        .or_else(|| {
            form_chirho
                .aliases_chirho
                .iter()
                .find_map(|alias_chirho| spec_chirho.strip_prefix(alias_chirho))
        })
        .is_some_and(|rest_chirho| rest_chirho.starts_with(':'))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn dictionary_has_unique_ids_and_prefixes_chirho() {
        let mut ids_chirho = std::collections::BTreeSet::new();
        let mut prefixes_chirho = std::collections::BTreeSet::new();
        for form_chirho in capability_forms_chirho() {
            assert!(ids_chirho.insert(form_chirho.id_chirho));
            assert!(prefixes_chirho.insert(form_chirho.primary_prefix_chirho));
            assert!(!form_chirho.shape_chirho.trim().is_empty());
            assert!(!form_chirho.plain_template_chirho.trim().is_empty());
        }
    }

    #[test]
    fn resolves_aliases_and_parameterized_forms_chirho() {
        assert_eq!(
            capability_form_for_spec_chirho("write:orders-chirho")
                .unwrap()
                .id_chirho,
            "write_store_chirho"
        );
        assert_eq!(
            capability_form_for_spec_chirho("query:orders-chirho:caller-chirho:50")
                .unwrap()
                .id_chirho,
            "query_chirho"
        );
        assert!(capability_form_for_spec_chirho("unknown:thing-chirho").is_none());
        assert!(capability_form_for_spec_chirho("clock:junk").is_none());
        assert!(capability_form_for_spec_chirho("random:junk").is_none());
    }
}
