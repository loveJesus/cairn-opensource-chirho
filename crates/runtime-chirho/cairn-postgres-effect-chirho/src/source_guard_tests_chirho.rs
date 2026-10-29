// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

#[test]
fn p1_production_surface_has_no_direct_environment_reads_chirho() {
    const PRODUCTION_SOURCES_CHIRHO: &[(&str, &str)] = &[
        ("crypto_chirho.rs", include_str!("crypto_chirho.rs")),
        ("engine_chirho.rs", include_str!("engine_chirho.rs")),
        ("lib.rs", include_str!("lib.rs")),
        ("model_chirho.rs", include_str!("model_chirho.rs")),
        ("ports_chirho.rs", include_str!("ports_chirho.rs")),
        (
            "postgres_driver_chirho.rs",
            include_str!("postgres_driver_chirho.rs"),
        ),
        ("provider_chirho.rs", include_str!("provider_chirho.rs")),
    ];
    const FORBIDDEN_ENVIRONMENT_READS_CHIRHO: &[&str] =
        &["std::env::", "env::var(", "env::var_os("];

    for (path_chirho, source_chirho) in PRODUCTION_SOURCES_CHIRHO {
        for forbidden_chirho in FORBIDDEN_ENVIRONMENT_READS_CHIRHO {
            assert!(
                !source_chirho.contains(forbidden_chirho),
                "provider production source {path_chirho} reads host configuration directly via {forbidden_chirho}; composition must inject the evidence key through the existing secret-store root"
            );
        }
    }
}

#[test]
fn adapter_evidence_key_never_enters_the_postgres_schema_chirho() {
    let schema_chirho = crate::postgres_driver_chirho::INSTALL_SCHEMA_SQL_CHIRHO;
    for forbidden_chirho in [
        "adapter_evidence_key_chirho",
        "evidence_key_chirho",
        "secret_key_chirho",
        "key_material_chirho",
    ] {
        assert!(
            !schema_chirho.contains(forbidden_chirho),
            "operator-held adapter evidence key material must never enter PostgreSQL: {forbidden_chirho}"
        );
    }
}
