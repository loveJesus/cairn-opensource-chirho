// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use cairn_chirho::capability_spec_chirho;
use cairn_chirho::model_chirho::CapabilityChirho;

#[test]
fn parses_native_capability_specs_chirho() {
    let caps_chirho = capability_spec_chirho::parse_capabilities_chirho(&[
        "clock".to_string(),
        "paid:echo_paid_chirho:user/alice".to_string(),
        "identity:user/alice:native-cli:tok".to_string(),
        "query:user:user/alice:10".to_string(),
        "net:https://api.example.com/v1|http://127.0.0.1:8080/local".to_string(),
        "invoke:abc123".to_string(),
    ])
    .unwrap();
    assert!(matches!(caps_chirho[0], CapabilityChirho::ClockChirho));
    assert!(matches!(
        caps_chirho[1],
        CapabilityChirho::PaidEffectChirho { .. }
    ));
    assert!(matches!(
        caps_chirho[2],
        CapabilityChirho::UserIdentityChirho { .. }
    ));
    assert!(matches!(
        caps_chirho[3],
        CapabilityChirho::QueryChirho { .. }
    ));
    assert!(matches!(caps_chirho[4], CapabilityChirho::NetChirho { .. }));
    assert!(matches!(
        caps_chirho[5],
        CapabilityChirho::InvokeChirho { .. }
    ));
    assert!(capability_spec_chirho::parse_capabilities_chirho(&[
        "paid:echo_paid_chirho:user:alice".to_string()
    ])
    .is_err());
    assert!(capability_spec_chirho::parse_capabilities_chirho(&[
        "identity:user/alice:native-cli:tok:extra".to_string()
    ])
    .is_err());
    assert!(
        capability_spec_chirho::parse_capabilities_chirho(&["query:user:alice:0".to_string()])
            .is_err()
    );
    assert!(capability_spec_chirho::parse_capabilities_chirho(
        &["query:user:alice:0x".to_string()]
    )
    .is_err());
    assert!(capability_spec_chirho::parse_capabilities_chirho(&[
        "query:user:al:ice:10".to_string()
    ])
    .is_err());
    assert!(capability_spec_chirho::parse_capabilities_chirho(&["unknown".to_string()]).is_err());
}
