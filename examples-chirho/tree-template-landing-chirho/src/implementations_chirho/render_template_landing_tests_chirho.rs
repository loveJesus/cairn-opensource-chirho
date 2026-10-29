// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use crate::content_chirho::landing_public_copy_chirho::{
    landing_public_copy_chirho, try_landing_public_copy_chirho,
};
use crate::implementations_chirho::render_template_landing_chirho::render_template_landing_chirho;
use crate::types_chirho::app_params_landing_v1_chirho::{
    AppParamsLandingV1Chirho, TemplateFeatureChirho,
};
use crate::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;

fn request_with_params_chirho(params_chirho: AppParamsLandingV1Chirho) -> HttpRequestV1Chirho {
    HttpRequestV1Chirho {
        path_chirho: String::new(),
        user_principal_chirho: None,
        app_params_chirho: Some(params_chirho),
    }
}

fn sample_params_chirho() -> AppParamsLandingV1Chirho {
    AppParamsLandingV1Chirho {
        business_name_chirho: "Riverbend Roasters".to_string(),
        tagline_chirho: "Small-batch coffee, roasted on Main Street.".to_string(),
        features_chirho: vec![
            TemplateFeatureChirho {
                title_chirho: "Single-origin beans".to_string(),
                body_chirho: "Sourced direct and roasted weekly.".to_string(),
            },
            TemplateFeatureChirho {
                title_chirho: "Cozy corner cafe".to_string(),
                body_chirho: "Open early, every day.".to_string(),
            },
        ],
        contact_chirho: "hello@riverbend.example".to_string(),
    }
}

#[test]
fn source_dictionary_default_renders_reviewed_public_copy_chirho() {
    let default_copy_chirho = try_landing_public_copy_chirho().unwrap();
    assert_eq!(default_copy_chirho, landing_public_copy_chirho());
    let request_chirho = HttpRequestV1Chirho::default();
    assert_eq!(request_chirho.app_params_chirho, Some(default_copy_chirho));
    let page_chirho = render_template_landing_chirho(&request_chirho);
    let html_chirho = &page_chirho.html_chirho;
    assert!(html_chirho.trim().starts_with("<!doctype html>"));
    assert!(html_chirho.contains("Riverbend Roasters"));
    assert!(html_chirho.contains("Roasters on Main"));
    assert!(html_chirho.contains("Single-origin"));
    assert!(!html_chirho.contains("set up yet"));
}

#[test]
fn configured_params_render_the_brand_tagline_and_a_feature_chirho() {
    let page_chirho =
        render_template_landing_chirho(&request_with_params_chirho(sample_params_chirho()));
    let html_chirho = &page_chirho.html_chirho;
    assert!(html_chirho.trim().starts_with("<!doctype html>"));
    // The business name appears (in the topbar/hero/footer/title).
    assert!(html_chirho.contains("Riverbend Roasters"));
    // The tagline appears.
    assert!(html_chirho.contains("Small-batch coffee, roasted on Main Street."));
    // A feature's title and body appear.
    assert!(html_chirho.contains("Single-origin beans"));
    assert!(html_chirho.contains("Sourced direct and roasted weekly."));
    // The contact line appears.
    assert!(html_chirho.contains("hello@riverbend.example"));
    // It is the configured page, not the placeholder.
    assert!(!html_chirho.contains("hasn"));
}

#[test]
fn explicit_none_params_render_the_placeholder_and_no_business_name_chirho() {
    let request_chirho = HttpRequestV1Chirho {
        app_params_chirho: None,
        ..Default::default()
    };
    assert!(request_chirho.app_params_chirho.is_none());
    let page_chirho = render_template_landing_chirho(&request_chirho);
    let html_chirho = &page_chirho.html_chirho;
    assert!(html_chirho.trim().starts_with("<!doctype html>"));
    // The placeholder copy shows.
    assert!(html_chirho.contains("set up yet"));
    // No sample business name leaks into the placeholder.
    assert!(!html_chirho.contains("Riverbend Roasters"));
}

#[test]
fn blank_business_name_falls_back_to_the_placeholder_chirho() {
    // Params present but the business name is only whitespace ⇒ placeholder.
    let params_chirho = AppParamsLandingV1Chirho {
        business_name_chirho: "   ".to_string(),
        tagline_chirho: "ignored".to_string(),
        ..Default::default()
    };
    let page_chirho = render_template_landing_chirho(&request_with_params_chirho(params_chirho));
    assert!(page_chirho.html_chirho.contains("set up yet"));
    assert!(!page_chirho.html_chirho.contains("ignored"));
}

#[test]
fn dynamic_params_are_html_escaped_chirho() {
    let params_chirho = AppParamsLandingV1Chirho {
        business_name_chirho: "<script>alert(1)</script>".to_string(),
        tagline_chirho: "<img src=x onerror=alert(2)>".to_string(),
        features_chirho: vec![TemplateFeatureChirho {
            title_chirho: "<b>bold</b>".to_string(),
            body_chirho: "<i>body</i>".to_string(),
        }],
        contact_chirho: "<a href=evil>x</a>".to_string(),
    };
    let page_chirho = render_template_landing_chirho(&request_with_params_chirho(params_chirho));
    let html_chirho = &page_chirho.html_chirho;
    // The XSS attempt shows up escaped, not as raw markup. Askama may choose numeric entities.
    assert!(html_chirho.contains("script"));
    assert!(!html_chirho.contains("<script>alert(1)</script>"));
    // The other dynamic fields are escaped too.
    assert!(!html_chirho.contains("<img src=x onerror=alert(2)>"));
    assert!(!html_chirho.contains("<b>bold</b>"));
    assert!(!html_chirho.contains("<a href=evil>x</a>"));
}
