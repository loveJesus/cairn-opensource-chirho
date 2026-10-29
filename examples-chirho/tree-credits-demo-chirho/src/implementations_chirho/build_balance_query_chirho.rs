// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Build the one config-owned published-projection request used by the balance route.
//!
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.

use crate::types_chirho::published_projection_read_chirho::{
    ScopedProjectionQueryV1Chirho, BALANCE_PROJECTION_NAME_CHIRHO,
};

pub fn build_balance_query_chirho() -> ScopedProjectionQueryV1Chirho {
    ScopedProjectionQueryV1Chirho {
        prefix_chirho: BALANCE_PROJECTION_NAME_CHIRHO.to_string(),
        limit_chirho: Some(1),
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn query_is_fixed_to_the_reviewed_balance_projection_chirho() {
        let query_chirho = build_balance_query_chirho();
        assert_eq!(query_chirho.prefix_chirho, BALANCE_PROJECTION_NAME_CHIRHO);
        assert_eq!(query_chirho.limit_chirho, Some(1));
        assert_eq!(
            serde_json::to_vec(&query_chirho).unwrap(),
            br#"{"prefix_chirho":"credits-balance-chirho","limit_chirho":1}"#
        );
    }
}
