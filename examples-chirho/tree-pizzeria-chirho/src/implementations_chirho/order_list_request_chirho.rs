// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Pure request shaper for the order-list route: the scoped query over the orders namespace that the
//! blessed query door runs. The only Rust a human writes for this role.

/// The scoped query the order-list route asks for (the orders namespace, up to 50 rows). A fixed v0
/// query; a real app might page or filter.
pub fn order_list_request_chirho() -> String {
    r#"{"prefix_chirho":"orders-chirho","limit_chirho":50}"#.to_string()
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn requests_the_orders_namespace_chirho() {
        let request_chirho = order_list_request_chirho();
        assert!(request_chirho.contains("\"prefix_chirho\":\"orders-chirho\""));
        assert!(request_chirho.contains("\"limit_chirho\":50"));
    }
}
