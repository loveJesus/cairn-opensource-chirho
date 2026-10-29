// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fail-closed extraction of the ListObjectsV2 fields the adapter needs (`Key`, `IsTruncated`,
//! `NextContinuationToken`, plus a `KeyCount` consistency check): the bucket is exclusively a
//! cairn root mirror, so any entity, comment, CDATA, tag variant, truncation inconsistency, or
//! declared-vs-returned count disagreement fails the WHOLE listing — a silent key-skip would be a
//! coverage hole the fold verifier only catches later (R2).

use cairn_core_chirho::ports_chirho::{StoreErrorChirho, StoreResultChirho};

/// One parsed listing page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPageChirho {
    pub keys_chirho: Vec<String>,
    pub is_truncated_chirho: bool,
    pub next_continuation_token_chirho: Option<String>,
}

/// Parse one ListObjectsV2 response body, failing closed on anything outside the plain dialect
/// Ceph RGW / Garage / MinIO emit for a cairn-mirror bucket.
pub fn parse_list_objects_v2_chirho(xml_chirho: &str) -> StoreResultChirho<ListPageChirho> {
    if xml_chirho.contains("<!--") || xml_chirho.contains("<![CDATA[") {
        return Err(StoreErrorChirho::invalid_chirho(
            "s3 listing: comment/CDATA in response; refusing the whole listing",
        ));
    }
    // `<Key` may only continue as our exact `<Key>` tag or as the benign `<KeyCount>` sibling.
    let keys_chirho = exact_tag_texts_chirho(xml_chirho, "Key", &["Count>"])?;
    for key_chirho in &keys_chirho {
        if key_chirho.is_empty() {
            return Err(StoreErrorChirho::invalid_chirho(
                "s3 listing: empty <Key>; refusing the whole listing",
            ));
        }
    }
    let truncated_texts_chirho = exact_tag_texts_chirho(xml_chirho, "IsTruncated", &[])?;
    let is_truncated_chirho = match truncated_texts_chirho.as_slice() {
        [value_chirho] if value_chirho == "true" => true,
        [value_chirho] if value_chirho == "false" => false,
        _ => {
            return Err(StoreErrorChirho::invalid_chirho(
                "s3 listing: expected exactly one <IsTruncated> of true/false",
            ))
        }
    };
    // Honest-server consistency: when the page declares a `KeyCount`, it must equal the keys
    // actually returned — a disagreement means entries were dropped or padded somewhere.
    let key_count_texts_chirho = exact_tag_texts_chirho(xml_chirho, "KeyCount", &[])?;
    match key_count_texts_chirho.as_slice() {
        [] => {}
        [count_chirho] => {
            let declared_chirho: u64 = count_chirho.parse().map_err(|_| {
                StoreErrorChirho::invalid_chirho("s3 listing: non-numeric <KeyCount>")
            })?;
            if declared_chirho != keys_chirho.len() as u64 {
                return Err(StoreErrorChirho::invalid_chirho(format!(
                    "s3 listing: KeyCount {declared_chirho} disagrees with {} returned key(s)",
                    keys_chirho.len()
                )));
            }
        }
        _ => {
            return Err(StoreErrorChirho::invalid_chirho(
                "s3 listing: multiple <KeyCount> tags",
            ))
        }
    }
    let token_texts_chirho = exact_tag_texts_chirho(xml_chirho, "NextContinuationToken", &[])?;
    let next_continuation_token_chirho = match token_texts_chirho.as_slice() {
        [] => None,
        [token_chirho] if !token_chirho.is_empty() => Some(token_chirho.clone()),
        _ => {
            return Err(StoreErrorChirho::invalid_chirho(
                "s3 listing: malformed <NextContinuationToken>",
            ))
        }
    };
    // Truncation and token must agree BOTH ways: truncated-without-token would silently drop the
    // tail; token-without-truncated is a dialect we do not speak. Either fails closed.
    if is_truncated_chirho && next_continuation_token_chirho.is_none() {
        return Err(StoreErrorChirho::invalid_chirho(
            "s3 listing: IsTruncated without NextContinuationToken; refusing a silent partial",
        ));
    }
    if !is_truncated_chirho && next_continuation_token_chirho.is_some() {
        return Err(StoreErrorChirho::invalid_chirho(
            "s3 listing: NextContinuationToken without IsTruncated",
        ));
    }
    Ok(ListPageChirho {
        keys_chirho,
        is_truncated_chirho,
        next_continuation_token_chirho,
    })
}

/// Collect the text of every exact `<tag>…</tag>` span. Any `<tag`-prefixed variant that is not the
/// exact tag or an allowed longer sibling (e.g. `<KeyCount>` beside `<Key>`) fails closed, so an
/// attribute-carrying or exotic form can never make an entry silently unparseable. Span text may
/// contain neither `<` nor `&`: cairn mirror keys never need escaping, so an entity IS foreign data.
fn exact_tag_texts_chirho(
    xml_chirho: &str,
    tag_chirho: &str,
    allowed_sibling_suffixes_chirho: &[&str],
) -> StoreResultChirho<Vec<String>> {
    let open_prefix_chirho = format!("<{tag_chirho}");
    let close_chirho = format!("</{tag_chirho}>");
    let mut texts_chirho = Vec::new();
    let mut search_from_chirho = 0usize;
    while let Some(found_chirho) = xml_chirho[search_from_chirho..].find(&open_prefix_chirho) {
        let open_at_chirho = search_from_chirho + found_chirho;
        let after_prefix_chirho = &xml_chirho[open_at_chirho + open_prefix_chirho.len()..];
        if let Some(rest_chirho) = after_prefix_chirho.strip_prefix('>') {
            let Some(text_len_chirho) = rest_chirho.find(&close_chirho) else {
                return Err(StoreErrorChirho::invalid_chirho(format!(
                    "s3 listing: unterminated <{tag_chirho}>; refusing the whole listing"
                )));
            };
            let text_chirho = &rest_chirho[..text_len_chirho];
            if text_chirho.contains('<') || text_chirho.contains('&') {
                return Err(StoreErrorChirho::invalid_chirho(format!(
                    "s3 listing: <{tag_chirho}> content needs escaping; refusing the whole listing"
                )));
            }
            texts_chirho.push(text_chirho.to_string());
            search_from_chirho = open_at_chirho
                + open_prefix_chirho.len()
                + 1
                + text_len_chirho
                + close_chirho.len();
        } else if allowed_sibling_suffixes_chirho
            .iter()
            .any(|suffix_chirho| after_prefix_chirho.starts_with(suffix_chirho))
        {
            search_from_chirho = open_at_chirho + open_prefix_chirho.len();
        } else {
            return Err(StoreErrorChirho::invalid_chirho(format!(
                "s3 listing: unexpected <{tag_chirho}… tag variant; refusing the whole listing"
            )));
        }
    }
    Ok(texts_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn page_chirho(body_chirho: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult>{body_chirho}</ListBucketResult>"
        )
    }

    #[test]
    fn parses_a_final_page_with_key_count_sibling_chirho() {
        let xml_chirho = page_chirho(
            "<Name>b</Name><KeyCount>2</KeyCount><IsTruncated>false</IsTruncated>\
             <Contents><Key>objects-chirho/ab/cd</Key></Contents>\
             <Contents><Key>objects-chirho/ab/ce</Key></Contents>",
        );
        let parsed_chirho = parse_list_objects_v2_chirho(&xml_chirho).unwrap();
        assert_eq!(
            parsed_chirho.keys_chirho,
            vec!["objects-chirho/ab/cd", "objects-chirho/ab/ce"]
        );
        assert!(!parsed_chirho.is_truncated_chirho);
        assert!(parsed_chirho.next_continuation_token_chirho.is_none());
    }

    #[test]
    fn parses_a_truncated_page_with_token_chirho() {
        let xml_chirho = page_chirho(
            "<IsTruncated>true</IsTruncated><Contents><Key>objects-chirho/ab/cd</Key></Contents>\
             <NextContinuationToken>tok+1/2=</NextContinuationToken>",
        );
        let parsed_chirho = parse_list_objects_v2_chirho(&xml_chirho).unwrap();
        assert!(parsed_chirho.is_truncated_chirho);
        assert_eq!(
            parsed_chirho.next_continuation_token_chirho.as_deref(),
            Some("tok+1/2=")
        );
    }

    #[test]
    fn refuses_truncated_without_token_chirho() {
        let xml_chirho = page_chirho(
            "<IsTruncated>true</IsTruncated><Contents><Key>objects-chirho/ab/cd</Key></Contents>",
        );
        let message_chirho = parse_list_objects_v2_chirho(&xml_chirho)
            .unwrap_err()
            .to_string();
        assert!(
            message_chirho.contains("silent partial"),
            "{message_chirho}"
        );
    }

    #[test]
    fn refuses_token_without_truncated_chirho() {
        let xml_chirho = page_chirho(
            "<IsTruncated>false</IsTruncated><NextContinuationToken>t</NextContinuationToken>",
        );
        assert!(parse_list_objects_v2_chirho(&xml_chirho).is_err());
    }

    #[test]
    fn refuses_entities_comments_and_tag_variants_chirho() {
        for body_chirho in [
            "<IsTruncated>false</IsTruncated><Contents><Key>a&amp;b</Key></Contents>",
            "<!-- x --><IsTruncated>false</IsTruncated>",
            "<![CDATA[x]]><IsTruncated>false</IsTruncated>",
            "<IsTruncated>false</IsTruncated><Key attr=\"v\">k</Key>",
            "<IsTruncated>false</IsTruncated><Key>unterminated",
            "<IsTruncated>maybe</IsTruncated>",
            "<Key>k</Key>",
        ] {
            let xml_chirho = page_chirho(body_chirho);
            assert!(
                parse_list_objects_v2_chirho(&xml_chirho).is_err(),
                "should refuse: {body_chirho}"
            );
        }
    }

    #[test]
    fn refuses_key_count_inconsistencies_chirho() {
        for body_chirho in [
            // Declared 3, returned 2.
            "<KeyCount>3</KeyCount><IsTruncated>false</IsTruncated>\
             <Contents><Key>a</Key></Contents><Contents><Key>b</Key></Contents>",
            "<KeyCount>x</KeyCount><IsTruncated>false</IsTruncated>",
            "<KeyCount>0</KeyCount><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated>",
        ] {
            let xml_chirho = page_chirho(body_chirho);
            assert!(
                parse_list_objects_v2_chirho(&xml_chirho).is_err(),
                "should refuse: {body_chirho}"
            );
        }
        let consistent_chirho = page_chirho(
            "<KeyCount>1</KeyCount><IsTruncated>false</IsTruncated><Contents><Key>a</Key></Contents>",
        );
        assert!(parse_list_objects_v2_chirho(&consistent_chirho).is_ok());
    }

    #[test]
    fn refuses_a_doubled_is_truncated_chirho() {
        let xml_chirho =
            page_chirho("<IsTruncated>false</IsTruncated><IsTruncated>false</IsTruncated>");
        assert!(parse_list_objects_v2_chirho(&xml_chirho).is_err());
    }
}
