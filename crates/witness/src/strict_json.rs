//! Strict JSON for everything a verifier decodes: duplicated object keys are refused. `serde_json` keeps the LAST value of a duplicated key,
//! a signature is checked on that value, and a reader that keeps the FIRST value would see a forged one (H1.3, finding V7). The scan runs on
//! text that is already valid JSON; keys are compared after unescaping, so `"a"` and `"a"` are the same key.

use std::collections::HashSet;

/// Does any object in this (valid) JSON text hold the same key twice?
pub fn has_duplicate_keys(text: &str) -> bool {
    let b = text.as_bytes();
    let mut stack: Vec<Option<HashSet<String>>> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'{' => stack.push(Some(HashSet::new())),
            b'[' => stack.push(None),
            b'}' | b']' => {
                stack.pop();
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                let end = i.min(b.len().saturating_sub(1));
                let mut j = end + 1;
                while j < b.len() && matches!(b[j], b' ' | b'\n' | b'\r' | b'\t') {
                    j += 1;
                }
                if j < b.len() && b[j] == b':' {
                    if let Some(Some(keys)) = stack.last_mut() {
                        let key = serde_json::from_str::<String>(&text[start..=end])
                            .unwrap_or_else(|_| text[start..=end].to_string());
                        if !keys.insert(key) {
                            return true;
                        }
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Parse JSON text into a value, refusing duplicated keys.
pub fn from_str(text: &str) -> Result<serde_json::Value, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if has_duplicate_keys(text) {
        return Err("duplicated object key".into());
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_duplicates_at_any_depth_and_escaped_equivalents() {
        assert!(has_duplicate_keys(r#"{"a":1,"a":2}"#));
        assert!(has_duplicate_keys(r#"{"a":1,"a":2}"#));
        assert!(has_duplicate_keys(r#"{"x":{"k":1,"k":1}}"#));
        assert!(has_duplicate_keys(r#"[{"k":1,"k":1}]"#));
        assert!(has_duplicate_keys("{\"a\" : 1,\n \"a\"\t:2}"));
    }

    #[test]
    fn accepts_the_same_key_in_different_objects_and_strings_that_look_like_keys() {
        assert!(!has_duplicate_keys(
            r#"{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}]}"#
        ));
        assert!(!has_duplicate_keys(r#"{"a":"x\":1,\"a\":2","b":"a"}"#));
        assert!(!has_duplicate_keys(r#"["a","a",{"a":1}]"#));
        assert!(!has_duplicate_keys("{}"));
        assert!(from_str(r#"{"a":1}"#).is_ok());
        assert!(from_str(r#"{"a":1,"a":2}"#).is_err());
    }
}
