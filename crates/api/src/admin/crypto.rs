//! Key hashing/generation and slug derivation for partner records.

/// BLAKE3 hex hash of a raw API key — this, never the plaintext key, is what gets
/// stored in Firestore. A database read alone can never leak a live credential.
pub fn hash_key(raw_key: &str) -> String {
    hex::encode(blake3::hash(raw_key.as_bytes()).as_bytes())
}

/// Generate a new raw API key — 24 random bytes, hex-encoded, same shape as
/// `PARTNER_KEYS.md`'s existing manually-generated keys (`openssl rand -hex 24`).
pub fn generate_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Turns a display name into a URL-safe, `ENTROPA_API_KEYS`-name-safe slug:
/// lowercase, non-alphanumeric runs collapsed to a single `-`, no leading/trailing
/// `-`. Falls back to `"partner"` if nothing alphanumeric survives.
pub fn slugify(name: &str) -> String {
    let mut slug = String::new();
    let mut last_was_dash = true; // suppresses a leading dash
    for c in name.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c);
            last_was_dash = false;
        } else if !last_was_dash {
            slug.push('-');
            last_was_dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "partner".to_string()
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_key_is_deterministic_and_never_reversible_looking() {
        let key = "abc123";
        assert_eq!(hash_key(key), hash_key(key));
        assert_ne!(hash_key(key), key);
    }

    #[test]
    fn hash_key_differs_for_different_keys() {
        assert_ne!(hash_key("key-a"), hash_key("key-b"));
    }

    #[test]
    fn generate_key_produces_48_hex_chars() {
        let key = generate_key();
        assert_eq!(key.len(), 48);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_key_is_random_each_time() {
        assert_ne!(generate_key(), generate_key());
    }

    #[test]
    fn slugify_basic_name() {
        assert_eq!(slugify("Acme Corp"), "acme-corp");
    }

    #[test]
    fn slugify_collapses_punctuation_and_case() {
        assert_eq!(slugify("Acme, Corp!! (Demo)"), "acme-corp-demo");
    }

    #[test]
    fn slugify_trims_trailing_dash() {
        assert_eq!(slugify("Trailing---"), "trailing");
    }

    #[test]
    fn slugify_falls_back_when_nothing_alphanumeric_survives() {
        assert_eq!(slugify("!!!"), "partner");
    }
}
