//! The exact byte encoding of a stored record (format v2, see docs/adr/0011-record-encoding-v2.md).
//!
//! A record is `(payload, label)`; its single valid encoding is
//! `0x02 || u32be(len payload) || payload || flag || [u32be(len label) || label]`
//! with `flag` 0 (no label) or 1 (label follows). Since these bytes are exactly what gets
//! hashed into a Merkle leaf, the encoding must be injective (different records never share
//! bytes) and canonical (every accepted byte string re-encodes to itself), otherwise
//! independent verification ("hash your own copy and compare") is meaningless.
//!
//! `label` is optional customer-disclosed metadata (e.g. "loan-underwriting:approved") --
//! never the customer's sensitive data, which stays an opaque hash in `payload`. Folding it
//! into the same leaf means a label cannot change after the fact without breaking the
//! record's own proof.

/// Version byte of this format. (v1, the NUL-joined form, carried no tag.)
pub const RECORD_FORMAT_VERSION: u8 = 2;
/// Maximum length in bytes of the payload and, separately, of the label.
pub const MAX_FIELD_BYTES: usize = 1 << 20;

const FLAG_NO_LABEL: u8 = 0;
const FLAG_LABEL: u8 = 1;

/// Why a record could not be encoded or decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The payload or label is longer than [`MAX_FIELD_BYTES`].
    #[error("{field} of {len} bytes exceeds the {MAX_FIELD_BYTES}-byte limit")]
    FieldTooLarge {
        /// Which field: `"payload"` or `"label"`.
        field: &'static str,
        /// The offending length in bytes.
        len: usize,
    },
    /// The input ended before the structure was complete.
    #[error("record is truncated")]
    Truncated,
    /// The first byte is not [`RECORD_FORMAT_VERSION`].
    #[error("unknown record format version {0}")]
    UnknownVersion(u8),
    /// The label flag byte is neither 0 nor 1.
    #[error("invalid label flag {0}")]
    BadFlag(u8),
    /// A field is not valid UTF-8.
    #[error("{0} is not valid UTF-8")]
    InvalidUtf8(&'static str),
    /// Bytes remain after the record ended.
    #[error("{0} trailing bytes after the record")]
    TrailingBytes(usize),
}

fn push_field(out: &mut Vec<u8>, field: &'static str, bytes: &[u8]) -> Result<(), RecordError> {
    if bytes.len() > MAX_FIELD_BYTES {
        return Err(RecordError::FieldTooLarge {
            field,
            len: bytes.len(),
        });
    }
    // MAX_FIELD_BYTES < u32::MAX, so this cast is lossless.
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Encodes `(payload, label)` into the exact bytes that get hashed as a Merkle leaf.
/// `None` and `Some("")` are different records and encode differently.
pub fn encode_record(payload: &str, label: Option<&str>) -> Result<Vec<u8>, RecordError> {
    let mut out = Vec::with_capacity(10 + payload.len() + label.map_or(0, str::len));
    out.push(RECORD_FORMAT_VERSION);
    push_field(&mut out, "payload", payload.as_bytes())?;
    match label {
        None => out.push(FLAG_NO_LABEL),
        Some(l) => {
            out.push(FLAG_LABEL);
            push_field(&mut out, "label", l.as_bytes())?;
        }
    }
    Ok(out)
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8], RecordError> {
    if bytes.len() < n {
        return Err(RecordError::Truncated);
    }
    let (head, rest) = bytes.split_at(n);
    *bytes = rest;
    Ok(head)
}

fn take_field(bytes: &mut &[u8], field: &'static str) -> Result<String, RecordError> {
    let len_bytes: [u8; 4] = take(bytes, 4)?
        .try_into()
        .map_err(|_| RecordError::Truncated)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FIELD_BYTES {
        return Err(RecordError::FieldTooLarge { field, len });
    }
    let raw = take(bytes, len)?;
    std::str::from_utf8(raw)
        .map(str::to_owned)
        .map_err(|_| RecordError::InvalidUtf8(field))
}

/// Strict decoder: accepts exactly the byte strings [`encode_record`] can produce.
pub fn decode_record(bytes: &[u8]) -> Result<(String, Option<String>), RecordError> {
    let mut rest = bytes;
    let version = take(&mut rest, 1)?[0];
    if version != RECORD_FORMAT_VERSION {
        return Err(RecordError::UnknownVersion(version));
    }
    let payload = take_field(&mut rest, "payload")?;
    let flag = take(&mut rest, 1)?[0];
    let label = match flag {
        FLAG_NO_LABEL => None,
        FLAG_LABEL => Some(take_field(&mut rest, "label")?),
        other => return Err(RecordError::BadFlag(other)),
    };
    if !rest.is_empty() {
        return Err(RecordError::TrailingBytes(rest.len()));
    }
    Ok((payload, label))
}

/// Display-only decode: bytes that are not a valid record show as an empty payload with the
/// label `ENTROPA_UNDECODABLE_RECORD`, so views never panic or silently show wrong content.
/// Never use this for verification; the leaf hash is always over the raw bytes.
pub fn decode_record_or_marker(bytes: &[u8]) -> (String, Option<String>) {
    decode_record(bytes).unwrap_or_else(|_| {
        (
            String::new(),
            Some("ENTROPA_UNDECODABLE_RECORD".to_string()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(p: &str, l: Option<&str>) -> Vec<u8> {
        encode_record(p, l).unwrap()
    }

    #[test]
    fn f4_the_old_colliding_pair_now_encodes_differently() {
        assert_ne!(enc("a\0b", None), enc("a", Some("b\0")));
    }

    #[test]
    fn round_trips_with_and_without_a_label() {
        for (p, l) in [
            ("abc123hash", Some("loan-underwriting:approved")),
            ("abc123hash", None),
            ("", None),
            ("", Some("")),
            ("a\0b\u{2}\u{1}", Some("\0\u{2}é")),
        ] {
            assert_eq!(
                decode_record(&enc(p, l)),
                Ok((p.to_string(), l.map(str::to_string)))
            );
        }
    }

    #[test]
    fn an_empty_label_is_a_different_record_from_no_label() {
        assert_ne!(enc("p", Some("")), enc("p", None));
    }

    #[test]
    fn two_different_labels_produce_two_different_encodings() {
        assert_ne!(enc("same", Some("approved")), enc("same", Some("denied")));
    }

    #[test]
    fn the_decoder_rejects_every_malformed_shape() {
        let good = enc("ab", Some("cd"));
        assert_eq!(decode_record(&[]), Err(RecordError::Truncated));
        let mut bad_version = good.clone();
        bad_version[0] = 1;
        assert_eq!(
            decode_record(&bad_version),
            Err(RecordError::UnknownVersion(1))
        );
        for cut in 1..good.len() {
            assert!(decode_record(&good[..cut]).is_err(), "truncated at {cut}");
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(decode_record(&trailing), Err(RecordError::TrailingBytes(1)));
        let mut bad_flag = enc("ab", None);
        *bad_flag.last_mut().unwrap() = 2;
        assert_eq!(decode_record(&bad_flag), Err(RecordError::BadFlag(2)));
        let mut bad_utf8 = enc("ab", None);
        bad_utf8[5] = 0xff;
        assert_eq!(
            decode_record(&bad_utf8),
            Err(RecordError::InvalidUtf8("payload"))
        );
        let mut bad_label_utf8 = enc("a", Some("b"));
        let n = bad_label_utf8.len();
        bad_label_utf8[n - 1] = 0xff;
        assert_eq!(
            decode_record(&bad_label_utf8),
            Err(RecordError::InvalidUtf8("label"))
        );
        // old v1 bytes are not accepted
        assert!(decode_record(b"abc123hash\0label").is_err());
    }

    #[test]
    fn the_decoder_rejects_oversize_length_prefixes_without_allocating() {
        let mut huge = vec![RECORD_FORMAT_VERSION];
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            decode_record(&huge),
            Err(RecordError::FieldTooLarge {
                field: "payload",
                ..
            })
        ));
    }

    #[test]
    fn size_limits_are_enforced_at_the_boundary() {
        let at_limit = "x".repeat(MAX_FIELD_BYTES);
        assert!(encode_record(&at_limit, Some(&at_limit)).is_ok());
        let over = "x".repeat(MAX_FIELD_BYTES + 1);
        assert!(matches!(
            encode_record(&over, None),
            Err(RecordError::FieldTooLarge {
                field: "payload",
                ..
            })
        ));
        assert!(matches!(
            encode_record("", Some(&over)),
            Err(RecordError::FieldTooLarge { field: "label", .. })
        ));
        // and the decoder enforces the same limit
        let max = encode_record(&at_limit, Some(&at_limit)).unwrap();
        assert!(decode_record(&max).is_ok());
    }

    #[test]
    fn display_helper_marks_undecodable_bytes() {
        assert_eq!(
            decode_record_or_marker(b"junk"),
            (
                String::new(),
                Some("ENTROPA_UNDECODABLE_RECORD".to_string())
            )
        );
        assert_eq!(
            decode_record_or_marker(&enc("p", None)),
            ("p".to_string(), None)
        );
    }
}
