//! Real AWS KMS client behind the `aws` feature (ADR 0012, 0013).
//!
//! Pure, offline-testable pieces live at the top (config, error mapping, request and
//! response checks); [`AwsKmsClient`] is the thin network layer on top of them.
//! Credentials come only from the standard environment variables; nothing here reads a file.

use crate::{raw_key_from_spki, KmsClient, KmsError};
use aws_config::environment::EnvironmentVariableCredentialsProvider;
use aws_config::retry::RetryConfig;
use aws_config::timeout::TimeoutConfig;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeySpec, MessageType, SigningAlgorithmSpec};
use entropa_core::signer::RAW_SIGN_LIMIT_BYTES;
use std::time::Duration;

/// Region used when `AWS_REGION` is unset (the key lives in us-west-2).
pub const DEFAULT_REGION: &str = "us-west-2";
/// The only signing algorithm Entropa uses with KMS ML-DSA keys.
pub const SIGNING_ALGORITHM: &str = "ML_DSA_SHAKE_256";
/// Messages are sent raw (not pre-digested).
pub const MESSAGE_TYPE: &str = "RAW";
/// The key spec KMS must report for the key.
pub const KEY_SPEC: &str = "ML_DSA_65";

/// Connection settings, parsed from the environment by [`AwsKmsConfig::from_vars`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsKmsConfig {
    /// Key id, key ARN or `alias/...` name (from `ENTROPA_KMS_KEY_ID`).
    pub key_id: String,
    /// AWS region (from `AWS_REGION`, default [`DEFAULT_REGION`]).
    pub region: String,
    /// Per-attempt operation timeout.
    pub timeout: Duration,
}

impl AwsKmsConfig {
    /// Parse settings from a variable lookup (pass `|k| std::env::var(k).ok()`).
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Self, KmsError> {
        let key_id = get("ENTROPA_KMS_KEY_ID")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                KmsError("ENTROPA_KMS_KEY_ID is not set (key id, ARN or alias)".into())
            })?;
        let region = get("AWS_REGION")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_REGION.to_string());
        Ok(Self {
            key_id,
            region,
            timeout: Duration::from_secs(10),
        })
    }
}

fn is_throttle(code: &str) -> bool {
    matches!(
        code,
        "ThrottlingException" | "LimitExceededException" | "RequestLimitExceeded"
    )
}

/// Map an SDK error code to a [`KmsError`] that carries the operation and AWS error code only.
/// The SDK's free-text message is dropped on purpose: it can contain ARNs and account ids.
pub fn map_error(operation: &'static str, code: Option<&str>) -> KmsError {
    // Only short alphanumeric codes are echoed; anything else is treated as unknown.
    let code = code.filter(|c| {
        !c.is_empty() && c.len() <= 64 && c.chars().all(|ch| ch.is_ascii_alphanumeric())
    });
    KmsError(match code {
        Some(c) if is_throttle(c) => format!("{operation} throttled ({c})"),
        Some(c @ ("AccessDeniedException" | "AccessDenied")) => {
            format!("{operation} access denied ({c})")
        }
        Some(c) => format!("{operation} failed ({c})"),
        None => format!("{operation} failed"),
    })
}

/// Validate a message before any network call (raw limit 4096 bytes).
pub fn check_sign_message(msg: &[u8]) -> Result<(), KmsError> {
    if msg.len() > RAW_SIGN_LIMIT_BYTES {
        return Err(KmsError(format!(
            "message of {} bytes exceeds the {RAW_SIGN_LIMIT_BYTES}-byte raw signing limit",
            msg.len()
        )));
    }
    Ok(())
}

/// Turn a `GetPublicKey` answer into the raw 1952-byte ML-DSA-65 key: the reported key spec
/// (when present) must be [`KEY_SPEC`], and the SPKI must strip via `raw_key_from_spki`.
pub fn raw_key_from_get_public_key(
    key_spec: Option<&str>,
    spki: &[u8],
) -> Result<Vec<u8>, KmsError> {
    if let Some(spec) = key_spec {
        if spec != KEY_SPEC {
            return Err(KmsError(format!("key spec is {spec}, expected {KEY_SPEC}")));
        }
    }
    raw_key_from_spki(spki)
}

/// Error label for an SDK error: the AWS error code, or the failure class for transport errors.
fn label<E, R>(e: &SdkError<E, R>) -> Option<String>
where
    E: ProvideErrorMetadata,
{
    e.code().map(str::to_owned).or_else(|| match e {
        SdkError::TimeoutError(_) => Some("TimeoutError".into()),
        SdkError::DispatchFailure(_) => Some("DispatchFailure".into()),
        _ => None,
    })
}

/// A [`KmsClient`] backed by a real AWS KMS key. Synchronous: it owns a private current-thread
/// tokio runtime (ADR 0013), so call it from `spawn_blocking` when inside async code.
pub struct AwsKmsClient {
    client: aws_sdk_kms::Client,
    runtime: tokio::runtime::Runtime,
    key_id: String,
}

impl std::fmt::Debug for AwsKmsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsClient")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl AwsKmsClient {
    /// Build a client. Credentials come ONLY from the AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
    /// and AWS_SESSION_TOKEN environment variables (no profile or config files are read).
    pub fn connect(cfg: &AwsKmsConfig) -> Result<Self, KmsError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| KmsError("could not start the KMS runtime".into()))?;
        let timeouts = TimeoutConfig::builder()
            .operation_attempt_timeout(cfg.timeout)
            .operation_timeout(cfg.timeout * 3)
            .build();
        // The SDK builds its HTTP client lazily, inside the runtime.
        let conf = {
            let _guard = runtime.enter();
            aws_sdk_kms::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(cfg.region.clone()))
                .credentials_provider(EnvironmentVariableCredentialsProvider::new())
                .timeout_config(timeouts)
                .retry_config(RetryConfig::standard())
                .build()
        };
        Ok(Self {
            client: aws_sdk_kms::Client::from_conf(conf),
            runtime,
            key_id: cfg.key_id.clone(),
        })
    }
}

impl KmsClient for AwsKmsClient {
    fn public_key_raw(&self) -> Result<Vec<u8>, KmsError> {
        let out = self
            .runtime
            .block_on(self.client.get_public_key().key_id(&self.key_id).send())
            .map_err(|e| map_error("GetPublicKey", label(&e).as_deref()))?;
        let spki = out
            .public_key()
            .ok_or_else(|| KmsError("GetPublicKey returned no public key".into()))?;
        raw_key_from_get_public_key(out.key_spec().map(KeySpec::as_str), spki.as_ref())
    }

    fn sign_raw(&self, msg: &[u8]) -> Result<Vec<u8>, KmsError> {
        check_sign_message(msg)?;
        let out = self
            .runtime
            .block_on(
                self.client
                    .sign()
                    .key_id(&self.key_id)
                    .message(Blob::new(msg))
                    .message_type(MessageType::Raw)
                    .signing_algorithm(SigningAlgorithmSpec::MlDsaShake256)
                    .send(),
            )
            .map_err(|e| map_error("Sign", label(&e).as_deref()))?;
        out.signature()
            .map(|b| b.as_ref().to_vec())
            .ok_or_else(|| KmsError("Sign returned no signature".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SPKI_PREFIX};
    use std::collections::HashMap;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn config_defaults_the_region_to_us_west_2() {
        let c = AwsKmsConfig::from_vars(vars(&[(
            "ENTROPA_KMS_KEY_ID",
            "alias/entropa-checkpoint-signer",
        )]))
        .unwrap();
        assert_eq!(c.region, "us-west-2");
        assert_eq!(c.key_id, "alias/entropa-checkpoint-signer");
        assert!(c.timeout >= Duration::from_secs(1));
    }

    #[test]
    fn config_takes_an_explicit_region() {
        let c = AwsKmsConfig::from_vars(vars(&[
            ("ENTROPA_KMS_KEY_ID", "1234abcd-12ab-34cd-56ef-1234567890ab"),
            ("AWS_REGION", "eu-west-1"),
        ]))
        .unwrap();
        assert_eq!(c.region, "eu-west-1");
    }

    #[test]
    fn config_requires_a_key_id_and_rejects_a_blank_one() {
        assert!(AwsKmsConfig::from_vars(vars(&[])).is_err());
        assert!(AwsKmsConfig::from_vars(vars(&[("ENTROPA_KMS_KEY_ID", "   ")])).is_err());
    }

    #[test]
    fn config_error_names_the_variable_not_a_value() {
        let e = AwsKmsConfig::from_vars(vars(&[])).unwrap_err();
        assert!(e.0.contains("ENTROPA_KMS_KEY_ID"), "{e}");
    }

    #[test]
    fn throttling_and_access_denied_map_to_distinct_readable_errors() {
        let t = map_error("Sign", Some("ThrottlingException"));
        let a = map_error("GetPublicKey", Some("AccessDeniedException"));
        assert!(t.0.to_lowercase().contains("throttl"), "{t}");
        assert!(t.0.contains("Sign"), "{t}");
        assert!(a.0.to_lowercase().contains("access denied"), "{a}");
        assert!(a.0.contains("GetPublicKey"), "{a}");
        assert_ne!(t, a);
    }

    #[test]
    fn other_codes_are_reported_by_code_and_unknown_is_generic() {
        let d = map_error("Sign", Some("DisabledException"));
        assert!(d.0.contains("DisabledException"), "{d}");
        let u = map_error("Sign", None);
        assert!(u.0.contains("Sign"), "{u}");
    }

    #[test]
    fn error_messages_never_carry_free_text_secrets() {
        // Only the code is accepted, so a secret in an SDK message cannot reach the output.
        let e = map_error("Sign", Some("AccessDeniedException"));
        for needle in ["arn:aws", "AKIA", "ASIA", "secret", "token"] {
            assert!(!e.0.contains(needle), "leaked {needle}: {e}");
        }
    }

    #[test]
    fn sign_rejects_messages_over_4096_bytes_before_any_network_call() {
        assert!(check_sign_message(&vec![0u8; 4096]).is_ok());
        assert!(check_sign_message(&[]).is_ok());
        assert!(check_sign_message(&vec![0u8; 4097]).is_err());
    }

    #[test]
    fn request_constants_are_raw_and_ml_dsa_shake_256() {
        assert_eq!(MESSAGE_TYPE, "RAW");
        assert_eq!(SIGNING_ALGORITHM, "ML_DSA_SHAKE_256");
    }

    fn spki() -> Vec<u8> {
        let mut der = ML_DSA_65_SPKI_PREFIX.to_vec();
        der.extend(vec![5u8; ML_DSA_65_PUBLIC_KEY_BYTES]);
        der
    }

    #[test]
    fn the_public_key_is_stripped_with_raw_key_from_spki() {
        let raw = raw_key_from_get_public_key(Some("ML_DSA_65"), &spki()).unwrap();
        assert_eq!(raw.len(), ML_DSA_65_PUBLIC_KEY_BYTES);
        assert!(raw.iter().all(|b| *b == 5));
        assert!(raw_key_from_get_public_key(None, &spki()).is_ok());
    }

    #[test]
    fn a_non_ml_dsa_65_key_is_rejected() {
        assert!(raw_key_from_get_public_key(Some("ML_DSA_44"), &spki()).is_err());
        assert!(raw_key_from_get_public_key(Some("RSA_2048"), &spki()).is_err());
        let mut wrong_prefix = spki();
        wrong_prefix[5] ^= 1;
        assert!(raw_key_from_get_public_key(Some("ML_DSA_65"), &wrong_prefix).is_err());
        assert!(raw_key_from_get_public_key(Some("ML_DSA_65"), &[1, 2, 3]).is_err());
    }
}
