//! Google Cloud KMS client (`PQ_SIGN_ML_DSA_65`) behind the `gcp` feature.
//!
//! The parsing and request pieces are pure and tested against responses recorded from the real service; the
//! network layer is thin. Credentials: on Cloud Run the access token comes from the metadata server; elsewhere
//! (tests, a workstation) it can be supplied in `GCP_ACCESS_TOKEN`. Nothing here reads a key file.

use crate::{KmsClient, KmsError};
use base64::Engine;
use entropa_core::signer::RAW_SIGN_LIMIT_BYTES;
use serde_json::Value;
use std::time::Duration;

/// The public-key format that returns the raw FIPS 204 key.
pub const PUBLIC_KEY_FORMAT: &str = "NIST_PQC";
const API: &str = "https://cloudkms.googleapis.com/v1";

/// Settings parsed from the environment by [`GcpKmsConfig::from_vars`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcpKmsConfig {
    /// Full key-version resource name (`projects/.../cryptoKeys/K/cryptoKeyVersions/N`), from `ENTROPA_GCP_KMS_KEY`.
    pub key_version: String,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl GcpKmsConfig {
    /// Parse settings from a variable lookup (pass `|k| std::env::var(k).ok()`).
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Self, KmsError> {
        let v = get("ENTROPA_GCP_KMS_KEY")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| KmsError("ENTROPA_GCP_KMS_KEY is not set".into()))?;
        let parts: Vec<&str> = v.split('/').collect();
        let shape = parts.len() == 10
            && parts[0] == "projects"
            && parts[2] == "locations"
            && parts[4] == "keyRings"
            && parts[6] == "cryptoKeys"
            && parts[8] == "cryptoKeyVersions"
            && parts.iter().all(|p| {
                !p.is_empty()
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            });
        if !shape {
            return Err(KmsError(
                "ENTROPA_GCP_KMS_KEY must be a full cryptoKeyVersions resource name".into(),
            ));
        }
        Ok(Self {
            key_version: v,
            timeout: Duration::from_secs(10),
        })
    }
}

fn bad(what: &str) -> KmsError {
    KmsError(format!("unexpected {what} response"))
}

fn b64(v: &Value) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str()?)
        .ok()
}

/// Parse a `publicKey` response (format [`PUBLIC_KEY_FORMAT`]) into the raw 1,952-byte ML-DSA-65 key.
pub fn parse_public_key_response(body: &str) -> Result<Vec<u8>, KmsError> {
    let v: Value = serde_json::from_str(body).map_err(|_| bad("public key"))?;
    let raw = b64(&v["publicKey"]["data"]).ok_or_else(|| bad("public key"))?;
    if raw.len() != crate::ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(bad("public key"));
    }
    Ok(raw)
}

/// Parse an `asymmetricSign` response into the raw 3,309-byte ML-DSA-65 signature.
pub fn parse_sign_response(body: &str) -> Result<Vec<u8>, KmsError> {
    let v: Value = serde_json::from_str(body).map_err(|_| bad("signature"))?;
    let sig = b64(&v["signature"]).ok_or_else(|| bad("signature"))?;
    if sig.len() != crate::ML_DSA_65_SIGNATURE_BYTES {
        return Err(bad("signature"));
    }
    Ok(sig)
}

/// The JSON body of an `asymmetricSign` request for a raw message.
pub fn sign_request_body(msg: &[u8]) -> String {
    format!(
        "{{\"data\":\"{}\"}}",
        base64::engine::general_purpose::STANDARD.encode(msg)
    )
}

/// The network client.
pub struct GcpKmsClient {
    cfg: GcpKmsConfig,
}

impl GcpKmsClient {
    /// Build from a parsed configuration.
    pub fn new(cfg: GcpKmsConfig) -> Self {
        Self { cfg }
    }

    fn token(&self) -> Result<String, KmsError> {
        if let Ok(t) = std::env::var("GCP_ACCESS_TOKEN") {
            if !t.trim().is_empty() {
                return Ok(t.trim().to_string());
            }
        }
        let r = reqwest::blocking::Client::new()
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .timeout(self.cfg.timeout)
            .send()
            .map_err(|_| KmsError("no credentials: metadata server unreachable".into()))?;
        let v: Value = r.json().map_err(|_| bad("token"))?;
        v["access_token"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| bad("token"))
    }

    fn call(&self, req: reqwest::blocking::RequestBuilder) -> Result<String, KmsError> {
        let resp = req
            .bearer_auth(self.token()?)
            .timeout(self.cfg.timeout)
            .send()
            .map_err(|_| KmsError("request to Cloud KMS failed".into()))?;
        let status = resp.status();
        let text = resp.text().map_err(|_| bad("body"))?;
        if !status.is_success() {
            // Google's error status code is safe to show (for example PERMISSION_DENIED); the message is not echoed.
            let code = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v["error"]["status"].as_str().map(str::to_string))
                .unwrap_or_default();
            return Err(KmsError(format!(
                "Cloud KMS returned HTTP {} {}",
                status.as_u16(),
                code
            )));
        }
        Ok(text)
    }
}

impl KmsClient for GcpKmsClient {
    fn public_key_raw(&self) -> Result<Vec<u8>, KmsError> {
        let url = format!(
            "{API}/{}/publicKey?publicKeyFormat={PUBLIC_KEY_FORMAT}",
            self.cfg.key_version
        );
        parse_public_key_response(&self.call(reqwest::blocking::Client::new().get(url))?)
    }

    fn sign_raw(&self, msg: &[u8]) -> Result<Vec<u8>, KmsError> {
        if msg.len() > RAW_SIGN_LIMIT_BYTES {
            return Err(KmsError("message exceeds the raw signing limit".into()));
        }
        let url = format!("{API}/{}:asymmetricSign", self.cfg.key_version);
        let req = reqwest::blocking::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(sign_request_body(msg));
        parse_sign_response(&self.call(req)?)
    }
}
