//! `entropa-witnessd`: the witness service. Environment: `WITNESS_KEY_FILE` (hex seed of the witness key),
//! `WITNESS_LOGS` or `WITNESS_LOGS_FILE` (JSON: `[{"pubkey_hex":"...","allow_first":true}]`), `WITNESS_STATE_DIR` (default `/data/witness`),
//! `PORT` (default 8080), `BIND` (default 0.0.0.0). With the `aws` feature: `ENTROPA_KMS_KEY_ID` (sign with an AWS KMS ML-DSA-65
//! key instead of a key file) and `WITNESS_S3_BUCKET` (+ optional `WITNESS_S3_PREFIX`, `AWS_REGION`) for S3-backed state.
use entropa_core::Probe;
use entropa_witnessd::{app, FileStateStore, WitnessConfig};
use serde_json::Value;
use std::path::Path;

fn die(m: &str) -> ! {
    eprintln!("error: {m}");
    std::process::exit(1)
}

fn signer() -> Box<dyn entropa_core::CheckpointSigner + Send + Sync> {
    #[cfg(feature = "aws")]
    if std::env::var("ENTROPA_KMS_KEY_ID").is_ok() {
        use entropa_kms::aws::{AwsKmsClient, AwsKmsConfig};
        use entropa_kms::{KeySpec, KmsSigner};
        let cfg = AwsKmsConfig::from_vars(|k| std::env::var(k).ok())
            .unwrap_or_else(|e| die(&e.to_string()));
        let client = AwsKmsClient::connect(&cfg).unwrap_or_else(|e| die(&e.to_string()));
        let s = KmsSigner::new(client, KeySpec::MlDsa65).unwrap_or_else(|e| die(&e.to_string()));
        return Box::new(s);
    }
    let key_file =
        std::env::var("WITNESS_KEY_FILE").unwrap_or_else(|_| die("WITNESS_KEY_FILE is not set"));
    let seed =
        std::fs::read_to_string(&key_file).unwrap_or_else(|_| die("cannot read the witness key"));
    Box::new(
        Probe::from_signing_key_hex(seed.trim())
            .unwrap_or_else(|| die("the witness key is not valid")),
    )
}

fn main() {
    let signer = signer();
    // The list can be large (a post-quantum public key is about 3.9 KB), more than Lambda's 4 KB environment limit:
    // WITNESS_LOGS_FILE names a JSON file with the same content.
    let logs_json = match std::env::var("WITNESS_LOGS") {
        Ok(v) => v,
        Err(_) => std::env::var("WITNESS_LOGS_FILE")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_else(|| die("WITNESS_LOGS (or a readable WITNESS_LOGS_FILE) is not set")),
    };
    let v: Value =
        serde_json::from_str(&logs_json).unwrap_or_else(|_| die("WITNESS_LOGS is not JSON"));
    let logs = v
        .as_array()
        .unwrap_or_else(|| die("WITNESS_LOGS must be an array"))
        .iter()
        .map(|l| {
            (
                l["pubkey_hex"]
                    .as_str()
                    .unwrap_or_else(|| die("a log needs pubkey_hex"))
                    .to_string(),
                l["allow_first"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    #[cfg(feature = "aws")]
    let router = if let Ok(bucket) = std::env::var("WITNESS_S3_BUCKET") {
        let store = entropa_witnessd::s3::S3StateStore::connect(entropa_witnessd::s3::S3Config {
            bucket,
            prefix: std::env::var("WITNESS_S3_PREFIX").unwrap_or_default(),
            region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()),
            endpoint: std::env::var("WITNESS_S3_ENDPOINT")
                .ok()
                .filter(|e| !e.is_empty()),
        })
        .unwrap_or_else(|e| die(&e));
        app(WitnessConfig { logs }, store, signer).unwrap_or_else(|e| die(&e))
    } else {
        let dir =
            std::env::var("WITNESS_STATE_DIR").unwrap_or_else(|_| "/data/witness".to_string());
        let store = FileStateStore::open(Path::new(&dir)).unwrap_or_else(|e| die(&e));
        app(WitnessConfig { logs }, store, signer).unwrap_or_else(|e| die(&e))
    };
    #[cfg(not(feature = "aws"))]
    let router = {
        let dir =
            std::env::var("WITNESS_STATE_DIR").unwrap_or_else(|_| "/data/witness".to_string());
        let store = FileStateStore::open(Path::new(&dir)).unwrap_or_else(|e| die(&e));
        app(WitnessConfig { logs }, store, signer).unwrap_or_else(|e| die(&e))
    };
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);
    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0".to_string());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap_or_else(|_| die("no runtime"));
    let r = rt.block_on(async move {
        let l = tokio::net::TcpListener::bind((bind.as_str(), port)).await?;
        axum::serve(l, router).await
    });
    if r.is_err() {
        die("server stopped");
    }
}
