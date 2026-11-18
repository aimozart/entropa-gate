//! State in S3 (feature `aws`): one small object per log, replaced with a conditional write so that two writers
//! cannot both win. The version tag is the object's ETag. Equivocation evidence is one small object per event
//! (S3 cannot append), capped at the same count as the file store. Credentials come from the environment only.

use crate::{check_id, fail, MAX_EVIDENCE_LINES};
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use entropa_witness::{State, StateStore, StoreError};

/// Connection settings.
#[derive(Debug, Clone)]
pub struct S3Config {
    /// Bucket name.
    pub bucket: String,
    /// Key prefix (for example `witness/`), may be empty.
    pub prefix: String,
    /// Region.
    pub region: String,
    /// Endpoint override, for a local S3-compatible server in tests. Empty means real AWS.
    pub endpoint: Option<String>,
}

/// S3-backed [`StateStore`]. Synchronous: it owns a private runtime, so call it from `spawn_blocking`.
pub struct S3StateStore {
    client: Client,
    rt: tokio::runtime::Runtime,
    cfg: S3Config,
}

impl S3StateStore {
    /// Build the client. Credentials: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` (set by Lambda).
    pub fn connect(cfg: S3Config) -> Result<Self, String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "could not start the S3 runtime".to_string())?;
        let key = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| "AWS_ACCESS_KEY_ID is not set".to_string())?;
        let secret = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| "AWS_SECRET_ACCESS_KEY is not set".to_string())?;
        let token = std::env::var("AWS_SESSION_TOKEN").ok();
        let conf = {
            let _g = rt.enter();
            let mut b = aws_sdk_s3::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(cfg.region.clone()))
                .credentials_provider(Credentials::new(key, secret, token, None, "env"));
            if let Some(ep) = &cfg.endpoint {
                b = b.endpoint_url(ep.clone()).force_path_style(true);
            }
            b.build()
        };
        Ok(Self {
            client: Client::from_conf(conf),
            rt,
            cfg,
        })
    }

    fn key(&self, log_id: &str) -> String {
        format!("{}{log_id}.state", self.cfg.prefix)
    }
}

fn is_precondition<E: ProvideErrorMetadata, R>(e: &SdkError<E, R>) -> bool {
    matches!(
        e.code(),
        Some("PreconditionFailed" | "ConditionalRequestConflict")
    )
}

fn parse(text: &str) -> Result<State, StoreError> {
    let mut it = text.split_whitespace();
    let size: usize = it
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| fail("corrupt state"))?;
    let raw = hex::decode(it.next().ok_or_else(|| fail("corrupt state"))?)
        .map_err(|_| fail("corrupt state"))?;
    if raw.len() != 32 {
        return Err(fail("corrupt state"));
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&raw);
    Ok(State { size, root })
}

impl StateStore for S3StateStore {
    fn get(&self, log_id: &str) -> Result<Option<(State, String)>, StoreError> {
        check_id(log_id)?;
        let out = self.rt.block_on(
            self.client
                .get_object()
                .bucket(&self.cfg.bucket)
                .key(self.key(log_id))
                .send(),
        );
        match out {
            Ok(o) => {
                let etag = o
                    .e_tag()
                    .map(str::to_owned)
                    .ok_or_else(|| fail("no version tag"))?;
                let bytes = self
                    .rt
                    .block_on(o.body.collect())
                    .map_err(|_| fail("cannot read the state"))?
                    .into_bytes();
                let text = String::from_utf8(bytes.to_vec()).map_err(|_| fail("corrupt state"))?;
                Ok(Some((parse(&text)?, etag)))
            }
            Err(e) if matches!(e.code(), Some("NoSuchKey" | "NotFound")) => Ok(None),
            Err(_) => Err(fail("cannot read the state")),
        }
    }

    fn compare_and_swap(
        &self,
        log_id: &str,
        expected: Option<&str>,
        new: &State,
    ) -> Result<(), StoreError> {
        check_id(log_id)?;
        let mut req = self
            .client
            .put_object()
            .bucket(&self.cfg.bucket)
            .key(self.key(log_id))
            .body(ByteStream::from(
                format!("{} {}\n", new.size, hex::encode(new.root)).into_bytes(),
            ));
        req = match expected {
            Some(tag) => req.if_match(tag),
            None => req.if_none_match("*"),
        };
        match self.rt.block_on(req.send()) {
            Ok(_) => Ok(()),
            Err(e) if is_precondition(&e) => Err(StoreError::Conflict),
            Err(_) => Err(fail("cannot write the state")),
        }
    }

    fn record_equivocation(&self, log_id: &str, evidence: &str) -> Result<(), StoreError> {
        check_id(log_id)?;
        let prefix = format!("{}{log_id}.equivocation/", self.cfg.prefix);
        let listed = self
            .rt
            .block_on(
                self.client
                    .list_objects_v2()
                    .bucket(&self.cfg.bucket)
                    .prefix(&prefix)
                    .max_keys(MAX_EVIDENCE_LINES as i32)
                    .send(),
            )
            .map_err(|_| fail("cannot record evidence"))?;
        if listed.key_count().unwrap_or(0) as usize >= MAX_EVIDENCE_LINES {
            return Ok(()); // capped so a flood of bad proofs cannot grow the bucket without bound
        }
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        self.rt
            .block_on(
                self.client
                    .put_object()
                    .bucket(&self.cfg.bucket)
                    .key(format!("{prefix}{n}"))
                    .body(ByteStream::from(
                        evidence.replace(['\n', '\r'], " ").into_bytes(),
                    ))
                    .send(),
            )
            .map(|_| ())
            .map_err(|_| fail("cannot record evidence"))
    }
}
