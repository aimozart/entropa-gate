//! S2 (a stage record (not published)): release supply chain with the tools already on the machine. No network, no clock, no randomness in any output.
use entropa_core::CheckpointSigner;
use std::path::{Path, PathBuf};

/// Why a release step failed (closed list; never echoes file contents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    /// The lock file is not a valid Cargo.lock.
    Lock(String),
    /// The cargo metadata text is not valid.
    Metadata(String),
    /// Two things that must agree do not (SBOM against metadata, manifest against files).
    Mismatch(String),
    /// The manifest or envelope is malformed or too large.
    Manifest(String),
    /// A signature does not verify.
    Signature(String),
    /// A tool or file failed.
    Io(String),
}
impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ReleaseError {}

/// One dependency of the build.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Component {
    /// Crate name.
    pub name: String,
    /// Exact version.
    pub version: String,
    /// Registry or git source (None for a workspace member).
    pub source: Option<String>,
    /// The sha256 recorded in Cargo.lock (None for a workspace member or a git source).
    pub checksum: Option<String>,
}

/// SBOM from the lock file.
pub mod sbom {
    use super::{Component, ReleaseError};
    use serde_json::{json, Value};
    use std::collections::BTreeSet;

    const SOURCE_PROP: &str = "cargo:source";

    /// Every `[[package]]` of a Cargo.lock, sorted by name and version.
    pub fn from_lock(lock: &str) -> Result<Vec<Component>, ReleaseError> {
        let bad = |m: &str| ReleaseError::Lock(m.to_string());
        let t: toml::Table = lock.parse().map_err(|_| bad("not valid TOML"))?;
        let pkgs = t
            .get("package")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| bad("no [[package]] entries"))?;
        let mut out = Vec::with_capacity(pkgs.len());
        for p in pkgs {
            let get = |k: &str| p.get(k).and_then(toml::Value::as_str).map(str::to_string);
            out.push(Component {
                name: get("name").ok_or_else(|| bad("a package has no name"))?,
                version: get("version").ok_or_else(|| bad("a package has no version"))?,
                source: get("source"),
                checksum: get("checksum"),
            });
        }
        if out.is_empty() {
            return Err(bad("no [[package]] entries"));
        }
        out.sort();
        Ok(out)
    }

    fn purl(c: &Component) -> String {
        format!("pkg:cargo/{}@{}", c.name, c.version)
    }

    /// A CycloneDX 1.5 JSON document, byte-for-byte deterministic (no timestamp, no random serial).
    pub fn to_cyclonedx(
        components: &[Component],
        product: &str,
        version: &str,
    ) -> Result<String, ReleaseError> {
        let comps: Vec<Value> = components
            .iter()
            .map(|c| {
                let mut o = json!({"type": "library", "name": c.name, "version": c.version, "purl": purl(c)});
                if let Some(h) = &c.checksum {
                    o["hashes"] = json!([{"alg": "SHA-256", "content": h}]);
                }
                if let Some(src) = &c.source {
                    o["properties"] = json!([{"name": SOURCE_PROP, "value": src}]);
                }
                o
            })
            .collect();
        let doc = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {"component": {"type": "application", "name": product, "version": version}},
            "components": comps,
        });
        serde_json::to_string(&doc).map_err(|e| ReleaseError::Metadata(e.to_string()))
    }

    /// Read the components back from a CycloneDX document written by `to_cyclonedx`.
    pub fn parse_cyclonedx(json: &str) -> Result<Vec<Component>, ReleaseError> {
        let bad = |m: &str| ReleaseError::Metadata(m.to_string());
        let v: Value = serde_json::from_str(json).map_err(|_| bad("not JSON"))?;
        let arr = v["components"]
            .as_array()
            .ok_or_else(|| bad("no components"))?;
        let mut out = Vec::with_capacity(arr.len());
        for c in arr {
            let text = |k: &str| c[k].as_str().map(str::to_string);
            out.push(Component {
                name: text("name").ok_or_else(|| bad("a component has no name"))?,
                version: text("version").ok_or_else(|| bad("a component has no version"))?,
                source: c["properties"]
                    .as_array()
                    .and_then(|ps| ps.iter().find(|p| p["name"] == SOURCE_PROP))
                    .and_then(|p| p["value"].as_str())
                    .map(str::to_string),
                checksum: c["hashes"][0]["content"].as_str().map(str::to_string),
            });
        }
        out.sort();
        Ok(out)
    }

    /// What a cross-check measured.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CrossReport {
        /// Packages of the metadata that the SBOM covers (all of them, or the check failed).
        pub checked: usize,
        /// SBOM components the metadata does not use (other platforms only: `cargo metadata --offline` cannot resolve them without downloads).
        pub not_in_metadata: usize,
    }

    /// The SBOM must equal the lock file's package list (this is what finds a planted extra or missing component).
    pub fn check_lock(components: &[Component], lock: &str) -> Result<(), ReleaseError> {
        if from_lock(lock)? == components {
            Ok(())
        } else {
            Err(ReleaseError::Mismatch(
                "the sbom is not the lock file's package list".into(),
            ))
        }
    }

    /// Compare the SBOM with `cargo metadata --format-version 1` output (any platform filter): every (name, version, source) of the metadata must be in the SBOM.
    pub fn cross_check(
        components: &[Component],
        metadata_json: &str,
    ) -> Result<CrossReport, ReleaseError> {
        let v: Value = serde_json::from_str(metadata_json)
            .map_err(|_| ReleaseError::Metadata("not JSON".into()))?;
        let pkgs = v["packages"]
            .as_array()
            .ok_or_else(|| ReleaseError::Metadata("no packages".into()))?;
        let key = |n: &str, ver: &str, s: Option<&str>| {
            (n.to_string(), ver.to_string(), s.map(str::to_string))
        };
        let theirs: BTreeSet<_> = pkgs
            .iter()
            .map(|p| {
                key(
                    p["name"].as_str().unwrap_or(""),
                    p["version"].as_str().unwrap_or(""),
                    p["source"].as_str(),
                )
            })
            .collect();
        let ours: BTreeSet<_> = components
            .iter()
            .map(|c| key(&c.name, &c.version, c.source.as_deref()))
            .collect();
        let only_meta = theirs.difference(&ours).count();
        if only_meta == 0 {
            return Ok(CrossReport {
                checked: theirs.len(),
                not_in_metadata: ours.len() - theirs.len(),
            });
        }
        let first = theirs
            .difference(&ours)
            .next()
            .map(|(n, v, _)| format!("{n} {v}"))
            .unwrap_or_default();
        Err(ReleaseError::Mismatch(format!(
            "{only_meta} packages of cargo metadata are not in the sbom (first: {first})"
        )))
    }
}

/// Signed release manifest.
pub mod manifest {
    use super::{CheckpointSigner, ReleaseError};
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    /// The largest envelope `verify` reads (bytes).
    pub const MAX_ENVELOPE_BYTES: usize = 1 << 20;
    const SCHEMA: &str = "entropa-release-manifest-1";
    const KIND: &str = "release-manifest";

    /// What a verified manifest says.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Verified {
        /// Product name.
        pub product: String,
        /// Version.
        pub version: String,
        /// Number of artifacts checked.
        pub artifacts: usize,
        /// The signer's short key id.
        pub key_id: String,
    }

    fn sha256_hex(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }
    fn q(s: &str) -> String {
        serde_json::to_string(s).unwrap_or_default()
    }
    fn key_id(pubkey_hex: &str) -> String {
        match hex::decode(pubkey_hex) {
            Ok(b) if !b.is_empty() => hex::encode(&blake3::hash(&b).as_bytes()[..8]),
            _ => String::new(),
        }
    }
    fn name_ok(n: &str) -> bool {
        (1..=128).contains(&n.len())
            && n.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    }

    /// The canonical manifest text: product, version, the artifacts (name, sha256, size; sorted by name) and the sha256 of the SBOM.
    pub fn build(
        product: &str,
        version: &str,
        artifacts: &[(String, Vec<u8>)],
        sbom_json: &str,
    ) -> Result<String, ReleaseError> {
        if !name_ok(product) || version.is_empty() || version.len() > 64 {
            return Err(ReleaseError::Manifest(
                "product or version not acceptable".into(),
            ));
        }
        let mut sorted: Vec<&(String, Vec<u8>)> = artifacts.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        if sorted.windows(2).any(|w| w[0].0 == w[1].0) || sorted.iter().any(|a| !name_ok(&a.0)) {
            return Err(ReleaseError::Manifest(
                "artifact names must be unique and plain".into(),
            ));
        }
        let items: Vec<String> = sorted
            .iter()
            .map(|(n, b)| {
                format!(
                    "{{\"name\":{},\"sha256\":{},\"size\":{}}}",
                    q(n),
                    q(&sha256_hex(b)),
                    b.len()
                )
            })
            .collect();
        Ok(format!(
            "{{\"artifacts\":[{}],\"product\":{},\"sbom_sha256\":{},\"schema\":{},\"version\":{}}}",
            items.join(","),
            q(product),
            q(&sha256_hex(sbom_json.as_bytes())),
            q(SCHEMA),
            q(version)
        ))
    }

    fn digest(manifest: &str) -> [u8; 32] {
        entropa_tokens::digest(KIND, manifest.as_bytes())
    }

    /// Sign a manifest with ML-DSA-65: the envelope JSON holds the manifest text, the algorithm label, the key id and the signature.
    pub fn sign(manifest: &str, signer: &dyn CheckpointSigner) -> Result<String, ReleaseError> {
        let sig = signer
            .try_sign_hex(&digest(manifest))
            .map_err(|e| ReleaseError::Signature(e.to_string()))?;
        Ok(format!(
            "{{\"alg\":{},\"key_id\":{},\"manifest\":{},\"signature\":{}}}",
            q(signer.algorithm()),
            q(&key_id(&signer.pubkey_hex())),
            q(manifest),
            q(&sig)
        ))
    }

    fn mismatch<T>(m: impl Into<String>) -> Result<T, ReleaseError> {
        Err(ReleaseError::Mismatch(m.into()))
    }
    fn bad<T>(m: &str) -> Result<T, ReleaseError> {
        Err(ReleaseError::Manifest(m.to_string()))
    }

    /// What a clean machine does: check the envelope's signature under `pubkey_hex`, then recompute every file's sha256 and size.
    /// Every given file must be listed and every listed file given.
    pub fn verify(
        envelope: &str,
        pubkey_hex: &str,
        files: &[(String, Vec<u8>)],
    ) -> Result<Verified, ReleaseError> {
        if envelope.len() > MAX_ENVELOPE_BYTES {
            return bad("envelope too large");
        }
        let env = entropa_witness::strict_json::from_str(envelope)
            .or_else(|_| bad("envelope is not JSON (or has a duplicated key)"))?;
        let Some(obj) = env.as_object() else {
            return bad("envelope must be an object");
        };
        if obj.len() != 4
            || ["alg", "key_id", "manifest", "signature"]
                .iter()
                .any(|k| !obj.contains_key(*k))
        {
            return bad("envelope fields are not exactly alg, key_id, manifest, signature");
        }
        let text = |k: &str| obj[k].as_str().map(str::to_string);
        let (Some(alg), Some(kid), Some(man), Some(sig)) = (
            text("alg"),
            text("key_id"),
            text("manifest"),
            text("signature"),
        ) else {
            return bad("envelope fields must be text");
        };
        let fail = |m: &str| Err(ReleaseError::Signature(m.to_string()));
        if alg != "ML-DSA-65" {
            return fail("unsupported algorithm");
        }
        if kid != key_id(pubkey_hex) || kid.is_empty() {
            return fail("the key id does not match the given key");
        }
        if sig.len() != entropa_tokens::SIG_HEX_LEN
            || !sig.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
            || !entropa_core::verify_hex(pubkey_hex, &digest(&man), &sig)
        {
            return fail("the signature does not verify");
        }
        let m: Value = entropa_witness::strict_json::from_str(&man)
            .or_else(|_| bad("manifest is not JSON (or has a duplicated key)"))?;
        if m["schema"] != SCHEMA {
            return bad("unknown manifest schema");
        }
        let (Some(product), Some(version), Some(listed)) = (
            m["product"].as_str(),
            m["version"].as_str(),
            m["artifacts"].as_array(),
        ) else {
            return bad("manifest lacks product, version or artifacts");
        };
        if listed.len() != files.len() {
            return mismatch(format!(
                "{} files listed, {} given",
                listed.len(),
                files.len()
            ));
        }
        for a in listed {
            let (Some(n), Some(h), Some(sz)) =
                (a["name"].as_str(), a["sha256"].as_str(), a["size"].as_u64())
            else {
                return bad("an artifact entry is malformed");
            };
            let Some((_, bytes)) = files.iter().find(|(fname, _)| fname == n) else {
                return mismatch(format!("{n} is listed but not given"));
            };
            if bytes.len() as u64 != sz || sha256_hex(bytes) != h {
                return mismatch(format!("{n} does not match the manifest"));
            }
        }
        Ok(Verified {
            product: product.to_string(),
            version: version.to_string(),
            artifacts: listed.len(),
            key_id: kid,
        })
    }
}

/// The installed `minisign` for outside verifiers.
pub mod minisign {
    use super::{Path, PathBuf, ReleaseError};
    use std::process::{Command, Stdio};

    fn run(args: &[&std::ffi::OsStr]) -> Result<(), ReleaseError> {
        let o = Command::new("minisign")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|_| ReleaseError::Io("minisign cannot be started".into()))?;
        if o.status.success() {
            Ok(())
        } else {
            Err(ReleaseError::Signature("minisign refused".into()))
        }
    }

    /// Sign `file` with the (password-less) secret key file; returns the path of the `.minisig` written next to it.
    pub fn sign(file: &Path, secret_key: &Path) -> Result<PathBuf, ReleaseError> {
        run(&[
            "-S".as_ref(),
            "-s".as_ref(),
            secret_key.as_os_str(),
            "-m".as_ref(),
            file.as_os_str(),
        ])?;
        let mut p = file.as_os_str().to_owned();
        p.push(".minisig");
        Ok(PathBuf::from(p))
    }
    /// Verify `file` (with its `.minisig` next to it) under the public key file.
    pub fn verify(file: &Path, public_key: &Path) -> Result<(), ReleaseError> {
        run(&[
            "-V".as_ref(),
            "-p".as_ref(),
            public_key.as_os_str(),
            "-m".as_ref(),
            file.as_os_str(),
        ])
    }
}

/// The command line (S2e, a stage record (not published)): `keygen`, `sbom`, `sign`, `verify`.
pub mod cli {
    use super::{manifest, sbom};
    use entropa_core::Probe;
    use std::io::{Read, Write};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::Path;

    const MAX_FILES: usize = 1000;
    const MAX_FILE_BYTES: u64 = 256 << 20;
    const MAX_SBOM_BYTES: u64 = 64 << 20;
    const USAGE: &str = "usage: entropa-release keygen --out FILE | sbom --lock FILE --product P --version V --out FILE | sign --dir DIR --product P --version V --sbom FILE --key FILE --out FILE | verify --dir DIR --manifest FILE --pubkey HEX";

    fn flag(args: &[String], name: &str) -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    }
    /// The key id of a public key (hex), as printed by `keygen` (shared with entropa-check).
    pub fn key_id(pubkey_hex: &str) -> String {
        hex::decode(pubkey_hex)
            .map(|b| hex::encode(&blake3::hash(&b).as_bytes()[..8]))
            .unwrap_or_default()
    }
    /// Create `path` (mode 0600 when `private`), refusing to overwrite.
    fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if private { 0o600 } else { 0o644 })
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    "the output file exists; refusing to overwrite".to_string()
                } else {
                    "cannot create the output file".to_string()
                }
            })?;
        f.write_all(bytes)
            .map_err(|_| "cannot write the output file".to_string())
    }
    fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
        let f = std::fs::File::open(path).map_err(|_| "cannot open an input file".to_string())?;
        let mut b = Vec::new();
        f.take(cap + 1)
            .read_to_end(&mut b)
            .map_err(|_| "cannot read an input file".to_string())?;
        if b.len() as u64 > cap {
            return Err("an input file is too large".into());
        }
        Ok(b)
    }
    /// Every regular file of `dir` (no subdirectories), sorted by name, except `skip`.
    fn list(dir: &Path, skip: Option<&Path>) -> Result<Vec<(String, Vec<u8>)>, String> {
        let skip = skip.and_then(|p| std::fs::canonicalize(p).ok());
        let rd =
            std::fs::read_dir(dir).map_err(|_| "cannot read the release directory".to_string())?;
        let mut out = Vec::new();
        for e in rd {
            let e = e.map_err(|_| "cannot read the release directory".to_string())?;
            let path = e.path();
            let md =
                std::fs::symlink_metadata(&path).map_err(|_| "cannot read a file".to_string())?;
            if !md.is_file() {
                return Err(
                    "the release directory may hold only regular files (no subdirectory, no link)"
                        .into(),
                );
            }
            if skip.is_some() && std::fs::canonicalize(&path).ok() == skip {
                continue;
            }
            if out.len() >= MAX_FILES {
                return Err("too many files in the release directory".into());
            }
            let name = e.file_name().to_string_lossy().into_owned();
            out.push((name, read_capped(&path, MAX_FILE_BYTES)?));
        }
        if out.is_empty() {
            return Err("the release directory has no files".into());
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
    /// Load a signing key file (a 0600 hex seed); shared with entropa-check so one key format serves both tools.
    pub fn load_key(path: &Path) -> Result<Probe, String> {
        let md = std::fs::metadata(path).map_err(|_| "no key file".to_string())?;
        if md.permissions().mode() & 0o077 != 0 {
            return Err(
                "the key file must not be readable by group or others (permission 0600)".into(),
            );
        }
        let t =
            std::fs::read_to_string(path).map_err(|_| "cannot read the key file".to_string())?;
        Probe::from_signing_key_hex(t.trim())
            .ok_or_else(|| "the key file is not a valid key".to_string())
    }

    fn keygen(out: &Path) -> Result<String, String> {
        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut seed))
            .map_err(|_| "no random source".to_string())?;
        let seed_hex = hex::encode(seed);
        let probe = Probe::from_signing_key_hex(&seed_hex)
            .ok_or_else(|| "key generation failed".to_string())?;
        write_new(out, format!("{seed_hex}\n").as_bytes(), true)?;
        let pk = probe.pubkey_hex();
        Ok(format!("public key: {pk}\nkey id: {}", key_id(&pk)))
    }

    /// Run the command line; returns the exit code (0 ok, 1 refused or failed, 2 usage).
    pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
        let usage = |err: &mut dyn Write| {
            let _ = writeln!(err, "{USAGE}");
            2
        };
        let get = |n: &str| flag(args, n);
        let result: Result<String, String> = match args.first().map(String::as_str) {
            Some("keygen") => match get("--out") {
                Some(o) => keygen(Path::new(&o)),
                None => return usage(err),
            },
            Some("sbom") => match (
                get("--lock"),
                get("--product"),
                get("--version"),
                get("--out"),
            ) {
                (Some(l), Some(p), Some(v), Some(o)) => (|| {
                    let lock = String::from_utf8(read_capped(Path::new(&l), MAX_SBOM_BYTES)?)
                        .map_err(|_| "the lock file is not UTF-8".to_string())?;
                    let comps = sbom::from_lock(&lock).map_err(|e| e.to_string())?;
                    let text = sbom::to_cyclonedx(&comps, &p, &v).map_err(|e| e.to_string())?;
                    write_new(Path::new(&o), text.as_bytes(), false)?;
                    Ok(format!("sbom components={}", comps.len()))
                })(),
                _ => return usage(err),
            },
            Some("sign") => match (
                get("--dir"),
                get("--product"),
                get("--version"),
                get("--sbom"),
                get("--key"),
                get("--out"),
            ) {
                (Some(d), Some(p), Some(v), Some(sb), Some(k), Some(o)) => (|| {
                    if Path::new(&o).exists() {
                        return Err("the output file exists; refusing to overwrite".to_string());
                    }
                    let probe = load_key(Path::new(&k))?;
                    let files = list(Path::new(&d), None)?;
                    let sbom_text = String::from_utf8(read_capped(Path::new(&sb), MAX_SBOM_BYTES)?)
                        .map_err(|_| "the sbom is not UTF-8".to_string())?;
                    let m =
                        manifest::build(&p, &v, &files, &sbom_text).map_err(|e| e.to_string())?;
                    let env = manifest::sign(&m, &probe).map_err(|e| e.to_string())?;
                    write_new(Path::new(&o), env.as_bytes(), false)?;
                    Ok(format!(
                        "signed artifacts={} key_id={}",
                        files.len(),
                        key_id(&probe.pubkey_hex())
                    ))
                })(),
                _ => return usage(err),
            },
            Some("verify") => match (get("--dir"), get("--manifest"), get("--pubkey")) {
                (Some(d), Some(m), Some(pk)) => (|| {
                    let env = String::from_utf8(read_capped(
                        Path::new(&m),
                        manifest::MAX_ENVELOPE_BYTES as u64,
                    )?)
                    .map_err(|_| "the manifest is not UTF-8".to_string())?;
                    let files = list(Path::new(&d), Some(Path::new(&m)))?;
                    let v = manifest::verify(&env, &pk, &files).map_err(|e| e.to_string())?;
                    Ok(format!(
                        "OK {} {} artifacts={} key_id={}",
                        v.product, v.version, v.artifacts, v.key_id
                    ))
                })(),
                _ => return usage(err),
            },
            _ => return usage(err),
        };
        match result {
            Ok(m) => {
                let _ = writeln!(out, "{m}");
                0
            }
            Err(m) => {
                let _ = writeln!(err, "refused: {m}");
                1
            }
        }
    }
}
