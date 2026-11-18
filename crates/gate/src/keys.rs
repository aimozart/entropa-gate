//! The client's own signing key: created by `init`, mode 0600 in a 0700 directory, never returned to a caller as bytes. The only function that
//! reads the key file is `load`, which hands back a signer object (it can sign; it cannot be turned back into the seed by this crate).
use crate::{GateError, Res};
use entropa_core::Probe;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

fn io<T>(m: &str) -> Res<T> {
    Err(GateError::Io(m.to_string()))
}

/// Create the data directory (0700), the key file (0600) and the ledger store. Refuses to run twice.
pub fn init(dir: &Path) -> Res<()> {
    let key = dir.join("platinum.key");
    if key.exists() {
        return io("already initialised");
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|_| GateError::Io("cannot create the directory".into()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| GateError::Io("cannot make the directory private".into()))?;
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|_| GateError::Io("no random source".into()))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key)
        .map_err(|_| GateError::Io("cannot create the key file".into()))?;
    std::io::Write::write_all(&mut f, format!("{}\n", hex::encode(seed)).as_bytes())
        .map_err(|_| GateError::Io("cannot write the key file".into()))?;
    std::fs::create_dir_all(dir.join("ledger"))
        .map_err(|_| GateError::Io("cannot create the store".into()))?;
    Ok(())
}

/// Load the signer from the key file in `dir`. Fails closed: a key file that group or others can read is refused.
pub(crate) fn load(dir: &Path) -> Res<Probe> {
    let p = dir.join("platinum.key");
    let meta =
        std::fs::metadata(&p).map_err(|_| GateError::Io("no key file (run init first)".into()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return io("the key file must not be readable by group or others (chmod 600)");
    }
    let seed = std::fs::read_to_string(&p)
        .map_err(|_| GateError::Io("cannot read the key file".into()))?;
    Probe::from_signing_key_hex(seed.trim())
        .ok_or_else(|| GateError::Io("the key file is not a valid key".into()))
}
