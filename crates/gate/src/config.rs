//! The strict config file (closed keys): `org_name` (required) and `witnesses` (optional list of https URLs). Anything else is refused.
use crate::{GateError, Res};

/// The parsed config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Organisation name shown in the explorer (1 to 80 characters, no control characters).
    pub org_name: String,
    /// Witness URLs the client allows (the only outbound destinations); empty by default.
    pub witnesses: Vec<String>,
    /// Accent colour of the explorer as `#rrggbb` (default `#1a73e8`).
    pub accent_color: String,
    /// Path of a logo file (png, jpg, gif or svg, at most 100 KiB) copied into the explorer, if any.
    pub logo_file: Option<String>,
    /// Tier names shown in the explorer (at most 8, plain words), empty by default.
    pub tiers: Vec<String>,
}

/// The default accent colour.
pub const DEFAULT_ACCENT: &str = "#1a73e8";

fn bad<T>(m: &str) -> Res<T> {
    Err(GateError::Invalid(m.to_string()))
}

impl Config {
    /// Parse a config text. Unknown keys, wrong types, tables, duplicate keys and out-of-range values are refused; the error names the key, never the value.
    pub fn parse(text: &str) -> Res<Config> {
        if text.len() > 16 * 1024 {
            return bad("config: too large");
        }
        let table: toml::Table = toml::from_str(text).map_err(|_| {
            GateError::Invalid("config: not valid TOML (or a duplicated key)".into())
        })?;
        if let Some(k) = table.keys().find(|k| {
            !matches!(
                k.as_str(),
                "org_name" | "witnesses" | "accent_color" | "logo_file" | "tiers"
            )
        }) {
            return Err(GateError::Invalid(format!(
                "config: unknown key: {}",
                k.chars().take(32).collect::<String>()
            )));
        }
        let org_name = match table.get("org_name") {
            Some(toml::Value::String(s)) => s.clone(),
            Some(_) => return bad("config: org_name must be text"),
            None => return bad("config: org_name is required"),
        };
        let n = org_name.chars().count();
        if !(1..=80).contains(&n) || org_name.chars().any(char::is_control) {
            return bad("config: org_name must be 1 to 80 characters without control characters");
        }
        let mut witnesses = Vec::new();
        match table.get("witnesses") {
            None => {}
            Some(toml::Value::Array(a)) => {
                if a.len() > 16 {
                    return bad("config: at most 16 witnesses");
                }
                for v in a {
                    let toml::Value::String(u) = v else {
                        return bad("config: witnesses must be text");
                    };
                    if !u.starts_with("https://")
                        || u.len() > 200
                        || u.len() <= 8
                        || u.chars().any(|c| c.is_control() || c.is_whitespace())
                    {
                        return bad("config: a witness must be an https URL without spaces");
                    }
                    witnesses.push(u.clone());
                }
            }
            Some(_) => return bad("config: witnesses must be a list"),
        }
        let accent_color = match table.get("accent_color") {
            None => DEFAULT_ACCENT.to_string(),
            Some(toml::Value::String(c)) => {
                let h = c.as_bytes();
                if h.len() != 7 || h[0] != b'#' || !h[1..].iter().all(u8::is_ascii_hexdigit) {
                    return bad("config: accent_color must be #rrggbb");
                }
                c.to_ascii_lowercase()
            }
            Some(_) => return bad("config: accent_color must be text"),
        };
        let logo_file = match table.get("logo_file") {
            None => None,
            Some(toml::Value::String(p))
                if !p.is_empty() && p.len() <= 300 && !p.chars().any(char::is_control) =>
            {
                Some(p.clone())
            }
            Some(_) => return bad("config: logo_file must be a path of at most 300 characters"),
        };
        let mut tiers = Vec::new();
        match table.get("tiers") {
            None => {}
            Some(toml::Value::Array(a)) => {
                if a.len() > 8 {
                    return bad("config: at most 8 tiers");
                }
                for v in a {
                    let toml::Value::String(t) = v else {
                        return bad("config: tiers must be text");
                    };
                    let ok = (1..=24).contains(&t.chars().count())
                        && t.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '_' || c == '-');
                    if !ok {
                        return bad("config: a tier name is 1 to 24 letters, digits, spaces, hyphens or underscores");
                    }
                    tiers.push(t.clone());
                }
            }
            Some(_) => return bad("config: tiers must be a list"),
        }
        Ok(Config {
            org_name,
            witnesses,
            accent_color,
            logo_file,
            tiers,
        })
    }
}
