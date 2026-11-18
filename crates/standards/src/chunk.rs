//! Clause-level chunkers. Each turns one source's text into clauses with canonical ids. All are deterministic and refuse a source from which
//! no clause can be taken.

use regex::Regex;
use serde_json::Value;

/// A clause as the chunker sees it, before sealing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawClause {
    /// Canonical clause id.
    pub id: String,
    /// Clause text, whitespace-normalised.
    pub text: String,
}

/// The source formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// NIST OSCAL catalog JSON: one clause per control or enhancement.
    Oscal,
    /// Official Journal text (as from pdftotext): one clause per article, plus annexes.
    EuText,
    /// PCI-style requirement text (as from pdftotext): one clause per requirement id.
    PciText,
    /// An HTML page of a regulation section: one clause per lettered standard.
    Html,
}

impl Format {
    /// The wire name used in corpus specs.
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Oscal => "oscal",
            Format::EuText => "eu_text",
            Format::PciText => "pci_text",
            Format::Html => "html",
        }
    }
    /// Parse a wire name.
    pub fn parse(s: &str) -> Option<Format> {
        match s {
            "oscal" => Some(Format::Oscal),
            "eu_text" => Some(Format::EuText),
            "pci_text" => Some(Format::PciText),
            "html" => Some(Format::Html),
            _ => None,
        }
    }
}

/// Why a source could not be chunked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkError(pub String);

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Chunk one source's text.
pub fn chunk(format: Format, text: &str) -> Result<Vec<RawClause>, ChunkError> {
    let out = match format {
        Format::Oscal => oscal(text)?,
        Format::EuText => eu(text),
        Format::PciText => pci(text),
        Format::Html => html(text)?,
    };
    if out.is_empty() {
        return Err(ChunkError("no clauses found in the source".into()));
    }
    Ok(out)
}

// ---- OSCAL ----
fn oscal_id(raw: &str) -> String {
    match raw.split_once('.') {
        Some((base, rest)) => format!("{}({})", base.to_uppercase(), rest),
        None => raw.to_uppercase(),
    }
}

fn prose_of(parts: &Value, out: &mut Vec<String>) {
    if let Some(arr) = parts.as_array() {
        for p in arr {
            if let Some(s) = p.get("prose").and_then(Value::as_str) {
                out.push(s.to_string());
            }
            prose_of(p.get("parts").unwrap_or(&Value::Null), out);
        }
    }
}

fn oscal_walk(controls: &Value, param: &Regex, out: &mut Vec<RawClause>) {
    let Some(arr) = controls.as_array() else {
        return;
    };
    for c in arr {
        let id = c.get("id").and_then(Value::as_str).unwrap_or("");
        let title = c.get("title").and_then(Value::as_str).unwrap_or("");
        let mut statement = Vec::new();
        let mut guidance = Vec::new();
        if let Some(parts) = c.get("parts").and_then(Value::as_array) {
            for p in parts {
                let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                let mut v = Vec::new();
                if let Some(s) = p.get("prose").and_then(Value::as_str) {
                    v.push(s.to_string());
                }
                prose_of(p.get("parts").unwrap_or(&Value::Null), &mut v);
                match name {
                    "statement" => statement.extend(v),
                    "guidance" => guidance.extend(v),
                    _ => {}
                }
            }
        }
        if !id.is_empty() && !statement.is_empty() {
            let body = format!("{title} {} {}", statement.join(" "), guidance.join(" "));
            out.push(RawClause {
                id: oscal_id(id),
                text: squash(&param.replace_all(&body, "[organization-defined parameter]")),
            });
        }
        oscal_walk(c.get("controls").unwrap_or(&Value::Null), param, out);
    }
}

fn oscal(text: &str) -> Result<Vec<RawClause>, ChunkError> {
    let v: Value = serde_json::from_str(text)
        .map_err(|_| ChunkError("the source is not valid JSON".into()))?;
    let cat = v
        .get("catalog")
        .ok_or_else(|| ChunkError("no catalog in the source".into()))?;
    let param = Regex::new(r"\{\{[^}]*\}\}").map_err(|_| ChunkError("internal".into()))?;
    let mut out = Vec::new();
    fn groups(g: &Value, param: &Regex, out: &mut Vec<RawClause>) {
        if let Some(arr) = g.as_array() {
            for grp in arr {
                oscal_walk(grp.get("controls").unwrap_or(&Value::Null), param, out);
                groups(grp.get("groups").unwrap_or(&Value::Null), param, out);
            }
        }
    }
    oscal_walk(
        cat.get("controls").unwrap_or(&Value::Null),
        &param,
        &mut out,
    );
    groups(cat.get("groups").unwrap_or(&Value::Null), &param, &mut out);
    Ok(out)
}

// ---- EU Official Journal text ----
fn eu(text: &str) -> Vec<RawClause> {
    let noise = Regex::new(r"^(OJ L, .*|EN|\d+/\d+|ELI: .*)$").ok();
    let article = Regex::new(r"^Article (\d+)$").ok();
    let annex = Regex::new(r"^ANNEX ([IVXL]+)$").ok();
    let stop = Regex::new(r"^(CHAPTER|SECTION|TITLE) ").ok();
    let para = Regex::new(r"^\d+\.$").ok();
    let (Some(noise), Some(article), Some(annex), Some(stop), Some(para)) =
        (noise, article, annex, stop, para)
    else {
        return vec![];
    };
    let mut order: Vec<String> = Vec::new();
    let mut best: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut cur: Option<(String, Vec<String>)> = None;
    let flush = |cur: &mut Option<(String, Vec<String>)>,
                 order: &mut Vec<String>,
                 best: &mut std::collections::HashMap<String, String>| {
        if let Some((id, lines)) = cur.take() {
            let t = squash(&lines.join(" "));
            match best.get(&id) {
                None => {
                    order.push(id.clone());
                    best.insert(id, t);
                }
                Some(old) if t.chars().count() > old.chars().count() => {
                    best.insert(id, t);
                }
                _ => {}
            }
        }
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || noise.is_match(line) {
            continue;
        }
        if let Some(c) = article.captures(line) {
            flush(&mut cur, &mut order, &mut best);
            cur = Some((format!("Art.{}", &c[1]), vec![]));
        } else if let Some(c) = annex.captures(line) {
            flush(&mut cur, &mut order, &mut best);
            cur = Some((format!("Annex {}", &c[1]), vec![]));
        } else if stop.is_match(line) {
            flush(&mut cur, &mut order, &mut best);
        } else if let Some((_, lines)) = cur.as_mut() {
            if !para.is_match(line) {
                lines.push(line.to_string());
            }
        }
    }
    flush(&mut cur, &mut order, &mut best);
    order
        .into_iter()
        .filter_map(|id| {
            best.remove(&id)
                .filter(|t| !t.is_empty())
                .map(|text| RawClause { id, text })
        })
        .collect()
}

// ---- PCI-style requirement text ----
fn pci(text: &str) -> Vec<RawClause> {
    let Ok(idline) = Regex::new(r"^(\d{1,2}(?:\.\d{1,2}){1,3})\s+(\S.*)$") else {
        return vec![];
    };
    let mut order: Vec<(Vec<u32>, String)> = Vec::new();
    let mut by_id: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut cur: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            cur = None;
            continue;
        }
        if let Some(c) = idline.captures(line) {
            let id = c[1].to_string();
            let nums: Vec<u32> = id.split('.').filter_map(|p| p.parse().ok()).collect();
            if nums.first().is_some_and(|n| (1..=12).contains(n)) {
                if !by_id.contains_key(&id) {
                    order.push((nums, id.clone()));
                }
                by_id.entry(id.clone()).or_default().push(c[2].to_string());
                cur = Some(id);
                continue;
            }
            cur = None;
            continue;
        }
        if let Some(id) = &cur {
            if let Some(v) = by_id.get_mut(id) {
                v.push(line.to_string());
            }
        }
    }
    order.sort();
    order
        .into_iter()
        .filter_map(|(_, id)| {
            by_id.remove(&id).map(|v| RawClause {
                text: squash(&v.join(" ")),
                id,
            })
        })
        .collect()
}

// ---- HTML section ----
fn unescape(s: &str) -> String {
    let named = s
        .replace("&nbsp;", " ")
        .replace("&sect;", "§")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    let Ok(num) = Regex::new(r"&#(x[0-9A-Fa-f]+|\d+);") else {
        return named;
    };
    num.replace_all(&named, |c: &regex::Captures| {
        let g = &c[1];
        let v = if let Some(h) = g.strip_prefix('x') {
            u32::from_str_radix(h, 16).ok()
        } else {
            g.parse().ok()
        };
        v.and_then(char::from_u32)
            .map(String::from)
            .unwrap_or_default()
    })
    .into_owned()
}

fn html(text: &str) -> Result<Vec<RawClause>, ChunkError> {
    let strip = |re: &str, s: &str| {
        Regex::new(re)
            .map(|r| r.replace_all(s, " ").into_owned())
            .unwrap_or_else(|_| s.to_string())
    };
    let mut t = strip(
        r"(?is)<(script|style|nav|footer|head)\b.*?</(script|style|nav|footer|head)>",
        text,
    );
    t = strip(r"(?s)<[^>]+>", &t);
    let t = squash(&unescape(&t));
    let sec = Regex::new(r"§\s*(\d+\.\d+)")
        .ok()
        .and_then(|r| r.captures(&t).map(|c| c[1].to_string()))
        .ok_or_else(|| ChunkError("no section number found".into()))?;
    let marker = Regex::new(r"\(([a-z])\)\s*(?:\(1\)\s*)?Standard:")
        .map_err(|_| ChunkError("internal".into()))?;
    let spots: Vec<(usize, String)> = marker
        .captures_iter(&t)
        .filter_map(|c| c.get(0).map(|m| (m.start(), c[1].to_string())))
        .collect();
    let mut out = Vec::new();
    for (i, (start, letter)) in spots.iter().enumerate() {
        let end = spots.get(i + 1).map_or(t.len(), |n| n.0);
        out.push(RawClause {
            id: format!("{sec}({letter})"),
            text: squash(&t[*start..end]),
        });
    }
    Ok(out)
}
