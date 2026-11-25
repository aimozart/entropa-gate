//! The report `entropa-report-v1`: counts, 95 percent bounds, ids, hashes, closed reasons and calibration rows ONLY. Never an input, the target's output, a secret or a path.
use crate::forecast::Forecast;
use crate::set::Set;
use crate::stats::bounds;
use crate::target::Outcome;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// What the report records about the pre-registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreregInfo {
    /// A matching pre-registration (the stage id, and whether it was found anchored in a ledger).
    Matched {
        /// The stage id.
        stage: String,
        /// True only when a verifying ledger holds the record's anchor.
        anchored: bool,
    },
    /// No pre-registration was given (the run was explicitly unregistered).
    None,
}

/// The hashes recorded in the report.
#[derive(Debug, Clone)]
pub struct Hashes {
    /// The set file.
    pub set: String,
    /// The runner file.
    pub runner: String,
    /// The target file.
    pub target: String,
    /// The forecast file, when given.
    pub forecast: Option<String>,
}

/// Round to 6 decimals so the text is stable across platforms.
fn r6(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

fn bar_result(op: &str, measured: f64, value: f64) -> &'static str {
    let ok = match op {
        "<=" => measured <= value,
        "<" => measured < value,
        ">=" => measured >= value,
        _ => measured > value,
    };
    if ok {
        "met"
    } else {
        "missed"
    }
}

/// Build the report from the set, the outcomes (same order) and the recorded hashes.
pub fn build(
    set: &Set,
    outcomes: &[Outcome],
    h: &Hashes,
    forecast: Option<&Forecast>,
    prereg: &PreregInfo,
) -> Value {
    #[derive(Default)]
    struct Acc {
        cases: usize,
        failed: usize,
        accepted: usize,
        failed_ids: Vec<String>,
    }
    let mut classes: BTreeMap<String, Acc> = BTreeMap::new();
    let mut reasons: BTreeMap<&'static str, usize> = BTreeMap::new();
    let (mut failed, mut accepted) = (0usize, 0usize);
    for (c, o) in set.cases.iter().zip(outcomes) {
        let a = classes.entry(c.class.clone()).or_default();
        a.cases += 1;
        if let Some(r) = o.failed {
            a.failed += 1;
            a.failed_ids.push(c.id.clone());
            failed += 1;
            *reasons.entry(r.as_str()).or_insert(0) += 1;
        }
        if c.attack && o.verdict == crate::target::Verdict::Allow {
            a.accepted += 1;
            accepted += 1;
        }
    }
    let n = set.cases.len();
    let mut cj = Map::new();
    for (name, a) in &classes {
        let b = bounds(a.failed, a.cases).map(|b| b.upper).unwrap_or(1.0);
        cj.insert(
            name.clone(),
            json!({"cases": a.cases, "passed": a.cases - a.failed, "failed": a.failed, "accepted_attacks": a.accepted, "failed_ids": a.failed_ids,
                   "upper95_of_failure_rate": r6(b), "small_n": a.cases < 10}),
        );
    }
    let tb = bounds(failed, n).ok();
    let rate = if n == 0 {
        0.0
    } else {
        failed as f64 / n as f64
    };
    let prereg_json = match prereg {
        PreregInfo::Matched { stage, anchored } => {
            json!({"matched": true, "anchored": anchored, "stage": stage})
        }
        PreregInfo::None => json!({"matched": false, "anchored": false, "reason": "none given"}),
    };
    let mut cal = Vec::new();
    if let Some(f) = forecast {
        for m in &f.metrics {
            let measured = match m.name.as_str() {
                "failed_rate" => rate,
                "accepted_attacks" => accepted as f64,
                "failed" => failed as f64,
                other => {
                    let class = other
                        .strip_prefix("class:")
                        .and_then(|r| r.strip_suffix(":failed_rate"))
                        .unwrap_or("");
                    classes
                        .get(class)
                        .map_or(0.0, |a| a.failed as f64 / a.cases as f64)
                }
            };
            let result = if measured >= m.low && measured <= m.high {
                "hit"
            } else {
                "miss"
            };
            let bar = m
                .bar
                .as_ref()
                .map_or("none", |b| bar_result(&b.op, measured, b.value));
            cal.push(json!({"metric": m.name, "low": m.low, "central": m.central, "high": m.high, "measured": r6(measured), "result": result, "bar": bar}));
        }
    }
    let mut v = json!({
        "schema": "entropa-report-v1", "set_sha256": h.set, "runner_sha256": h.runner, "target_sha256": h.target,
        "prereg": prereg_json, "classes": Value::Object(cj),
        "totals": {"cases": n, "failed": failed, "accepted_attacks": accepted, "failed_rate": r6(rate),
                   "upper95_of_failure_rate": r6(tb.map_or(1.0, |b| b.upper)), "lower95_of_failure_rate": r6(tb.map_or(0.0, |b| b.lower))},
        "reasons": reasons, "calibration": cal,
    });
    if let (Some(fh), Some(o)) = (&h.forecast, v.as_object_mut()) {
        o.insert("forecast_sha256".into(), json!(fh));
    }
    v
}
