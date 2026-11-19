//! The forecast `entropa-forecast-v1`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_check::forecast::parse;

const OK: &str = r#"{"schema":"entropa-forecast-v1","stage":"S1","written":"2026-11-18","metrics":[
 {"name":"failed_rate","low":0.0,"central":0.02,"high":0.05,"bar":{"op":"<=","value":0.01}},
 {"name":"class:secrets:failed_rate","low":0.0,"central":0.1,"high":0.3}]}"#;

#[test]
fn f1_a_valid_forecast_parses() {
    let f = parse(OK.as_bytes()).unwrap();
    assert_eq!(f.stage, "S1");
    assert_eq!(f.metrics.len(), 2);
    assert_eq!(f.metrics[0].name, "failed_rate");
    assert_eq!(f.metrics[0].bar.as_ref().unwrap().op, "<=");
    assert!(f.metrics[1].bar.is_none());
}

fn refused(doc: &str, why: &str) {
    let e = parse(doc.as_bytes()).unwrap_err();
    assert!(
        !e.0.contains("not yet implemented"),
        "{why}: still the red-phase stub"
    );
}

#[test]
fn f2_every_refusal() {
    refused("nope", "not json");
    refused(
        &OK.replace("entropa-forecast-v1", "entropa-forecast-v9"),
        "schema",
    );
    refused(
        &OK.replace(r#""name":"failed_rate""#, r#""name":"vibes""#),
        "unknown metric name",
    );
    refused(
        &OK.replace(r#""central":0.02"#, r#""central":0.5"#),
        "central above high",
    );
    refused(
        &OK.replace(
            r#""low":0.0,"central":0.02"#,
            r#""low":0.03,"central":0.02"#,
        ),
        "low above central",
    );
    refused(&OK.replace(r#""op":"<=""#, r#""op":"~""#), "bad operator");
    refused(
        &OK.replace(r#""stage":"S1""#, r#""stage":"S 1""#),
        "stage outside the pattern",
    );
    refused(
        &OK.replace(r#""metrics":["#, r#""extra":1,"metrics":["#),
        "unknown field",
    );
    refused(
        r#"{"schema":"entropa-forecast-v1","stage":"S1","written":"x","metrics":[]}"#,
        "no metrics",
    );
    refused(
        &OK.replace(
            r#""low":0.0,"central":0.02,"high":0.05"#,
            r#""low":0.0,"central":0.02,"high":0.05,"low":0.1"#,
        ),
        "duplicate key",
    );
}
