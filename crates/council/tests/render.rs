//! What a model is shown: a deterministic rendering of closed codes, never free text, never a canary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use serde_json::json;

#[test]
fn m1_the_rendering_is_the_documented_closed_code_text() {
    // the default finding event (subject idx:1), not the finding(1) helper, whose subject is idx:2
    let out = must(render_for_model(&[
        ev("finding.submitted", json!({})),
        ev("decision.recorded", json!({})),
    ]));
    assert_eq!(
        out,
        "decision f-1 decision=accept reason=evidence_sufficient change=test attested=false\n\
         finding f-1 subject=idx:1 class=missing_approval severity=high confidence=medium change=test evidence=ledger_index:idx:1\n"
    );
}

#[test]
fn m2_the_order_of_the_events_does_not_change_the_rendering() {
    let a = must(render_for_model(&[
        finding(1),
        finding(2),
        ev("decision.recorded", json!({})),
    ]));
    let b = must(render_for_model(&[
        ev("decision.recorded", json!({})),
        finding(2),
        finding(1),
    ]));
    assert_eq!(a, b);
}

#[test]
fn m3_nothing_but_codes_references_and_layout_reaches_the_model() {
    let hashy = ev(
        "finding.submitted",
        json!({"text_hash": hex64('c'), "evidence": [{"kind":"event_hash","ref": hex64('9')}]}),
    );
    let out = must(render_for_model(&[
        hashy,
        ev("decision.recorded", json!({"auth_ref": hex64('d')})),
    ]));
    assert!(
        out.chars()
            .all(|c| c.is_ascii_alphanumeric() || " _.:/=,-\n".contains(c)),
        "{out:?}"
    );
    assert!(!out.contains(&hex64('c')), "the text hash is not shown");
    assert!(
        !out.contains(&hex64('d')),
        "the passkey assertion reference is not shown"
    );
    assert!(!out.contains("sig"), "no signature is shown");
    assert!(
        entropa_synthetic::scan(&out).is_empty(),
        "no canary reaches a model input"
    );
}

#[test]
fn m4_only_reviewable_events_can_be_rendered() {
    for kind in [
        "session.opened",
        "packet.compiled",
        "proof.recorded",
        "evaluation.recorded",
    ] {
        assert!(
            matches!(
                render_for_model(&[ev(kind, json!({}))]),
                Err(CouncilError::Invalid(_))
            ),
            "{kind}"
        );
    }
}
