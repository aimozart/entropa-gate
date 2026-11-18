//! The deterministic rendering of decisions that a model is shown: closed codes and references only.

use crate::{CouncilError, Event};

fn evidence(e: &Event) -> String {
    let items: Vec<String> = e
        .array_field("evidence")
        .iter()
        .filter_map(|i| {
            Some(format!(
                "{}:{}",
                i.get("kind")?.as_str()?,
                i.get("ref")?.as_str()?
            ))
        })
        .collect();
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(",")
    }
}

/// One line for an event, or `None` for an event type that is not shown to a model.
pub(crate) fn line(e: &Event) -> Option<String> {
    let s = |k: &str| e.str_field(k).unwrap_or_default().to_string();
    Some(match e.event_type() {
        "finding.submitted" => format!(
            "finding {} subject={} class={} severity={} confidence={} change={} evidence={}",
            s("finding_id"),
            s("subject_ref"),
            s("class"),
            s("severity"),
            s("confidence"),
            s("proposed_change"),
            evidence(e)
        ),
        "rebuttal.submitted" => format!(
            "rebuttal {} stance={} counter={} evidence={}",
            s("finding_id"),
            s("stance"),
            s("counter"),
            evidence(e)
        ),
        "decision.recorded" => format!(
            "decision {} decision={} reason={} change={} attested={}",
            s("finding_id"),
            s("decision"),
            s("reason"),
            s("change_kind"),
            e.bool_field("attested").unwrap_or(false)
        ),
        "outcome.recorded" => format!(
            "outcome {} outcome={} delay={} source={}",
            s("decision_ref"),
            s("outcome"),
            e.u64_field("delay_secs").unwrap_or(0),
            s("source")
        ),
        _ => return None,
    })
}

/// Render in-window decision events as the closed-code text a reviewer model sees: only the codes and references
/// of the events, in a fixed order and layout, never any vault text, hash of a text, or signature.
pub fn render_for_model(events: &[Event]) -> Result<String, CouncilError> {
    let mut lines = Vec::with_capacity(events.len());
    for e in events {
        lines.push(line(e).ok_or_else(|| {
            CouncilError::Invalid("this event type is not rendered for a model".into())
        })?);
    }
    lines.sort();
    let out: String = lines.iter().map(|l| format!("{l}\n")).collect();
    if !entropa_synthetic::scan(&out).is_empty() {
        return Err(CouncilError::Invalid(
            "a canary token reached a model input".into(),
        ));
    }
    Ok(out)
}
