//! The closed-code schema of every council event (the council design notes section 6).

/// What a field may hold.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    /// 64 lower-case hex digits.
    Hex64,
    /// 64 lower-case hex digits or null.
    Hex64OrNull,
    /// An id or reference token: 1 to 64 characters of `A-Za-z0-9._:/-`.
    Token,
    /// A token or null.
    TokenOrNull,
    /// One of a closed list.
    Enum(&'static [&'static str]),
    /// A non-negative integer.
    U64,
    /// An integer from 0 to 1000.
    Permille,
    /// A boolean.
    Bool,
    /// At most 8 `{kind, ref}` evidence items.
    Evidence,
    /// At most 5 tokens.
    TokenList5,
    /// At most 64 tokens.
    TokenList64,
    /// At most 12 `{finding_id, check, recommendation}` packet items.
    Items,
}

pub(crate) const PROVIDERS: &[&str] = &["bedrock", "vertex", "fake"];
pub(crate) const SEVERITIES: &[&str] = &["low", "medium", "high", "hard_rule"];
pub(crate) const CHANGE_KINDS: &[&str] = &["test", "cedar_change", "lesson", "none"];
pub(crate) const EVIDENCE_KINDS: &[&str] = &["ledger_index", "event_hash", "precedent_id"];
pub(crate) const CHECKS: &[&str] = &["verified", "ref_missing", "ref_foreign", "ref_mismatch"];
pub(crate) const RECOMMENDATIONS: &[&str] = &["accept", "reject", "defer"];
const CLASSES: &[&str] = &[
    "missing_approval",
    "wrong_subject",
    "policy_gap",
    "overbroad_allow",
    "unsupported_claim",
    "inconsistent_with_precedent",
    "calibration_drift",
    "cost_anomaly",
    "promote_precedent",
    "other",
];
const LEVELS: &[&str] = &["low", "medium", "high"];
const STANCES: &[&str] = &["agree", "disagree", "partial", "cannot_assess"];
const COUNTERS: &[&str] = &[
    "evidence_missing",
    "evidence_misread",
    "policy_intended",
    "hindsight_bias",
    "duplicate",
    "out_of_scope",
    "low_impact",
];
const REASONS: &[&str] = &[
    "evidence_sufficient",
    "evidence_insufficient",
    "already_handled",
    "risk_accepted",
    "out_of_scope",
    "wait_for_data",
];
const LINKED: &[&str] = &["test", "cedar_change", "lesson"];
const CLOSINGS: &[&str] = &["all_decided", "expired_pending", "no_quorum"];
const OUTCOMES: &[&str] = &[
    "as_intended",
    "overridden_by_human",
    "reversed",
    "incident",
    "no_signal",
];
const SOURCES: &[&str] = &["scenario_label", "human_override", "incident_flag"];
const FOLLOWED: &[&str] = &["yes", "no", "partly", "not_judged"];

/// Event types that belong to a session (they carry `session_id`).
pub(crate) fn is_session_bound(ty: &str) -> bool {
    !matches!(
        ty,
        "outcome.recorded"
            | "precedent.referenced"
            | "evaluation.recorded"
            | "index.built"
            | "precedent.revoked"
    )
}

/// The type-specific fields of an event type, or `None` for an unknown type.
pub(crate) fn fields_of(ty: &str) -> Option<&'static [(&'static str, Kind)]> {
    use Kind::*;
    Some(match ty {
        "session.opened" => &[
            ("cadence", Enum(&["weekly", "triggered", "retrospective"])),
            (
                "trigger",
                Enum(&[
                    "schedule",
                    "override_spike",
                    "policy_failure",
                    "incident",
                    "hard_rule_request",
                ]),
            ),
            ("period_start", U64),
            ("period_end", U64),
            ("window_hash", Hex64),
            ("n_decisions", U64),
            ("expires", U64),
        ],
        "finding.submitted" => &[
            ("finding_id", Token),
            ("subject_ref", Token),
            ("class", Enum(CLASSES)),
            ("severity", Enum(SEVERITIES)),
            ("confidence", Enum(LEVELS)),
            ("proposed_change", Enum(CHANGE_KINDS)),
            ("evidence", Evidence),
            ("provider", Enum(PROVIDERS)),
            ("model_id", Token),
            ("text_hash", Hex64OrNull),
        ],
        "report.submitted" => &[("n_findings", U64), ("findings_hash", Hex64)],
        "rebuttal.submitted" => &[
            ("finding_id", Token),
            ("stance", Enum(STANCES)),
            ("counter", Enum(COUNTERS)),
            ("evidence", Evidence),
            ("provider", Enum(PROVIDERS)),
            ("model_id", Token),
            ("text_hash", Hex64OrNull),
        ],
        "packet.compiled" => &[
            ("packet_hash", Hex64),
            ("item_count", U64),
            ("findings_hash", Hex64),
            ("items", Items),
            ("text_hash", Hex64OrNull),
        ],
        "decision.recorded" => &[
            ("finding_id", Token),
            ("decision", Enum(RECOMMENDATIONS)),
            ("reason", Enum(REASONS)),
            ("change_kind", Enum(CHANGE_KINDS)),
            ("approval_ref", TokenOrNull),
            ("attested", Bool),
            ("auth_ref", Hex64OrNull),
        ],
        "change.linked" => &[
            ("finding_id", Token),
            ("change_kind", Enum(LINKED)),
            ("ref", Token),
        ],
        "proof.recorded" => &[
            ("finding_id", Token),
            ("policy_set_hash_before", Hex64),
            ("policy_set_hash_after", Hex64),
            ("replay_set_hash", Hex64),
            ("n_replayed", U64),
            ("n_changed", U64),
            ("newly_denied", U64),
            ("newly_allowed", U64),
        ],
        "session.closed" | "session.expired" => &[
            ("closing", Enum(CLOSINGS)),
            ("accepted", U64),
            ("rejected", U64),
            ("deferred", U64),
            ("pending", U64),
        ],
        "outcome.recorded" => &[
            ("decision_ref", Token),
            ("outcome", Enum(OUTCOMES)),
            ("delay_secs", U64),
            ("source", Enum(SOURCES)),
        ],
        "precedent.referenced" => &[
            ("decision_ref", Token),
            ("index_hash", Hex64),
            ("precedent_ids", TokenList5),
            ("k", U64),
            ("followed", Enum(FOLLOWED)),
        ],
        "evaluation.recorded" => &[
            ("reviewer_provider", Enum(PROVIDERS)),
            ("reviewer_model_id", Token),
            ("suite_hash", Hex64),
            ("detection_permille", Permille),
            ("detection_high_permille", Permille),
            ("false_positive_permille", Permille),
            ("hallucinations", U64),
            ("hindsight_gap_pp", U64),
            ("stability_permille", Permille),
            ("injection_permille", Permille),
        ],
        "index.built" => &[
            ("kind", Enum(&["lexical", "dense"])),
            ("index_hash", Hex64),
            ("n_entries", U64),
            ("previous_index_hash", Hex64OrNull),
            ("manifest_hash", Hex64),
        ],
        "precedent.revoked" => &[
            ("precedent_id", Token),
            (
                "reason",
                Enum(&[
                    "wrong_outcome",
                    "superseded",
                    "policy_changed",
                    "poisoned",
                    "other",
                ]),
            ),
        ],
        "carryover.recorded" => &[
            ("n_candidates", U64),
            ("carried_ids", TokenList64),
            ("carried_hash", Hex64),
            ("to_period_start", U64),
        ],
        _ => return None,
    })
}
