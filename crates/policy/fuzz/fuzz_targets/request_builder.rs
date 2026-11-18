#![no_main]
use entropa_approvals::{ActionClass, BlockReason, GateDecision};
use entropa_policy::*;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn engine() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| {
        Engine::new(
            include_str!("../../../../policies/entropa.cedarschema"),
            include_str!("../../../../policies/entropa.cedar"),
        )
        .expect("reference policies load")
    })
}

// Arbitrary request fields never panic, and an Allow always carries a Cedar allow.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let mut parts = text.splitn(5, '|');
    let mut next = || parts.next().unwrap_or("").to_string();
    let (principal, subject_hash, subject_kind, action_name) = (next(), next(), next(), next());
    let flags = next().bytes().fold(0u8, |a, b| a.wrapping_add(b));
    let action = Action::parse(&action_name).unwrap_or(Action::CallTool);
    let req = Request {
        principal,
        role: [RoleName::Human, RoleName::Ai, RoleName::Service][(flags % 3) as usize],
        has_key: flags & 4 != 0,
        action,
        subject_hash,
        subject_kind,
        now: u64::from(flags) << 56,
        env: if flags & 8 != 0 { Env::Prod } else { Env::Dev },
    };
    let gate = if flags & 16 != 0 {
        GateDecision::Allowed { request_id: "r".into(), approver: "0123456789abcdef".into(), attested: flags & 32 != 0 }
    } else {
        GateDecision::Blocked(BlockReason::Pending)
    };
    let d = engine().decide(&req, &gate, Mode::Enforce);
    if d.outcome == Outcome::Allow {
        assert_eq!(d.cedar, Some(Outcome::Allow));
        assert!(d.error_policies.is_empty());
    }
    let _ = ActionClass::Delete;
});
