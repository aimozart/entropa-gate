#![no_main]
use entropa_council::*;
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

const SID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NOW: u64 = 1_800_000_000;

fn base(ty: &str, extra: Value) -> Value {
    let mut v = extra;
    let m = v.as_object_mut().unwrap();
    m.insert("v".into(), json!(1));
    m.insert("type".into(), json!(ty));
    m.insert("alg".into(), json!("ML-DSA-65"));
    m.insert("actor".into(), json!("0123456789abcdef"));
    m.insert("ts".into(), json!(NOW + 100));
    m.insert("session_id".into(), json!(SID));
    m.insert("sig".into(), json!("abcd"));
    v
}

// A structure-aware state-machine fuzzer: the bytes pick event types, fields, roles and times. Whatever the order, the
// session never panics, a quorum-less session approves nothing, and every approved change has an approval reference.
fuzz_target!(|data: &[u8]| {
    let refs = ["idx:1".to_string(), "idx:2".to_string(), "idx:3".to_string()];
    let scope = Scope { decisions: vec![(refs[0].clone(), Provider::Bedrock), (refs[1].clone(), Provider::Vertex), (refs[2].clone(), Provider::Bedrock)] };
    let open = base("session.opened", json!({"cadence":"weekly","trigger":"schedule","period_start":1,"period_end":2,"window_hash":window_hash(&refs),"n_decisions":3,"expires":NOW+604_800}));
    let Ok(open) = decode_event(&open.to_string()) else { return };
    let Ok(mut s) = Session::open(&open, Role::Scheduler, &scope) else { return };
    let roles = [Role::Scheduler, Role::Critic, Role::Contestor, Role::Orchestrator, Role::Human, Role::Builder];
    let provs = ["bedrock", "vertex", "fake"];
    for w in data.chunks(4).take(60) {
        let b = |i: usize| usize::from(w.get(i).copied().unwrap_or(0));
        let id = format!("f-{}", b(1) % 4);
        let n = b(1) % 4;
        let ids: Vec<String> = (0..n).map(|i| format!("f-{i}")).collect();
        let (subject, sev, prov) = (refs[b(2) % 3].clone(), ["low", "hard_rule"][b(3) % 2], provs[b(3) % 3]);
        let (decision, change, with_ref) = (["accept", "reject", "defer"][b(2) % 3], ["none", "test"][b(3) % 2], b(2) % 2 == 1);
        let (approval, auth) = (if with_ref { json!("appr") } else { Value::Null }, if with_ref { json!("d".repeat(64)) } else { Value::Null });
        let closing = ["expired_pending", "no_quorum"][b(2) % 2];
        let ev = match b(0) % 8 {
            0 => base("finding.submitted", json!({"finding_id":id,"subject_ref":subject,"class":"policy_gap","severity":sev,"confidence":"low","proposed_change":"test","evidence":[],"provider":prov,"model_id":"m","text_hash":null})),
            1 => base("report.submitted", json!({"n_findings":n,"findings_hash":findings_hash(&ids)})),
            2 => base("rebuttal.submitted", json!({"finding_id":id,"stance":"agree","counter":"duplicate","evidence":[],"provider":prov,"model_id":"m","text_hash":null})),
            3 => base("packet.compiled", json!({"packet_hash":"e".repeat(64),"item_count":n,"findings_hash":findings_hash(&ids),"items":ids.iter().map(|i| json!({"finding_id":i,"check":"verified","recommendation":"accept"})).collect::<Vec<_>>(),"text_hash":null})),
            4 => base("decision.recorded", json!({"finding_id":id,"decision":decision,"reason":"risk_accepted","change_kind":change,"approval_ref":approval,"attested":b(3)%2==0,"auth_ref":auth})),
            5 => base("session.closed", json!({"closing":"all_decided","accepted":b(2)%3,"rejected":b(3)%3,"deferred":0,"pending":0})),
            6 => base("session.expired", json!({"closing":closing,"accepted":0,"rejected":0,"deferred":0,"pending":b(3)%3})),
            _ => base("carryover.recorded", json!({"n_candidates":9,"carried_ids":["f-9"],"carried_hash":findings_hash(&["f-9".to_string()]),"to_period_start":NOW})),
        };
        let Ok(ev) = decode_event(&ev.to_string()) else { continue };
        let at = NOW + (b(2) as u64) * if b(3) % 7 == 0 { 200_000 } else { 10 };
        let _ = s.apply(&ev, roles[b(3) % roles.len()], at);
        if !s.quorum().valid() {
            assert!(s.approved_changes().is_empty());
        }
        assert!(s.approved_changes().iter().all(|c| !c.approval_ref.is_empty()));
        let p = s.pending_items();
        assert!(p.windows(2).all(|x| x[0] < x[1]), "pending items are sorted and unique");
        let _ = s.state(at);
    }
});
