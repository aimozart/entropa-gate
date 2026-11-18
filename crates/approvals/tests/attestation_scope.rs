//! S3c addition, found by the P1 property test on a later random seed: an attestation may open the
//! gate for the `direction` class only. Merge, deploy and policy_change are not hard-rule classes,
//! but the reviewer's ruling is that attestation yields Allowed for direction alone, whatever the policy
//! argument lists.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::*;

#[test]
fn r11c_an_attestation_for_any_class_other_than_direction_is_not_accepted() {
    let f = fx();
    for class in ActionClass::ALL {
        let req = f.request(class, "s1", NOW - 1000, 86_400);
        let a = f.attest_approve(&req.event.request_id, NOW - 500);
        let state = replay(&log_with(&[req, a]), &f.dir, NOW);
        assert_eq!(state.rejected, vec![], "{class:?}: still recorded");
        let got = check(&state, class, &subject("s1"), NOW, &policy_all());
        if class == ActionClass::Direction {
            assert!(
                matches!(got, GateDecision::Allowed { attested: true, .. }),
                "{got:?}"
            );
        } else {
            assert_eq!(
                got,
                GateDecision::Blocked(BlockReason::AttestationNotAccepted),
                "{class:?}"
            );
        }
    }
}

#[test]
fn r11d_a_policy_that_omits_direction_blocks_even_direction() {
    let f = fx();
    let req = f.request(ActionClass::Direction, "s1", NOW - 1000, 86_400);
    let a = f.attest_approve(&req.event.request_id, NOW - 500);
    let state = replay(&log_with(&[req, a]), &f.dir, NOW);
    let none = AttestationPolicy {
        accepted_for: vec![],
    };
    assert_eq!(
        check(&state, ActionClass::Direction, &subject("s1"), NOW, &none),
        GateDecision::Blocked(BlockReason::AttestationNotAccepted)
    );
}
