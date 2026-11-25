//! EG1f red tests, part 1: the context detector and pipeline v2 (a stage record (not published)). Expected results are written by hand from the syntax, not from the code; DEV bars are fixed in the plan.
//! Secret-shaped values are synthetic words and tokens; no identifier-shaped numbers. Red against the stub (`context::scan` finds nothing, v2 equals v1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common_f;
use common_f::*;
use entropa_egress::context::scan;
use entropa_egress::decide::Action;
use serde_json::json;

fn blocked_v2(body: &str) -> bool {
    let p = policy_of("eval_dev_f");
    v2(
        &json!({"body": body, "body_is_json": false, "expect": "no_leak", "tier": "T1"}),
        &p,
    ) == Action::Block
}

// the value placeholders used below are synthetic (words and a mixed token)
const V: &str = "Xk39fQ2zLp";
const W: &str = "island ember 42! harbor";

#[test]
fn x1_the_context_scan_finds_the_value_in_every_round_5_syntax() {
    let cases: Vec<String> = vec![
        format!("ALTER USER app_user PASSWORD '{W}';"),
        format!("CREATE USER app_user IDENTIFIED BY '{V}';"),
        format!("<password>{V}</password>"),
        format!("<client_secret>{W}</client_secret>"),
        format!("'password' => '{W}',"),
        format!("$p = ConvertTo-SecureString \"{V}\" -AsPlainText -Force"),
        format!("mytool --password {V}"),
        format!("mytool --password \"{W}\""),
        format!("mytool --api-key={V}"),
        format!("docker run -e SECRET_KEY={V} image:1"),
        format!("db.password={V}"),
        format!("X-API-Key: {V}"),
        format!("Authorization: Token {V}"),
        format!("sec/ret_k/ey={V}"),
        format!("s-e-c-r-e-t_k:e:y: {V}"),
        format!("service/auth/password: {V}"),
        format!("{{\"client_secret\": \"{W}\"}}"),
        format!("password = \"{W}\""),
        "token: abc.def-123_xyz".to_string(),
        format!("$password = \"{V}\""),
        format!("API_KEY={V}"),
        format!("Authorization: Be-ar-er {V}AB"),
        format!("ENV['DB_PASSWORD'] = \"{V}\""),
        format!("wget --password={V} https://files.example.test/a"),
        format!("string dbPassword = \"{W}\";"),
        format!("let access_key = \"{V}\";"),
        format!("variable \"password\" {{ default = \"{W}\" }}"),
        format!("curl -H 'Authorization: Token {V}' https://api.example.test/v1"),
    ];
    for c in &cases {
        assert!(
            !scan(c).is_empty(),
            "the context scan found nothing in: {c}"
        );
        assert!(blocked_v2(c), "v2 did not block: {c}");
    }
    // the hit covers the value, not the key
    let t = format!("password = \"{W}\"");
    let hits = scan(&t);
    assert_eq!(&t[hits[0].start..hits[0].end], W);
}

#[test]
fn x2_references_placeholders_and_prose_are_not_secrets() {
    let clean = [
        "$password = Read-Host -AsSecureString",
        "$password = $env:DB_PASSWORD",
        "$token = Get-Secret -Name ProdDb -AsPlainText",
        "$apiKey = $config.ApiKey",
        "$password = getenv('DB_PASSWORD');",
        "$token = $_ENV['TOKEN'];",
        "$secret = config('app.secret');",
        "password = os.environ['DB_PASSWORD']",
        "password = get_password()",
        "api_key = \"\"",
        "token = None",
        "secret = ${SECRET}",
        "TOKEN={{ token }}",
        "password: <your-password>",
        "api_key = \"changeme\"",
        "password = \"your-password-here\"",
        "client_secret: ********",
        "db.password=${DB_PASS}",
        "db.password=",
        "The password policy requires at least twelve characters.",
        "API key rotation happens every ninety days.",
        "Token expired, please log in again.",
        "Keep the secret key out of the repository.",
        "Where is the private key stored?",
        "API key: required for all calls",
        "Reset your password from the account page.",
    ];
    for c in clean {
        assert!(
            scan(c).is_empty(),
            "false positive in the context scan: {c}"
        );
        // v1 itself blocks "API key: required for all calls" through a decoded view (its own false positive, not touched in this stage); the context scan alone must not flag it
        if c != "API key: required for all calls" {
            assert!(!blocked_v2(c), "v2 blocked harmless text: {c}");
        }
    }
    // a placeholder word with a real tail is still a secret
    assert!(blocked_v2("api_key = \"changeme-Xk39fQ2zLp\""));
}

#[test]
fn x3_the_scan_never_splits_a_character_and_never_panics_on_hostile_strings() {
    let frags = [
        "password",
        "pass-word",
        "sec/ret_k:ey",
        "token",
        "=",
        ":",
        "=>",
        "\"",
        "'",
        "<",
        ">",
        "--",
        " ",
        "é",
        "日本",
        "\u{1F600}",
        "\u{202e}",
        "\u{0}",
        "ß",
        "İ",
        "ａｐｉ",
        "Xk39fQ",
        "(",
        ")",
        "$",
        "\\",
        "\n",
        "-e ",
        "IDENTIFIED BY ",
        "ConvertTo-SecureString ",
    ];
    let mut x: u64 = 0x1234_5678_9ABC_DEF1;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..60_000 {
        let n = 1 + (next() % 14) as usize;
        let mut s = String::new();
        for _ in 0..n {
            s.push_str(frags[(next() % frags.len() as u64) as usize]);
        }
        let r = std::panic::catch_unwind(|| scan(&s));
        let hits = r.unwrap_or_else(|_| panic!("panic on {s:?}"));
        for h in hits {
            assert!(
                h.start <= h.end && h.end <= s.len(),
                "range outside the text on {s:?}"
            );
            assert!(
                s.is_char_boundary(h.start) && s.is_char_boundary(h.end),
                "the hit splits a character on {s:?}"
            );
        }
    }
}

#[test]
fn x4_dev_f_secrets_leak_at_most_ten_of_1080_under_v2_and_clean_blocks_at_most_twelve_of_630() {
    let p = policy_of("eval_dev_f");
    let secrets = cases("eval_dev_f", "eg_secrets.jsonl");
    let clean = cases("eval_dev_f", "eg_clean.jsonl");
    assert_eq!((secrets.len(), clean.len()), (1080, 630));
    let leaked: Vec<String> = secrets
        .iter()
        .filter(|c| leaks(c, v2(c, &p)))
        .map(|c| c["family"].as_str().unwrap().to_string())
        .collect();
    let blocked: Vec<String> = clean
        .iter()
        .filter(|c| blocks_clean(c, v2(c, &p)))
        .map(|c| c["family"].as_str().unwrap().to_string())
        .collect();
    assert!(
        leaked.len() <= 10,
        "{} of 1080 leaked; by family: {:?}",
        leaked.len(),
        leaked.iter().take(12).collect::<Vec<_>>()
    );
    assert!(
        blocked.len() <= 12,
        "{} of 630 blocked; by family: {:?}",
        blocked.len(),
        blocked.iter().take(12).collect::<Vec<_>>()
    );
    for fam in ["ps_assign", "php_assign", "placeholder"] {
        let n = clean.iter().filter(|c| c["family"] == fam).count();
        let b = clean
            .iter()
            .filter(|c| c["family"] == fam && blocks_clean(c, v2(c, &p)))
            .count();
        assert!(b * 100 <= 3 * n, "{fam}: {b} of {n} blocked");
    }
}

#[test]
fn x5_older_dev_sets_get_no_new_block_and_no_new_leak_under_v2() {
    for set in ["eval_dev", "eval_dev_c", "eval_dev_d", "eval_dev_e"] {
        let p = policy_of(set);
        for file in [
            "eg_secrets.jsonl",
            "eg_clean.jsonl",
            "eg_personal.jsonl",
            "eg_terms.jsonl",
            "eg_destination.jsonl",
            "eg_abuse.jsonl",
        ] {
            let Ok(text) = std::fs::read_to_string(dir(set).join(file)) else {
                continue;
            };
            // every 4th case in the test (the full comparison is made with the runner in release: `egress-eval dev-eval --pipeline v1` against `--pipeline v2`, evidence docs/evidence/eg1f/)
            for l in text.lines().filter(|l| !l.trim().is_empty()).step_by(4) {
                let c: serde_json::Value = serde_json::from_str(l).unwrap();
                let (a1, a2) = (v1(&c, &p), v2(&c, &p));
                if c["expect"] == "allow" {
                    assert!(
                        !(a1 != Action::Block && a2 == Action::Block),
                        "{set}/{file}: v2 blocks what v1 allowed: {}",
                        c["id"]
                    );
                }
                if c["expect"] == "no_leak" {
                    assert!(
                        !(a1 == Action::Block && a2 != Action::Block),
                        "{set}/{file}: v2 allows what v1 blocked: {}",
                        c["id"]
                    );
                }
            }
        }
    }
}

#[test]
fn x6_the_old_decide_is_unchanged_in_behaviour_and_v2_never_allows_what_v1_blocked_among_secrets() {
    // among SECRET cases v2 only adds blocks. Among clean cases v2 may lift the guard's heuristic credential block on a harmless assignment (that is its purpose), so for them only "no new block" is asserted.
    let p = policy_of("eval_dev_f");
    for c in cases("eval_dev_f", "eg_secrets.jsonl") {
        let (a1, a2) = (v1(&c, &p), v2(&c, &p));
        assert!(!(a1 == Action::Block && a2 != Action::Block), "{}", c["id"]);
    }
    for c in cases("eval_dev_f", "eg_clean.jsonl") {
        let (a1, a2) = (v1(&c, &p), v2(&c, &p));
        assert!(!(a1 != Action::Block && a2 == Action::Block), "{}", c["id"]);
    }
}
