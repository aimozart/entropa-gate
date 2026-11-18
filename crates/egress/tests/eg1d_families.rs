//! EG1d red tests (a stage record (not published)). A: the assignment rule tells a literal credential from a reference (call, lookup, path, variable) and keeps blocking literals, including camelCase
//! names, Go `:=` and a literal passed to a call. B: a hyphen grouping that starts mid-line, irregular hyphens and compounds of two disguises. Synthetic values only; results by hand.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action};
use entropa_egress::policy::Tier;

fn act(body: &str) -> Action {
    decide(&text_req(body), &policy(), Tier::T1, &conv(), &Mem::new()).action()
}
const T: &str = "Ab3dE6gH9jK2mN5pQ7rS9tU1vW";

#[test]
fn a1_references_are_allowed() {
    for l in [
        "token = next_token()",
        "api_key = os.environ[\"API_KEY\"]",
        "password = getpass.getpass()",
        "api_key = get_api_key(config)",
        "token = self.refresh_token()",
        "let apiKey = process.env.API_KEY;",
        "client_secret = config.get(\"auth\", \"client_secret\")",
        "secret = load_secret(name)",
        "password = var.db_password",
        "token = settings.TOKEN",
        "String password = System.getenv(\"DB_PASSWORD\");",
        "let api_key = std::env::var(\"API_KEY\")?;",
        "api_key = db_api_key_value",
        "token = cfg.Token",
        "secret: ref+vault://secret/app#token",
        "password: ${DB_PASSWORD}",
        "const token = await getToken();",
        "SECRET := secretStore.Fetch(ctx, id)",
        "secret = secrets_client.get_secret_value(SecretId=sid)[\"SecretString\"]",
        "ENV API_KEY=${API_KEY}",
    ] {
        assert_eq!(act(l), Action::Allow, "{l}");
        assert_eq!(
            act(&format!("Notes:\n{l}\nThanks.")),
            Action::Allow,
            "among prose: {l}"
        );
    }
}

#[test]
fn a2_literal_credentials_stay_blocked_in_every_form() {
    for l in [
        format!("password = \"{T}\""),
        format!("password = '{T}'"),
        format!("password = {T}"),
        format!("dbPassword = \"{T}\""),
        format!("{{\"dbPassword\": \"{T}\"}}"),
        format!("githubToken: {T}"),
        format!("apiKey := \"{T}\""),
        format!("API_KEY := \"{T}\""),
        format!("export API_KEY={T}"),
        format!("https://svc.example.invalid/v1/items?api_key={T}&limit=5"),
        format!("String password = \"{T}\";"),
        format!("let secret = \"{T}\";"),
        format!("ENV API_KEY={T}"),
    ] {
        assert_eq!(act(&l), Action::Block, "{l}");
        assert_eq!(
            act(&format!("Notes:\n{l}\nThanks.")),
            Action::Block,
            "among prose: {l}"
        );
    }
}

#[test]
fn a3_a_literal_inside_a_call_is_still_a_credential() {
    for l in [
        format!("api_key = get_key(\"{T}\")"),
        format!("token = fetch(\"{T}\")"),
        format!("get_credentials(\"{T}\")  # api_key"),
        format!("load_token(\"{T}\")"),
        format!("secret = config.get(\"{T}\")"),
    ] {
        assert_eq!(act(&l), Action::Block, "{l}");
    }
    // a call whose arguments are names, not credentials, stays allowed
    for l in [
        "token = get_token(\"production\", retries=3)",
        "api_key = config.get(\"service_api_key\")",
        "password = prompt(\"Enter your password:\")",
    ] {
        assert_eq!(act(l), Action::Allow, "{l}");
    }
}

fn hyphen(s: &str, g: usize) -> String {
    s.chars()
        .collect::<Vec<_>>()
        .chunks(g)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            o => o,
        })
        .collect()
}
const PH: [&str; 3] = [
    "Authorization: Bearer Cn5WJHxOY6UF2EkNqdM5QdDG2tZ8",
    "password = \"Cn5WJHxOY6UF2EkNqdM5QdDG2tZ8\"",
    "secret: Cn5WJHxOY6UF2EkNqdM5QdDG2tZ8",
];

#[test]
fn b1_a_hyphen_grouping_that_starts_mid_line_is_seen() {
    for p in PH {
        for g in 2..=10 {
            let l = format!("see this: {}", hyphen(p, g));
            assert_eq!(act(&l), Action::Block, "g={g}: {l}");
        }
    }
}

#[test]
fn b2_irregular_hyphens_through_the_phrase_are_seen() {
    for p in PH {
        let mut out = String::new();
        let (mut i, mut k) = (0, 0usize);
        let cs: Vec<char> = p.chars().collect();
        while i < cs.len() {
            let g = [2, 5, 3, 9, 4, 7, 6, 10][k % 8];
            out.extend(&cs[i..(i + g).min(cs.len())]);
            i += g;
            if i < cs.len() {
                out.push('-');
            }
            k += 1;
        }
        assert_eq!(act(&out), Action::Block, "{out}");
        assert_eq!(
            act(&format!("I pasted {out}")),
            Action::Block,
            "mid-line {out}"
        );
    }
}

#[test]
fn b3_a_compound_of_two_disguises_is_seen() {
    for p in PH {
        let rev: String = p.chars().rev().collect();
        for (n, d) in [
            ("rot13 of reverse", rot13(&rev)),
            ("hyphen of reverse", hyphen(&rev, 4)),
            ("hyphen of rot13", hyphen(&rot13(p), 5)),
            ("rot13 of hyphen", rot13(&hyphen(p, 6))),
        ] {
            assert_eq!(act(&d), Action::Block, "{n}: {d}");
        }
    }
}

#[test]
fn b4_ordinary_hyphenated_text_stays_allowed() {
    for t in [
        "Call the desk on 555-0142 or 555-0187.",
        "Dates: 2026-03-14 to 2026-04-02.",
        "A well-known, state-of-the-art, end-to-end, long-term, open-source, read-only, multi-step plan.",
        "id 3f2a9c1e-77b4-4d1a-9e0c-5a6b7c8d9e0f was created",
        "See pages 12-48 and figures 3-17.",
        "I pasted the part numbers AB12-CD34-EF56, 90AB-12CD-34EF.",
        "see this: well-known long-term read-only state-of-the-art plan",
    ] {
        assert_eq!(act(t), Action::Allow, "{t}");
    }
}
