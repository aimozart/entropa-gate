//! EG1f: hostile strings through the context detector and the v2 pipeline: no panic, no character split, every hit inside the text (a stage record (not published) bar). Deterministic (xorshift); synthetic fragments only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common_f;
use common_f::*;
use entropa_egress::context::{analyze, scan};

const FRAGMENTS: &[&str] = &[
    "password",
    "pass-word",
    "pa-ss-wo-rd",
    "sec/ret_k:ey",
    "secret_key",
    "api_key",
    "api key",
    "token",
    "Bearer ",
    "Authorization: ",
    "Token ",
    "IDENTIFIED BY ",
    "PASSWORD ",
    "ConvertTo-SecureString ",
    "--password ",
    "--api-key=",
    "-e ",
    "export ",
    "<password>",
    "</password>",
    "'password' => ",
    "$password = ",
    "$env:",
    "Read-Host",
    "getenv(",
    "ENV['",
    "']",
    "config(",
    "${",
    "}",
    "{{",
    "%(",
    ")s",
    "<",
    ">",
    "=",
    ":",
    ":=",
    "=>",
    "->",
    " = ",
    "\"",
    "'",
    "`",
    "(",
    ")",
    "[",
    "]",
    "\\",
    "\n",
    "\r\n",
    " ",
    "\t",
    ";",
    ",",
    "variable ",
    "{ default = ",
    " }",
    "db.",
    "service/auth/",
    "vault/kv/",
    "changeme",
    "your-password-here",
    "****",
    "null",
    "None",
    "!secret ",
    "ref+vault://",
    "é",
    "ü",
    "日本",
    "\u{1F600}",
    "\u{202e}",
    "\u{200b}",
    "\u{0}",
    "ß",
    "İ",
    "ｐａｓｓ",
    "Xk39fQ2zLp",
    "river stone 42!",
    "AKIA",
    "eyJ",
    "-----BEGIN ",
    "%41%42",
    "UGFzc3dvcmQ9",
    "1",
    "12345",
];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
fn gen(r: &mut Rng) -> String {
    let n = 1 + r.below(28);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(FRAGMENTS[r.below(FRAGMENTS.len())]);
    }
    if r.below(3) == 0 && !s.is_empty() {
        let mut k = r.below(s.len() + 1);
        while !s.is_char_boundary(k) {
            k -= 1;
        }
        s.truncate(k);
    }
    s
}

#[test]
fn h1_four_hundred_thousand_hostile_strings_never_panic_the_context_scan_and_hits_stay_inside_the_text(
) {
    let mut r = Rng(0xA5A5_1234_9E37_79B9);
    for _ in 0..400_000u32 {
        let s = gen(&mut r);
        let a =
            std::panic::catch_unwind(|| analyze(&s)).unwrap_or_else(|_| panic!("panic on {s:?}"));
        for h in a.secrets.iter().chain(a.references.iter()) {
            assert!(
                h.start <= h.end && h.end <= s.len(),
                "range outside the text on {s:?}"
            );
            assert!(
                s.is_char_boundary(h.start) && s.is_char_boundary(h.end),
                "a hit splits a character on {s:?}"
            );
        }
        assert_eq!(scan(&s), a.secrets);
    }
}

#[test]
fn h2_the_v2_pipeline_never_panics_on_hostile_strings_in_any_tier() {
    use entropa_egress::policy::Tier;
    let p = policy_of("eval_dev_f");
    let mut r = Rng(0x0F0F_C0DE_1BAD_5EED);
    let iters: u32 = if cfg!(debug_assertions) {
        40_000
    } else {
        200_000
    };
    for i in 0..iters {
        let s = gen(&mut r);
        let tier = [Tier::T0, Tier::T1, Tier::T2, Tier::T3][(i % 4) as usize];
        let req = request(&serde_json::json!({"body": s}));
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            entropa_egress::v2::decide_v2(&req, &p, tier, &conv(), &Null)
        }));
        assert!(res.is_ok(), "panic on {s:?}");
    }
}
