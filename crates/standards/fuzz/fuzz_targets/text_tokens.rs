#![no_main]
use entropa_standards::{flags, text};
use libfuzzer_sys::fuzz_target;

// The tokenizer, stemmer, sanitiser, quote window and the flag detectors on arbitrary text.
fuzz_target!(|data: &[u8]| {
    let (n, rest) = data.split_first().map_or((0, data), |(s, r)| (usize::from(*s), r));
    let half = rest.len() / 2;
    let a = String::from_utf8_lossy(&rest[..half]).into_owned();
    let b = String::from_utf8_lossy(&rest[half..]).into_owned();
    let toks = text::tokens(&a);
    let qt = text::tokens(&b);
    let _ = text::sanitise(&a);
    let _ = text::first_words(&a, n);
    let w = text::best_window(&a, &qt, n);
    assert!(w.split_whitespace().count() <= n.max(a.split_whitespace().count()));
    let _ = text::stem(&a);
    let df = flags::gram_df(std::iter::once(toks.as_slice()));
    let _ = flags::static_flags(&a, &toks, &df);
    let _ = flags::query_flags(&qt, &toks, flags::is_question(&b));
    let _ = flags::longest_run(&qt, &toks);
});
