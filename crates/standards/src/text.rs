//! Text helpers shared by indexing and querying: tokenisation, sanitising output, and word windows for short quotes.

/// Fixed stop words (documents and queries).
const STOP: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "from", "has", "have", "how",
    "i", "in", "is", "it", "its", "of", "on", "or", "that", "the", "their", "this", "to", "was",
    "were", "what", "when", "where", "which", "who", "why", "will", "with", "shall", "must", "may",
    "not", "should", "can", "do", "does", "about", "into", "over", "under", "such", "these",
    "those", "than", "then", "there", "if", "all", "any", "each", "every", "per", "via", "using",
    "use", "used", "we", "you", "your", "our", "me", "my",
];

/// The ASCII letter a look-alike (Cyrillic, Greek, full-width) character stands for, if it is one.
pub fn fold_confusable(c: char) -> Option<char> {
    let f = match c {
        '\u{ff01}'..='\u{ff5e}' => char::from_u32(c as u32 - 0xfee0)?,
        '\u{430}' | '\u{3b1}' => 'a',
        '\u{435}' => 'e',
        '\u{43e}' | '\u{3bf}' => 'o',
        '\u{440}' | '\u{3c1}' => 'p',
        '\u{441}' => 'c',
        '\u{445}' => 'x',
        '\u{443}' => 'y',
        '\u{456}' | '\u{3b9}' => 'i',
        '\u{458}' => 'j',
        '\u{455}' => 's',
        '\u{501}' => 'd',
        '\u{4bb}' => 'h',
        '\u{3bd}' => 'v',
        '\u{3ba}' => 'k',
        '\u{3c5}' => 'u',
        '\u{410}' | '\u{391}' => 'A',
        '\u{412}' | '\u{392}' => 'B',
        '\u{415}' | '\u{395}' => 'E',
        '\u{41a}' | '\u{39a}' => 'K',
        '\u{41c}' | '\u{39c}' => 'M',
        '\u{41d}' | '\u{397}' => 'H',
        '\u{41e}' | '\u{39f}' => 'O',
        '\u{420}' | '\u{3a1}' => 'P',
        '\u{421}' => 'C',
        '\u{422}' | '\u{3a4}' => 'T',
        '\u{425}' | '\u{3a7}' => 'X',
        '\u{406}' | '\u{399}' => 'I',
        '\u{408}' => 'J',
        '\u{405}' => 'S',
        '\u{396}' => 'Z',
        '\u{39d}' => 'N',
        '\u{3a5}' => 'Y',
        _ => return None,
    };
    Some(f)
}

/// Is this a look-alike character (see [`fold_confusable`])?
pub fn is_confusable(c: char) -> bool {
    fold_confusable(c).is_some()
}

/// Lowercase alphanumeric tokens, stop words dropped, zero-width characters removed, look-alike letters folded to ASCII, words stemmed (see
/// [`stem`]). Digits are kept.
pub fn tokens(s: &str) -> Vec<String> {
    let clean: String = s
        .chars()
        .filter(|c| !is_format(*c) && *c != '\u{ad}')
        .map(|c| fold_confusable(c).unwrap_or(c))
        .collect();
    clean
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty() && !STOP.contains(t))
        .map(stem)
        .collect()
}

/// A small deterministic stemmer: plural `s`, then `ing`, `ed` or `ion`, then a final `e`; a stem keeps at least four characters, and a doubled
/// final consonant left by `ing` or `ed` is collapsed (`logging` and `logs` both give `log`).
pub fn stem(t: &str) -> String {
    // a few irregular past forms and their base, so that "kept" meets "keep" (a fixed table, not a list of subject names)
    let irregular = match t {
        "kept" => Some("keep"),
        "held" => Some("hold"),
        "wrote" | "written" => Some("write"),
        "taken" | "took" => Some("take"),
        "given" | "gave" => Some("give"),
        "ran" => Some("run"),
        "built" => Some("build"),
        "sent" => Some("send"),
        "lost" => Some("lose"),
        "stored" => Some("store"),
        "known" | "knew" => Some("know"),
        _ => None,
    };
    if let Some(b) = irregular {
        return stem(b);
    }
    let mut w = t.to_string();
    if w.chars().count() > 3 && w.ends_with('s') && !w.ends_with("ss") {
        w.pop();
    }
    let n = w.chars().count();
    for suf in ["ing", "ed", "ion"] {
        if n >= suf.len() + 4 && w.ends_with(suf) {
            w.truncate(w.len() - suf.len());
            if suf != "ion" {
                let b = w.as_bytes();
                if b.len() >= 2
                    && b[b.len() - 1] == b[b.len() - 2]
                    && !b"aeiouls".contains(&b[b.len() - 1])
                {
                    w.pop();
                }
            }
            break;
        }
    }
    if w.chars().count() > 4 && w.ends_with('e') {
        w.pop();
    }
    w
}

/// Extra function words that carry no subject matter in a question (beyond [`STOP`], which also filters documents). Used only by the
/// abstention gate to decide which query words are CONTENT words; indexing and scoring are unchanged.
const FUNCTION_EXTRA: &[&str] = &[
    "did",
    "doing",
    "done",
    "would",
    "could",
    "might",
    "just",
    "also",
    "very",
    "more",
    "most",
    "some",
    "other",
    "another",
    "only",
    "own",
    "same",
    "so",
    "too",
    "up",
    "down",
    "out",
    "off",
    "again",
    "both",
    "few",
    "here",
    "they",
    "them",
    "he",
    "she",
    "him",
    "her",
    "his",
    "hers",
    "been",
    "being",
    "am",
    "get",
    "got",
    "go",
    "goes",
    "make",
    "made",
    "give",
    "please",
    "help",
    "know",
    "thing",
    "things",
    "kind",
    "sort",
    "one",
    "much",
    "many",
    "long",
    "often",
    "way",
    "ways",
    "good",
    "best",
    "new",
    "old",
    "after",
    "before",
    "during",
    "while",
    "because",
    "so",
    "if",
    "while",
    "now",
    "let",
    "lets",
    "like",
    "want",
    "need",
    "needs",
    "should",
    "ever",
    "even",
    "still",
    "yet",
    "about",
    "between",
    "through",
    "across",
    "against",
    "without",
    "within",
    "around",
    "no",
    "nor",
    "yes",
    "my",
    "mine",
    "our",
    "ours",
    "us",
    "i",
    "something",
    "anything",
    "everything",
    "someone",
    "anyone",
    "everyone",
    "who",
    "whom",
    "whose",
    "whether",
    "tell",
    "show",
    "list",
];

/// Is this a stemmed query token a content word (not a stop word and not one of [`FUNCTION_EXTRA`])?
pub fn is_content_token(t: &str) -> bool {
    !STOP.contains(&t)
        && !FUNCTION_EXTRA.contains(&t)
        && !FUNCTION_EXTRA.iter().any(|f| stem(f) == t)
}

/// Is this (lowercased, punctuation-trimmed) word a stop word?
pub fn is_stop_word(w: &str) -> bool {
    STOP.contains(
        &w.trim_matches(|c: char| !c.is_alphanumeric())
            .to_lowercase()
            .as_str(),
    )
}

fn is_format(c: char) -> bool {
    matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

/// Is this a zero-width, bidirectional or soft-hyphen character (RS1 `hidden_chars`)?
pub fn is_hidden(c: char) -> bool {
    is_format(c) || c == '\u{ad}'
}

/// Remove control, bidirectional and zero-width characters (newlines and tabs become spaces). Everything else is kept.
pub fn sanitise(s: &str) -> String {
    s.chars()
        .filter_map(|c| {
            if c == '\n' || c == '\t' {
                Some(' ')
            } else if c.is_control() || is_format(c) {
                None
            } else {
                Some(c)
            }
        })
        .collect()
}

/// The first `n` whitespace-separated words.
pub fn first_words(s: &str, n: usize) -> String {
    s.split_whitespace().take(n).collect::<Vec<_>>().join(" ")
}

/// The `n`-word window holding the most words that match one of `terms` (tokens); the earliest window wins a tie.
pub fn best_window(s: &str, terms: &[String], n: usize) -> String {
    let words: Vec<&str> = s.split_whitespace().collect();
    if words.len() <= n {
        return words.join(" ");
    }
    let hit: Vec<bool> = words
        .iter()
        .map(|w| tokens(w).iter().any(|t| terms.contains(t)))
        .collect();
    let mut best = (0usize, 0usize);
    let mut cur: usize = hit[..n].iter().filter(|h| **h).count();
    best.1 = cur;
    for start in 1..=(words.len() - n) {
        cur = cur + usize::from(hit[start + n - 1]) - usize::from(hit[start - 1]);
        if cur > best.1 {
            best = (start, cur);
        }
    }
    words[best.0..best.0 + n].join(" ")
}
