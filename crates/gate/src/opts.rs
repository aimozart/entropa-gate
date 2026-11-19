//! Strict option parsing for the gate's subcommands: an unknown option, an extra word, a missing value, or an option that may not repeat is a usage error (the caller prints its usage line and exits 2).
//! A mistyped `--require-anchors` must never be ignored. An option that takes a value takes the NEXT word as that value, whatever it looks like.

/// What a subcommand accepts (all names include the leading `--`).
pub struct Spec<'a> {
    /// Options with one value that may appear once.
    pub once: &'a [&'a str],
    /// Options with one value that may repeat.
    pub many: &'a [&'a str],
    /// Options without a value that may appear once.
    pub flags: &'a [&'a str],
}

/// The parsed options.
#[derive(Debug, Default)]
pub struct Opts {
    values: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Opts {
    /// The value of an option that may appear once.
    pub fn one(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    /// Every value of an option, in order.
    pub fn all(&self, name: &str) -> Vec<&str> {
        self.values
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
    /// Whether a flag was given.
    pub fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }
}

/// Parse `args` (the words after the subcommand). `None` = a usage error.
pub fn parse(args: &[String], spec: &Spec<'_>) -> Option<Opts> {
    let mut out = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if spec.flags.contains(&a) {
            if out.flag(a) {
                return None;
            }
            out.flags.push(a.to_string());
        } else if spec.once.contains(&a) || spec.many.contains(&a) {
            let value = args.get(i + 1)?;
            if spec.once.contains(&a) && out.one(a).is_some() {
                return None;
            }
            out.values.push((a.to_string(), value.clone()));
            i += 1;
        } else {
            return None;
        }
        i += 1;
    }
    Some(out)
}
