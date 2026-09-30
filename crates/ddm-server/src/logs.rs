use regex::Regex;
use serde::Deserialize;

/// Server-side log filter parameters shared by REST snapshot + WS follow.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LogFilter {
    /// Case-insensitive substring match.
    #[serde(default)]
    pub grep: Option<String>,
    /// Regex match (applied after grep).
    #[serde(default)]
    pub regex: Option<String>,
    /// Exclude regex.
    #[serde(default)]
    pub exclude_regex: Option<String>,
    /// "stdout" | "stderr" | absent = both.
    #[serde(default)]
    pub stream: Option<String>,
    /// Unix seconds; only entries after this timestamp (docker --since).
    #[serde(default)]
    pub since: Option<i64>,
    /// Compose service / container name filter.
    #[serde(default)]
    pub container: Option<String>,
}

#[derive(Clone)]
pub struct CompiledFilter {
    grep_lower: Option<String>,
    regex: Option<Regex>,
    exclude: Option<Regex>,
    stream: Option<String>,
    container: Option<String>,
}

impl CompiledFilter {
    pub fn compile(f: &LogFilter) -> Result<Self, regex::Error> {
        Ok(Self {
            grep_lower: f.grep.as_ref().map(|g| g.to_lowercase()),
            regex: f.regex.as_deref().map(Regex::new).transpose()?,
            exclude: f.exclude_regex.as_deref().map(Regex::new).transpose()?,
            stream: f.stream.clone(),
            container: f.container.clone(),
        })
    }

    /// Does a log line pass the filter? `container` is the emitting compose
    /// service name (if known).
    pub fn matches(&self, text: &str, stream: &str, container: Option<&str>) -> bool {
        if let Some(s) = &self.stream {
            if s != "all" && s != stream {
                return false;
            }
        }
        if let Some(want) = &self.container {
            if want != "*" && Some(want.as_str()) != container {
                return false;
            }
        }
        if let Some(g) = &self.grep_lower {
            if !text.to_lowercase().contains(g) {
                return false;
            }
        }
        if let Some(r) = &self.regex {
            if !r.is_match(text) {
                return false;
            }
        }
        if let Some(x) = &self.exclude {
            if x.is_match(text) {
                return false;
            }
        }
        true
    }
}

/// Filter a blob of log text line by line. Input lines keep their newline;
/// `stream` is unknown for combined text → pass "stdout".
pub fn filter_text(text: &str, filter: &CompiledFilter) -> String {
    text.lines()
        .filter(|l| filter.matches(l, "stdout", None))
        .map(|l| format!("{l}\n"))
        .collect()
}

/// Strip ANSI escape codes (for the UI log viewer / plain-text clients).
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // ESC [ ... letter
            if chars.peek() == Some(&'[') {
                chars.next();
                for c2 in chars.by_ref() {
                    if c2.is_ascii_alphabetic() || c2 == '@' {
                        break;
                    }
                }
                continue;
            }
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(f: LogFilter) -> CompiledFilter {
        CompiledFilter::compile(&f).unwrap()
    }

    #[test]
    fn grep_case_insensitive() {
        let f = filter(LogFilter {
            grep: Some("ERROR".into()),
            ..Default::default()
        });
        assert!(f.matches("an error occurred", "stdout", None));
        assert!(!f.matches("all good", "stdout", None));
    }

    #[test]
    fn regex_and_exclude() {
        let f = filter(LogFilter {
            regex: Some("WARN|ERROR".into()),
            exclude_regex: Some("healthcheck".into()),
            ..Default::default()
        });
        assert!(f.matches("ERROR disk full", "stdout", None));
        assert!(!f.matches("WARN healthcheck slow", "stdout", None));
        assert!(!f.matches("INFO ok", "stdout", None));
    }

    #[test]
    fn stream_and_container() {
        let f = filter(LogFilter {
            stream: Some("stderr".into()),
            container: Some("web".into()),
            ..Default::default()
        });
        assert!(f.matches("x", "stderr", Some("web")));
        assert!(!f.matches("x", "stdout", Some("web")));
        assert!(!f.matches("x", "stderr", Some("db")));
    }

    #[test]
    fn ansi_stripped() {
        assert_eq!(strip_ansi("\u{1b}[31mred\u{1b}[0m"), "red");
    }
}
