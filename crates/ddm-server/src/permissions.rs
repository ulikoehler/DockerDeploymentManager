use crate::config::DefaultAccess;
use crate::users::{AccessEffect, AccessRule, AccessRuleType, User};
use globset::{Glob, GlobMatcher};
use regex::Regex;

/// Compiled access rule for fast repeated evaluation.
pub struct CompiledRule {
    effect: AccessEffect,
    matcher: CompiledMatcher,
}

enum CompiledMatcher {
    Exact(String),
    Glob(GlobMatcher),
    Regex(Regex),
}

impl CompiledRule {
    pub fn compile(rule: &AccessRule) -> Option<Self> {
        let matcher = match rule.kind {
            AccessRuleType::Exact => CompiledMatcher::Exact(rule.pattern.clone()),
            AccessRuleType::Glob => CompiledMatcher::Glob(Glob::new(&rule.pattern).ok()?.compile_matcher()),
            AccessRuleType::Regex => CompiledMatcher::Regex(Regex::new(&rule.pattern).ok()?),
        };
        Some(Self {
            effect: rule.effect,
            matcher,
        })
    }

    fn matches(&self, service: &str) -> bool {
        match &self.matcher {
            CompiledMatcher::Exact(s) => s == service,
            CompiledMatcher::Glob(g) => g.is_match(service),
            CompiledMatcher::Regex(r) => r.is_match(service),
        }
    }
}

/// Evaluate whether `user` may access `service`.
/// Admins always allowed. Otherwise first matching rule wins; no match
/// falls back to `default_access`.
pub fn can_access_service(user: &User, service: &str, default: DefaultAccess) -> bool {
    if user.is_admin() {
        return true;
    }
    for rule in &user.access {
        let Some(compiled) = CompiledRule::compile(rule) else {
            continue; // invalid rules are skipped (validated at write time)
        };
        if compiled.matches(service) {
            return compiled.effect == AccessEffect::Allow;
        }
    }
    default == DefaultAccess::Allow
}

/// Filter a service list to those the user may see.
pub fn filter_services<'a, I>(user: &User, services: I, default: DefaultAccess) -> Vec<String>
where
    I: IntoIterator<Item = &'a String>,
{
    services
        .into_iter()
        .filter(|s| can_access_service(user, s, default))
        .cloned()
        .collect()
}

/// Match a `ServiceMatcher` (from global monitoring rules etc.) against a name.
pub fn matcher_matches(m: &crate::config::ServiceMatcher, name: &str) -> bool {
    if let Some(e) = &m.exact {
        if e == name {
            return true;
        }
    }
    if let Some(g) = &m.glob {
        if let Ok(g) = Glob::new(g) {
            if g.compile_matcher().is_match(name) {
                return true;
            }
        }
    }
    if let Some(r) = &m.regex {
        if let Ok(re) = Regex::new(r) {
            if re.is_match(name) {
                return true;
            }
        }
    }
    false
}

/// Validate a service name: directory-safe, no traversal.
pub fn valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
        && !name.starts_with(['.', '-', '_'])
        && name.chars().next().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::{User, UserFeatures};

    fn user(rules: Vec<AccessRule>) -> User {
        User {
            name: "t".into(),
            password_hash: "x".into(),
            roles: vec!["operator".into()],
            access: rules,
            features: UserFeatures::default(),
            compose_policy: None,
        }
    }

    fn rule(kind: AccessRuleType, pattern: &str, effect: AccessEffect) -> AccessRule {
        AccessRule {
            kind,
            pattern: pattern.to_string(),
            effect,
        }
    }

    #[test]
    fn admin_bypasses() {
        let mut u = user(vec![]);
        u.roles = vec!["admin".into()];
        assert!(can_access_service(&u, "anything", DefaultAccess::Deny));
    }

    #[test]
    fn glob_allow() {
        let u = user(vec![rule(AccessRuleType::Glob, "web-*", AccessEffect::Allow)]);
        assert!(can_access_service(&u, "web-1", DefaultAccess::Deny));
        assert!(!can_access_service(&u, "db-1", DefaultAccess::Deny));
    }

    #[test]
    fn regex_allow() {
        let u = user(vec![rule(AccessRuleType::Regex, "^stg-[0-9]+$", AccessEffect::Allow)]);
        assert!(can_access_service(&u, "stg-12", DefaultAccess::Deny));
        assert!(!can_access_service(&u, "stg-x", DefaultAccess::Deny));
    }

    #[test]
    fn first_match_wins_deny_first() {
        let u = user(vec![
            rule(AccessRuleType::Exact, "web-secret", AccessEffect::Deny),
            rule(AccessRuleType::Glob, "web-*", AccessEffect::Allow),
        ]);
        assert!(!can_access_service(&u, "web-secret", DefaultAccess::Deny));
        assert!(can_access_service(&u, "web-1", DefaultAccess::Deny));
    }

    #[test]
    fn allow_then_deny_blocks() {
        // allow listed first still loses for a matching deny written first
        let u = user(vec![
            rule(AccessRuleType::Glob, "prod-*", AccessEffect::Deny),
            rule(AccessRuleType::Glob, "*", AccessEffect::Allow),
        ]);
        assert!(!can_access_service(&u, "prod-x", DefaultAccess::Deny));
        assert!(can_access_service(&u, "dev-x", DefaultAccess::Deny));
    }

    #[test]
    fn default_access_fallback() {
        let u = user(vec![]);
        assert!(can_access_service(&u, "x", DefaultAccess::Allow));
        assert!(!can_access_service(&u, "x", DefaultAccess::Deny));
    }

    #[test]
    fn service_name_validation() {
        assert!(valid_service_name("web-1"));
        assert!(valid_service_name("a.b_c"));
        assert!(!valid_service_name("../etc"));
        assert!(!valid_service_name("UPPER"));
        assert!(!valid_service_name("-lead"));
        assert!(!valid_service_name(""));
        assert!(!valid_service_name("a/b"));
    }
}
