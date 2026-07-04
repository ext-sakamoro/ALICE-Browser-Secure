//! Content Security Policy

use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspDirective {
    pub name: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ContentSecurityPolicy {
    directives: Vec<CspDirective>,
}

impl ContentSecurityPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            directives: Vec::new(),
        }
    }

    pub fn add_directive(&mut self, name: &str, sources: &[&str]) {
        self.directives.push(CspDirective {
            name: String::from(name),
            sources: sources.iter().map(|s| String::from(*s)).collect(),
        });
    }

    /// CSPヘッダー文字列を生成
    #[must_use]
    pub fn to_header(&self) -> String {
        let mut parts = Vec::new();
        for d in &self.directives {
            let mut s = d.name.clone();
            for src in &d.sources {
                s.push(' ');
                s.push_str(src);
            }
            parts.push(s);
        }
        let mut result = String::new();
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                result.push_str("; ");
            }
            result.push_str(part);
        }
        result
    }

    /// ソースが許可されているかチェック
    #[must_use]
    pub fn allows_source(&self, directive: &str, source: &str) -> bool {
        self.directives
            .iter()
            .find(|d| d.name == directive)
            .is_some_and(|d| d.sources.iter().any(|s| s == source || s == "*"))
    }
}

impl Default for ContentSecurityPolicy {
    fn default() -> Self {
        Self::new()
    }
}
