//! URL Validation
//!
//! [`UrlAllowList`] decides whether a URL may be followed: the URL is parsed strictly (the authority ends at the
//! first `/`, `?` or `#`, never at a later character) and its scheme, host, port and path are compared with the
//! caller's list. The list is data the caller passes in, not code.

use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};

use crate::error::SecurityError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    pub scheme: String,
    pub host: String,
    pub path: String,
}

/// 簡易URL解析
///
/// The host is everything up to the first `/`, so `https://evil.example#@good.example/` reports
/// `evil.example#@good.example` as the host. Use [`parse_strict`] to decide anything about a URL.
#[deprecated(
    note = "splits at the first '/', not at the authority's end; use parse_strict / UrlAllowList"
)]
#[must_use]
pub fn parse_url(url: &str) -> Option<ParsedUrl> {
    let scheme_end = url.find("://")?;
    let scheme = &url[..scheme_end];
    let rest = &url[scheme_end + 3..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..host_end];
    let path = if host_end < rest.len() {
        &rest[host_end..]
    } else {
        "/"
    };

    if host.is_empty() {
        return None;
    }

    Some(ParsedUrl {
        scheme: String::from(scheme),
        host: String::from(host),
        path: String::from(path),
    })
}

/// 安全なURL判定
///
/// `true` for an `http` / `https` / `ftp` URL or a relative reference; `false` for any other scheme (`javascript:`,
/// `data:`, `file:`, a custom scheme), for `..` and for a NUL byte. The scheme is read the way a browser reads it:
/// leading and trailing control characters and spaces are dropped, and tabs and newlines are removed anywhere.
/// This says nothing about the host: use [`UrlAllowList`] to decide whether a URL may be followed.
#[deprecated(
    note = "checks the scheme only; use UrlAllowList to decide whether a URL may be followed"
)]
#[must_use]
pub fn is_safe_url(url: &str) -> bool {
    if url.contains("..") || url.contains('\0') {
        return false;
    }
    let cleaned: String = url
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    match leading_scheme(&cleaned) {
        Some(scheme) => matches!(scheme.as_str(), "http" | "https" | "ftp"),
        None => true,
    }
}

/// The scheme of `url` in lowercase, if it starts with one (`scheme ":"` before any `/`, `?` or `#`).
fn leading_scheme(url: &str) -> Option<String> {
    let colon = url.find(':')?;
    let candidate = &url[..colon];
    if url[..colon].contains(['/', '?', '#']) || !valid_scheme(candidate) {
        return None;
    }
    Some(candidate.to_ascii_lowercase())
}

/// `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`
fn valid_scheme(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

/// Why [`UrlAllowList::check`] or [`parse_strict`] refused a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlRejection {
    /// Not a URL of the form `scheme://host[:port][/path][?query][#fragment]`, or it carries a control character,
    /// a space, a backslash, a percent-encoded host or a non-ASCII byte outside the host.
    Malformed,
    /// The scheme is not on the list.
    Scheme,
    /// The authority carries `user[:password]@`.
    Userinfo,
    /// An explicit port other than the scheme's default (or an empty, non-numeric or zero-padded port).
    Port,
    /// The host is not a canonical ASCII host name, or is not on the list.
    Host,
    /// The path is outside the list's path prefix.
    PathPrefix,
    /// The path carries a dot segment (`.` / `..`), a malformed escape, or a percent-encoded `%`, `/`, `\\`, `.`,
    /// reserved or control byte: a server that decodes the path (once or more) would resolve it somewhere else.
    Path,
}

impl core::fmt::Display for UrlRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed url",
            Self::Scheme => "scheme not allowed",
            Self::Userinfo => "userinfo not allowed",
            Self::Port => "port not allowed",
            Self::Host => "host not allowed",
            Self::PathPrefix => "path outside the allowed prefix",
            Self::Path => "path carries a dot segment or an encoded separator",
        })
    }
}

/// A URL parsed by [`parse_strict`]: scheme and host in lowercase, `port` only when it is not the default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
}

impl StrictUrl {
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
    /// The explicit port, when it is not the scheme's default.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }
    /// The path, `/` when the URL has none.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }
    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }
}

const fn default_port(scheme: &str) -> Option<u16> {
    match scheme.as_bytes() {
        b"http" | b"ws" => Some(80),
        b"https" | b"wss" => Some(443),
        _ => None,
    }
}

/// The scheme of a URL that has no control character, space or backslash; `Malformed` otherwise.
fn split_scheme(url: &str) -> Result<(String, &str), UrlRejection> {
    if url.is_empty() || url.bytes().any(|b| b <= b' ' || b == 0x7f || b == b'\\') {
        return Err(UrlRejection::Malformed);
    }
    let colon = url.find(':').ok_or(UrlRejection::Malformed)?;
    let scheme = &url[..colon];
    if !valid_scheme(scheme) {
        return Err(UrlRejection::Malformed);
    }
    Ok((scheme.to_ascii_lowercase(), &url[colon + 1..]))
}

/// A canonical ASCII host name: lowercase letters, digits, `-` and `.`, no empty label, no label that starts or
/// ends with `-`, no trailing dot. `None` for anything else (including an IP literal in brackets).
fn canonical_host(host: &str) -> Option<String> {
    if host.is_empty() {
        return None;
    }
    let lower = host.to_ascii_lowercase();
    let ok = lower.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    ok.then_some(lower)
}

/// The rest of a URL after `scheme:`, parsed: it must start with `//`, the authority ends at the first `/`, `?` or
/// `#`.
fn parse_after_scheme(scheme: String, rest: &str) -> Result<StrictUrl, UrlRejection> {
    let rest = rest.strip_prefix("//").ok_or(UrlRejection::Malformed)?;
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);
    if authority.contains('@') {
        return Err(UrlRejection::Userinfo);
    }
    if authority.contains('%') {
        return Err(UrlRejection::Malformed);
    }
    if authority.starts_with('[') {
        return Err(UrlRejection::Host);
    }
    let (host, port) = match authority.rfind(':') {
        Some(i) => (&authority[..i], Some(&authority[i + 1..])),
        None => (authority, None),
    };
    let port = match port {
        None => None,
        Some(p) => {
            let canonical =
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && !p.starts_with('0');
            let n = if canonical {
                p.parse::<u16>().ok()
            } else {
                None
            };
            match (n, default_port(&scheme)) {
                (Some(n), Some(d)) if n == d => None,
                _ => return Err(UrlRejection::Port),
            }
        }
    };
    let host = canonical_host(host).ok_or(UrlRejection::Host)?;
    if !tail.is_ascii() {
        return Err(UrlRejection::Malformed);
    }
    let (before_fragment, fragment) = match tail.find('#') {
        Some(i) => (&tail[..i], Some(tail[i + 1..].to_owned())),
        None => (tail, None),
    };
    let (path, query) = match before_fragment.find('?') {
        Some(i) => (
            &before_fragment[..i],
            Some(before_fragment[i + 1..].to_owned()),
        ),
        None => (before_fragment, None),
    };
    Ok(StrictUrl {
        scheme,
        host,
        port,
        path: if path.is_empty() {
            "/".to_string()
        } else {
            path.to_owned()
        },
        query,
        fragment,
    })
}

/// Parse `scheme://host[:port][/path][?query][#fragment]` strictly. See [`UrlRejection`] for what is refused.
///
/// # Errors
/// The [`UrlRejection`] of the first part that does not parse.
pub fn parse_strict(url: &str) -> Result<StrictUrl, UrlRejection> {
    let (scheme, rest) = split_scheme(url)?;
    parse_after_scheme(scheme, rest)
}

/// `true` when the path carries a `.` / `..` segment, a malformed `%` escape, or a `%XX` that decodes to a
/// control byte, `%`, `.`, `/`, `\\` or another reserved character (`:?#[]@!$&'()*+,;=`). Nothing is decoded:
/// such a path is refused, so the answer does not depend on how many times a server decodes it.
fn unsafe_path(path: &str) -> bool {
    const REFUSED: &[u8] = b"%./\\:?#[]@!$&'()*+,;=";
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = |j: usize| bytes.get(j).and_then(|c| char::from(*c).to_digit(16));
            let Some(decoded) = hex(i + 1).zip(hex(i + 2)).map(|(h, l)| h * 16 + l) else {
                return true;
            };
            let decoded = decoded as u8;
            if decoded < 0x20 || decoded == 0x7f || REFUSED.contains(&decoded) {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    has_dot_segment(path)
}

/// `true` when a path segment is `.` or `..`, written plainly or percent-encoded (`%2e`, any case).
fn has_dot_segment(path: &str) -> bool {
    path.split('/').any(|seg| {
        let lower = seg.to_ascii_lowercase().replace("%2e", ".");
        lower == "." || lower == ".."
    })
}

/// The schemes, exact hosts and optional path prefix a URL must match to be followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlAllowList {
    schemes: Vec<String>,
    hosts: Vec<String>,
    path_prefix: Option<String>,
}

impl UrlAllowList {
    /// A list allowing `schemes` (any case) and exactly `hosts` (canonical host names, any case).
    ///
    /// # Errors
    /// [`SecurityError::InvalidUrl`] when either list is empty or an entry is not a valid scheme / host name.
    pub fn new(schemes: &[&str], hosts: &[&str]) -> Result<Self, SecurityError> {
        if schemes.is_empty() || hosts.is_empty() {
            return Err(SecurityError::InvalidUrl);
        }
        let schemes = schemes
            .iter()
            .map(|s| valid_scheme(s).then(|| s.to_ascii_lowercase()))
            .collect::<Option<Vec<_>>>()
            .ok_or(SecurityError::InvalidUrl)?;
        let hosts = hosts
            .iter()
            .map(|h| canonical_host(h))
            .collect::<Option<Vec<_>>>()
            .ok_or(SecurityError::InvalidUrl)?;
        Ok(Self {
            schemes,
            hosts,
            path_prefix: None,
        })
    }

    /// The same list, with the path required to be `prefix` or below it (whole segments: `/pay` allows
    /// `/pay` and `/pay/x`, not `/payment`).
    ///
    /// # Errors
    /// [`SecurityError::InvalidUrl`] when `prefix` does not start with `/`, carries a dot segment, or has a query,
    /// fragment, control character, space, backslash or non-ASCII byte.
    pub fn with_path_prefix(mut self, prefix: &str) -> Result<Self, SecurityError> {
        let bad = !prefix.starts_with('/')
            || !prefix.is_ascii()
            || prefix
                .bytes()
                .any(|b| b <= b' ' || b == 0x7f || matches!(b, b'\\' | b'?' | b'#'))
            || has_dot_segment(prefix);
        if bad {
            return Err(SecurityError::InvalidUrl);
        }
        let trimmed = prefix.trim_end_matches('/');
        self.path_prefix = Some(trimmed.to_owned());
        Ok(self)
    }

    /// The parsed URL when it matches the list.
    ///
    /// # Errors
    /// The [`UrlRejection`] of the first check it fails: malformed, scheme, then userinfo / port / host, then a
    /// dot segment or encoded separator in the path ([`UrlRejection::Path`], with or without a prefix), then the
    /// prefix.
    pub fn check(&self, url: &str) -> Result<StrictUrl, UrlRejection> {
        let (scheme, rest) = split_scheme(url)?;
        if !self.schemes.contains(&scheme) {
            return Err(UrlRejection::Scheme);
        }
        let parsed = parse_after_scheme(scheme, rest)?;
        if !self.hosts.contains(&parsed.host) {
            return Err(UrlRejection::Host);
        }
        if unsafe_path(&parsed.path) {
            return Err(UrlRejection::Path);
        }
        if let Some(prefix) = &self.path_prefix {
            let inside = parsed.path == *prefix
                || prefix.is_empty()
                || parsed
                    .path
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|rest| rest.starts_with('/'));
            if !inside {
                return Err(UrlRejection::PathPrefix);
            }
        }
        Ok(parsed)
    }

    /// `true` when [`check`](Self::check) accepts `url`.
    #[must_use]
    pub fn allows(&self, url: &str) -> bool {
        self.check(url).is_ok()
    }
}
