//! URL Validation

use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    pub scheme: String,
    pub host: String,
    pub path: String,
}

/// 簡易URL解析
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
#[must_use]
pub fn is_safe_url(url: &str) -> bool {
    let lower: Vec<u8> = url
        .bytes()
        .take(20)
        .map(|b| if b.is_ascii_uppercase() { b + 32 } else { b })
        .collect();
    let prefix = core::str::from_utf8(&lower).unwrap_or("");
    if prefix.starts_with("javascript:")
        || prefix.starts_with("data:")
        || prefix.starts_with("vbscript:")
    {
        return false;
    }
    if url.contains("..") || url.contains('\0') {
        return false;
    }
    true
}
