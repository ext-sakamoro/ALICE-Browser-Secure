//! XSS Detection

use alloc::vec::Vec;

/// XSS攻撃パターン検出
#[must_use]
pub fn detect_xss(input: &str) -> Vec<XssThreat> {
    let mut threats = Vec::new();
    let lower: Vec<u8> = input
        .bytes()
        .map(|b| if b.is_ascii_uppercase() { b + 32 } else { b })
        .collect();
    let s = core::str::from_utf8(&lower).unwrap_or("");

    if s.contains("<script") {
        threats.push(XssThreat::ScriptTag);
    }
    if s.contains("javascript:") {
        threats.push(XssThreat::JavascriptUri);
    }
    if s.contains("onerror")
        || s.contains("onload")
        || s.contains("onclick")
        || s.contains("onmouseover")
    {
        threats.push(XssThreat::EventHandler);
    }
    if s.contains("eval(") || s.contains("document.cookie") || s.contains("innerhtml") {
        threats.push(XssThreat::DomManipulation);
    }
    threats
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XssThreat {
    ScriptTag,
    JavascriptUri,
    EventHandler,
    DomManipulation,
}
