//! HTML Sanitizer

use alloc::{string::String, vec::Vec};

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
