//! `UrlAllowList`: a URL is allowed only when its parsed scheme, host, port and path match the caller's list.
//! The bypass cases are the ones a first-'/' split or a substring check lets through.

use alice_browser_secure::{parse_strict, UrlAllowList, UrlRejection};

fn stripe() -> UrlAllowList {
    UrlAllowList::new(&["https"], &["checkout.stripe.com"]).expect("valid list")
}

#[test]
fn the_listed_origin_is_allowed() {
    let l = stripe();
    for url in [
        "https://checkout.stripe.com",
        "https://checkout.stripe.com/",
        "https://checkout.stripe.com/pay/session?id=1#top",
        "https://checkout.stripe.com:443/explicit-default-port",
        // the host is compared in its canonical (lowercase) form
        "https://CHECKOUT.Stripe.COM/upper",
    ] {
        assert_eq!(l.check(url).map(|u| u.host().to_owned()), Ok("checkout.stripe.com".to_owned()), "{url}");
    }
}

#[test]
fn the_host_is_the_authority_not_a_substring() {
    let l = stripe();
    for (url, why) in [
        ("https://evil.example#@checkout.stripe.com/", UrlRejection::Host),
        ("https://evil.example?@checkout.stripe.com/", UrlRejection::Host),
        ("https://evil.example/@checkout.stripe.com/", UrlRejection::Host),
        ("https://checkout.stripe.com.evil.example/", UrlRejection::Host),
        ("https://evilcheckout.stripe.com/", UrlRejection::Host),
        ("https://checkout.stripe.com./trailing-dot", UrlRejection::Host),
        ("https://[::1]/", UrlRejection::Host),
    ] {
        assert_eq!(l.check(url).err(), Some(why), "{url}");
    }
}

#[test]
fn userinfo_is_rejected() {
    let l = stripe();
    for url in [
        "https://checkout.stripe.com@evil.example/",
        "https://user:pass@checkout.stripe.com/",
        "https://@checkout.stripe.com/",
    ] {
        assert_eq!(l.check(url).err(), Some(UrlRejection::Userinfo), "{url}");
    }
}

#[test]
fn a_non_default_port_is_rejected() {
    let l = stripe();
    for url in [
        "https://checkout.stripe.com:8443/",
        "https://checkout.stripe.com:0443/",
        "https://checkout.stripe.com:/",
        "https://checkout.stripe.com:99999/",
    ] {
        assert_eq!(l.check(url).err(), Some(UrlRejection::Port), "{url}");
    }
}

#[test]
fn schemes_outside_the_list_are_rejected() {
    let l = stripe();
    for url in [
        "http://checkout.stripe.com/",
        "file:///etc/passwd",
        "file://checkout.stripe.com/etc/passwd",
        "myapp://checkout.stripe.com/",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ] {
        assert_eq!(l.check(url).err(), Some(UrlRejection::Scheme), "{url}");
    }
}

#[test]
fn malformed_and_obfuscated_forms_are_rejected() {
    let l = stripe();
    for url in [
        " https://checkout.stripe.com/",
        "https://checkout.stripe.com/\n",
        "https://checkout.stripe.com\t.evil.example/",
        "https:/checkout.stripe.com/",
        "https:\\\\checkout.stripe.com/",
        "https://evil.example\\@checkout.stripe.com/",
        "https://%63heckout.stripe.com/",
        "https://checkout.stripe.com\u{0}/",
        "",
        "checkout.stripe.com/pay",
    ] {
        assert_eq!(l.check(url).err(), Some(UrlRejection::Malformed), "{url:?}");
    }
}

#[test]
fn an_idn_lookalike_host_is_rejected() {
    let l = stripe();
    // Cyrillic і (U+0456) in place of i, and a punycode host that is not on the list
    assert_eq!(l.check("https://checkout.str\u{456}pe.com/").err(), Some(UrlRejection::Host));
    assert_eq!(l.check("https://xn--checkout-stripe-xyz.com/").err(), Some(UrlRejection::Host));
}

#[test]
fn the_path_prefix_matches_whole_segments() {
    let l = stripe().with_path_prefix("/pay").expect("valid prefix");
    assert!(l.allows("https://checkout.stripe.com/pay"));
    assert!(l.allows("https://checkout.stripe.com/pay/"));
    assert!(l.allows("https://checkout.stripe.com/pay/session?id=1"));
    for url in [
        "https://checkout.stripe.com/payment",
        "https://checkout.stripe.com/PAY",
        "https://checkout.stripe.com/",
        "https://checkout.stripe.com/pay/../admin",
        "https://checkout.stripe.com/pay/%2e%2e/admin",
        "https://checkout.stripe.com/pay/%2E%2e/admin",
    ] {
        assert_eq!(l.check(url).err(), Some(UrlRejection::PathPrefix), "{url}");
    }
}

#[test]
fn the_list_is_data_and_is_validated() {
    // entries are normalised the way URLs are (lowercase host, lowercase scheme)
    let l = UrlAllowList::new(&["HTTPS"], &["Checkout.Stripe.Com"]).expect("valid list");
    assert!(l.allows("https://checkout.stripe.com/"));
    for (schemes, hosts) in [
        (&[][..], &["checkout.stripe.com"][..]),
        (&["https"][..], &[][..]),
        (&["https"][..], &["checkout.stripe.com/pay"][..]),
        (&["https"][..], &["user@checkout.stripe.com"][..]),
        (&["https"][..], &["checkout.str\u{456}pe.com"][..]),
        (&["htt ps"][..], &["checkout.stripe.com"][..]),
    ] {
        assert!(UrlAllowList::new(schemes, hosts).is_err(), "{schemes:?} {hosts:?}");
    }
    assert!(stripe().with_path_prefix("pay").is_err());
    assert!(stripe().with_path_prefix("/pay/../x").is_err());
}

#[test]
fn parse_strict_reports_the_parts() {
    let u = parse_strict("https://Checkout.Stripe.com:443/pay?id=1#f").expect("parses");
    assert_eq!((u.scheme(), u.host(), u.port(), u.path()), ("https", "checkout.stripe.com", None, "/pay"));
    assert_eq!((u.query(), u.fragment()), (Some("id=1"), Some("f")));
}
