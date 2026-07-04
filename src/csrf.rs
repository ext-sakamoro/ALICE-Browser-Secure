//! CSRF Token

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
