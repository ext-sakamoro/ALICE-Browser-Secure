//! Error

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
