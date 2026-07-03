//! AAA - authentication token object.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Autoentication tokens to verify.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub enum AuthToken {
    /// No verifiable tokens were provided.
    #[default]
    Absent,
    /// Token is verified externally, always accept.
    ExternallyVerified,
    /// Plaintext password to compare with auth data provider.
    PlainPassword(String),
    // TODO: HashedPassword, SaltedHashedPassword, HmacPassword, CRAM/SCRAM/Digest?
}

impl fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.debug_tuple("Absent").finish(),
            Self::ExternallyVerified => f.debug_tuple("ExternallyVerified").finish(),
            Self::PlainPassword(_) => write!(f, "PlainPassword(***)"),
        }
    }
}

impl From<String> for AuthToken {
    fn from(item: String) -> Self {
        Self::PlainPassword(item)
    }
}
