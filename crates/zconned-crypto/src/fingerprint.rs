//! The identity fingerprint: SHA3-256 over a signing public key.

use core::fmt::{self, Display};

use getset::Getters;
use sha3::{Digest as _, Sha3_256};

use crate::peer::SIGN_PUB_LEN;

/// Digest algorithm name used in the ratified display notation;
/// the name implies the output length.
pub const DIGEST_ALGO: &str = "sha3-256";

/// Digest length in bytes.
pub const DIGEST_LEN: usize = 32;

type DigestBytes = [u8; DIGEST_LEN];

/// SHA3-256 digest of a signing public key: the identity anchor
/// for out-of-band comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Getters)]
pub struct Fingerprint {
    /// The raw digest bytes.
    #[getset(get = "pub")]
    digest: DigestBytes,
}

impl Fingerprint {
    /// Compute over a signing public key.
    pub fn of(sign_pub: &[u8; SIGN_PUB_LEN]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(sign_pub);
        Self {
            digest: hasher.finalize().into(),
        }
    }
}

impl Display for Fingerprint {
    /// Ratified notation: `<DIGEST_ALGO>:<lowercase hex>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{DIGEST_ALGO}:")?;
        for b in &self.digest {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::{assert_eq, assert_ne};

    #[test]
    fn display_matches_ratified_notation() {
        let fp = Fingerprint::of(&[0u8; SIGN_PUB_LEN]);
        let display = fp.to_string();
        assert!(display.starts_with(DIGEST_ALGO));
        assert_eq!(display.len(), DIGEST_ALGO.len() + 1 + 2 * DIGEST_LEN);
        assert!(
            display[DIGEST_ALGO.len() + 1..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn deterministic_and_distinct() {
        let a = Fingerprint::of(&[7u8; SIGN_PUB_LEN]);
        let b = Fingerprint::of(&[7u8; SIGN_PUB_LEN]);
        let c = Fingerprint::of(&[8u8; SIGN_PUB_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
