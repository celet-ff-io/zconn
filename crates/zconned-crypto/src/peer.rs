use getset::Getters;
use typed_builder::TypedBuilder;

use crate::fingerprint;

/// Signing public-key length: the Ed25519 public-key size.
pub const SIGN_PUB_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// Static-DH public-key length (curve requirement; x25519-dalek
/// exports no length constant).
pub const STATIC_DH_PUB_LEN: usize = 32;

/// An identity's two long-term public halves, held as raw bytes.
///
/// The ADDRESS — the S3 addressing anchor — is the hash of the sign
/// half, not this key set: see [`crate::fingerprint::Fingerprint`].
///
/// The JSON form lives in the `zconned-codec` crate.
#[derive(Debug, Clone, PartialEq, Eq, Getters, TypedBuilder)]
pub struct PublicKeySet {
    /// The signing public half.
    #[getset(get = "pub")]
    sign: [u8; SIGN_PUB_LEN],

    /// The static DH public half.
    #[getset(get = "pub")]
    static_dh: [u8; STATIC_DH_PUB_LEN],
}

impl PublicKeySet {
    /// The fingerprint: SHA3-256 over the signing public key —
    /// the addressing anchor.
    /// @see [`crate::fingerprint::Fingerprint`].
    pub fn fingerprint(&self) -> fingerprint::Fingerprint {
        fingerprint::Fingerprint::of(&self.sign)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn accessors_borrow_raw_bytes() {
        let keys = PublicKeySet::builder()
            .sign([7u8; 32])
            .static_dh([9u8; 32])
            .build();
        assert_eq!(keys.sign(), &[7u8; 32]);
        assert_eq!(keys.static_dh(), &[9u8; 32]);
    }

    #[test]
    fn fingerprint_is_hash_of_sign_half() {
        let keys = PublicKeySet::builder()
            .sign([3u8; 32])
            .static_dh([4u8; 32])
            .build();
        assert_eq!(keys.fingerprint(), fingerprint::Fingerprint::of(&[3u8; 32]));
        assert_eq!(keys.fingerprint(), fingerprint::Fingerprint::of(&[3u8; 32]));
    }
}
