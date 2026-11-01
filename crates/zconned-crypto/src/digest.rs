//! General-purpose SHA3-256 digesting.

use sha3::{Digest as _, Sha3_256};

use crate::fingerprint::DIGEST_LEN;

/// SHA3-256 digest of arbitrary bytes — the general form of the
/// digest primitive; the message-material digest machine's
/// operation. The identity anchor is its signing-key
/// specialization, see [`crate::Fingerprint`].
pub fn digest(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Fingerprint, peer::SIGN_PUB_LEN};

    #[test]
    fn agrees_with_the_fingerprint_primitive() {
        let mut key = [0u8; SIGN_PUB_LEN];
        key[0] = 7;
        assert_eq!(digest(&key), *Fingerprint::of(&key).bytes());
    }
}
