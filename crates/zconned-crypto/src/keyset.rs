use ed25519_dalek::SigningKey;
use getset::Getters;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize as _;

use crate::error::IdentityError;
use crate::fingerprint;
use crate::kdf;
use crate::peer::{MailboxPublicSet, STATIC_DH_PUB_LEN};

/// Byte length of the master key: the size the derivation
/// algorithm requires.
pub const MASTER_LEN: usize = 32;

/// Signing-seed length: the Ed25519 secret-key size.
const SIGN_SEED_LEN: usize = ed25519_dalek::SECRET_KEY_LENGTH;

/// Static-DH-key secret material length (curve requirement).
const STATIC_DH_SECRET_LEN: usize = 32;

/// KMAC256 customization string for deriving the signing seed.
const SIGN_LABEL: &[u8] = b"zconned/v1/sign";

/// KMAC256 customization string for deriving the static DH key.
const STATIC_DH_LABEL: &[u8] = b"zconned/v1/static_dh";

/// The identity's key material in two layers: the master (root
/// state — the only part that serializes) and the two-key set
/// derived from it (working state — recomputable from the master).
///
/// Secrets zeroize on drop; the [`Debug`] implementation shows only
/// public halves.
///
/// @see [`crate::kdf::derive`].
#[derive(Getters)]
pub struct KeySet {
    /// Root state: the master; every key below derives from it.
    master: [u8; MASTER_LEN],
    /// Working state: derived from the master at construction.
    #[getset(get = "pub")]
    derived: DerivedKeys,
}

/// The two keys derived from the master: the signing key and the
/// static DH key.
#[derive(Getters)]
pub struct DerivedKeys {
    /// The signing key.
    #[getset(get = "pub")]
    sign: SigningKey,

    /// The static DH key (the long-term DH key).
    #[getset(get = "pub")]
    static_dh: StaticSecret,
}

impl DerivedKeys {
    /// The static DH public half, as raw bytes.
    fn static_dh_public_bytes(&self) -> [u8; STATIC_DH_PUB_LEN] {
        *XPublicKey::from(&self.static_dh).as_bytes()
    }
}

impl Drop for KeySet {
    fn drop(&mut self) {
        self.master.zeroize();
    }
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets are never formatted; only the public halves appear.
        f.debug_struct("KeySet")
            .field("sign_verifying", &self.derived.sign.verifying_key())
            .field("static_dh_public", &self.derived.static_dh_public_bytes())
            .finish()
    }
}

impl KeySet {
    /// Generate a fresh identity from OS randomness.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Entropy`] if the OS randomness source is
    /// unavailable (environmental, not an invariant failure —
    /// unlike the encoding invariants below, the entropy source
    /// can genuinely fail on unsupported platforms).
    pub fn generate() -> Result<Self, IdentityError> {
        let mut master = [0u8; MASTER_LEN];
        getrandom::fill(&mut master)?;
        let keyset = Self::from_master(&master);
        master.zeroize();
        Ok(keyset)
    }

    /// Derive the two-key set from the master: the only
    /// construction path — the derived keys are a deterministic
    /// function of the master, so no parts-taking constructor exists.
    pub fn from_master(master: &[u8; MASTER_LEN]) -> Self {
        let mut seed = [0u8; SIGN_SEED_LEN];
        let mut static_dh_secret = [0u8; STATIC_DH_SECRET_LEN];
        kdf::derive(master, SIGN_LABEL, &mut seed);
        kdf::derive(master, STATIC_DH_LABEL, &mut static_dh_secret);
        let keyset = Self {
            master: *master,
            derived: DerivedKeys {
                sign: SigningKey::from_bytes(&seed),
                static_dh: StaticSecret::from(static_dh_secret),
            },
        };
        seed.zeroize();
        static_dh_secret.zeroize();
        keyset
    }

    /// The static DH public half, as raw bytes.
    pub fn static_dh_public_bytes(&self) -> [u8; STATIC_DH_PUB_LEN] {
        self.derived.static_dh_public_bytes()
    }

    /// The fingerprint: SHA3-256 over the signing public key.
    /// @see [`crate::fingerprint::Fingerprint`].
    pub fn fingerprint(&self) -> fingerprint::Fingerprint {
        fingerprint::Fingerprint::of(self.derived.sign.verifying_key().as_bytes())
    }

    /// The public counterpart of this key set: both long-term
    /// public halves.
    pub fn public(&self) -> MailboxPublicSet {
        MailboxPublicSet::builder()
            .sign(*self.derived.sign.verifying_key().as_bytes())
            .static_dh(self.derived.static_dh_public_bytes())
            .build()
    }

    /// Serialize to the raw master encoding.
    pub fn to_bytes(&self) -> [u8; MASTER_LEN] {
        self.master
    }

    /// Parse from the master encoding (exactly [`MASTER_LEN`] bytes
    /// of raw master) and derive the two-key set from it.
    ///
    /// # Errors
    /// [`IdentityError::InvalidMasterFormat`] unless the bytes match
    /// the master encoding exactly.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != MASTER_LEN {
            return Err(IdentityError::InvalidMasterFormat {
                expected: MASTER_LEN,
                found: bytes.len(),
            });
        }
        let mut master = [0u8; MASTER_LEN];
        // The length was just checked; copy_from_slice cannot panic.
        master.copy_from_slice(bytes);
        Ok(Self::from_master(&master))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::{assert_eq, assert_ne};

    #[test]
    fn generate_produces_independent_keys() {
        let a = KeySet::generate().expect("os randomness");
        let b = KeySet::generate().expect("os randomness");
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.static_dh_public_bytes(), b.static_dh_public_bytes());
    }

    #[test]
    fn to_bytes_roundtrips() {
        let ks = KeySet::generate().expect("os randomness");
        let bytes = ks.to_bytes();
        assert_eq!(bytes.len(), MASTER_LEN);
        let back = KeySet::from_bytes(&bytes).expect("from_bytes");
        assert_eq!(back.fingerprint(), ks.fingerprint());
        assert_eq!(back.static_dh_public_bytes(), ks.static_dh_public_bytes());
    }

    #[test]
    fn from_bytes_rejects_malformed_format() {
        match KeySet::from_bytes(&[0u8; 10]) {
            Err(IdentityError::InvalidMasterFormat {
                expected: MASTER_LEN,
                found: 10,
                ..
            }) => {}
            other => panic!("expected InvalidMasterFormat error, got {other:?}"),
        }
    }

    #[test]
    fn same_master_yields_same_keys() {
        let mut master = [0u8; MASTER_LEN];
        getrandom::fill(&mut master).expect("os randomness unavailable");
        let a = KeySet::from_master(&master);
        let b = KeySet::from_master(&master);
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.static_dh_public_bytes(), b.static_dh_public_bytes());
    }
}
