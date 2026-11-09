//! X3DH establishment: the shared-secret core of an asynchronous
//! session. Both parties compute the same 32-byte seed from the
//! receiver's published prekeys; the sender's ephemeral private
//! half burns inside the call.

use getset::Getters;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize as _;

use crate::error::IdentityError;
use crate::kdf;

/// The X25519 public-key size, one per DH term.
pub const ESTABLISHMENT_PUB_LEN: usize = 32;

/// The seed length the establishment outputs.
pub const SEED_LEN: usize = 32;

/// The establishment derivation's key: 32 bytes of 0xFF — the
/// paper's F (the no-key convention, repurposed as the KMAC key).
const F_KEY: [u8; 32] = [0xFF; 32];

/// Domain label for the establishment extract.
const ESTABLISH_LABEL: &[u8] = b"zconned/v1/mail-establish";

/// The 32-byte shared secret that seeds a session's symmetric
/// chain. Zeroizes on drop; the secret half never formats.
#[derive(Clone, Getters)]
pub struct SessionSeed {
    /// The session's seed material.
    #[getset(get = "pub")]
    priv_: [u8; SEED_LEN],
}

impl Drop for SessionSeed {
    fn drop(&mut self) {
        self.priv_.zeroize();
    }
}

impl std::fmt::Debug for SessionSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionSeed(<secret>)")
    }
}

/// The sender's establishment output: the session seed plus the
/// ephemeral public half (the receiver's first decryption input).
#[derive(Clone, Debug, Getters)]
pub struct Established {
    #[getset(get = "pub")]
    seed: SessionSeed,

    /// The ephemeral public half; rides the session-start mail.
    #[getset(get = "pub")]
    eph_pub: [u8; ESTABLISHMENT_PUB_LEN],
}

/// Sender-side establishment.
///
/// `receiver_opk_pub = None` is the degraded 3-term form (pool
/// exhausted); the receiver must omit its OPK term the same way or
/// the seeds diverge. The ephemeral private half is generated here
/// and zeroized before return.
///
/// # Errors
///
/// [`IdentityError::Entropy`] if the OS randomness source is
/// unavailable.
pub fn establish(
    sender_static_priv: &[u8; 32],
    receiver_static_pub: &[u8; ESTABLISHMENT_PUB_LEN],
    receiver_spk_pub: &[u8; ESTABLISHMENT_PUB_LEN],
    receiver_opk_pub: Option<&[u8; ESTABLISHMENT_PUB_LEN]>,
) -> Result<Established, IdentityError> {
    let sender_static = StaticSecret::from(*sender_static_priv);
    let mut eph_priv = [0u8; 32];
    getrandom::fill(&mut eph_priv)?;
    let eph = StaticSecret::from(eph_priv);
    eph_priv.zeroize();
    let eph_pub = XPublicKey::from(&eph);

    let dh1 = sender_static
        .diffie_hellman(&XPublicKey::from(*receiver_spk_pub))
        .to_bytes();
    let dh2 = eph
        .diffie_hellman(&XPublicKey::from(*receiver_static_pub))
        .to_bytes();
    let dh3 = eph
        .diffie_hellman(&XPublicKey::from(*receiver_spk_pub))
        .to_bytes();
    let dh4 = receiver_opk_pub.map(|pub_| eph.diffie_hellman(&XPublicKey::from(*pub_)).to_bytes());

    Ok(Established {
        seed: seed_from_terms(dh1, dh2, dh3, dh4),
        eph_pub: *eph_pub.as_bytes(),
    })
}

/// Receiver-side establishment: mirrors the sender's term list.
///
/// `receiver_opk_priv = None` must pair with a sender-side `None`.
/// A mismatched term list produces a different seed and the
/// session fails at first decryption, not here.
pub fn receive(
    sender_static_pub: &[u8; ESTABLISHMENT_PUB_LEN],
    sender_eph_pub: &[u8; ESTABLISHMENT_PUB_LEN],
    receiver_static_priv: &[u8; 32],
    receiver_spk_priv: &[u8; 32],
    receiver_opk_priv: Option<&[u8; 32]>,
) -> Result<SessionSeed, IdentityError> {
    let sender_eph = XPublicKey::from(*sender_eph_pub);
    let dh1 = StaticSecret::from(*receiver_spk_priv)
        .diffie_hellman(&XPublicKey::from(*sender_static_pub))
        .to_bytes();
    let dh2 = StaticSecret::from(*receiver_static_priv)
        .diffie_hellman(&sender_eph)
        .to_bytes();
    let dh3 = StaticSecret::from(*receiver_spk_priv)
        .diffie_hellman(&sender_eph)
        .to_bytes();
    let dh4 = receiver_opk_priv.map(|priv_| {
        StaticSecret::from(*priv_)
            .diffie_hellman(&sender_eph)
            .to_bytes()
    });

    Ok(seed_from_terms(dh1, dh2, dh3, dh4))
}

/// SK = KMAC256(key=F, data=DH1‖DH2‖DH3[‖DH4], label).
fn seed_from_terms(
    dh1: [u8; 32],
    dh2: [u8; 32],
    dh3: [u8; 32],
    dh4: Option<[u8; 32]>,
) -> SessionSeed {
    let mut ikm = [0u8; 128];
    ikm[..32].copy_from_slice(&dh1);
    ikm[32..64].copy_from_slice(&dh2);
    ikm[64..96].copy_from_slice(&dh3);
    let len = match dh4 {
        Some(d) => {
            ikm[96..128].copy_from_slice(&d);
            128
        }
        None => 96,
    };
    let mut out = [0u8; SEED_LEN];
    kdf::derive(&F_KEY, ESTABLISH_LABEL, &ikm[..len], &mut out);
    ikm.zeroize();
    SessionSeed { priv_: out }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_ne;

    fn priv_key() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("os randomness unavailable");
        bytes
    }

    fn pub_of(priv_: &[u8; 32]) -> [u8; 32] {
        *XPublicKey::from(&StaticSecret::from(*priv_)).as_bytes()
    }

    #[test]
    fn both_sides_derive_the_same_seed() {
        let sender = priv_key();
        let receiver_static = priv_key();
        let receiver_spk = priv_key();
        let receiver_opk = priv_key();
        let out = establish(
            &sender,
            &pub_of(&receiver_static),
            &pub_of(&receiver_spk),
            Some(&pub_of(&receiver_opk)),
        )
        .expect("os randomness");
        let back = receive(
            &pub_of(&sender),
            out.eph_pub(),
            &receiver_static,
            &receiver_spk,
            Some(&receiver_opk),
        )
        .expect("derivation is infallible");
        assert_eq!(out.seed().priv_(), back.priv_());
    }

    #[test]
    fn degraded_three_term_matches_on_both_sides() {
        let sender = priv_key();
        let receiver_static = priv_key();
        let receiver_spk = priv_key();
        let out = establish(
            &sender,
            &pub_of(&receiver_static),
            &pub_of(&receiver_spk),
            None,
        )
        .expect("os randomness");
        let back = receive(
            &pub_of(&sender),
            out.eph_pub(),
            &receiver_static,
            &receiver_spk,
            None,
        )
        .expect("derivation is infallible");
        assert_eq!(out.seed().priv_(), back.priv_());
    }

    #[test]
    fn term_list_mismatch_yields_different_seeds() {
        let sender = priv_key();
        let receiver_static = priv_key();
        let receiver_spk = priv_key();
        let receiver_opk = priv_key();
        let four = establish(
            &sender,
            &pub_of(&receiver_static),
            &pub_of(&receiver_spk),
            Some(&pub_of(&receiver_opk)),
        )
        .expect("os randomness");
        let back = receive(
            &pub_of(&sender),
            four.eph_pub(),
            &receiver_static,
            &receiver_spk,
            None,
        )
        .expect("derivation is infallible");
        assert_ne!(four.seed().priv_(), back.priv_());
    }

    #[test]
    fn fresh_establishments_are_independent() {
        let sender = priv_key();
        let receiver_static = priv_key();
        let receiver_spk = priv_key();
        let spk_pub = pub_of(&receiver_spk);
        let static_pub = pub_of(&receiver_static);
        let a = establish(&sender, &static_pub, &spk_pub, None).expect("os randomness");
        let b = establish(&sender, &static_pub, &spk_pub, None).expect("os randomness");
        assert_ne!(a.seed().priv_(), b.seed().priv_());
        assert_ne!(a.eph_pub(), b.eph_pub());
    }
}

/// A clamped X25519 keypair for the standing and batch slots. The
/// public half always derives from the clamped private half — a
/// raw-byte public half would disagree with every DH evaluation.
#[derive(Clone, Getters)]
pub struct DhSecret {
    /// The clamped private half.
    #[getset(get = "pub")]
    priv_: [u8; 32],

    /// The public half, derived from the clamped private half.
    #[getset(get = "pub")]
    pub_: [u8; 32],
}

impl DhSecret {
    fn clamp(priv_: &mut [u8; 32]) {
        priv_[0] &= 248;
        priv_[31] &= 127;
        priv_[31] |= 64;
    }

    /// Fresh OS-random slot.
    ///
    /// # Errors
    /// [`IdentityError::Entropy`] if the OS randomness source is
    /// unavailable.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut priv_ = [0u8; 32];
        getrandom::fill(&mut priv_)?;
        Self::clamp(&mut priv_);
        let pub_ = *XPublicKey::from(&StaticSecret::from(priv_)).as_bytes();
        Ok(Self { priv_, pub_ })
    }

    /// Adopt an existing private half (restore path); clamped on
    /// the way in.
    pub fn from_priv(mut priv_: [u8; 32]) -> Self {
        Self::clamp(&mut priv_);
        let pub_ = *XPublicKey::from(&StaticSecret::from(priv_)).as_bytes();
        Self { priv_, pub_ }
    }
}

impl std::fmt::Debug for DhSecret {
    /// The public half formats; the private half never does.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhSecret")
            .field("pub_", &self.pub_)
            .finish()
    }
}
