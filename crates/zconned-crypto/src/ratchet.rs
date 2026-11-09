//! Double Ratchet: the symmetric-chain machine over an
//! established session seed. Concretized per the genericity strip:
//! KDF = KMAC256 (the crate's single derivation primitive), cipher
//! = ChaCha20-Poly1305, header = raw bytes; the ONLY injection
//! point is [`SkippedKeyStore`].

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};
use getset::Getters;
use typed_builder::TypedBuilder;

use crate::kdf;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize as _;

/// The X25519 public-key size riding every ratchet header.
pub const RATCHET_PUB_LEN: usize = 32;

/// The message-key size (ChaCha20-Poly1305 key length).
pub const MESSAGE_KEY_LEN: usize = 32;

/// The per-message nonce size (the cipher's requirement).
pub const NONCE_LEN: usize = 12;

/// KMAC256 customization strings, one per derivation stream.
const ROOT_LABEL: &[u8] = b"zconned/v1/ratchet-root";
const CHAIN_NEXT_LABEL: &[u8] = b"zconned/v1/chain-next";
const CHAIN_MSG_LABEL: &[u8] = b"zconned/v1/chain-msg-key";
const MSG_NONCE_LABEL: &[u8] = b"zconned/v1/msg-nonce";

/// A ratchet header, raw: the sender's current DH public half and
/// the message's chain position. The wire layer wraps these bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Getters, TypedBuilder)]
pub struct RatchetHeader {
    /// The sender's current DH public half.
    #[getset(get = "pub")]
    dh: [u8; RATCHET_PUB_LEN],

    /// The message's session-linear chain position.
    #[getset(get = "pub")]
    seq: u64,
}

/// Where a skipped message key lives: the receiving chain it was
/// derived for plus its position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Getters, TypedBuilder)]
pub struct SkippedKeyId {
    /// The receiving chain's DH public half.
    #[getset(get = "pub")]
    dh: [u8; RATCHET_PUB_LEN],

    /// The skipped message's session-linear position.
    #[getset(get = "pub")]
    seq: u64,
}

/// The only injection point in this crate: storage for message
/// keys derived for messages that arrive out of order.
///
/// `take` removes on read (a message key burns after one use).
pub trait SkippedKeyStore {
    fn insert(&mut self, id: SkippedKeyId, key: [u8; MESSAGE_KEY_LEN]);
    fn take(&mut self, id: &SkippedKeyId) -> Option<[u8; MESSAGE_KEY_LEN]>;
}

/// The in-memory store; the default for short-lived and test use.
#[derive(Debug, Clone, Default)]
pub struct MemorySkippedKeys(std::collections::HashMap<SkippedKeyId, [u8; MESSAGE_KEY_LEN]>);

impl SkippedKeyStore for MemorySkippedKeys {
    fn insert(&mut self, id: SkippedKeyId, key: [u8; MESSAGE_KEY_LEN]) {
        self.0.insert(id, key);
    }

    fn take(&mut self, id: &SkippedKeyId) -> Option<[u8; MESSAGE_KEY_LEN]> {
        self.0.remove(id)
    }
}

/// Errors the ratchet machine can surface.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RatchetError {
    #[error("decryption failed: wrong key, tampered, or unknown chain")]
    DecryptionFailed,
    #[error("skipped-key window exceeded: cap {cap}, gap {gap}")]
    SkippedLimitExceeded { cap: u64, gap: u64 },
    #[error("cannot send before this session has a send chain")]
    NoSendChain,
    #[error("corrupt ratchet state encoding: {reason}")]
    CorruptState { reason: &'static str },
}

/// One DH ratchet keypair: the clamped-secret discipline lives in
/// [`crate::x3dh::DhSecret`] (generate = fresh, from_priv =
/// restore; the private half zeroizes on drop).
type DhPair = crate::x3dh::DhSecret;

fn dh_pair_fresh() -> DhPair {
    DhPair::generate().expect("os randomness unavailable")
}

fn dh_pair_from(priv_: [u8; 32]) -> DhPair {
    DhPair::from_priv(priv_)
}

/// The Double Ratchet state for one session. Serialize at every
/// step (the persisted state is the working state — every return
/// visit starts from it).
pub struct Ratchet<S: SkippedKeyStore = MemorySkippedKeys> {
    root: [u8; 32],
    ours: DhPair,
    theirs: [u8; RATCHET_PUB_LEN],
    send_chain: Option<[u8; 32]>,
    recv_chain: Option<[u8; 32]>,
    /// The next message's session-linear number (what goes on the
    /// wire as chain_seq; never resets — the ack/cursor bookkeeping
    /// keys on it).
    send_seq: u64,
    recv_next: u64,
    /// The session-linear number at which the CURRENT send chain
    /// started (its position 0).
    send_offset: u64,
    /// The session-linear number at which the CURRENT receive
    /// chain started (pinned by the switch's trigger message).
    recv_offset: u64,
    max_skip: u64,
    skipped: S,
}

impl<S: SkippedKeyStore> std::fmt::Debug for Ratchet<S> {
    /// The secret halves never format; only the position bookkeeping
    /// and the public halves appear.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ratchet")
            .field("ours", &self.ours)
            .field("theirs", &self.theirs)
            .field("send_seq", &self.send_seq)
            .field("recv_next", &self.recv_next)
            .field("send_offset", &self.send_offset)
            .field("recv_offset", &self.recv_offset)
            .field("max_skip", &self.max_skip)
            .finish()
    }
}

impl<S: SkippedKeyStore> Ratchet<S> {
    /// Sender-side init: the session seed from [`crate::x3dh`] and
    /// the receiver's SPK public half (the receiver's initial
    /// ratchet key). Performs the first DH step, so the very first
    /// message can go out.
    pub fn init_sender(
        seed: &crate::x3dh::SessionSeed,
        receiver_spk_pub: &[u8; RATCHET_PUB_LEN],
        max_skip: u64,
        skipped: S,
    ) -> Self {
        let ours = dh_pair_fresh();
        let (root, send_chain) = root_step(seed.priv_(), &ours, receiver_spk_pub);
        Self {
            root,
            ours,
            theirs: *receiver_spk_pub,
            send_chain: Some(send_chain),
            recv_chain: None,
            send_seq: 0,
            recv_next: 0,
            send_offset: 0,
            recv_offset: 0,
            max_skip,
            skipped,
        }
    }

    /// Receiver-side init: the session seed and the SPK keypair
    /// (the receiver's standing medium key doubles as the initial
    /// ratchet keypair — the sender's first DH step used its
    /// public half).
    pub fn init_receiver(
        seed: &crate::x3dh::SessionSeed,
        spk_priv: [u8; 32],
        max_skip: u64,
        skipped: S,
    ) -> Self {
        Self {
            root: *seed.priv_(),
            ours: dh_pair_from(spk_priv),
            theirs: [0; RATCHET_PUB_LEN],
            send_chain: None,
            recv_chain: None,
            send_seq: 0,
            recv_next: 0,
            send_offset: 0,
            recv_offset: 0,
            max_skip,
            skipped,
        }
    }

    /// Whether a send chain exists (an establishment and at least
    /// one receive happened on this side, or this side is the
    /// session's initiator).
    pub fn has_send_chain(&self) -> bool {
        self.send_chain.is_some()
    }

    /// Encrypt one message; the send chain advances per call.
    ///
    /// # Errors
    /// [`RatchetError::NoSendChain`] when this side has never
    /// received a DH step (it has no send chain to draw from).
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), RatchetError> {
        let ck = self.send_chain.take().ok_or(RatchetError::NoSendChain)?;
        let (mk, next) = chain_step(&ck);
        self.send_chain = Some(next);
        let header = RatchetHeader::builder()
            .dh(*self.ours.pub_())
            .seq(self.send_seq)
            .build();
        self.send_seq += 1;
        let ct = aead_seal(&mk, &nonce_of(&mk), plaintext, ad)?;
        Ok((header, ct))
    }

    /// Decrypt one message; skipped keys absorb reorder and loss.
    ///
    /// # Errors
    /// [`RatchetError::DecryptionFailed`] on wrong key/tamper/
    /// unknown chain; [`RatchetError::SkippedLimitExceeded`] when
    /// the gap outgrows the cap.
    pub fn decrypt(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        if let Some(mk) = self.skipped.take(&SkippedKeyId {
            dh: *header.dh(),
            seq: *header.seq(),
        }) {
            return aead_open(&mk, &nonce_of(&mk), ciphertext, ad);
        }
        if self.recv_chain.is_none() || header.dh != self.theirs {
            // The sender started a new DH chain (or this is the
            // first receive). No old-chain skipping: the plane
            // streams are FIFO per direction and retries re-push
            // the SAME sealed bytes, so the old chain holds no
            // in-flight messages at switch time — cross-chain
            // reorder is a SESSION-boundary event, handled by the
            // session layer (previous sessions stay alive until
            // their mail is drained).
            self.dh_step(&header.dh);
        }
        self.skip_to(header.seq)?;
        let ck = self
            .recv_chain
            .as_mut()
            .ok_or(RatchetError::DecryptionFailed)?;
        let (mk, next) = chain_step(ck);
        *ck = next;
        self.recv_next += 1;
        aead_open(&mk, &nonce_of(&mk), ciphertext, ad)
    }

    /// Stash message keys for every position from the current recv
    /// position up to (excluding) `to`, then advance. Loud at the
    /// cap (Minecraft-class flood would otherwise eat memory).
    /// Stash message keys for every in-chain position from the
    /// current receive position up to (excluding) the linear
    /// number `to`, then advance. Loud at the cap (a flood of
    /// never-sent positions would otherwise eat memory).
    fn skip_to(&mut self, to: u64) -> Result<(), RatchetError> {
        let Some(ck) = self.recv_chain else {
            return Ok(());
        };
        let gap = to.saturating_sub(self.recv_next);
        if gap > self.max_skip {
            return Err(RatchetError::SkippedLimitExceeded {
                cap: self.max_skip,
                gap,
            });
        }
        let mut ck = ck;
        for seq in self.recv_next..to {
            let (mk, next) = chain_step(&ck);
            self.skipped.insert(
                SkippedKeyId {
                    dh: self.theirs,
                    seq,
                },
                mk,
            );
            ck = next;
        }
        self.recv_chain = Some(ck);
        self.recv_next = to;
        Ok(())
    }

    fn dh_step(&mut self, theirs: &[u8; RATCHET_PUB_LEN]) {
        // Paper order: the receiving chain comes from the CURRENT
        // DHs (the keypair the sender already stepped with); the
        // fresh keypair serves the SENDING chain. The linear
        // counters never reset: the new chain's position 0 sits at
        // the switch message's linear number (the sender's chain
        // starts with its first post-switch message, which is the
        // message carrying this new DH public half).
        self.theirs = *theirs;
        let (root, recv_chain) = root_step(&self.root, &self.ours, theirs);
        self.root = root;
        self.recv_chain = Some(recv_chain);
        self.recv_offset = self.recv_next;
        self.ours = dh_pair_fresh();
        let (root, send_chain) = root_step(&self.root, &self.ours, theirs);
        self.root = root;
        self.send_chain = Some(send_chain);
        self.send_offset = self.send_seq;
    }

    /// Serialize the state to the raw at-rest encoding (format
    /// byte + fixed-order fields). The skipped-key store persists
    /// separately, through its own path.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 5 + 8 * 5 + 3);
        out.push(STATE_FORMAT);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(self.ours.priv_());
        out.extend_from_slice(&self.theirs);
        out.extend_from_slice(self.send_chain.as_ref().unwrap_or(&[0; 32]));
        out.extend_from_slice(self.recv_chain.as_ref().unwrap_or(&[0; 32]));
        out.extend_from_slice(&self.send_seq.to_be_bytes());
        out.extend_from_slice(&self.recv_next.to_be_bytes());
        out.extend_from_slice(&self.send_offset.to_be_bytes());
        out.extend_from_slice(&self.recv_offset.to_be_bytes());
        out.extend_from_slice(&self.max_skip.to_be_bytes());
        out.push(if self.send_chain.is_some() { 1 } else { 0 });
        out.push(if self.recv_chain.is_some() { 1 } else { 0 });
        out
    }

    /// Parse from the raw at-rest encoding, rebinding a skipped-key
    /// store.
    ///
    /// # Errors
    /// [`RatchetError::CorruptState`] on any encoding violation.
    pub fn from_bytes(bytes: &[u8], skipped: S) -> Result<Self, RatchetError> {
        let exp = 1 + 32 * 5 + 8 * 5 + 2;
        if bytes.len() != exp {
            return Err(RatchetError::CorruptState {
                reason: "length mismatch",
            });
        }
        if bytes[0] != STATE_FORMAT {
            return Err(RatchetError::CorruptState {
                reason: "unknown format byte",
            });
        }
        let mut at = 1;
        let take32 = |b: &[u8], at: &mut usize| {
            let mut v = [0u8; 32];
            v.copy_from_slice(&b[*at..*at + 32]);
            *at += 32;
            v
        };
        let root = take32(bytes, &mut at);
        let ours_priv = take32(bytes, &mut at);
        let theirs = take32(bytes, &mut at);
        let send = take32(bytes, &mut at);
        let recv = take32(bytes, &mut at);
        let be64 = |b: &[u8], at: &mut usize| {
            let mut v = [0u8; 8];
            v.copy_from_slice(&b[*at..*at + 8]);
            *at += 8;
            u64::from_be_bytes(v)
        };
        let send_seq = be64(bytes, &mut at);
        let recv_next = be64(bytes, &mut at);
        let send_offset = be64(bytes, &mut at);
        let recv_offset = be64(bytes, &mut at);
        let max_skip = be64(bytes, &mut at);
        let send_chain = if bytes[at] == 1 { Some(send) } else { None };
        let recv_chain = if bytes[at + 1] == 1 { Some(recv) } else { None };
        Ok(Self {
            root,
            ours: dh_pair_from(ours_priv),
            theirs,
            send_chain,
            recv_chain,
            send_seq,
            recv_next,
            send_offset,
            recv_offset,
            max_skip,
            skipped,
        })
    }
}

const STATE_FORMAT: u8 = 1;

fn root_step(
    current_root: &[u8; 32],
    ours: &DhPair,
    theirs: &[u8; RATCHET_PUB_LEN],
) -> ([u8; 32], [u8; 32]) {
    let mut dh = StaticSecret::from(*ours.priv_())
        .diffie_hellman(&XPublicKey::from(*theirs))
        .to_bytes();
    let mut okm = [0u8; 64];
    // The old root keys the MAC; the DH output is the absorbed
    // data — one evaluation replaces the extract-expand pair.
    kdf::derive(current_root, ROOT_LABEL, &dh, &mut okm);
    dh.zeroize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&okm[..32]);
    let mut chain = [0u8; 32];
    chain.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (root, chain)
}

/// KDF_CK: one chain-key squeeze yields the next chain key and the
/// message key, each its own label domain. The message nonce is a
/// deterministic function of the message key (below), so a skipped
/// key stores the message key alone.
fn chain_step(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mk = [0u8; 32];
    kdf::derive(ck, CHAIN_MSG_LABEL, &[], &mut mk);
    let mut next = [0u8; 32];
    kdf::derive(ck, CHAIN_NEXT_LABEL, &[], &mut next);
    (mk, next)
}

/// The message nonce, derived from the message key.
fn nonce_of(mk: &[u8; 32]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    kdf::derive(mk, MSG_NONCE_LABEL, &[], &mut nonce);
    nonce
}

fn aead_seal(
    mk: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, RatchetError> {
    ChaCha20Poly1305::new(mk.into())
        .encrypt(
            nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| RatchetError::DecryptionFailed)
}

fn aead_open(
    mk: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, RatchetError> {
    ChaCha20Poly1305::new(mk.into())
        .decrypt(
            nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| RatchetError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh;
    use pretty_assertions::{assert_eq, assert_ne};

    const MAX_SKIP: u64 = 100;

    /// Establish a session both sides agree on: returns the seed,
    /// the receiver's SPK keypair and the receiver's SPK pub.
    fn established() -> (x3dh::SessionSeed, [u8; 32], [u8; RATCHET_PUB_LEN]) {
        let ks = crate::KeySet::generate().expect("os randomness");
        let sender_static = ks.static_dh_secret_bytes();
        let ks2 = crate::KeySet::generate().expect("os randomness");
        let receiver_static = ks2.static_dh_secret_bytes();
        let spk = x3dh::DhSecret::generate().expect("os randomness unavailable");
        let spk_priv = *spk.priv_();
        let spk_pub = *spk.pub_();
        let out = x3dh::establish(&sender_static, &pub_of(&receiver_static), &spk_pub, None)
            .expect("os randomness");
        let back = x3dh::receive(
            &pub_of(&sender_static),
            out.eph_pub(),
            &receiver_static,
            &spk_priv,
            None,
        )
        .expect("derivation is infallible");
        assert_eq!(out.seed().priv_(), back.priv_());
        (back, spk_priv, spk_pub)
    }

    fn pub_of(priv_: &[u8; 32]) -> [u8; 32] {
        *XPublicKey::from(&StaticSecret::from(*priv_)).as_bytes()
    }

    #[test]
    fn seal_unseal_roundtrip_over_the_chain() {
        let (seed, spk_priv, spk_pub) = established();
        let mut alice = Ratchet::<MemorySkippedKeys>::init_sender(
            &seed,
            &spk_pub,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        let mut bob = Ratchet::<MemorySkippedKeys>::init_receiver(
            &seed,
            spk_priv,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        for i in 0u64..5 {
            let (header, ct) = alice
                .encrypt(format!("message {i}").as_bytes(), b"ad")
                .expect("send chain exists");
            assert_eq!(header.seq, i);
            let pt = bob.decrypt(&header, &ct, b"ad").expect("chain decrypts");
            assert_eq!(pt, format!("message {i}").as_bytes());
        }
    }

    #[test]
    fn wrong_ad_fails_loudly() {
        let (seed, spk_priv, spk_pub) = established();
        let mut alice = Ratchet::<MemorySkippedKeys>::init_sender(
            &seed,
            &spk_pub,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        let mut bob = Ratchet::<MemorySkippedKeys>::init_receiver(
            &seed,
            spk_priv,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        let (header, ct) = alice.encrypt(b"secret", b"ad-a").expect("send");
        match bob.decrypt(&header, &ct, b"ad-b") {
            Err(RatchetError::DecryptionFailed) => {}
            other => panic!("expected DecryptionFailed, got {other:?}"),
        }
    }

    #[test]
    fn receiver_replies_and_sender_follows() {
        let (seed, spk_priv, spk_pub) = established();
        let mut alice = Ratchet::<MemorySkippedKeys>::init_sender(
            &seed,
            &spk_pub,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        let mut bob = Ratchet::<MemorySkippedKeys>::init_receiver(
            &seed,
            spk_priv,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        let (h1, c1) = alice.encrypt(b"hello", b"ad").expect("send");
        let _ = bob.decrypt(&h1, &c1, b"ad").expect("recv");
        // Bob replies: his first send follows the DH step his
        // receive already performed.
        let (h2, c2) = bob.encrypt(b"hi back", b"ad").expect("reply send");
        let pt = alice.decrypt(&h2, &c2, b"ad").expect("reply decrypts");
        assert_eq!(pt, b"hi back");
        assert_ne!(h1.dh, h2.dh);
        // The conversation continues on the stepped chains.
        let (h3, c3) = alice.encrypt(b"again", b"ad").expect("send");
        let pt = bob.decrypt(&h3, &c3, b"ad").expect("decrypts");
        assert_eq!(pt, b"again");
    }

    #[test]
    fn out_of_order_arrivals_absorb_through_skipped_keys() {
        let (seed, spk_priv, spk_pub) = established();
        let mut alice = Ratchet::<MemorySkippedKeys>::init_sender(
            &seed,
            &spk_pub,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        let mut bob = Ratchet::<MemorySkippedKeys>::init_receiver(
            &seed,
            spk_priv,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        let mail: Vec<(RatchetHeader, Vec<u8>)> = (0..3)
            .map(|i| {
                alice
                    .encrypt(format!("msg-{i}").as_bytes(), b"ad")
                    .expect("send")
            })
            .collect();
        // Arrival order 2, 0, 1 — the reorder the or-cache mix and
        // sender retries can produce.
        let last = bob
            .decrypt(&mail[2].0, &mail[2].1, b"ad")
            .expect("skipped-window decrypts");
        assert_eq!(last, b"msg-2");
        assert_eq!(
            bob.decrypt(&mail[0].0, &mail[0].1, b"ad")
                .expect("decrypts"),
            b"msg-0"
        );
        assert_eq!(
            bob.decrypt(&mail[1].0, &mail[1].1, b"ad")
                .expect("decrypts"),
            b"msg-1"
        );
        // A skipped key burns after one use.
        match bob.decrypt(&mail[0].0, &mail[0].1, b"ad") {
            Err(RatchetError::DecryptionFailed) => {}
            other => panic!("expected DecryptionFailed, got {other:?}"),
        }
    }

    #[test]
    fn skipped_window_caps_loudly() {
        let (seed, spk_priv, spk_pub) = established();
        let mut alice = Ratchet::<MemorySkippedKeys>::init_sender(
            &seed,
            &spk_pub,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        let mut bob = Ratchet::<MemorySkippedKeys>::init_receiver(
            &seed,
            spk_priv,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        // The chain starts on the first message (the establishment
        // mail is always the session's first mail), then a same-
        // chain gap beyond the cap fires the cap. An or-side
        // eviction gap BEFORE the first arrival is not a skipped-
        // window event: the chain simply starts where the sender's
        // line starts (R23: eviction = permanent chain gaps).
        let (h0, c0) = alice.encrypt(b"first", b"ad").expect("send");
        bob.decrypt(&h0, &c0, b"ad").expect("recv");
        let mut far = None;
        // seqs 1..=MAX_SKIP+2: the final gap = MAX_SKIP+1 > cap.
        for i in 1..=(MAX_SKIP + 2) {
            far = Some(
                alice
                    .encrypt(i.to_string().as_bytes(), b"ad")
                    .expect("send")
                    .0,
            );
        }
        match bob.decrypt(far.as_ref().expect("non-empty"), b"anything", b"ad") {
            Err(RatchetError::SkippedLimitExceeded { cap: MAX_SKIP, .. }) => {}
            other => panic!("expected SkippedLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn state_serializes_and_restores() {
        let (seed, spk_priv, spk_pub) = established();
        let mut alice = Ratchet::<MemorySkippedKeys>::init_sender(
            &seed,
            &spk_pub,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        let (h1, c1) = alice.encrypt(b"before", b"ad").expect("send");
        let bytes = alice.to_bytes();
        let mut restored =
            Ratchet::<MemorySkippedKeys>::from_bytes(&bytes, MemorySkippedKeys::default())
                .expect("state encoding");
        let (h2, c2) = restored.encrypt(b"after", b"ad").expect("send");
        assert_eq!(h2.seq, 1);
        let mut bob = Ratchet::<MemorySkippedKeys>::init_receiver(
            &seed,
            spk_priv,
            MAX_SKIP,
            MemorySkippedKeys::default(),
        );
        assert_eq!(bob.decrypt(&h1, &c1, b"ad").expect("recv"), b"before");
        assert_eq!(bob.decrypt(&h2, &c2, b"ad").expect("recv"), b"after");
    }
}
