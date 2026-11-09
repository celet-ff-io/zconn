//! The mail layer: the keyring, the prekey lifecycle, and the
//! seal/unseal over the sealed-mail wire shape. Establishment and
//! ratchet math live in the crypto crate; this module wires them
//! to the wire types and holds per-peer session state.

use std::collections::{BTreeMap, HashMap, HashSet};

use getset::{Getters, Setters};
use prost::Message as _;
use typed_builder::TypedBuilder;
use zconned_crypto as crypto;
use zconnor_mail_types::mail;
use zconnor_mail_types::relay;

use crypto::{DhSecret, ESTABLISHMENT_PUB_LEN, SessionSeed};
use crypto::{
    Fingerprint, KeySet, MemorySkippedKeys, Ratchet, RatchetError, RatchetHeader, SIGN_PUB_LEN,
    establish, receive, verify_strict,
};

/// The signing algorithm's canonical name (the wire algo field).
const SIGN_ALGO: &str = "ed25519";
/// The static DH algorithm's canonical name.
const DH_ALGO: &str = "x25519";

/// Errors the mail layer surfaces.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MailError {
    #[error(transparent)]
    Entropy(#[from] crypto::IdentityError),
    #[error("sender anchor mismatch or no session for the sender")]
    UnknownSender,
    #[error("signature check failed")]
    SigInvalid,
    #[error("establishment references SPK epoch {epoch}, current is {current}")]
    StalePrekey { epoch: u32, current: u32 },
    #[error("the ratchet rejected the message")]
    Decryption(#[from] RatchetError),
}

/// One arrival's outcome: fresh plaintext, or an already-processed
/// duplicate (absorbed via the processed ledger).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arrival {
    Decrypted {
        /// The unsealed payload (the material's bytes).
        plaintext: Vec<u8>,
        header: RatchetHeader,
    },
    Duplicate,
}

/// The receiver's prekey material a sender needs to seal: what the
/// or's bundle reply carries, minus the or's bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq, Getters, TypedBuilder)]
pub struct ReceiverPrekeys {
    /// The receiver's standing medium key: public half + epoch.
    #[getset(get = "pub")]
    spk: SpkPub,
    /// The consumed pool slot; absent = the 3-term degraded
    /// establishment.
    #[getset(get = "pub")]
    opk: Option<OpkPub>,
}

/// The standing medium key's public face.
#[derive(Debug, Clone, PartialEq, Eq, Getters, TypedBuilder)]
pub struct SpkPub {
    #[getset(get = "pub")]
    key: [u8; ESTABLISHMENT_PUB_LEN],
    /// The owner's monotone epoch; the sender stamps it as the
    /// mail's key_version.
    #[getset(get = "pub")]
    ver: u32,
}

/// One pool slot's public face.
#[derive(Debug, Clone, PartialEq, Eq, Getters, TypedBuilder)]
pub struct OpkPub {
    #[getset(get = "pub")]
    id: u32,
    #[getset(get = "pub")]
    key: [u8; ESTABLISHMENT_PUB_LEN],
}

/// One established session with one peer: the ratchet plus the
/// peer's signed public face (mid-chain mails verify against it).
#[derive(Debug)]
struct Session {
    peer: mail::MailboxPublicSet,
    ratchet: Ratchet<MemorySkippedKeys>,
    /// The SPK epoch this session's establishment used; every mail
    /// of the session stamps it.
    epoch: u32,
    /// Processed (dh, seq) pairs — duplicate arrivals absorb here.
    processed: HashSet<([u8; ESTABLISHMENT_PUB_LEN], u64)>,
}

#[derive(Debug)]
pub struct PeerSessions {
    current: Session,
    previous: Vec<Session>,
}

/// The standing medium key's private slot + its epoch.
#[derive(Debug)]
pub struct SpkSlot {
    secret: DhSecret,
    ver: u32,
}

/// The local identity's mail-side state: the prekey slots, the
/// per-peer sessions, and the pool lifecycle. Persistence is the
/// caller's concern (the store layer); this type is the in-memory
/// working state.
#[derive(Debug, Getters, Setters, TypedBuilder)]
pub struct MailKeyring {
    identity: KeySet,
    /// The pool's full size; refill target after a dip.
    #[getset(get = "pub", set = "pub")]
    pool_size: u64,
    /// Refill fires when the pool dips below this.
    #[getset(get = "pub", set = "pub")]
    replenish_threshold: u64,
    /// The ratchet's skipped-window cap.
    #[getset(get = "pub", set = "pub")]
    max_skip: u64,
    #[builder(default = SpkSlot { secret: DhSecret::generate().expect("os randomness unavailable"), ver: 1 }, setter(skip))]
    spk: SpkSlot,
    /// The one-time pool: private slots by id.
    #[builder(default = BTreeMap::new(), setter(skip))]
    opks: BTreeMap<u32, DhSecret>,
    #[builder(default = 1, setter(skip))]
    next_opk_id: u32,
    #[builder(default = HashMap::new(), setter(skip))]
    sessions: HashMap<[u8; crypto::DIGEST_LEN], PeerSessions>,
}

impl MailKeyring {
    /// This identity's addressing anchor (the fingerprint bytes).
    pub fn anchor(&self) -> [u8; crypto::DIGEST_LEN] {
        *self.identity.fingerprint().bytes()
    }

    /// The public face the or's directory holds, self-signed.
    pub fn public_set(&self) -> mail::MailboxPublicSet {
        let shell = mail::MailboxPublicSet {
            ver: 1,
            sign_algo: SIGN_ALGO.into(),
            sign_pub: self
                .identity
                .derived()
                .sign()
                .verifying_key()
                .as_bytes()
                .to_vec(),
            dh_algo: DH_ALGO.into(),
            static_dh_pub: self.identity.static_dh_public_bytes().to_vec(),
            sig: Vec::new(),
        };
        let sig = self.identity.sign(&shell.encode_to_vec());
        mail::MailboxPublicSet {
            sig: sig.to_vec(),
            ..shell
        }
    }

    /// The bundle-reply payload: the standing key + one pool slot;
    /// refills the pool on the way. The or's BundleGet wraps this.
    pub fn serve_bundle(&mut self, mailbox: &[u8]) -> relay::Bundle {
        self.replenish();
        let spk = mail::Spk {
            key: self.spk.secret.pub_().to_vec(),
            sig: self.sign_spk(),
            ver: self.spk.ver,
        };
        let opk = self.opks.iter().next().map(|(id, secret)| mail::Opk {
            id: *id,
            key: secret.pub_().to_vec(),
        });
        relay::Bundle {
            mailbox: mailbox.to_vec(),
            spk: Some(spk),
            opk,
            pool_remaining: self.opks.len() as u64,
        }
    }

    /// Rotate the standing medium key: the epoch advances, the old
    /// private half dies. Called at each visit's flip step; old
    /// privates are gone from that moment.
    pub fn flip_spk(&mut self) -> Result<(), MailError> {
        self.spk = SpkSlot {
            secret: DhSecret::generate()?,
            ver: self.spk.ver + 1,
        };
        Ok(())
    }

    /// Refill the pool from OS randomness when it dips below the
    /// low-water mark.
    pub fn replenish(&mut self) {
        if self.opks.len() as u64 >= self.replenish_threshold {
            return;
        }
        while (self.opks.len() as u64) < self.pool_size {
            let id = self.next_opk_id;
            self.next_opk_id += 1;
            match DhSecret::generate() {
                Ok(secret) => {
                    self.opks.insert(id, secret);
                }
                Err(_) => return,
            }
        }
    }

    /// Seal one mail to `to_mailbox` (the peer's anchor): establish
    /// a fresh session over the prekeys the caller supplied, run
    /// the first ratchet step, stamp the envelope. The freshness
    /// rule: every seal speaks the newest establishment — a reply
    /// to a peer re-establishes on its current prekeys.
    pub fn seal(
        &mut self,
        to_mailbox: &[u8; crypto::DIGEST_LEN],
        peer_set: &mail::MailboxPublicSet,
        prekeys: &ReceiverPrekeys,
        plaintext: &[u8],
    ) -> Result<mail::Mail, MailError> {
        if self
            .sessions
            .get_mut(to_mailbox)
            .is_some_and(|sessions| sessions.current.ratchet.has_send_chain())
        {
            // Continue the live session: one establishment per
            // session; later mails ride the ratchet chain.
            return self.seal_continued(to_mailbox, plaintext);
        }
        self.seal_fresh(to_mailbox, peer_set, prekeys, plaintext)
    }

    /// Continue the live session (mid-chain mail: no establishment
    /// kit, the session's epoch rides key_version).
    fn seal_continued(
        &mut self,
        to_mailbox: &[u8; crypto::DIGEST_LEN],
        plaintext: &[u8],
    ) -> Result<mail::Mail, MailError> {
        let sessions = self.sessions.get_mut(to_mailbox).expect("checked");
        let epoch = sessions.current.epoch;
        let (header, ciphertext) = sessions
            .current
            .ratchet
            .encrypt(plaintext, b"")
            .map_err(MailError::Decryption)?;
        let mut m = mail::Mail {
            to_mailbox: to_mailbox.to_vec(),
            from_mailbox: self.anchor().to_vec(),
            key_version: epoch,
            dr_header: Some(mail::DrHeader {
                ratchet_pub: header.dh().to_vec(),
                chain_seq: *header.seq(),
            }),
            sig: Vec::new(),
            ciphertext,
            establishment: None,
        };
        let sign_input = m.encode_to_vec();
        m.sig = self.identity.sign(&sign_input).to_vec();
        Ok(m)
    }

    /// Force a fresh establishment over the supplied prekeys: the
    /// recovery path after the sender learns its establishment went
    /// stale (pending timeout -> re-fetch -> new prekeys). The old
    /// session retires to the previous list; its mail still drains.
    pub fn seal_fresh(
        &mut self,
        to_mailbox: &[u8; crypto::DIGEST_LEN],
        peer_set: &mail::MailboxPublicSet,
        prekeys: &ReceiverPrekeys,
        plaintext: &[u8],
    ) -> Result<mail::Mail, MailError> {
        let out = establish(
            &self.identity.static_dh_secret_bytes(),
            &static_dh_bytes(peer_set)?,
            prekeys.spk().key(),
            prekeys.opk().as_ref().map(|o| o.key()),
        )?;
        let mut ratchet = Ratchet::init_sender(
            out.seed(),
            prekeys.spk().key(),
            self.max_skip,
            MemorySkippedKeys::default(),
        );
        let (header, ciphertext) = ratchet.encrypt(plaintext, b"")?;

        // The kit carries the SENDER's own self-signed face — the
        // receiver verifies it against the from anchor.
        let establishment = mail::Establishment {
            mailbox: Some(self.public_set()),
            eph_pub: out.eph_pub().to_vec(),
            opk_id: prekeys.opk().as_ref().map(|o| *o.id()),
        };
        let mut m = mail::Mail {
            to_mailbox: to_mailbox.to_vec(),
            from_mailbox: self.anchor().to_vec(),
            key_version: *prekeys.spk().ver(),
            dr_header: Some(mail::DrHeader {
                ratchet_pub: header.dh().to_vec(),
                chain_seq: *header.seq(),
            }),
            sig: Vec::new(),
            ciphertext,
            establishment: Some(establishment),
        };
        // The outer gate: Sign over the deterministic encoding with
        // sig unset (empty bytes never serialize).
        let sign_input = m.encode_to_vec();
        m.sig = self.identity.sign(&sign_input).to_vec();

        let session = Session {
            peer: peer_set.clone(),
            ratchet,
            epoch: *prekeys.spk().ver(),
            processed: HashSet::new(),
        };
        self.remember(to_mailbox, session);
        Ok(m)
    }

    /// Unseal one arrival: verify the outer gate, establish or
    /// resume the session, decrypt, absorb duplicates, burn the
    /// consumed pool slot at first processing.
    pub fn unseal(&mut self, m: &mail::Mail) -> Result<Arrival, MailError> {
        let mut from = [0u8; crypto::DIGEST_LEN];
        from.copy_from_slice(&m.from_mailbox);
        let (peer_set, establishment) = match &m.establishment {
            Some(est) => {
                let set = est.mailbox.as_ref().ok_or(MailError::UnknownSender)?;
                // The mail carries its own face: the anchor and the
                // face's inner sig must both hold before any key
                // work.
                if fingerprint_of(set)? != from {
                    return Err(MailError::UnknownSender);
                }
                // The outer gate runs on EVERY mail, kit or not.
                verify_mail_sig(m, set)?;
                verify_set_sig(set)?;
                (set.clone(), Some(est.clone()))
            }
            None => {
                // Mid-chain mail: the sender's face comes from the
                // established session.
                let sessions = self.sessions.get(&from).ok_or(MailError::UnknownSender)?;
                let set = sessions.current.peer.clone();
                verify_mail_sig(m, &set)?;
                (set, None)
            }
        };

        let header = dr_header_bytes(m)?;
        let ledger_key = (*header.dh(), *header.seq());
        let seen = self
            .sessions
            .get(&from)
            .map(|s| {
                s.previous
                    .iter()
                    .chain(std::iter::once(&s.current))
                    .any(|sess| sess.processed.contains(&ledger_key))
            })
            .unwrap_or(false);
        if seen {
            return Ok(Arrival::Duplicate);
        }

        match establishment {
            Some(est) => {
                if m.key_version != self.spk.ver {
                    return Err(MailError::StalePrekey {
                        epoch: m.key_version,
                        current: self.spk.ver,
                    });
                }
                let seed = self.establish_seed(m, &peer_set, &est)?;
                let mut ratchet = Ratchet::init_receiver(
                    &seed,
                    *self.spk.secret.priv_(),
                    self.max_skip,
                    MemorySkippedKeys::default(),
                );
                let plaintext = ratchet.decrypt(&header, &m.ciphertext, b"")?;
                // First processing: the consumed pool slot burns.
                if let Some(id) = est.opk_id {
                    self.opks.remove(&id);
                }
                self.remember(
                    &from,
                    Session {
                        peer: peer_set,
                        ratchet,
                        epoch: m.key_version,
                        processed: HashSet::new(),
                    },
                );
                self.sessions
                    .get_mut(&from)
                    .expect("just inserted")
                    .current
                    .processed
                    .insert(ledger_key);
                Ok(Arrival::Decrypted { plaintext, header })
            }
            None => {
                let sessions = self
                    .sessions
                    .get_mut(&from)
                    .ok_or(MailError::UnknownSender)?;
                // The current session first, then the previous ones
                // (an old-session mail drains late after a
                // re-establishment).
                if let Ok(plaintext) = sessions
                    .current
                    .ratchet
                    .decrypt(&header, &m.ciphertext, b"")
                {
                    sessions.current.processed.insert(ledger_key);
                    return Ok(Arrival::Decrypted { plaintext, header });
                }
                for prev in sessions.previous.iter_mut() {
                    if let Ok(plaintext) = prev.ratchet.decrypt(&header, &m.ciphertext, b"") {
                        prev.processed.insert(ledger_key);
                        return Ok(Arrival::Decrypted { plaintext, header });
                    }
                }
                Err(MailError::Decryption(RatchetError::DecryptionFailed))
            }
        }
    }

    /// Drop a peer's previous sessions (its cached mail drained).
    pub fn retire_previous_sessions(&mut self, anchor: &[u8; crypto::DIGEST_LEN]) {
        if let Some(sessions) = self.sessions.get_mut(anchor) {
            sessions.previous.clear();
        }
    }

    /// Rebuild the seed from the establishment's terms. The claimed
    /// OPK id either still lives or the establishment is stale (a
    /// double-handout second mail fails loudly here — the sender
    /// re-establishes on its next visit).
    fn establish_seed(
        &self,
        m: &mail::Mail,
        peer_set: &mail::MailboxPublicSet,
        est: &mail::Establishment,
    ) -> Result<SessionSeed, MailError> {
        let sender_static = static_dh_bytes(peer_set)?;
        let sender_eph = eph_pub_bytes(est)?;
        let (seed, _header) = match est.opk_id {
            Some(id) => {
                let priv_ = self.opks.get(&id).ok_or(MailError::StalePrekey {
                    epoch: m.key_version,
                    current: self.spk.ver,
                })?;
                let seed = receive(
                    &sender_static,
                    &sender_eph,
                    &self.identity.static_dh_secret_bytes(),
                    self.spk.secret.priv_(),
                    Some(priv_.priv_()),
                )?;
                (seed, ())
            }
            None => {
                let seed = receive(
                    &sender_static,
                    &sender_eph,
                    &self.identity.static_dh_secret_bytes(),
                    self.spk.secret.priv_(),
                    None,
                )?;
                (seed, ())
            }
        };
        Ok(seed)
    }

    fn remember(&mut self, anchor: &[u8; crypto::DIGEST_LEN], session: Session) {
        match self.sessions.get_mut(anchor) {
            Some(entry) => {
                // Session replacement: the old session stays until
                // its cached mail drains (retiring it now would
                // lose its in-flight mail).
                let old = std::mem::replace(&mut entry.current, session);
                entry.previous.push(old);
            }
            None => {
                self.sessions.insert(
                    *anchor,
                    PeerSessions {
                        current: session,
                        previous: Vec::new(),
                    },
                );
            }
        }
    }

    fn sign_spk(&self) -> Vec<u8> {
        let shell = mail::Spk {
            key: self.spk.secret.pub_().to_vec(),
            sig: Vec::new(),
            ver: self.spk.ver,
        };
        self.identity.sign(&shell.encode_to_vec()).to_vec()
    }
}

fn fingerprint_of(set: &mail::MailboxPublicSet) -> Result<[u8; crypto::DIGEST_LEN], MailError> {
    let mut sign = [0u8; SIGN_PUB_LEN];
    sign.copy_from_slice(&set.sign_pub);
    Ok(*Fingerprint::of(&sign).bytes())
}

fn verify_set_sig(set: &mail::MailboxPublicSet) -> Result<(), MailError> {
    let mut sign = [0u8; SIGN_PUB_LEN];
    sign.copy_from_slice(&set.sign_pub);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&set.sig);
    let shell = mail::MailboxPublicSet {
        sig: Vec::new(),
        ..set.clone()
    };
    if verify_strict(&sign, &shell.encode_to_vec(), &sig) {
        Ok(())
    } else {
        Err(MailError::SigInvalid)
    }
}

fn verify_mail_sig(m: &mail::Mail, peer_set: &mail::MailboxPublicSet) -> Result<(), MailError> {
    let mut sign = [0u8; SIGN_PUB_LEN];
    sign.copy_from_slice(&peer_set.sign_pub);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&m.sig);
    let shell = mail::Mail {
        sig: Vec::new(),
        ..m.clone()
    };
    if verify_strict(&sign, &shell.encode_to_vec(), &sig) {
        Ok(())
    } else {
        Err(MailError::SigInvalid)
    }
}

fn static_dh_bytes(set: &mail::MailboxPublicSet) -> Result<[u8; ESTABLISHMENT_PUB_LEN], MailError> {
    let mut k = [0u8; ESTABLISHMENT_PUB_LEN];
    k.copy_from_slice(&set.static_dh_pub);
    Ok(k)
}

fn eph_pub_bytes(est: &mail::Establishment) -> Result<[u8; ESTABLISHMENT_PUB_LEN], MailError> {
    let mut k = [0u8; ESTABLISHMENT_PUB_LEN];
    k.copy_from_slice(&est.eph_pub);
    Ok(k)
}

fn dr_header_bytes(m: &mail::Mail) -> Result<RatchetHeader, MailError> {
    let dh_header = m.dr_header.as_ref().ok_or(MailError::UnknownSender)?;
    let mut dh = [0u8; ESTABLISHMENT_PUB_LEN];
    dh.copy_from_slice(&dh_header.ratchet_pub);
    Ok(RatchetHeader::builder()
        .dh(dh)
        .seq(dh_header.chain_seq)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::DIGEST_LEN;
    use pretty_assertions::assert_eq;

    const POOL: u64 = 4;
    const THRESHOLD: u64 = 2;
    const MAX_SKIP: u64 = 100;

    struct Node {
        keyring: MailKeyring,
        anchor: [u8; DIGEST_LEN],
        face: mail::MailboxPublicSet,
    }

    fn node() -> Node {
        let keyring = MailKeyring::builder()
            .identity(KeySet::generate().expect("os randomness"))
            .pool_size(POOL)
            .replenish_threshold(THRESHOLD)
            .max_skip(MAX_SKIP)
            .build();
        let anchor = keyring.anchor();
        let face = keyring.public_set();
        Node {
            keyring,
            anchor,
            face,
        }
    }

    /// The or's bundle round trip: b serves a bundle to a.
    fn bundle_of(b: &mut Node, a: &Node) -> ReceiverPrekeys {
        let bundle = b.keyring.serve_bundle(&a.anchor);
        let spk = bundle.spk.expect("standing key present");
        ReceiverPrekeys::builder()
            .spk(
                SpkPub::builder()
                    .key(spk.key.as_slice().try_into().expect("32-byte SPK"))
                    .ver(spk.ver)
                    .build(),
            )
            .opk(bundle.opk.map(|o| {
                OpkPub::builder()
                    .id(o.id)
                    .key(o.key.as_slice().try_into().expect("32-byte OPK"))
                    .build()
            }))
            .build()
    }

    #[test]
    fn seal_unseal_roundtrip_with_strangers() {
        let mut a = node();
        let mut b = node();
        let prekeys = bundle_of(&mut b, &a);
        let mail = a
            .keyring
            .seal(&b.anchor, &b.face, &prekeys, b"hello b")
            .expect("seal");
        assert_eq!(mail.key_version, 1);
        // The sealed form carries the establishment kit and is
        // anchored both ways.
        assert!(mail.establishment.is_some());
        assert_eq!(mail.from_mailbox.as_slice(), &a.anchor);
    }

    #[test]
    fn full_loop_two_nodes_reply_and_reorder() {
        let mut a = node();
        let mut b = node();
        let prekeys = bundle_of(&mut b, &a);
        let m1 = a
            .keyring
            .seal(&b.anchor, &b.face, &prekeys, b"first")
            .expect("seal");
        let arrival = b.keyring.unseal(&m1).expect("unseal");
        match arrival {
            Arrival::Decrypted { plaintext, .. } => assert_eq!(plaintext, b"first"),
            Arrival::Duplicate => panic!("first arrival is fresh"),
        }
        // b replies: it seals on a's freshest prekeys.
        let prekeys_a = bundle_of(&mut a, &b);
        let m2 = b
            .keyring
            .seal(&a.anchor, &a.face, &prekeys_a, b"hi back")
            .expect("seal");
        match a.keyring.unseal(&m2).expect("unseal") {
            Arrival::Decrypted { plaintext, .. } => assert_eq!(plaintext, b"hi back"),
            Arrival::Duplicate => panic!("reply is fresh"),
        }
    }

    #[test]
    fn duplicate_arrival_absorbs_via_the_ledger() {
        let mut a = node();
        let mut b = node();
        let prekeys = bundle_of(&mut b, &a);
        let m = a
            .keyring
            .seal(&b.anchor, &b.face, &prekeys, b"once")
            .expect("seal");
        assert!(matches!(
            b.keyring.unseal(&m).expect("unseal"),
            Arrival::Decrypted { .. }
        ));
        assert!(matches!(
            b.keyring.unseal(&m).expect("unseal"),
            Arrival::Duplicate
        ));
        assert!(matches!(
            b.keyring.unseal(&m).expect("unseal"),
            Arrival::Duplicate
        ));
    }

    #[test]
    fn three_term_degraded_establishment_roundtrips() {
        let mut a = node();
        let mut b = node();
        // The pool is dry for the sender: the bundle's OPK slot is
        // absent (the or could not hand one out) — the degraded
        // 3-term establishment. serve_bundle's auto-replenish is
        // bypassed by handing the caller an opk-less prekey set.
        let bundle = b.keyring.serve_bundle(&a.anchor);
        let spk = bundle.spk.expect("spk");
        let prekeys = ReceiverPrekeys::builder()
            .spk(
                SpkPub::builder()
                    .key(spk.key.as_slice().try_into().expect("32B"))
                    .ver(spk.ver)
                    .build(),
            )
            .opk(None)
            .build();
        let m = a
            .keyring
            .seal(&b.anchor, &b.face, &prekeys, b"degraded")
            .expect("seal");
        match b.keyring.unseal(&m).expect("unseal") {
            Arrival::Decrypted { plaintext, .. } => assert_eq!(plaintext, b"degraded"),
            Arrival::Duplicate => panic!("fresh"),
        }
    }

    #[test]
    fn stale_epoch_establishment_is_rejected() {
        let mut a = node();
        let mut b = node();
        let prekeys = bundle_of(&mut b, &a);
        let m = a
            .keyring
            .seal(&b.anchor, &b.face, &prekeys, b"aged")
            .expect("seal");
        // The receiver flips its standing key BEFORE processing: the
        // mail's epoch is stale and its private half is gone.
        b.keyring.flip_spk().expect("flip");
        match b.keyring.unseal(&m) {
            Err(MailError::StalePrekey {
                epoch: 1,
                current: 2,
            }) => {}
            other => panic!("expected StalePrekey, got {other:?}"),
        }
    }

    #[test]
    fn re_establishment_keeps_the_old_session_until_retired() {
        let mut a = node();
        let mut b = node();
        let prekeys = bundle_of(&mut b, &a);
        // Session 1: the establishment mail, then a continued
        // mid-chain mail.
        let m1 = a
            .keyring
            .seal(&b.anchor, &b.face, &prekeys, b"old-1")
            .expect("seal");
        assert!(m1.establishment.is_some());
        let _ = b.keyring.unseal(&m1).expect("unseal");
        let m2 = a
            .keyring
            .seal(&b.anchor, &b.face, &prekeys, b"old-2")
            .expect("seal");
        assert!(m2.establishment.is_none(), "continued mail carries no kit");
        assert_eq!(m2.key_version, 1);
        // a re-establishes (it learned the old establishment went
        // stale) over b's flipped prekeys; m2 is still in flight in
        // the or-cache.
        b.keyring.flip_spk().expect("flip");
        let fresh_prekeys = bundle_of(&mut b, &a);
        let m3 = a
            .keyring
            .seal_fresh(&b.anchor, &b.face, &fresh_prekeys, b"fresh")
            .expect("seal");
        assert_eq!(m3.key_version, 2);
        // The new session's mail lands first.
        match b.keyring.unseal(&m3).expect("unseal") {
            Arrival::Decrypted { plaintext, .. } => assert_eq!(plaintext, b"fresh"),
            Arrival::Duplicate => panic!("fresh"),
        }
        // The old session's mid-chain mail still decrypts (the
        // previous session stayed alive).
        match b.keyring.unseal(&m2).expect("old session survives") {
            Arrival::Decrypted { plaintext, .. } => assert_eq!(plaintext, b"old-2"),
            Arrival::Duplicate => panic!("fresh old mail"),
        }
        // Drain: the previous sessions retire.
        b.keyring.retire_previous_sessions(&a.anchor);
    }

    #[test]
    fn pool_lifecycle_burn_and_replenish() {
        let mut b = node();
        b.keyring.replenish();
        assert_eq!(b.keyring.opks.len() as u64, POOL);
        let pool_before: Vec<u32> = b.keyring.opks.keys().copied().collect();
        let mut a = node();
        let prekeys = bundle_of(&mut b, &a);
        let opk_id = prekeys.opk().as_ref().expect("4-term").id;
        assert!(pool_before.contains(&opk_id));
        let m = a
            .keyring
            .seal(&b.anchor, &b.face, &prekeys, b"burn")
            .expect("seal");
        let _ = b.keyring.unseal(&m).expect("unseal");
        // The consumed slot burned at first processing.
        assert!(!b.keyring.opks.contains_key(&opk_id));
        assert_eq!(b.keyring.opks.len() as u64, POOL - 1);
        // Dips below the threshold -> the next serve refills.
        while b.keyring.opks.len() as u64 >= THRESHOLD {
            b.keyring.opks.pop_last();
        }
        b.keyring.replenish();
        assert_eq!(b.keyring.opks.len() as u64, POOL);
    }

    #[test]
    fn forged_sender_is_rejected_by_the_gate() {
        let mut a = node();
        let mut b = node();
        let mallory = node();
        let prekeys = bundle_of(&mut b, &a);
        let mut m = a
            .keyring
            .seal(&b.anchor, &b.face, &prekeys, b"real")
            .expect("seal");
        // Mallory swaps the sender face for its own: the anchor
        // check kills it before any key work.
        let establishment = mail::Establishment {
            mailbox: Some(mallory.face.clone()),
            ..m.establishment.clone().expect("establishment")
        };
        m.establishment = Some(establishment);
        match b.keyring.unseal(&m) {
            Err(MailError::UnknownSender) => {}
            other => panic!("expected UnknownSender, got {other:?}"),
        }
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut a = node();
        let mut b = node();
        let prekeys = bundle_of(&mut b, &a);
        let mut m = a
            .keyring
            .seal(&b.anchor, &b.face, &prekeys, b"intact")
            .expect("seal");
        let last = m.ciphertext.pop();
        m.ciphertext.push(last.expect("non-empty") ^ 0x01);
        match b.keyring.unseal(&m) {
            Err(MailError::SigInvalid) => {}
            other => panic!("expected SigInvalid (outer gate), got {other:?}"),
        }
    }
}
