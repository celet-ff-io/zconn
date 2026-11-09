//! The core session state machine: one compose cursor, one draft,
//! one thread-file store. The record carries pointers; this staging
//! layer holds the plaintext (kind, data) pairs and binds them to
//! addresses via H(canonical Value{kind, data}).

use std::collections::HashMap;

use crate::store::{CommitValues, Store, ThreadId};
use prost::Message as _;
use zconned_crypto::{DIGEST_ALGO, DIGEST_LEN};
use zconned_material::{CLAIM_KIND_TS, Claim, Msg, MsgRef, ResourceRef, Value, resource_digest};
use zconned_stdio_types::{
    Entry, Error as WireError, Fresh, IncomingFrame, MsgAdded, MsgCursorPush, MsgCursorSet,
    MsgDraftClaimsAdd, MsgDraftClaimsRemove, MsgDraftContentSet, MsgDraftPush, MsgThreadsLogGet,
    MsgThreadsLogPush, MsgThreadsPush, OutgoingFrame, ResolvedClaim, ResolvedSlot, ResourceGet,
    ResourcePush, RowMeta, ThreadEntry, incoming_frame::Method, outgoing_frame::Frame,
};

/// Compose cursor: locked refs (branch/merge base) or a fresh
/// core-generated genesis parent.
#[derive(Debug, Clone)]
enum Cursor {
    At(Vec<MsgRef>),
    Fresh(MsgRef),
}

impl Cursor {
    fn refs(&self) -> Vec<MsgRef> {
        match self {
            Cursor::At(refs) => refs.clone(),
            Cursor::Fresh(r) => vec![r.clone()],
        }
    }
}

/// The draft: the plaintext staging layer. content = the (kind,data)
/// pair to commit; claims = the ordered (kind,data) set — registry
/// kinds carry empty data until the commit stamps them.
#[derive(Debug, Default, Clone)]
struct Draft {
    content: Option<Value>,
    claims: Vec<Value>,
}

impl Draft {
    /// The wire snapshot: the staged plaintext pairs themselves (no
    /// digests — the draft domain has no identity pre-commit).
    fn snapshot(&self) -> MsgDraftPush {
        MsgDraftPush {
            content: self.content.clone(),
            claims: self.claims.clone(),
        }
    }
}

pub(crate) struct Session {
    store: Store,
    /// message digest -> thread (built at open, extended per commit).
    index: HashMap<Vec<u8>, ThreadId>,
    cursor: Option<Cursor>,
    draft: Draft,
}

impl Session {
    pub(crate) fn open(store: Store) -> crate::error::Result<Session> {
        let index = store.digest_index()?;
        Ok(Session {
            store,
            index,
            cursor: None,
            draft: Draft::default(),
        })
    }

    /// Handle one incoming frame; a commit answers with two frames
    /// (msg_added + the resting draft). An all-default frame gets an
    /// error and the session lives.
    pub(crate) fn handle(&mut self, incoming: IncomingFrame) -> Vec<OutgoingFrame> {
        match incoming.method {
            Some(op) => self.dispatch(op),
            None => vec![self.error("internal", "no op in frame")],
        }
    }

    fn dispatch(&mut self, method: Method) -> Vec<OutgoingFrame> {
        match method {
            Method::MsgCursorSet(MsgCursorSet { at, fresh }) => self.cursor_set(at, fresh),
            Method::MsgDraftContentSet(MsgDraftContentSet { kind, data }) => {
                if kind.is_empty() {
                    return vec![self.error("kind_required", "content kind must not be empty")];
                }
                self.draft.content = Some(Value { kind, data });
                vec![self.draft_reply()]
            }
            Method::MsgDraftContentReset(_) => {
                self.draft.content = None;
                vec![self.draft_reply()]
            }
            Method::MsgDraftClaimsAdd(MsgDraftClaimsAdd { kind, data }) => {
                if kind.is_empty() {
                    return vec![self.error("kind_required", "claim kind must not be empty")];
                }
                // Ensure-present: a duplicate kind is a no-op.
                if !self.draft.claims.iter().any(|v| v.kind == kind) {
                    self.draft.claims.push(Value { kind, data });
                }
                vec![self.draft_reply()]
            }
            Method::MsgDraftClaimsRemove(MsgDraftClaimsRemove { kind }) => {
                self.draft.claims.retain(|v| v.kind != kind);
                vec![self.draft_reply()]
            }
            Method::MsgDraftClaimsClear(_) => {
                self.draft.claims.clear();
                vec![self.draft_reply()]
            }
            Method::MsgDraftGet(_) => vec![self.draft_reply()],
            Method::MsgDraftCommit(_) => self.commit(),
            Method::MsgThreadsGet(_) => {
                let threads = match self.store.threads() {
                    Ok(threads) => threads,
                    Err(e) => return vec![self.internal(&e)],
                };
                vec![reply(Frame::MsgThreadsPush(MsgThreadsPush {
                    threads: threads
                        .iter()
                        .map(|t| ThreadEntry {
                            thread: t.to_ref().ok(),
                        })
                        .collect(),
                }))]
            }
            Method::MsgThreadsLogGet(MsgThreadsLogGet { thread }) => self.thread_log(thread),
            Method::ResourceGet(ResourceGet { r#ref }) => self.resource_get(r#ref),
        }
    }

    fn cursor_set(&mut self, at: Vec<MsgRef>, fresh: Option<Fresh>) -> Vec<OutgoingFrame> {
        let has_at = !at.is_empty();
        match (has_at, fresh.is_some()) {
            (true, true) => {
                vec![self.error("malformed_frame", "cursor method carries both at and fresh")]
            }
            (false, false) => {
                vec![self.error(
                    "malformed_frame",
                    "cursor method carries neither at nor fresh",
                )]
            }
            (true, false) => {
                // Absent refs are tolerated (lazy-backfill semantics);
                // the lock is intent, not a lookup.
                let refs = at;
                self.cursor = Some(Cursor::At(refs.clone()));
                vec![reply(Frame::MsgCursorPush(MsgCursorPush { refs }))]
            }
            (false, true) => {
                // Core-side entropy: the interface never invents the
                // genesis parent.
                let mut digest = [0u8; DIGEST_LEN];
                if let Err(e) = getrandom::fill(&mut digest) {
                    return vec![self.internal(&e)];
                }
                let r = MsgRef {
                    ver_major: 1,
                    ver_minor: 0,
                    algo: DIGEST_ALGO.to_owned(),
                    digest: digest.to_vec(),
                };
                self.cursor = Some(Cursor::Fresh(r.clone()));
                vec![reply(Frame::MsgCursorPush(MsgCursorPush { refs: vec![r] }))]
            }
        }
    }

    fn commit(&mut self) -> Vec<OutgoingFrame> {
        let Some(cursor) = self.cursor.clone() else {
            return vec![self.error(
                "cursor_required",
                "no compose cursor: call msg_cursor_set before committing",
            )];
        };
        let Some(content) = self.draft.content.clone() else {
            return vec![self.error(
                "content_required",
                "the draft has no content; set content before commit",
            )];
        };
        if content.kind.is_empty() {
            return vec![self.error("kind_required", "content kind must not be empty")];
        }

        let now = now_rfc3339();
        // Stamp registry kinds at commit; interface-supplied values
        // are overwritten.
        let claims: Vec<Value> = self
            .draft
            .claims
            .iter()
            .map(|v| {
                if v.kind == CLAIM_KIND_TS {
                    Value {
                        kind: v.kind.clone(),
                        data: now.clone().into_bytes(),
                    }
                } else {
                    v.clone()
                }
            })
            .collect();
        let values = CommitValues {
            content: content.clone(),
            claims: claims.clone(),
        };

        // Assemble the anchor Msg: structure + addresses only.
        let msg = Msg {
            ver_major: 1,
            ver_minor: 0,
            prev: cursor.refs(),
            content: Some(ResourceRef {
                algo: DIGEST_ALGO.to_owned(),
                digest: resource_digest(&content.kind, &content.data).to_vec(),
            }),
            claims: claims
                .iter()
                .map(|b| Claim {
                    kind: b.kind.clone(),
                    r#ref: Some(ResourceRef {
                        algo: DIGEST_ALGO.to_owned(),
                        digest: resource_digest(&b.kind, &b.data).to_vec(),
                    }),
                })
                .collect(),
        };
        let bytes = msg.encode_to_vec();
        let thread = self.resolve_thread(&msg.prev);
        let (row, _) = match self
            .store
            .commit(&bytes, &msg, &values, &thread, now.clone())
        {
            Ok(pair) => pair,
            Err(e) => return vec![self.internal(&e)],
        };
        self.index.insert(
            crate::store::hex_to_bytes(&row.meta.digest).unwrap_or_default(),
            thread,
        );

        let Ok(ts) = rfc3339_to_pbjson(&now) else {
            return vec![self.internal(&"clock produced an unparsable timestamp")];
        };
        // The fused wire form: the anchor's refs + the committed
        // values, one fact per field.
        let entry = Entry {
            ver_major: msg.ver_major,
            ver_minor: msg.ver_minor,
            prev: msg.prev.clone(),
            meta: Some(RowMeta {
                ts: Some(ts),
                algo: row.meta.algo.clone(),
                digest: crate::store::hex_to_bytes(&row.meta.digest).unwrap_or_default(),
            }),
            content: Some(ResolvedSlot {
                r#ref: msg.content.clone(),
                value: Some(content),
            }),
            claims: msg
                .claims
                .iter()
                .zip(claims.iter())
                .map(|(anchor, v)| ResolvedClaim {
                    kind: anchor.kind.clone(),
                    r#ref: anchor.r#ref.clone(),
                    value: Some(v.clone()),
                })
                .collect(),
        };

        // The resting state: the draft is consumed by the commit.
        self.draft = Draft::default();
        vec![
            reply(Frame::MsgAdded(MsgAdded { entry: Some(entry) })),
            reply(Frame::MsgDraftPush(MsgDraftPush {
                content: None,
                claims: Vec::new(),
            })),
        ]
    }

    /// The commit's thread = prev[0]'s thread; an unknown prev[0]
    /// becomes its own thread id.
    fn resolve_thread(&self, prev: &[MsgRef]) -> ThreadId {
        match prev.first() {
            // The canonical binary digest IS the index key.
            Some(r) => self
                .index
                .get(&r.digest)
                .cloned()
                .unwrap_or_else(|| ThreadId::from_ref(r)),
            None => ThreadId {
                algo: DIGEST_ALGO.to_owned(),
                digest: Vec::new(),
            },
        }
    }

    fn thread_log(&self, thread: Option<MsgRef>) -> Vec<OutgoingFrame> {
        let Some(thread) = thread else {
            return vec![self.error("malformed_frame", "log method carries no thread ref")];
        };
        let id = ThreadId::from_ref(&thread);
        let rows = match self.store.thread_rows(&id) {
            Ok(rows) => rows,
            Err(e) => return vec![self.internal(&e)],
        };
        let resources = match self.store.resources(&id) {
            Ok(resources) => resources,
            Err(e) => return vec![self.internal(&e)],
        };
        let entries = rows
            .iter()
            .map(|row| reconstruct(row, &resources))
            .collect();
        vec![reply(Frame::MsgThreadsLogPush(MsgThreadsLogPush {
            entries,
        }))]
    }

    fn resource_get(&self, r: Option<zconned_material::ResourceRef>) -> Vec<OutgoingFrame> {
        let Some(r) = r else {
            return vec![self.error("malformed_frame", "resource method carries no ref")];
        };
        let row = match self.store.find_resource(&r.digest) {
            Ok(row) => row,
            Err(e) => return vec![self.internal(&e)],
        };
        let value = row.map(|row| Value {
            kind: row.kind,
            data: crate::store::base64_decode(&row.data).unwrap_or_default(),
        });
        vec![reply(Frame::ResourcePush(ResourcePush {
            r#ref: Some(r),
            value,
        }))]
    }

    fn draft_reply(&self) -> OutgoingFrame {
        reply(Frame::MsgDraftPush(self.draft.snapshot()))
    }

    fn error(&self, code: &str, message: &str) -> OutgoingFrame {
        reply(Frame::Error(WireError {
            code: code.to_owned(),
            message: message.to_owned(),
        }))
    }

    fn internal(&self, e: &(impl std::fmt::Display + ?Sized)) -> OutgoingFrame {
        log::error!("core internal failure: {e}");
        self.error("internal", &format!("{e}"))
    }
}

/// Reconstruct a wire entry from an anchor row + the thread's
/// resource rows: the anchor keeps every ref, each value rides its
/// own slot; a missing resource = the value field ABSENT (stated,
/// never implied).
fn reconstruct(row: &zconned_codec::Row, resources: &[zconned_codec::ResourceRow]) -> Entry {
    let lookup = |digest_hex: &str| -> Option<Value> {
        resources
            .iter()
            .find(|r| r.digest == digest_hex)
            .map(|r| Value {
                kind: r.kind.clone(),
                // The row's data = the base64 projection; resolve to
                // the raw bytes.
                data: crate::store::base64_decode(&r.data).unwrap_or_default(),
            })
    };
    let meta = RowMeta {
        ts: time::OffsetDateTime::parse(
            &row.meta.ts,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()
        .map(|dt| pbjson_types::Timestamp {
            seconds: dt.unix_timestamp(),
            nanos: dt.nanosecond() as i32,
        }),
        algo: row.meta.algo.clone(),
        digest: crate::store::hex_to_bytes(&row.meta.digest).unwrap_or_default(),
    };
    Entry {
        ver_major: row.msg.ver_major,
        ver_minor: row.msg.ver_minor,
        prev: row
            .msg
            .prev
            .iter()
            .map(|r| MsgRef {
                ver_major: r.ver_major,
                ver_minor: r.ver_minor,
                algo: r.algo.clone(),
                digest: crate::store::hex_to_bytes(&r.digest).unwrap_or_default(),
            })
            .collect(),
        meta: Some(meta),
        content: Some(ResolvedSlot {
            r#ref: Some(ResourceRef {
                algo: row.msg.content.algo.clone(),
                digest: crate::store::hex_to_bytes(&row.msg.content.digest).unwrap_or_default(),
            }),
            value: lookup(&row.msg.content.digest),
        }),
        claims: row
            .msg
            .claims
            .iter()
            .map(|c| ResolvedClaim {
                kind: c.kind.clone(),
                r#ref: Some(ResourceRef {
                    algo: c.ref_.algo.clone(),
                    digest: crate::store::hex_to_bytes(&c.ref_.digest).unwrap_or_default(),
                }),
                value: lookup(&c.ref_.digest),
            })
            .collect(),
    }
}

fn reply(frame: Frame) -> OutgoingFrame {
    OutgoingFrame { frame: Some(frame) }
}

fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 formatting cannot fail for a valid OffsetDateTime")
}

fn rfc3339_to_pbjson(s: &str) -> Result<pbjson_types::Timestamp, time::error::Parse> {
    use time::format_description::well_known::Rfc3339;
    let dt = time::OffsetDateTime::parse(s, &Rfc3339)?;
    Ok(pbjson_types::Timestamp {
        seconds: dt.unix_timestamp(),
        nanos: dt.nanosecond() as i32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zconned_stdio_types::{
        Fresh, MsgCursorSet, MsgDraftClaimsAdd, MsgDraftClaimsClear, MsgDraftClaimsRemove,
        MsgDraftCommit, MsgDraftContentSet, MsgDraftGet, MsgThreadsGet, MsgThreadsLogGet,
        ResourceGet,
    };

    fn temp_session() -> (Session, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let session = Session::open(store).unwrap();
        (session, dir)
    }

    fn first(frames: &[OutgoingFrame]) -> &Frame {
        frames[0].frame.as_ref().unwrap()
    }

    fn expect_error(frames: &[OutgoingFrame], code: &str) {
        match first(frames) {
            Frame::Error(e) => assert_eq!(e.code, code, "message: {}", e.message),
            other => panic!("expected error reply, got {other:?}"),
        }
    }

    fn fresh_cursor_set() -> IncomingFrame {
        IncomingFrame {
            method: Some(Method::MsgCursorSet(MsgCursorSet {
                at: vec![],
                fresh: Some(Fresh {}),
            })),
        }
    }

    fn at_cursor_set(refs: Vec<MsgRef>) -> IncomingFrame {
        IncomingFrame {
            method: Some(Method::MsgCursorSet(MsgCursorSet {
                at: refs,
                fresh: None,
            })),
        }
    }

    fn content_set(kind: &str, data: &str) -> IncomingFrame {
        IncomingFrame {
            method: Some(Method::MsgDraftContentSet(MsgDraftContentSet {
                kind: kind.to_owned(),
                data: data.as_bytes().to_vec(),
            })),
        }
    }

    fn claims_add(kind: &str, data: Option<&str>) -> IncomingFrame {
        IncomingFrame {
            method: Some(Method::MsgDraftClaimsAdd(MsgDraftClaimsAdd {
                kind: kind.to_owned(),
                data: data.map(|d| d.as_bytes().to_vec()).unwrap_or_default(),
            })),
        }
    }

    fn commit() -> IncomingFrame {
        IncomingFrame {
            method: Some(Method::MsgDraftCommit(MsgDraftCommit {})),
        }
    }

    #[test]
    fn full_compose_flow_fresh_to_commit() {
        let (mut s, _dir) = temp_session();

        // fresh -> msg_cursor_push{refs: [random]}
        let frames = s.handle(fresh_cursor_set());
        assert_eq!(frames.len(), 1);
        let genesis = match first(&frames) {
            Frame::MsgCursorPush(p) => p.refs[0].clone(),
            other => panic!("expected msg_cursor_push, got {other:?}"),
        };
        assert_eq!(genesis.algo, DIGEST_ALGO);
        assert_eq!(genesis.digest.len(), DIGEST_LEN);

        // stage content + claims; the snapshot = the plaintext pairs
        let frames = s.handle(content_set("text/plain", "hi"));
        match first(&frames) {
            Frame::MsgDraftPush(d) => {
                assert_eq!(d.content.as_ref().unwrap().kind, "text/plain");
                assert_eq!(d.content.as_ref().unwrap().data, b"hi");
                assert!(d.claims.is_empty());
            }
            other => panic!("expected msg_draft_push, got {other:?}"),
        }
        let frames = s.handle(claims_add("vnd.example.author", Some("KEY-1")));
        match first(&frames) {
            Frame::MsgDraftPush(d) => {
                assert_eq!(d.claims.len(), 1);
                assert_eq!(d.claims[0].kind, "vnd.example.author");
                assert_eq!(d.claims[0].data, b"KEY-1");
            }
            other => panic!("expected msg_draft_push, got {other:?}"),
        }
        // The registry kind stages PENDING: honest empty data, no digest.
        let frames = s.handle(claims_add(CLAIM_KIND_TS, None));
        match first(&frames) {
            Frame::MsgDraftPush(d) => {
                assert_eq!(d.claims.len(), 2);
                let ts = d.claims.iter().find(|c| c.kind == CLAIM_KIND_TS).unwrap();
                assert!(ts.data.is_empty(), "registry value unstaged");
            }
            other => panic!("expected msg_draft_push, got {other:?}"),
        }

        // commit -> msg_added(fused entry) + resting draft
        let frames = s.handle(commit());
        assert_eq!(frames.len(), 2);
        let (added, resting) = match (first(&frames), frames[1].frame.as_ref().unwrap()) {
            (Frame::MsgAdded(a), Frame::MsgDraftPush(d)) => (a, d),
            other => panic!("expected msg_added + msg_draft_push, got {other:?}"),
        };
        let entry = added.entry.as_ref().unwrap();
        assert_eq!(entry.prev, vec![genesis.clone()]);
        // The content slot: the anchor's digest + the value, fused.
        let content = entry.content.as_ref().unwrap();
        assert_eq!(
            content.r#ref.as_ref().unwrap().digest,
            resource_digest("text/plain", b"hi").to_vec()
        );
        assert_eq!(content.value.as_ref().unwrap().kind, "text/plain");
        assert_eq!(content.value.as_ref().unwrap().data, b"hi");
        // The claims list = the record's roster (author + ts).
        assert_eq!(entry.claims.len(), 2);
        let ts = entry
            .claims
            .iter()
            .find(|c| c.kind == CLAIM_KIND_TS)
            .expect("ts claim stamped");
        assert!(
            !ts.r#ref.as_ref().unwrap().digest.is_empty(),
            "registry digest computed at commit"
        );
        // Self-consistency: the slot's digest = H(the slot's value).
        assert_eq!(
            ts.r#ref.as_ref().unwrap().digest,
            resource_digest(CLAIM_KIND_TS, &ts.value.as_ref().unwrap().data).to_vec()
        );
        let meta = entry.meta.as_ref().unwrap();
        assert_eq!(meta.algo, DIGEST_ALGO);
        assert!(meta.ts.is_some());
        assert!(resting.content.is_none(), "resting draft: content cleared");
        assert!(resting.claims.is_empty(), "resting draft: claims cleared");

        // the store holds the thread named by the genesis parent
        let thread = ThreadId::from_ref(&genesis);
        let rows = s.store.thread_rows(&thread).unwrap();
        assert_eq!(rows.len(), 1);
        let resources = s.store.resources(&thread).unwrap();
        // The row's data = the base64 projection of the bytes.
        assert!(
            resources
                .iter()
                .any(|r| crate::store::base64_decode(&r.data).unwrap() == b"hi")
        );
    }

    #[test]
    fn commit_without_cursor_is_loud() {
        let (mut s, _dir) = temp_session();
        expect_error(&s.handle(commit()), "cursor_required");
    }

    #[test]
    fn commit_without_content_is_loud() {
        let (mut s, _dir) = temp_session();
        s.handle(fresh_cursor_set());
        expect_error(&s.handle(commit()), "content_required");
    }

    #[test]
    fn empty_kinds_are_loud() {
        let (mut s, _dir) = temp_session();
        expect_error(&s.handle(content_set("", "x")), "kind_required");
        expect_error(&s.handle(claims_add("", None)), "kind_required");
    }

    #[test]
    fn duplicate_claim_add_is_a_noop() {
        let (mut s, _dir) = temp_session();
        s.handle(claims_add("vnd.example.a", Some("1")));
        s.handle(claims_add("vnd.example.a", Some("2")));
        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgDraftGet(MsgDraftGet {})),
        });
        match first(&frames) {
            Frame::MsgDraftPush(d) => {
                assert_eq!(d.claims.len(), 1);
                assert_eq!(d.claims[0].data, b"1", "first add wins (ensure-present)");
            }
            other => panic!("expected msg_draft_push, got {other:?}"),
        }
    }

    #[test]
    fn claims_remove_and_clear_are_set_semantics() {
        let (mut s, _dir) = temp_session();
        s.handle(claims_add("vnd.example.a", None));
        s.handle(claims_add("vnd.example.b", None));
        s.handle(IncomingFrame {
            method: Some(Method::MsgDraftClaimsRemove(MsgDraftClaimsRemove {
                kind: "vnd.example.absent".to_owned(),
            })),
        });
        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgDraftClaimsRemove(MsgDraftClaimsRemove {
                kind: "vnd.example.a".to_owned(),
            })),
        });
        match first(&frames) {
            Frame::MsgDraftPush(d) => assert_eq!(d.claims.len(), 1),
            other => panic!("expected msg_draft_push, got {other:?}"),
        }
        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgDraftClaimsClear(MsgDraftClaimsClear {})),
        });
        match first(&frames) {
            Frame::MsgDraftPush(d) => assert!(d.claims.is_empty()),
            other => panic!("expected msg_draft_push, got {other:?}"),
        }
    }

    #[test]
    fn ts_claim_stamping_overwrites_interface_values() {
        let (mut s, _dir) = temp_session();
        s.handle(fresh_cursor_set());
        s.handle(content_set("text/plain", "x"));
        s.handle(claims_add(CLAIM_KIND_TS, Some("FAKE")));
        let frames = s.handle(commit());
        match first(&frames) {
            Frame::MsgAdded(a) => {
                let entry = a.entry.as_ref().unwrap();
                let ts = entry
                    .claims
                    .iter()
                    .find(|c| c.kind == CLAIM_KIND_TS)
                    .unwrap();
                assert_ne!(
                    ts.r#ref.as_ref().unwrap().digest,
                    resource_digest(CLAIM_KIND_TS, b"FAKE").to_vec(),
                    "interface-supplied value overwritten"
                );
                // The stamped value = a real RFC3339 timestamp.
                assert!(
                    time::OffsetDateTime::parse(
                        std::str::from_utf8(&ts.value.as_ref().unwrap().data).unwrap(),
                        &time::format_description::well_known::Rfc3339
                    )
                    .is_ok()
                );
            }
            other => panic!("expected msg_added, got {other:?}"),
        }
    }

    #[test]
    fn at_cursor_locks_the_refs_and_commit_uses_them() {
        let (mut s, _dir) = temp_session();
        let parent = MsgRef {
            ver_major: 1,
            ver_minor: 0,
            algo: DIGEST_ALGO.to_owned(),
            digest: vec![7u8; DIGEST_LEN],
        };
        let frames = s.handle(at_cursor_set(vec![parent.clone()]));
        match first(&frames) {
            Frame::MsgCursorPush(p) => assert_eq!(p.refs, vec![parent.clone()]),
            other => panic!("expected msg_cursor_push, got {other:?}"),
        }
        s.handle(content_set("text/plain", "x"));
        let frames = s.handle(commit());
        match first(&frames) {
            Frame::MsgAdded(a) => {
                assert_eq!(a.entry.as_ref().unwrap().prev, vec![parent.clone()]);
            }
            other => panic!("expected msg_added, got {other:?}"),
        }
        // The thread = the absent parent ref itself (lazy backfill).
        let rows = s.store.thread_rows(&ThreadId::from_ref(&parent)).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn cursor_op_with_both_or_neither_is_malformed() {
        let (mut s, _dir) = temp_session();
        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgCursorSet(MsgCursorSet {
                at: vec![MsgRef {
                    ver_major: 1,
                    ver_minor: 0,
                    algo: DIGEST_ALGO.to_owned(),
                    digest: vec![1; DIGEST_LEN],
                }],
                fresh: Some(Fresh {}),
            })),
        });
        expect_error(&frames, "malformed_frame");
        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgCursorSet(MsgCursorSet {
                at: vec![],
                fresh: None,
            })),
        });
        expect_error(&frames, "malformed_frame");
    }

    #[test]
    fn frame_without_op_acks_without_dying() {
        let (mut s, _dir) = temp_session();
        expect_error(&s.handle(IncomingFrame { method: None }), "internal");
        // The session lives: a normal op still works.
        let frames = s.handle(fresh_cursor_set());
        assert!(matches!(first(&frames), Frame::MsgCursorPush(_)));
    }

    #[test]
    fn threads_get_and_log_get_roundtrip() {
        let (mut s, _dir) = temp_session();
        s.handle(fresh_cursor_set());
        s.handle(content_set("text/plain", "hello"));
        s.handle(claims_add("vnd.example.author", Some("KEY-1")));
        s.handle(commit());

        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgThreadsGet(MsgThreadsGet {})),
        });
        let thread_ref = match first(&frames) {
            Frame::MsgThreadsPush(t) => t.threads[0].thread.clone().unwrap(),
            other => panic!("expected msg_threads_push, got {other:?}"),
        };

        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgThreadsLogGet(MsgThreadsLogGet {
                thread: Some(thread_ref),
            })),
        });
        match first(&frames) {
            Frame::MsgThreadsLogPush(l) => {
                assert_eq!(l.entries.len(), 1);
                let entry = &l.entries[0];
                // The roster mirrors the record (one author claim).
                assert_eq!(entry.claims.len(), 1);
                // Values fused in position: no matching, no sidecar.
                let content = entry.content.as_ref().unwrap();
                assert_eq!(content.value.as_ref().unwrap().kind, "text/plain");
                assert_eq!(content.value.as_ref().unwrap().data, b"hello");
                let author = entry
                    .claims
                    .iter()
                    .find(|c| c.kind == "vnd.example.author")
                    .unwrap();
                assert_eq!(author.value.as_ref().unwrap().data, b"KEY-1");
                // Every slot's digest = H(its own value).
                assert_eq!(
                    content.r#ref.as_ref().unwrap().digest,
                    resource_digest("text/plain", b"hello").to_vec()
                );
            }
            other => panic!("expected msg_threads_log_push, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_resource_is_stated_by_the_absent_value_key() {
        let (mut s, dir) = temp_session();
        let genesis = match first(&s.handle(fresh_cursor_set())) {
            Frame::MsgCursorPush(p) => p.refs[0].clone(),
            other => panic!("expected msg_cursor_push, got {other:?}"),
        };
        s.handle(content_set("text/plain", "gone"));
        s.handle(claims_add(CLAIM_KIND_TS, None));
        s.handle(commit());

        // Evict the content value behind the store's back (the
        // structure-survives-eviction property's wire face).
        let thread_dir = std::fs::read_dir(dir.path().join("threads"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let resources_path = thread_dir.join("resources.jsonl");
        let all = std::fs::read_to_string(&resources_path).unwrap();
        let kept: Vec<&str> = all.lines().filter(|l| !l.contains("text/plain")).collect();
        std::fs::write(&resources_path, kept.join("\n") + "\n").unwrap();

        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgThreadsLogGet(MsgThreadsLogGet {
                thread: Some(genesis),
            })),
        });
        match first(&frames) {
            Frame::MsgThreadsLogPush(l) => {
                let entry = &l.entries[0];
                let content = entry.content.as_ref().unwrap();
                assert_eq!(
                    content.r#ref.as_ref().unwrap().digest,
                    resource_digest("text/plain", b"gone").to_vec(),
                    "the digest survives the eviction"
                );
                assert!(
                    content.value.is_none(),
                    "the absent value IS the stated miss"
                );
                // The roster never shrinks; the ts claim keeps its value.
                assert_eq!(entry.claims.len(), 1);
                assert!(entry.claims[0].value.is_some());
            }
            other => panic!("expected msg_threads_log_push, got {other:?}"),
        }
    }

    #[test]
    fn resource_get_resolves_held_values_and_misses_echo_the_ref() {
        let (mut s, _dir) = temp_session();
        s.handle(fresh_cursor_set());
        s.handle(content_set("text/plain", "needle"));
        s.handle(commit());
        let digest = resource_digest("text/plain", b"needle").to_vec();

        let hit = s.handle(IncomingFrame {
            method: Some(Method::ResourceGet(ResourceGet {
                r#ref: Some(ResourceRef {
                    algo: DIGEST_ALGO.to_owned(),
                    digest: digest.clone(),
                }),
            })),
        });
        match first(&hit) {
            Frame::ResourcePush(p) => {
                assert_eq!(p.r#ref.as_ref().unwrap().digest, digest, "ref echo");
                assert_eq!(p.value.as_ref().unwrap().kind, "text/plain");
                assert_eq!(p.value.as_ref().unwrap().data, b"needle");
            }
            other => panic!("expected resource_push, got {other:?}"),
        }

        let miss = s.handle(IncomingFrame {
            method: Some(Method::ResourceGet(ResourceGet {
                r#ref: Some(ResourceRef {
                    algo: DIGEST_ALGO.to_owned(),
                    digest: vec![7u8; DIGEST_LEN],
                }),
            })),
        });
        match first(&miss) {
            Frame::ResourcePush(p) => {
                assert_eq!(
                    p.r#ref.as_ref().unwrap().digest,
                    vec![7u8; DIGEST_LEN],
                    "the miss echoes the ref"
                );
                assert!(p.value.is_none(), "the absent value = the stated miss");
            }
            other => panic!("expected resource_push, got {other:?}"),
        }

        expect_error(
            &s.handle(IncomingFrame {
                method: Some(Method::ResourceGet(ResourceGet { r#ref: None })),
            }),
            "malformed_frame",
        );
    }

    #[test]
    fn log_get_of_an_unknown_thread_is_an_empty_answer() {
        let (mut s, _dir) = temp_session();
        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgThreadsLogGet(MsgThreadsLogGet {
                thread: Some(MsgRef {
                    ver_major: 1,
                    ver_minor: 0,
                    algo: DIGEST_ALGO.to_owned(),
                    digest: vec![9u8; DIGEST_LEN],
                }),
            })),
        });
        match first(&frames) {
            Frame::MsgThreadsLogPush(l) => assert!(l.entries.is_empty()),
            other => panic!("expected msg_threads_log_push, got {other:?}"),
        }
    }

    #[test]
    fn second_commit_chains_onto_the_first() {
        let (mut s, _dir) = temp_session();
        s.handle(fresh_cursor_set());
        s.handle(content_set("text/plain", "first"));
        let frames = s.handle(commit());
        let first_digest = match first(&frames) {
            Frame::MsgAdded(a) => a
                .entry
                .as_ref()
                .unwrap()
                .meta
                .as_ref()
                .unwrap()
                .digest
                .clone(),
            other => panic!("expected msg_added, got {other:?}"),
        };

        // Branch off the first message.
        let first_ref = MsgRef {
            ver_major: 1,
            ver_minor: 0,
            algo: DIGEST_ALGO.to_owned(),
            digest: first_digest.clone(),
        };
        s.handle(at_cursor_set(vec![first_ref]));
        s.handle(content_set("text/plain", "second"));
        let frames = s.handle(commit());
        let second = match first(&frames) {
            Frame::MsgAdded(a) => a.entry.as_ref().unwrap().clone(),
            other => panic!("expected msg_added, got {other:?}"),
        };
        assert_eq!(second.prev[0].digest, first_digest);
        // Both rows live in ONE thread file (prev[0]'s thread).
        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgThreadsGet(MsgThreadsGet {})),
        });
        match first(&frames) {
            Frame::MsgThreadsPush(t) => assert_eq!(t.threads.len(), 1),
            other => panic!("expected msg_threads_push, got {other:?}"),
        }
    }
}
