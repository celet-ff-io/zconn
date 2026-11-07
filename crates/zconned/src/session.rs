//! The core session state machine: one compose cursor, one draft,
//! one thread-file store. The record carries pointers; this staging
//! layer holds the plaintext (kind, data) pairs and binds them to
//! addresses via H(canonical Value{kind, data}).

use std::collections::HashMap;

use crate::store::{CommitValues, Store, ThreadId};
use prost::Message as _;
use zconned_crypto::{DIGEST_ALGO, DIGEST_LEN};
use zconned_material::{
    CLAIM_KIND_TS, Claim, Msg, MsgRef, Resource, ResourceRef, Value, resource_digest,
};
use zconned_stdio_types::{
    Entry, Error as WireError, Fresh, IncomingFrame, MsgAdded, MsgCursorSet, MsgDraft,
    MsgDraftClaimsAdd, MsgDraftClaimsRemove, MsgDraftContentSet, MsgThreads, MsgThreadsLog,
    MsgThreadsLogGet, OutgoingFrame, PositionSet, RowMeta, ThreadEntry, incoming_frame::Method,
    outgoing_frame::Frame,
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
    /// The anchor projection (the snapshot the interface sees).
    fn snapshot(&self) -> MsgDraft {
        MsgDraft {
            content: self.content.as_ref().map(|b| ResourceRef {
                algo: DIGEST_ALGO.to_owned(),
                digest: resource_digest(&b.kind, &b.data).to_vec(),
            }),
            claims: self
                .claims
                .iter()
                .map(|b| Claim {
                    kind: b.kind.clone(),
                    r#ref: Some(ResourceRef {
                        algo: DIGEST_ALGO.to_owned(),
                        // Empty data = a pending registry stamp (the
                        // digest cannot exist before the value does).
                        digest: if b.data.is_empty() {
                            Vec::new()
                        } else {
                            resource_digest(&b.kind, &b.data).to_vec()
                        },
                    }),
                })
                .collect(),
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
                vec![reply(Frame::MsgThreads(MsgThreads {
                    threads: threads
                        .iter()
                        .map(|t| ThreadEntry {
                            thread: t.to_ref().ok(),
                        })
                        .collect(),
                }))]
            }
            Method::MsgThreadsLogGet(MsgThreadsLogGet { thread }) => self.thread_log(thread),
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
                vec![reply(Frame::PositionSet(PositionSet { refs }))]
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
                vec![reply(Frame::PositionSet(PositionSet { refs: vec![r] }))]
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
        let (row, resolved) = match self
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
        let entry = Entry {
            msg: Some(msg.clone()),
            meta: Some(RowMeta {
                ts: Some(ts),
                algo: row.meta.algo.clone(),
                digest: crate::store::hex_to_bytes(&row.meta.digest).unwrap_or_default(),
            }),
            values: resolved,
        };

        // The resting state: the draft is consumed by the commit.
        self.draft = Draft::default();
        vec![
            reply(Frame::MsgAdded(MsgAdded { entry: Some(entry) })),
            reply(Frame::MsgDraft(MsgDraft {
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
        vec![reply(Frame::MsgThreadsLog(MsgThreadsLog { entries }))]
    }

    fn draft_reply(&self) -> OutgoingFrame {
        reply(Frame::MsgDraft(self.draft.snapshot()))
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
/// resource rows. A missing resource = the anchor stays, the
/// sidecar omits it.
fn reconstruct(row: &zconned_codec::Row, resources: &[zconned_codec::ResourceRow]) -> Entry {
    let lookup = |digest_hex: &str| -> Option<Resource> {
        resources
            .iter()
            .find(|r| r.digest == digest_hex)
            .map(|r| Resource {
                algo: r.algo.clone(),
                digest: crate::store::hex_to_bytes(&r.digest).unwrap_or_default(),
                kind: r.kind.clone(),
                // The row's data = the base64 projection; resolve to
                // the raw bytes.
                data: crate::store::base64_decode(&r.data).unwrap_or_default(),
            })
    };
    let msg = Msg {
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
        content: Some(ResourceRef {
            algo: row.msg.content.algo.clone(),
            digest: crate::store::hex_to_bytes(&row.msg.content.digest).unwrap_or_default(),
        }),
        claims: row
            .msg
            .claims
            .iter()
            .map(|c| Claim {
                kind: c.kind.clone(),
                r#ref: Some(ResourceRef {
                    algo: c.ref_.algo.clone(),
                    digest: crate::store::hex_to_bytes(&c.ref_.digest).unwrap_or_default(),
                }),
            })
            .collect(),
    };
    let mut values = Vec::new();
    if let Some(v) = lookup(&row.msg.content.digest) {
        values.push(v);
    }
    for c in &row.msg.claims {
        if let Some(v) = lookup(&c.ref_.digest) {
            values.push(v);
        }
    }
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
        msg: Some(msg),
        meta: Some(meta),
        values,
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

        // fresh -> PositionSet{refs: [random]}
        let frames = s.handle(fresh_cursor_set());
        assert_eq!(frames.len(), 1);
        let genesis = match first(&frames) {
            Frame::PositionSet(p) => p.refs[0].clone(),
            other => panic!("expected position_set, got {other:?}"),
        };
        assert_eq!(genesis.algo, DIGEST_ALGO);
        assert_eq!(genesis.digest.len(), DIGEST_LEN);

        // stage content + claims; the snapshot = ANCHORS
        let frames = s.handle(content_set("text/plain", "hi"));
        match first(&frames) {
            Frame::MsgDraft(d) => {
                let content = d.content.as_ref().unwrap();
                // The anchor is kindless BY TYPE (no kind field): the
                // kind lives inside the addressed resource.
                assert_eq!(
                    content.digest,
                    resource_digest("text/plain", b"hi").to_vec()
                );
                assert!(d.claims.is_empty());
            }
            other => panic!("expected msg_draft, got {other:?}"),
        }
        let frames = s.handle(claims_add("vnd.example.author", Some("KEY-1")));
        match first(&frames) {
            Frame::MsgDraft(d) => {
                assert_eq!(d.claims.len(), 1);
                assert_eq!(d.claims[0].kind, "vnd.example.author");
                assert_eq!(
                    d.claims[0].r#ref.as_ref().unwrap().digest,
                    resource_digest("vnd.example.author", b"KEY-1").to_vec()
                );
            }
            other => panic!("expected msg_draft, got {other:?}"),
        }
        // The registry kind stages PENDING: empty digest.
        let frames = s.handle(claims_add(CLAIM_KIND_TS, None));
        match first(&frames) {
            Frame::MsgDraft(d) => {
                assert_eq!(d.claims.len(), 2);
                let ts = d.claims.iter().find(|c| c.kind == CLAIM_KIND_TS).unwrap();
                assert!(
                    ts.r#ref.as_ref().unwrap().digest.is_empty(),
                    "registry value unstaged"
                );
            }
            other => panic!("expected msg_draft, got {other:?}"),
        }

        // commit -> msg_added(entry + values sidecar) + resting draft
        let frames = s.handle(commit());
        assert_eq!(frames.len(), 2);
        let (added, resting) = match (first(&frames), frames[1].frame.as_ref().unwrap()) {
            (Frame::MsgAdded(a), Frame::MsgDraft(d)) => (a, d),
            other => panic!("expected msg_added + msg_draft, got {other:?}"),
        };
        let entry = added.entry.as_ref().unwrap();
        let msg = entry.msg.as_ref().unwrap();
        assert_eq!(msg.prev, vec![genesis.clone()]);
        let content = msg.content.as_ref().unwrap();
        assert_eq!(
            content.digest,
            resource_digest("text/plain", b"hi").to_vec()
        );
        let ts = msg
            .claims
            .iter()
            .find(|c| c.kind == CLAIM_KIND_TS)
            .expect("ts claim stamped");
        assert!(
            !ts.r#ref.as_ref().unwrap().digest.is_empty(),
            "registry digest computed at commit"
        );
        // Self-consistency: the anchor's digest = H(the sidecar value).
        let stamped_value = entry
            .values
            .iter()
            .find(|r| r.kind == CLAIM_KIND_TS)
            .expect("the stamped value rides the sidecar");
        assert_eq!(
            ts.r#ref.as_ref().unwrap().digest,
            resource_digest(CLAIM_KIND_TS, &stamped_value.data).to_vec()
        );
        let meta = entry.meta.as_ref().unwrap();
        assert_eq!(meta.algo, DIGEST_ALGO);
        assert!(meta.ts.is_some());
        // The sidecar = the resolved resources (content + stamped ts;
        // NOT the pending vendor value it never had).
        assert!(
            entry
                .values
                .iter()
                .any(|r| r.kind == "text/plain" && r.data == b"hi")
        );
        assert!(entry.values.iter().any(|r| r.kind == CLAIM_KIND_TS));
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
            Frame::MsgDraft(d) => {
                assert_eq!(d.claims.len(), 1);
                assert_eq!(
                    d.claims[0].r#ref.as_ref().unwrap().digest,
                    resource_digest("vnd.example.a", b"1").to_vec(),
                    "first add wins (ensure-present)"
                );
            }
            other => panic!("expected msg_draft, got {other:?}"),
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
            Frame::MsgDraft(d) => assert_eq!(d.claims.len(), 1),
            other => panic!("expected msg_draft, got {other:?}"),
        }
        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgDraftClaimsClear(MsgDraftClaimsClear {})),
        });
        match first(&frames) {
            Frame::MsgDraft(d) => assert!(d.claims.is_empty()),
            other => panic!("expected msg_draft, got {other:?}"),
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
                let msg = a.entry.as_ref().unwrap().msg.as_ref().unwrap();
                let ts = msg.claims.iter().find(|c| c.kind == CLAIM_KIND_TS).unwrap();
                assert_ne!(
                    ts.r#ref.as_ref().unwrap().digest,
                    resource_digest(CLAIM_KIND_TS, b"FAKE").to_vec(),
                    "interface-supplied value overwritten"
                );
                // The stamped resource = a real RFC3339 timestamp.
                let stamped = a
                    .entry
                    .as_ref()
                    .unwrap()
                    .values
                    .iter()
                    .find(|r| r.kind == CLAIM_KIND_TS)
                    .unwrap();
                assert!(
                    time::OffsetDateTime::parse(
                        std::str::from_utf8(&stamped.data).unwrap(),
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
            Frame::PositionSet(p) => assert_eq!(p.refs, vec![parent.clone()]),
            other => panic!("expected position_set, got {other:?}"),
        }
        s.handle(content_set("text/plain", "x"));
        let frames = s.handle(commit());
        match first(&frames) {
            Frame::MsgAdded(a) => {
                let msg = a.entry.as_ref().unwrap().msg.as_ref().unwrap();
                assert_eq!(msg.prev, vec![parent.clone()]);
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
        assert!(matches!(first(&frames), Frame::PositionSet(_)));
    }

    #[test]
    fn threads_get_and_log_get_roundtrip_via_the_sidecar() {
        let (mut s, _dir) = temp_session();
        s.handle(fresh_cursor_set());
        s.handle(content_set("text/plain", "hello"));
        s.handle(claims_add("vnd.example.author", Some("KEY-1")));
        s.handle(commit());

        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgThreadsGet(MsgThreadsGet {})),
        });
        let thread_ref = match first(&frames) {
            Frame::MsgThreads(t) => t.threads[0].thread.clone().unwrap(),
            other => panic!("expected msg_threads, got {other:?}"),
        };

        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgThreadsLogGet(MsgThreadsLogGet {
                thread: Some(thread_ref),
            })),
        });
        match first(&frames) {
            Frame::MsgThreadsLog(l) => {
                assert_eq!(l.entries.len(), 1);
                let entry = &l.entries[0];
                // The msg = anchors; the values = the sidecar.
                let msg = entry.msg.as_ref().unwrap();
                let values = &entry.values;
                assert!(
                    values
                        .iter()
                        .any(|r| r.kind == "text/plain" && r.data == b"hello")
                );
                assert!(
                    values
                        .iter()
                        .any(|r| r.kind == "vnd.example.author" && r.data == b"KEY-1")
                );
                // Every sidecar value's digest = its anchor's digest.
                let content_digest = &msg.content.as_ref().unwrap().digest;
                assert!(
                    values
                        .iter()
                        .any(|r| r.kind == "text/plain" && r.digest == *content_digest)
                );
            }
            other => panic!("expected msg_threads_log, got {other:?}"),
        }
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
            Frame::MsgThreadsLog(l) => assert!(l.entries.is_empty()),
            other => panic!("expected msg_threads_log, got {other:?}"),
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
            Frame::MsgAdded(a) => a.entry.as_ref().unwrap().msg.as_ref().unwrap().clone(),
            other => panic!("expected msg_added, got {other:?}"),
        };
        assert_eq!(second.prev[0].digest, first_digest);
        // Both rows live in ONE thread file (prev[0]'s thread).
        let frames = s.handle(IncomingFrame {
            method: Some(Method::MsgThreadsGet(MsgThreadsGet {})),
        });
        match first(&frames) {
            Frame::MsgThreads(t) => assert_eq!(t.threads.len(), 1),
            other => panic!("expected msg_threads, got {other:?}"),
        }
    }
}
