//! End-to-end tests: the real core over in-memory duplex pipes,
//! driven by a protobuf-path client. The translator's framing has
//! its own suite in zconned-json-translator.
//!
//! Coverage: handshake + the full op surface + the two-frame commit
//! answer + the record store on disk + the EOF teardown contract.

use tokio::io::{BufReader, duplex};

use zconned_io_link::{ReadLink, WriteLink, protobuf::LinkStruct as ProtobufLink};
use zconned_stdio_types::{
    Fresh, Handshake, IncomingFrame, MsgCursorSet, MsgDraftCommit, MsgDraftContentSet,
    MsgThreadsGet, MsgThreadsLogGet, OutgoingFrame, PROTOCOL_VERSION, incoming_frame::Method,
    outgoing_frame::Frame,
};

type CoreLink = ProtobufLink<BufReader<tokio::io::DuplexStream>, tokio::io::DuplexStream>;

struct Client {
    link: CoreLink,
}

impl Client {
    async fn handshake(&mut self) {
        self.link
            .write_frame(&Handshake {
                version: PROTOCOL_VERSION,
            })
            .await
            .unwrap();
        let ack: Handshake = self.link.read_frame().await.unwrap().unwrap();
        assert_eq!(ack.version, PROTOCOL_VERSION);
    }

    async fn send(&mut self, frame: IncomingFrame) {
        self.link.write_frame(&frame).await.unwrap();
    }

    async fn recv(&mut self) -> Frame {
        let frame: OutgoingFrame = self.link.read_frame().await.unwrap().unwrap();
        frame.frame.expect("outgoing frame carries a branch")
    }
}

fn method_frame(method: Option<Method>) -> IncomingFrame {
    IncomingFrame { method }
}

fn fresh_cursor() -> IncomingFrame {
    method_frame(Some(Method::MsgCursorSet(MsgCursorSet {
        at: vec![],
        fresh: Some(Fresh {}),
    })))
}

fn content_set(kind: &str, data: &[u8]) -> IncomingFrame {
    method_frame(Some(Method::MsgDraftContentSet(MsgDraftContentSet {
        kind: kind.to_owned(),
        data: data.to_vec(),
    })))
}

/// Spawn the real core over a duplex pipe; returns the client link.
async fn spawn_core(
    store: std::path::PathBuf,
) -> (
    tokio::task::JoinHandle<zconned::Result<()>>,
    tokio::io::DuplexStream,
    tokio::io::DuplexStream,
) {
    let (core_in, client_write) = duplex(64 * 1024);
    let (core_out, client_read) = duplex(64 * 1024);
    let mut core_out = core_out;
    let task = tokio::spawn(async move {
        let mut core_in = BufReader::new(core_in);
        zconned::run_with_store(store, &mut core_in, &mut core_out).await
    });
    (task, client_read, client_write)
}

async fn client(read: tokio::io::DuplexStream, write: tokio::io::DuplexStream) -> Client {
    Client {
        link: ProtobufLink::new(BufReader::new(read), write),
    }
}

#[tokio::test]
async fn happy_flow_fresh_to_commit_to_browse() {
    let dir = tempfile::tempdir().unwrap();
    let (task, read, write) = spawn_core(dir.path().to_path_buf()).await;
    let mut c = client(read, write).await;

    c.handshake().await;

    // fresh cursor.
    c.send(fresh_cursor()).await;
    let genesis = match c.recv().await {
        Frame::PositionSet(p) => {
            assert_eq!(p.refs.len(), 1);
            p.refs[0].clone()
        }
        other => panic!("expected position_set, got {other:?}"),
    };

    // Stage content; the snapshot pushes back (an ANCHOR: kindless,
    // digest = H(canonical Value{kind, data})).
    c.send(content_set("text/plain", b"hi")).await;
    let content_digest = match c.recv().await {
        Frame::MsgDraft(d) => {
            let r = d.content.as_ref().expect("content staged");
            assert_eq!(
                r.digest,
                zconned_material::resource_digest("text/plain", b"hi").to_vec()
            );
            r.digest.clone()
        }
        other => panic!("expected msg_draft, got {other:?}"),
    };

    // Commit: the two-frame answer — anchors + the values sidecar.
    c.send(method_frame(Some(Method::MsgDraftCommit(
        MsgDraftCommit {},
    ))))
    .await;
    let (digest, resting) = match (c.recv().await, c.recv().await) {
        (Frame::MsgAdded(a), Frame::MsgDraft(d)) => {
            let entry = a.entry.as_ref().unwrap();
            let msg = entry.msg.as_ref().unwrap();
            assert_eq!(msg.content.as_ref().unwrap().digest, content_digest);
            assert_eq!(msg.prev, vec![genesis.clone()]);
            let meta = entry.meta.as_ref().unwrap();
            assert!(meta.ts.is_some());
            // The sidecar carries the resolved value.
            let value = entry
                .values
                .iter()
                .find(|r| r.kind == "text/plain")
                .expect("the content value rides the sidecar");
            assert_eq!(value.data, b"hi");
            assert_eq!(value.digest, content_digest);
            (hex(&meta.digest), d)
        }
        other => panic!("expected msg_added + msg_draft, got {other:?}"),
    };
    assert_eq!(digest.len(), 64);
    assert!(resting.content.is_none() && resting.claims.is_empty());

    // Browse: threads -> log (values reconstructed from resources).
    c.send(method_frame(Some(Method::MsgThreadsGet(MsgThreadsGet {}))))
        .await;
    match c.recv().await {
        Frame::MsgThreads(t) => {
            assert_eq!(t.threads.len(), 1);
            assert_eq!(t.threads[0].thread, Some(genesis.clone()));
        }
        other => panic!("expected msg_threads, got {other:?}"),
    }
    c.send(method_frame(Some(Method::MsgThreadsLogGet(
        MsgThreadsLogGet {
            thread: Some(genesis.clone()),
        },
    ))))
    .await;
    match c.recv().await {
        Frame::MsgThreadsLog(l) => {
            assert_eq!(l.entries.len(), 1);
            let entry = &l.entries[0];
            let msg = entry.msg.as_ref().unwrap();
            assert_eq!(msg.content.as_ref().unwrap().digest, content_digest);
            let value = entry
                .values
                .iter()
                .find(|r| r.kind == "text/plain")
                .expect("browsing reconstructs the value via the sidecar");
            assert_eq!(value.data, b"hi");
        }
        other => panic!("expected msg_threads_log, got {other:?}"),
    }

    // EOF ends the session cleanly (exit 0): dropping the client
    // drops the duplex halves.
    drop(c);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn commit_before_cursor_is_a_loud_error() {
    let dir = tempfile::tempdir().unwrap();
    let (task, read, write) = spawn_core(dir.path().to_path_buf()).await;
    let mut c = client(read, write).await;

    c.handshake().await;
    c.send(method_frame(Some(Method::MsgDraftCommit(
        MsgDraftCommit {},
    ))))
    .await;
    match c.recv().await {
        Frame::Error(e) => assert_eq!(e.code, "cursor_required"),
        other => panic!("expected error, got {other:?}"),
    }

    // The session lives: the flow still works afterwards.
    c.send(fresh_cursor()).await;
    assert!(matches!(c.recv().await, Frame::PositionSet(_)));

    drop(c);
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test]
async fn version_mismatch_is_loud() {
    let dir = tempfile::tempdir().unwrap();
    let (task, read, write) = spawn_core(dir.path().to_path_buf()).await;
    let mut c = client(read, write).await;
    c.link
        .write_frame(&Handshake { version: 999 })
        .await
        .unwrap();
    let err = task
        .await
        .unwrap()
        .expect_err("version mismatch must be loud");
    assert!(format!("{err}").contains("version mismatch"), "{err}");
}

#[tokio::test]
async fn eof_before_handshake_is_loud() {
    let dir = tempfile::tempdir().unwrap();
    let (task, _read, _write) = spawn_core(dir.path().to_path_buf()).await;
    // Drop the client ends immediately: the core reads EOF where a
    // handshake was due.
    drop(_read);
    drop(_write);
    let err = task
        .await
        .unwrap()
        .expect_err("missing handshake must fail loudly");
    assert!(format!("{err}").contains("eof"), "{err}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
