//! End-to-end tests for the translator host, using real stdio semantics.
//!
//! # Suite map (what is pinned where)
//!
//! Harness (below): a fake core script + a duplex pipe pair standing in
//! for the client; `send`/`recv_exact` = one client-side exchange,
//! `finish` = client EOF (the only legal session end) + bounded join.
//! Every case asserts one of two things: the RESULT (echo/ack bytes,
//! clean exit) or a LOUD FAILURE (non-zero session end with a specific
//! diagnostic).
//!
//! - happy path + teardown contract: `happy_path_handshake_ack_and_echo`,
//!   `in_flight_request_then_client_eof_ends_cleanly` (in-flight reply
//!   must survive the client EOF — the EPIPE guard),
//!   `core_bad_exit_status_is_loud_after_client_eof` (BadExitStatus).
//! - five malformed-input classes, all loud:
//!   `client_version_mismatch_is_loud`, `garbage_body_json_is_loud`,
//!   `eof_before_handshake_is_loud`, `blank_line_is_a_loud_failure`,
//!   `unknown_fields_are_rejected_today` (tripwire: fires if the pbjson
//!   ignore_unknown_fields switch is ever flipped).
//! - uncooperative-peer boundaries: `core_dying_immediately_is_loud`,
//!   `core_eof_mid_session_is_loud` (client ACTIVE, core stdout EOF =
//!   loud death).
//!
//! The fake core is a `cat`-like shell script: it echoes every
//! length-delimited prost frame byte-for-byte, which is exactly the
//! ack/echo contract — frame #1 (our Handshake) comes back as the core
//! ack, body frames come back as bodies. Other scripts play the dying /
//! bad-exit / mid-session-death roles. NixOS has no /usr/bin
//! and no /bin/false, so every fake core is a `#!/bin/sh` script.

use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use prost::Message as _;

use pretty_assertions::assert_eq;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, duplex};
use tokio::time::timeout;

use zconned_json_translator::run;
use zconned_stdio_types::{Handshake, PROTOCOL_VERSION};

const BUDGET: Duration = Duration::from_secs(5);

/// The protocol version this suite speaks, wired to the types crate so a
/// version bump flows into the tests with the codegen instead of stale
/// literals.
const CLIENT_VERSION: u32 = PROTOCOL_VERSION;

/// The JSONL handshake line the fake client sends, derived from
/// `CLIENT_VERSION`.
fn handshake_line() -> String {
    format!("{{\"version\":{CLIENT_VERSION}}}\n")
}

/// The prost length-delimited `Handshake` frame the translator puts on
/// the core link. Used only for its length: the exact-reading fake cores
/// take their `dd` counts from the real encoder, so no wire bytes or
/// counts are hardcoded.
fn handshake_frame() -> Vec<u8> {
    let hs = Handshake {
        version: CLIENT_VERSION,
    };
    let mut buf = Vec::with_capacity(8);
    hs.encode_length_delimited(&mut buf)
        .expect("in-memory encode cannot fail");
    buf
}

/// The prost length-delimited body frame the fake cores emit: a valid
/// `OutgoingFrame` (an empty msg_cursor_push — the grammar-B answer a
/// canned core can speak). Since v3 the two directions carry
/// DIFFERENT types, so a byte-for-byte `cat` echo no longer yields a
/// decodable answer; the canned frames replace it.
fn canned_outgoing_frame() -> Vec<u8> {
    use zconned_stdio_types::{MsgCursorPush, OutgoingFrame, outgoing_frame::Frame};
    let frame = OutgoingFrame {
        frame: Some(Frame::MsgCursorPush(MsgCursorPush { refs: vec![] })),
    };
    let mut buf = Vec::with_capacity(8);
    frame
        .encode_length_delimited(&mut buf)
        .expect("in-memory encode cannot fail");
    buf
}

/// The JSON line the client receives for the canned outgoing frame
/// (derived by serializing the same type — no hand-counted bytes).
fn canned_outgoing_json() -> String {
    use zconned_stdio_types::{MsgCursorPush, OutgoingFrame, outgoing_frame::Frame};
    let frame = OutgoingFrame {
        frame: Some(Frame::MsgCursorPush(MsgCursorPush { refs: vec![] })),
    };
    let mut line = serde_json::to_string(&frame).unwrap();
    line.push('\n');
    line
}

/// A valid grammar-B client request line (op = msg_threads_get).
fn client_request_json() -> String {
    format!("{{\"msgThreadsGet\":{{}}}}\n")
}

/// Script table: every fake core the suite needs. ALL scripts are written
/// ONCE, up-front, before ANY test spawns anything: when write and exec
/// pipelines overlap across threads, a freshly-written file's exec hits a
/// kernel write→exec race (ETXTBSY, os error 26) — verified empirically
/// on this machine (btrfs AND tmpfs; no fd on the file is visible in
/// /proc at failure, so it is kernel-internal; single pipelines never
/// fail, ~10 concurrent ones fail ~3–5%, clustered at the startup
/// burst). Front-loading in one `OnceLock` makes the ordering global:
/// every test blocks on cache init until ALL scripts exist, so no exec
/// can ever overlap a write.
const SCRIPTS: &[(&str, &str)] = &[
    // Echoes every frame byte-for-byte: with v3's asymmetric types
    // this only works for the handshake (symmetric type) — used by
    // the malformed-INPUT tests where garbage fails client-side
    // before any frame reaches the core.
    ("echo", "cat"),
    ("instant-death", "exit 1"), // dead before the handshake ever lands
];

/// Every fake-core kind the suite materializes. The const-table kinds
/// live in `SCRIPTS`; kinds whose body needs runtime data (real encoder
/// lengths) are built in [`script_body`].
const SCRIPT_KINDS: &[&str] = &[
    "echo",
    "instant-death",
    "bad-exit",
    "ack-position",
    "echo-then-die",
];

/// Script body for `kind`, including the shebang line.
fn script_body(kind: &str) -> String {
    match kind {
        // Mid-session-death core: echoes the handshake frame and one
        // body frame back byte-for-byte, then exits on its own while
        // the client is still active. dd echoes whatever it reads (each
        // read byte goes to stdout) and reads EXACT counts, so the
        // counts come from the real encoder — no wire bytes are
        // hardcoded.
        // Acks the handshake, emits ONE canned position_set answer,
        // then stays quiet until client EOF (the only legal end).
        // The canned answer comes from a pre-written file (dd's stdin
        // here is the CORE link's request stream, not a source for
        // the canned bytes).
        "ack-position" => format!(
            "#!/bin/sh\ndd bs=1 count={} 2>/dev/null\ndd if=\"$0.canned\" bs=1 2>/dev/null\ncat >/dev/null",
            handshake_frame().len(),
        ),
        // Same, but exits 3 AFTER client EOF (teardown status contract).
        "bad-exit" => format!(
            "#!/bin/sh\ndd bs=1 count={} 2>/dev/null\ndd if=\"$0.canned\" bs=1 2>/dev/null\ncat >/dev/null\nexit 3",
            handshake_frame().len(),
        ),
        // Mid-session-death core: acks the handshake, answers one
        // request, then dies while the client is still active.
        "echo-then-die" => format!(
            "#!/bin/sh\ndd bs=1 count={} 2>/dev/null\ndd if=\"$0.canned\" bs=1 2>/dev/null\nsleep 0.5",
            handshake_frame().len(),
        ),
        _ => {
            let (_, body) = SCRIPTS
                .iter()
                .find(|(name, _)| *name == kind)
                .unwrap_or_else(|| panic!("unknown fake-core kind: {kind}"));
            format!("#!/bin/sh\n{body}")
        }
    }
}

/// Prefix identifying this suite's script directories under the system
/// temp dir. Each run gets its own unique private dir (tempfile: random
/// name, mode 0700 — no predictable fixed path); dirs older than
/// [`STALE_AFTER`] can only come from dead runs and are swept at startup,
/// so a crashed/killed run leaves at most one small dir until the next
/// run cleans it.
const SCRIPT_DIR_PREFIX: &str = "zconn-host-interop-tests-";
const STALE_AFTER: Duration = Duration::from_secs(60 * 60);

fn sweep_stale_script_dirs() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(SCRIPT_DIR_PREFIX)
        {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_dir() {
            continue;
        }
        let stale = meta
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age > STALE_AFTER);
        if stale {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The process-wide script directory, front-loaded on first use. The
/// `TempDir` lives in a static, so it is never dropped (std test
/// binaries have no exit hook) — the stale-dir sweep above is the
/// cleanup path.
fn script_dir() -> &'static Path {
    static DIR: OnceLock<TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        sweep_stale_script_dirs();
        let dir = tempfile::Builder::new()
            .prefix(SCRIPT_DIR_PREFIX)
            .tempdir()
            .expect("failed to create fake-core script dir");
        for kind in SCRIPT_KINDS {
            // The canned outgoing frame, pre-written next to each
            // answering script ($0.canned in the script body).
            std::fs::write(
                dir.path().join(format!("core-{kind}.canned")),
                canned_outgoing_frame(),
            )
            .unwrap();
            let path = dir.path().join(format!("core-{kind}"));
            std::fs::write(&path, script_body(kind)).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        dir
    })
    .path()
}

fn fake_core(kind: &str) -> String {
    let path = script_dir().join(format!("core-{kind}"));
    assert!(path.exists(), "unknown fake-core kind: {kind}");
    path.to_str().unwrap().to_owned()
}

/// `cat`: echoes frames byte-for-byte (handshake-only usable).
fn echo_core() -> String {
    fake_core("echo")
}

/// Acks the handshake, answers one request, then waits for EOF.
fn ack_position_core() -> String {
    fake_core("ack-position")
}

/// Same as ack-position but exits 3 after client EOF.
fn bad_exit_core() -> String {
    fake_core("bad-exit")
}

struct Harness {
    feed: tokio::io::DuplexStream,
    collect: tokio::io::DuplexStream,
    task: tokio::task::JoinHandle<zconned_json_translator::Result<()>>,
}

impl Harness {
    async fn spawn(core_bin: String) -> Self {
        let (feed, client_read_half) = duplex(4096);
        let (client_write_half, collect) = duplex(4096);
        let task = tokio::spawn(async move {
            let mut client_in = BufReader::new(client_read_half);
            let mut client_out = client_write_half;
            run(&core_bin, &mut client_in, &mut client_out).await
        });
        Self {
            feed,
            collect,
            task,
        }
    }

    async fn send(&mut self, line: &str) {
        self.feed.write_all(line.as_bytes()).await.unwrap();
    }

    async fn recv_exact(&mut self, n: usize) -> String {
        let mut buf = vec![0u8; n];
        timeout(BUDGET, self.collect.read_exact(&mut buf))
            .await
            .expect("reply did not arrive in time")
            .expect("pipe error while reading reply");
        String::from_utf8(buf).unwrap()
    }

    /// Client EOF (the legal session end) + join, asserting no hang.
    async fn finish(self) -> zconned_json_translator::Result<()> {
        drop(self.feed);
        timeout(BUDGET, self.task)
            .await
            .expect("session did not end in time")
            .expect("session task panicked")
    }
}

#[tokio::test]
async fn happy_path_handshake_ack_and_answer() {
    let mut h = Harness::spawn(ack_position_core()).await;
    let hs_line = handshake_line();
    h.send(&hs_line).await;
    assert_eq!(h.recv_exact(hs_line.len()).await, hs_line);
    let req = client_request_json();
    h.send(&req).await;
    let reply = canned_outgoing_json();
    assert_eq!(h.recv_exact(reply.len()).await, reply);
    h.finish().await.expect("session should end cleanly");
}

#[tokio::test]
async fn in_flight_request_then_client_eof_ends_cleanly() {
    let mut h = Harness::spawn(ack_position_core()).await;
    let hs_line = handshake_line();
    h.send(&hs_line).await;
    assert_eq!(h.recv_exact(hs_line.len()).await, hs_line);
    let req = client_request_json();
    h.send(&req).await;
    let reply = canned_outgoing_json();
    assert_eq!(h.recv_exact(reply.len()).await, reply);
    h.finish().await.expect("session should end cleanly");
}

#[tokio::test]
async fn client_version_mismatch_is_loud() {
    let mut h = Harness::spawn(echo_core()).await;
    h.send("{\"version\":999}\n").await;
    let err = h
        .finish()
        .await
        .expect_err("version mismatch must fail loudly");
    assert!(format!("{err}").contains("version mismatch"), "{err}");
}

#[tokio::test]
async fn garbage_body_json_is_loud() {
    let mut h = Harness::spawn(echo_core()).await;
    let hs_line = handshake_line();
    h.send(&hs_line).await;
    assert_eq!(h.recv_exact(hs_line.len()).await, hs_line);
    h.send("not json at all\n").await;
    let err = h.finish().await.expect_err("garbage body must fail loudly");
    assert!(
        format!("{err}").contains("failed to decode frame"),
        "expected a JSONL decode failure, got: {err}"
    );
}

#[tokio::test]
async fn eof_before_handshake_is_loud() {
    let h = Harness::spawn(echo_core()).await;
    let err = h
        .finish()
        .await
        .expect_err("missing handshake must fail loudly");
    assert!(format!("{err}").contains("eof"), "{err}");
}

#[tokio::test]
async fn core_dying_immediately_is_loud() {
    let mut h = Harness::spawn(fake_core("instant-death")).await;
    h.send(&handshake_line()).await;
    let result = h.finish().await;
    assert!(result.is_err(), "dead core must be a loud failure");
}

#[tokio::test]
async fn core_bad_exit_status_is_loud_after_client_eof() {
    let mut h = Harness::spawn(bad_exit_core()).await;
    let hs_line = handshake_line();
    h.send(&hs_line).await;
    assert_eq!(h.recv_exact(hs_line.len()).await, hs_line);
    let req = client_request_json();
    h.send(&req).await;
    let reply = canned_outgoing_json();
    assert_eq!(h.recv_exact(reply.len()).await, reply);
    let err = h
        .finish()
        .await
        .expect_err("core exiting 3 must fail loudly");
    assert!(
        format!("{err}").contains("bad status"),
        "expected BadExitStatus, got: {err}"
    );
}

#[tokio::test]
async fn core_eof_mid_session_is_loud() {
    let mut h = Harness::spawn(fake_core("echo-then-die")).await;
    let hs_line = handshake_line();
    h.send(&hs_line).await;
    assert_eq!(h.recv_exact(hs_line.len()).await, hs_line);
    let req = client_request_json();
    h.send(&req).await;
    let reply = canned_outgoing_json();
    assert_eq!(h.recv_exact(reply.len()).await, reply);
    let task = h.task;
    let join = timeout(BUDGET, task)
        .await
        .expect("session did not fail in time")
        .expect("session task panicked");
    let Harness {
        feed,
        collect,
        task: _,
    } = h;
    drop(feed);
    drop(collect);
    let err = join.expect_err("mid-session core EOF must fail loudly");
    assert!(format!("{err}").contains("eof"), "{err}");
}

#[tokio::test]
/// An empty line is a malformed frame
async fn blank_line_is_a_loud_failure() {
    let mut h = Harness::spawn(echo_core()).await;
    let hs_line = handshake_line();
    h.send(&hs_line).await;
    assert_eq!(h.recv_exact(hs_line.len()).await, hs_line);
    h.send("\n").await;
    let err = h.finish().await.expect_err("blank line must fail loudly");
    assert!(
        format!("{err}").contains("failed to decode frame"),
        "expected a decode failure, got: {err}"
    );
}

#[tokio::test]
/// `pbjson` REJECTS unknown fields
async fn unknown_fields_are_rejected_today() {
    let mut h = Harness::spawn(echo_core()).await;
    let hs_line = handshake_line();
    h.send(&hs_line).await;
    assert_eq!(h.recv_exact(hs_line.len()).await, hs_line);
    h.send("{\"msgThreadsGet\":{},\"bogus\":1}\n").await;
    let err = h
        .finish()
        .await
        .expect_err("unknown fields must be rejected today");
    assert!(
        format!("{err}").contains("unknown field"),
        "expected an unknown-field rejection, got: {err}"
    );
}
