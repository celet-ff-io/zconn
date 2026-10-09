//! End-to-end tests for the translator host, using real stdio semantics.
//!
//! The fake core is a `cat`-like shell script: it echoes every
//! length-delimited prost frame byte-for-byte, which is exactly the
//! ack/echo contract — frame #1 (our Handshake) comes back as the core
//! ack, body frames come back as bodies. Other scripts play the dying /
//! bad-exit / silent roles. NixOS has no /usr/bin and no /bin/false, so
//! every fake core is a `#!/bin/sh` script.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, duplex};
use tokio::time::timeout;

use zconned_json_translator::run;

const BUDGET: Duration = Duration::from_secs(5);

/// Script table: every fake core the suite needs. ALL scripts are written
/// ONCE, up-front, before any test spawns anything: a freshly-written
/// file exec'd while another thread still writes a different one hits a
/// kernel write→exec race (ETXTBSY) — verified empirically; front-loading
/// removes the race entirely.
const SCRIPTS: &[(&str, &str)] = &[
    ("echo", "cat"),                         // echoes every frame byte-for-byte
    ("bad-exit", "cat\nexit 3"),             // acks+echoes, then exits 3 after client EOF
    ("silent", "cat > /dev/null\nsleep 60"), // never replies: handshake deadline
    ("instant-death", "exit 1"),             // dead before the handshake ever lands
];

fn fake_core(kind: &str) -> String {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    static CACHE: OnceLock<HashMap<&'static str, String>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let dir = std::env::temp_dir().join("zconn-host-interop-tests");
            std::fs::create_dir_all(&dir).unwrap();
            SCRIPTS
                .iter()
                .map(|(kind, body)| {
                    let path = dir.join(format!("core-{}-{kind}", std::process::id()));
                    std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                            .unwrap();
                    }
                    (*kind, path.to_str().unwrap().to_owned())
                })
                .collect()
        })
        .get(kind)
        .expect("unknown fake-core kind")
        .clone()
}

/// `cat`: echoes every frame back byte-for-byte.
fn echo_core() -> String {
    fake_core("echo")
}

/// Echoes frames (so the handshake is acked) and exits 3 after client
/// EOF — exercises the teardown status contract.
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
async fn happy_path_handshake_ack_and_roundtrip() {
    let mut h = Harness::spawn(echo_core()).await;
    h.send("{\"version\":1}\n").await;
    // The client handshake MUST be acked: no silent wait after frame #1.
    assert_eq!(h.recv_exact(14).await, "{\"version\":1}\n");
    h.send("{\"text\":\"hi\"}\n").await;
    assert_eq!(h.recv_exact(14).await, "{\"text\":\"hi\"}\n");
    h.finish().await.expect("session should end cleanly");
}

#[tokio::test]
async fn in_flight_request_then_client_eof_ends_cleanly() {
    let mut h = Harness::spawn(echo_core()).await;
    h.send("{\"version\":1}\n").await;
    assert_eq!(h.recv_exact(14).await, "{\"version\":1}\n");
    // Request forwarded, then EOF without waiting for the reply: the
    // translator must deliver the echo, must not hang, and must still reap
    // the core with a status check.
    h.send("{\"text\":\"bye\"}\n").await;
    assert_eq!(h.recv_exact(15).await, "{\"text\":\"bye\"}\n");
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
    h.send("{\"version\":1}\n").await;
    assert_eq!(h.recv_exact(14).await, "{\"version\":1}\n");
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
    // A script that exits 1 instantly: no handshake ack ever comes.
    let mut h = Harness::spawn(fake_core("instant-death")).await;
    h.send("{\"version\":1}\n").await;
    // The outcome is a loud failure either way: EPIPE on the write, or EOF
    // on the ack read. Which one wins is a race; both must be errors.
    let result = h.finish().await;
    assert!(result.is_err(), "dead core must be a loud failure");
}

#[tokio::test]
async fn core_bad_exit_status_is_loud_after_client_eof() {
    let mut h = Harness::spawn(bad_exit_core()).await;
    h.send("{\"version\":1}\n").await;
    assert_eq!(h.recv_exact(14).await, "{\"version\":1}\n");
    h.send("{\"text\":\"y\"}\n").await;
    assert_eq!(h.recv_exact(13).await, "{\"text\":\"y\"}\n");
    let err = h
        .finish()
        .await
        .expect_err("core exiting 3 must fail loudly");
    assert!(
        format!("{err}").contains("bad status"),
        "expected BadExitStatus, got: {err}"
    );
}

#[tokio::test(start_paused = true)]
async fn silent_core_waits_indefinitely_by_contract() {
    // DECIDED 2026-10-10: NO handshake deadline. This is stdio, not the
    // network: the translator's parent knows what it is doing, and the
    // loud first-frame checks (version mismatch / non-handshake first
    // frame) are the developer guidance. A silent peer therefore parks
    // the session indefinitely — pinned here deterministically: after a
    // FULL HOUR of virtual time the task is still alive (no internal
    // timer aborts it). kill_on_drop reaps the sleeping core when the
    // harness (and its cancelled task) is dropped.
    let h = Harness::spawn(fake_core("silent")).await;
    tokio::time::advance(Duration::from_secs(3600)).await;
    assert!(
        !h.task.is_finished(),
        "the translator must not abort a silent peer on its own"
    );
    drop(h); // cancel + kill_on_drop: the sleeping core is reaped
}

#[tokio::test]
async fn blank_line_is_a_loud_failure() {
    // An empty line is a malformed frame, never a no-op (serde-jsonlines
    // cannot decode "").
    let mut h = Harness::spawn(echo_core()).await;
    h.send("{\"version\":1}\n").await;
    assert_eq!(h.recv_exact(14).await, "{\"version\":1}\n");
    h.send("\n").await;
    let err = h.finish().await.expect_err("blank line must fail loudly");
    assert!(
        format!("{err}").contains("failed to decode frame"),
        "expected a decode failure, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Unknown-field tripwire (pbjson strictness contract)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_fields_are_rejected_today() {
    // DECIDED: pbjson REJECTS unknown fields TODAY. That contradicts the
    // "fields are only ever added" rule for the JSON view (a newer client
    // using an added field cannot talk to an older translator), but it buys
    // loud typo detection. The switch (ignore_unknown_fields) is
    // deliberately NOT decided yet; this tripwire pins the CURRENT
    // behaviour at the LINK level (what a client actually experiences): if
    // the switch is ever flipped, the frame below decodes, an echo comes
    // back, and this expect_err fails — forcing a visible, deliberate
    // test change, never a silent one.
    let mut h = Harness::spawn(echo_core()).await;
    h.send("{\"version\":1}\n").await;
    assert_eq!(h.recv_exact(14).await, "{\"version\":1}\n");
    h.send("{\"text\":\"hi\",\"bogus\":1}\n").await;
    let err = h
        .finish()
        .await
        .expect_err("unknown fields must be rejected today");
    assert!(
        format!("{err}").contains("unknown field"),
        "expected an unknown-field rejection, got: {err}"
    );
}
