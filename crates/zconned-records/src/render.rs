use crate::error::Result;
use prost::Message as _;
use zconned_codec::{RowMeta, TranscriptRow};
use zconned_crypto::DIGEST_ALGO;
use zconned_material::Msg;

use core::fmt::Write as _;

/// Render a received message into a transcript row.
///
/// `transport_bytes` = the received transport bytes; the digest is
/// taken over them as-is (the official binary path carries
/// canonical bytes end-to-end — protocol.md). `recorded_at` = the
/// local record time, supplied by the consumer: the clock belongs
/// to the interface layer, never to this crate.
pub fn render_row(transport_bytes: &[u8], recorded_at: String) -> Result<TranscriptRow> {
    let msg = Msg::decode(transport_bytes)?;
    let digest = zconned_crypto::digest(transport_bytes);
    Ok(TranscriptRow {
        meta: RowMeta {
            ts: recorded_at,
            algo: DIGEST_ALGO.to_owned(),
            digest: to_lower_hex(&digest),
        },
        msg,
    })
}

fn to_lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsck::fsck_row;
    use pretty_assertions::assert_eq;
    use zconned_material::{Meta, Node};

    fn sample_bytes() -> Vec<u8> {
        let msg = Msg {
            ver_major: 1,
            ver_minor: 0,
            body: Some(Node {
                meta: Some(Meta { prev: vec![] }),
                kind: "text/plain".to_owned(),
                data: b"hello".to_vec(),
            }),
        };
        msg.encode_to_vec()
    }

    #[test]
    fn render_produces_the_observer_facts_and_verbatim_msg() {
        let bytes = sample_bytes();
        let row = render_row(&bytes, "2026-10-28T12:00:00Z".to_owned()).unwrap();
        assert_eq!(row.meta.ts, "2026-10-28T12:00:00Z");
        assert_eq!(row.meta.algo, "sha3-256");
        let expected_hex: String = zconned_crypto::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(row.meta.digest, expected_hex);
        assert_eq!(row.msg.body.as_ref().unwrap().kind, "text/plain");
    }

    #[test]
    fn render_rejects_bytes_that_do_not_decode() {
        assert!(render_row(b"garbage", "2026-10-28T12:00:00Z".to_owned()).is_err());
    }

    #[test]
    fn row_jsonl_roundtrip_preserves_the_row() {
        let bytes = sample_bytes();
        let row = render_row(&bytes, "2026-10-28T12:00:00Z".to_owned()).unwrap();
        let line = serde_json::to_string(&row).unwrap();
        let back: zconned_codec::TranscriptRow = serde_json::from_str(&line).unwrap();
        assert_eq!(back, row);
        assert!(fsck_row(&back).is_ok());
    }
}
