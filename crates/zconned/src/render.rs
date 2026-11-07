use prost::Message as _;

use crate::error::Result;
use zconned_codec::{Row, RowClaim, RowMeta, RowMsg, RowMsgRef, RowResourceRef};
use zconned_crypto::DIGEST_ALGO;
use zconned_material::Msg;

use core::fmt::Write as _;

/// Render a message into a transcript row (the anchor projection,
/// hex digests). The identity digest is taken over `transport_bytes`
/// as-is; the resource digests come from the Msg's anchors.
pub fn render_row(transport_bytes: &[u8], recorded_at: String) -> Result<Row> {
    let msg = Msg::decode(transport_bytes)?;
    let digest = zconned_crypto::digest(transport_bytes);
    let content = msg
        .content
        .as_ref()
        .ok_or(crate::error::Error::MissingContent)?;
    Ok(Row {
        meta: RowMeta {
            ts: recorded_at,
            algo: DIGEST_ALGO.to_owned(),
            digest: to_lower_hex(&digest),
        },
        msg: RowMsg {
            ver_major: msg.ver_major,
            ver_minor: msg.ver_minor,
            prev: msg.prev.iter().map(render_msg_ref).collect(),
            content: RowResourceRef {
                algo: content.algo.clone(),
                digest: to_lower_hex(&content.digest),
            },
            claims: msg.claims.iter().map(render_claim_ref).collect(),
        },
    })
}

fn render_msg_ref(r: &zconned_material::MsgRef) -> RowMsgRef {
    RowMsgRef {
        ver_major: r.ver_major,
        ver_minor: r.ver_minor,
        algo: r.algo.clone(),
        digest: to_lower_hex(&r.digest),
    }
}

fn render_claim_ref(c: &zconned_material::Claim) -> RowClaim {
    let (algo, digest) = c
        .r#ref
        .as_ref()
        .map(|r| (r.algo.clone(), to_lower_hex(&r.digest)))
        .unwrap_or_default();
    RowClaim {
        kind: c.kind.clone(),
        ref_: RowResourceRef { algo, digest },
    }
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
    use zconned_material::{Claim, ResourceRef, resource_digest};

    fn sample_bytes() -> Vec<u8> {
        let msg = Msg {
            ver_major: 1,
            ver_minor: 0,
            prev: vec![],
            content: Some(ResourceRef {
                algo: "sha3-256".to_owned(),
                digest: resource_digest("text/plain", b"hello").to_vec(),
            }),
            claims: vec![
                Claim {
                    kind: "application/vnd.zconn.ts".to_owned(),
                    r#ref: Some(ResourceRef {
                        algo: "sha3-256".to_owned(),
                        digest: resource_digest(
                            "application/vnd.zconn.ts",
                            b"2026-11-05T12:00:00Z",
                        )
                        .to_vec(),
                    }),
                },
                Claim {
                    kind: "vnd.example.author".to_owned(),
                    r#ref: Some(ResourceRef {
                        algo: "sha3-256".to_owned(),
                        digest: resource_digest("vnd.example.author", b"KEY-1").to_vec(),
                    }),
                },
            ],
        };
        msg.encode_to_vec()
    }

    #[test]
    fn render_produces_observer_facts_and_the_anchor_projection() {
        let bytes = sample_bytes();
        let row = render_row(&bytes, "2026-11-05T12:00:00Z".to_owned()).unwrap();
        assert_eq!(row.meta.ts, "2026-11-05T12:00:00Z");
        assert_eq!(row.meta.algo, "sha3-256");
        let expected_hex: String = zconned_crypto::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(row.meta.digest, expected_hex);
        // Addresses only — the content kindless, claims keyed.
        assert_eq!(row.msg.content.algo, "sha3-256");
        assert_eq!(
            row.msg.content.digest,
            to_lower_hex(&resource_digest("text/plain", b"hello"))
        );
        assert_eq!(row.msg.claims.len(), 2);
        assert_eq!(row.msg.claims[0].kind, "application/vnd.zconn.ts");
        assert_eq!(
            row.msg.claims[0].ref_.digest,
            to_lower_hex(&resource_digest(
                "application/vnd.zconn.ts",
                b"2026-11-05T12:00:00Z"
            ))
        );
        assert_eq!(row.msg.claims[1].kind, "vnd.example.author");
    }

    #[test]
    fn anchor_row_never_carries_payload_values() {
        let bytes = sample_bytes();
        let line = serde_json::to_string(&render_row(&bytes, "t".to_owned()).unwrap()).unwrap();
        assert!(!line.contains("hello"));
        assert!(!line.contains("2026-11-05T12:00:00Z"));
        assert!(!line.contains("KEY-1"));
    }

    #[test]
    fn claims_are_rg_able_by_kind() {
        // The row's semantic skeleton: claims keep kind, so a file
        // grep answers "which messages carry an author claim".
        let bytes = sample_bytes();
        let line = serde_json::to_string(&render_row(&bytes, "t".to_owned()).unwrap()).unwrap();
        assert!(line.contains("vnd.example.author"));
    }

    #[test]
    fn render_rejects_bytes_that_do_not_decode() {
        assert!(render_row(b"garbage", "t".to_owned()).is_err());
    }

    #[test]
    fn render_rejects_a_contentless_message() {
        let msg = Msg {
            ver_major: 1,
            ver_minor: 0,
            prev: vec![],
            content: None,
            claims: vec![],
        };
        assert!(matches!(
            render_row(&msg.encode_to_vec(), "t".to_owned()),
            Err(crate::error::Error::MissingContent)
        ));
    }

    #[test]
    fn row_jsonl_roundtrip_preserves_the_row() {
        let bytes = sample_bytes();
        let row = render_row(&bytes, "2026-11-05T12:00:00Z".to_owned()).unwrap();
        let line = serde_json::to_string(&row).unwrap();
        let back: Row = serde_json::from_str(&line).unwrap();
        assert_eq!(back, row);
        assert!(fsck_row(&back).is_ok());
    }

    #[test]
    fn row_is_rg_able_by_hash_match() {
        let bytes = sample_bytes();
        let row = render_row(&bytes, "t".to_owned()).unwrap();
        let line = serde_json::to_string(&row).unwrap();
        let want = to_lower_hex(&resource_digest("text/plain", b"hello"));
        assert!(line.contains(&want));
    }
}
