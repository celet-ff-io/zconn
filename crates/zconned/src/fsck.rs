use zconned_codec::Row;
use zconned_crypto::{DIGEST_ALGO, DIGEST_LEN};

use crate::error::{Error, Result};

/// fsck (file system check): read-only validation of a transcript
/// row — digest notation in every slot, and the claim kind-dup
/// invariant. No canonical bytes are rebuilt here.
pub fn fsck_row(row: &Row) -> Result<()> {
    if row.meta.algo != DIGEST_ALGO {
        return Err(Error::UnknownAlgo {
            expected: DIGEST_ALGO,
            found: row.meta.algo.clone(),
        });
    }
    check_digest(&row.meta.digest, "meta digest")?;
    for r in &row.msg.prev {
        check_digest(&r.digest, "prev digest")?;
    }
    check_digest(&row.msg.content.digest, "content digest")?;
    let mut seen_kinds: Vec<&str> = Vec::new();
    for c in &row.msg.claims {
        if seen_kinds.contains(&c.kind.as_str()) {
            return Err(Error::DuplicateClaimKind {
                kind: c.kind.clone(),
            });
        }
        seen_kinds.push(&c.kind);
        check_digest(&c.ref_.digest, "claim digest")?;
    }
    Ok(())
}

fn check_digest(hex: &str, what: &'static str) -> Result<()> {
    let expected = "64 lowercase hex digits";
    let is_lower_hex = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
    if hex.len() != 2 * DIGEST_LEN || !hex.bytes().all(is_lower_hex) {
        return Err(Error::DigestNotation {
            expected,
            found: format!("{what}: {hex}"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zconned_codec::{RowClaim, RowMeta, RowMsg, RowMsgRef, RowResourceRef};

    fn digest_hex(seed: u8) -> String {
        std::iter::repeat_n(seed, DIGEST_LEN)
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn valid_row() -> Row {
        Row {
            meta: RowMeta {
                ts: "2026-11-05T12:00:00Z".to_owned(),
                algo: DIGEST_ALGO.to_owned(),
                digest: digest_hex(0xab),
            },
            msg: RowMsg {
                ver_major: 1,
                ver_minor: 0,
                prev: vec![RowMsgRef {
                    ver_major: 1,
                    ver_minor: 0,
                    algo: DIGEST_ALGO.to_owned(),
                    digest: digest_hex(0xcd),
                }],
                content: RowResourceRef {
                    algo: DIGEST_ALGO.to_owned(),
                    digest: digest_hex(0x1e),
                },
                claims: vec![
                    RowClaim {
                        kind: "application/vnd.zconn.ts".to_owned(),
                        ref_: RowResourceRef {
                            algo: DIGEST_ALGO.to_owned(),
                            digest: digest_hex(0x3c),
                        },
                    },
                    RowClaim {
                        kind: "vnd.example.author".to_owned(),
                        ref_: RowResourceRef {
                            algo: DIGEST_ALGO.to_owned(),
                            digest: digest_hex(0x5a),
                        },
                    },
                ],
            },
        }
    }

    #[test]
    fn accepts_a_valid_row() {
        assert!(fsck_row(&valid_row()).is_ok());
    }

    #[test]
    fn accepts_a_genesis_row_without_claims() {
        let mut row = valid_row();
        row.msg.prev.clear();
        row.msg.claims.clear();
        assert!(fsck_row(&row).is_ok());
    }

    #[test]
    fn rejects_an_unknown_digest_algorithm() {
        let mut row = valid_row();
        row.meta.algo = "blake3".to_owned();
        assert!(matches!(fsck_row(&row), Err(Error::UnknownAlgo { .. })));
    }

    #[test]
    fn rejects_uppercase_hex_in_any_digest_slot() {
        let mut row = valid_row();
        row.meta.digest = row.meta.digest.to_uppercase();
        assert!(matches!(fsck_row(&row), Err(Error::DigestNotation { .. })));
        let mut row = valid_row();
        row.msg.content.digest = row.msg.content.digest.to_uppercase();
        assert!(matches!(fsck_row(&row), Err(Error::DigestNotation { .. })));
        let mut row = valid_row();
        row.msg.prev[0].digest = row.msg.prev[0].digest.to_uppercase();
        assert!(matches!(fsck_row(&row), Err(Error::DigestNotation { .. })));
        let mut row = valid_row();
        row.msg.claims[0].ref_.digest = row.msg.claims[0].ref_.digest.to_uppercase();
        assert!(matches!(fsck_row(&row), Err(Error::DigestNotation { .. })));
    }

    #[test]
    fn rejects_a_wrong_digest_length() {
        let mut row = valid_row();
        row.msg.content.digest.truncate(62);
        assert!(matches!(fsck_row(&row), Err(Error::DigestNotation { .. })));
    }

    #[test]
    fn rejects_duplicate_claim_kinds_without_resolution() {
        // The record-level set invariant.
        let mut row = valid_row();
        row.msg.claims[1].kind = row.msg.claims[0].kind.clone();
        assert!(matches!(
            fsck_row(&row),
            Err(Error::DuplicateClaimKind { .. })
        ));
    }
}
