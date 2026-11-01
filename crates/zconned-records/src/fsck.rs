use zconned_codec::TranscriptRow;
use zconned_crypto::{DIGEST_ALGO, DIGEST_LEN};

use crate::error::{Error, Result};

/// fsck (file system check): read-only consistency validation of a
/// transcript row. Checks the digest algorithm recognition and the
/// digest notation (lowercase hex; the algorithm name implies the
/// output length). The row grammar (exactly `meta` and `msg`) is
/// enforced by the dto's serde at parse time; the message structure
/// is enforced by the `Msg` type itself.
pub fn fsck_row(row: &TranscriptRow) -> Result<()> {
    if row.meta.algo != DIGEST_ALGO {
        return Err(Error::UnknownAlgo {
            expected: DIGEST_ALGO,
            found: row.meta.algo.clone(),
        });
    }
    let expected = "64 lowercase hex digits";
    let is_lower_hex = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
    if row.meta.digest.len() != 2 * DIGEST_LEN || !row.meta.digest.bytes().all(is_lower_hex) {
        return Err(Error::DigestNotation {
            expected,
            found: row.meta.digest.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zconned_codec::RowMeta;
    use zconned_material::{Meta, Msg, Node};

    fn valid_row() -> TranscriptRow {
        TranscriptRow {
            meta: RowMeta {
                ts: "2026-10-28T12:00:00Z".to_owned(),
                algo: "sha3-256".to_owned(),
                digest: "ab".repeat(DIGEST_LEN),
            },
            msg: Msg {
                ver_major: 1,
                ver_minor: 0,
                body: Some(Node {
                    meta: Some(Meta { prev: vec![] }),
                    kind: "text/plain".to_owned(),
                    data: b"hi".to_vec(),
                }),
            },
        }
    }

    #[test]
    fn accepts_a_valid_row() {
        assert!(fsck_row(&valid_row()).is_ok());
    }

    #[test]
    fn rejects_an_unknown_digest_algorithm() {
        let mut row = valid_row();
        row.meta.algo = "blake3".to_owned();
        assert!(matches!(fsck_row(&row), Err(Error::UnknownAlgo { .. })));
    }

    #[test]
    fn rejects_uppercase_hex() {
        let mut row = valid_row();
        row.meta.digest = row.meta.digest.to_uppercase();
        assert!(matches!(fsck_row(&row), Err(Error::DigestNotation { .. })));
    }

    #[test]
    fn rejects_a_wrong_digest_length() {
        let mut row = valid_row();
        row.meta.digest.truncate(62);
        assert!(matches!(fsck_row(&row), Err(Error::DigestNotation { .. })));
    }
}
