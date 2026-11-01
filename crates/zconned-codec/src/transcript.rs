use serde::{Deserialize, Serialize};

use zconned_material::Msg;

/// One transcript.jsonl row: the at-rest record of exactly one
/// message (R-a v2 row grammar; exactly the `meta` and `msg` keys
/// — sys rows live in a separate LOG file, never here).
///
/// `meta` = observer facts (local record time, computed algo/digest
/// — never transmitted, never hashed into the material); `msg` =
/// the material, serialized verbatim as the pbjson projection of
/// [`Msg`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptRow {
    /// Observer-side annotations.
    pub meta: RowMeta,
    /// The message material, verbatim pbjson projection.
    pub msg: Msg,
}

/// The observer-facts half of a [`TranscriptRow`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowMeta {
    /// Local record time, RFC 3339.
    pub ts: String,
    /// Digest algorithm name; the name implies the output length.
    pub algo: String,
    /// Lowercase hex digest of the message's canonical bytes.
    pub digest: String,
}
