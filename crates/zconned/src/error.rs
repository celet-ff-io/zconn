use crate::host::StdioHostError;

pub type Result<T> = core::result::Result<T, Error>;

/// Top-level error of the zconned core.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("stdio host error: {0}")]
    StdioHost(#[from] Box<StdioHostError>),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("material decode error: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error("unknown digest algorithm: expected {expected}, found {found}")]
    UnknownAlgo {
        expected: &'static str,
        found: String,
    },

    #[error("digest notation: expected {expected}, found {found}")]
    DigestNotation {
        expected: &'static str,
        found: String,
    },

    #[error("message has no content: the anchor row requires one")]
    MissingContent,

    #[error("duplicate claim kind: {kind} (the claims set is keyed by kind)")]
    DuplicateClaimKind { kind: String },

    #[error("anchor/value binding failure: {why}")]
    AnchorBinding { why: String },
}
