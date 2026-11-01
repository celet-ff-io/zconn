#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
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
}

pub type Result<T> = std::result::Result<T, Error>;
