#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CodecError {
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("field `{field}`: expected {expected}, found {found}")]
    Field {
        field: &'static str,

        expected: usize,

        found: usize,
    },
}
