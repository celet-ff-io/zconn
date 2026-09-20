#[derive(Debug, thiserror::Error)]
pub enum ZconnedError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),
}

pub type ZconnedResult<T> = std::result::Result<T, ZconnedError>;
