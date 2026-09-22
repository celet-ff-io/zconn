use protobuf_varint_framer::FrameError;

#[derive(Debug, thiserror::Error)]
pub enum ZconnedError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("protocol version mismatch: expected {expected}, received {received}")]
    VersionMismatch { expected: u32, received: u32 },

    #[error("truncated frame at EOF")]
    TruncatedFrame,

    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
}

pub type ZconnedResult<T> = std::result::Result<T, ZconnedError>;
