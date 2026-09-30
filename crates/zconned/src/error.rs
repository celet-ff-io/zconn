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

    #[error("EOF truncates frame")]
    TruncatedFrame,

    #[error("failed to deframe frame: {0}")]
    FrameDeframeFailed(#[from] protobuf_varint_deframer::Error),
}

pub type ZconnedResult<T> = std::result::Result<T, ZconnedError>;
