pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("communicating with core subprocess: {0}")]
    Core(#[from] core::Error),

    #[error("communicating with client: {0}")]
    Client(#[from] client::Error),
}

pub mod core {
    pub type Result<T> = std::result::Result<T, Error>;

    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        #[error("failed to spawn process")]
        ProcessSpawnFailed(#[source] std::io::Error),

        #[error("pipe {name} has been already consumed")]
        ProcessStdioPipeConsumed { name: String },

        #[error("IO error when trying to access pipe")]
        PipeIOError(#[source] std::io::Error),

        #[error("failed to deframe frame: {0}")]
        FrameDeframeFailed(#[from] protobuf_varint_deframer::Error),

        #[error("EOF truncates frame")]
        TruncatedFrame,

        #[error("EOF when trying to read a necessary frame")]
        UnexpectedEOF,

        #[error("failed to decode frame: {0}")]
        FrameDecodeFailed(#[from] prost::DecodeError),

        #[error("protocol version mismatch: translator version {this}, core version {received}")]
        VersionMismatch { this: u32, received: u32 },
    }
}

pub mod client {
    pub type Result<T> = std::result::Result<T, Error>;

    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        #[error("EOF when trying to read a necessary frame")]
        UnexpectedEOF,

        #[error("error when reading or writing JSONL: {0}")]
        IOError(#[from] std::io::Error),

        #[error("protocol version mismatch: translator version {this}, client version {received}")]
        VersionMismatch { this: u32, received: u32 },
    }
}
