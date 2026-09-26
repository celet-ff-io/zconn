pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("communicating with core subprocess: {0}")]
    Core(#[from] core::Error),

    #[error("communicating with client: {0}")]
    Client(#[from] client::Error),
}

pub mod core {
    use protobuf_varint_framer::FrameError;

    pub type Result<T> = std::result::Result<T, Error>;

    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        #[error("failed to spawn process")]
        ProcessSpawn(#[source] std::io::Error),

        #[error("pipe {name} has been already consumed")]
        ProcessStdioPipeConsumed { name: String },

        #[error("IO error when trying to access pipe")]
        PipeIO(#[source] std::io::Error),

        #[error("error occurs while framing: {0}")]
        FrameFraming(#[from] FrameError),

        #[error("EOF truncates frame")]
        TruncatedFrame,

        #[error("EOF when trying to read a necessary frame")]
        EOF,

        #[error("failed to decode frame: {0}")]
        FrameDecode(#[from] prost::DecodeError),

        #[error("protocol version mismatch: translator version {this}, core version {received}")]
        VersionMismatch { this: u32, received: u32 },
    }
}

pub mod client {
    pub type Result<T> = std::result::Result<T, Error>;

    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        #[error("EOF when trying to read a necessary frame")]
        EOF,

        #[error("while reading or writing JSONL: {0}")]
        IO(#[from] std::io::Error),

        #[error("protocol version mismatch: translator version {this}, client version {received}")]
        VersionMismatch { this: u32, received: u32 },
    }
}
