pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("communicating with core subprocess: {0}")]
    CoreProcess(#[from] core_process::Error),

    #[error("communicating with client: {0}")]
    ClientProcess(#[from] client_process::Error),
}

pub mod core_process {
    use zconned_io_link::protobuf::Error as ProtobufLinkError;

    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        #[error("failed to spawn process")]
        ProcessSpawnFailed(#[source] std::io::Error),

        #[error("pipe {name} has been already consumed")]
        ProcessStdioPipeConsumed { name: String },

        #[error("io error: {0}")]
        PipeIo(#[from] std::io::Error),

        #[error("{0}")]
        Link(#[from] ProtobufLinkError),

        #[error("eof when trying to read a necessary frame")]
        UnexpectedEof,

        #[error("protocol version mismatch: translator version {this}, core version {received}")]
        VersionMismatch { this: u32, received: u32 },
    }
}

pub mod client_process {
    use zconned_io_link::jsonl::Error as JsonlLinkError;

    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        #[error("io error: {0}")]
        Io(#[from] std::io::Error),

        #[error("{0}")]
        Link(#[from] JsonlLinkError),

        #[error("eof when trying to read a necessary frame")]
        UnexpectedEof,

        #[error("protocol version mismatch: translator version {this}, client version {received}")]
        VersionMismatch { this: u32, received: u32 },
    }
}
