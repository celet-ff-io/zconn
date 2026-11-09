use tap::Pipe as _;
use tokio::io::{AsyncBufRead, AsyncWrite};

use crate::store::Store;
use zconned_io_link::{
    ReadLink, WriteLink,
    protobuf::{Error as ProtobufLinkError, LinkStruct as ProtobufLink},
};
use zconned_stdio_types::{Handshake, IncomingFrame, PROTOCOL_VERSION};

use crate::session::Session;

/// Run the core host on the process stdio contract (storage root =
/// the default resolution, see [`storage_root`]).
pub async fn run<R, W>(stdin: &mut R, stdout: &mut W) -> crate::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    run_with_store(storage_root(), stdin, stdout).await
}

/// Run the core host against an explicit storage root (tests and
/// embedders; the CLI/config layer is deliberately deferred).
pub async fn run_with_store<R, W>(
    store_root: impl AsRef<std::path::Path>,
    stdin: &mut R,
    stdout: &mut W,
) -> crate::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let store = Store::open(store_root)
        .map_err(|e| crate::error::Error::from(Box::new(StdioHostError::StoreOpen(e))))?;
    let mut session =
        Session::open(store).map_err(|e| crate::error::Error::from(Box::new(StdioHostError::Session(e))))?;

    let mut stdio_link = ProtobufLink::builder().reader(stdin).writer(stdout).build();

    // Handshake with user via stdio
    let Handshake {
        version: user_version,
    } = stdio_link
        .read_frame()
        .await
        .map_err(|e| crate::error::Error::from(Box::new(StdioHostError::from(e))))?
        .ok_or_else(|| crate::error::Error::from(Box::new(StdioHostError::UnexpectedEof)))?;
    if user_version != PROTOCOL_VERSION {
        return Err(crate::error::Error::from(Box::new(
            StdioHostError::VersionMismatch {
                this: PROTOCOL_VERSION,
                received: user_version,
            },
        )));
    }

    Handshake {
        version: PROTOCOL_VERSION,
    }
    .pipe_ref(|m| stdio_link.write_frame(m))
    .await
    .map_err(|e| crate::error::Error::from(Box::new(StdioHostError::from(e))))?;
    log::info!("handshake with user ok (version {PROTOCOL_VERSION})");

    while let Some(incoming_frame) = stdio_link
        .read_frame::<IncomingFrame>()
        .await
        .map_err(|e| crate::error::Error::from(Box::new(StdioHostError::from(e))))?
    {
        // A commit answers with two frames (msg_added + the resting
        // draft); every other op with one.
        for outgoing_frame in session.handle(incoming_frame) {
            stdio_link
                .write_frame(&outgoing_frame)
                .await
                .map_err(|e| crate::error::Error::from(Box::new(StdioHostError::from(e))))?;
        }
    }
    log::info!("user disconnected (eof)");
    Ok(())
}

/// The storage root: ZCONNED_STORE overrides, else the XDG data dir
/// + zconned/store. (The config layer is deliberately deferred.)
fn storage_root() -> std::path::PathBuf {
    if let Some(dir) = std::env::var_os("ZCONNED_STORE") {
        return std::path::PathBuf::from(dir);
    }
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("zconned")
        .join("store")
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StdioHostError {
    #[error("{0}")]
    Link(#[from] ProtobufLinkError),

    #[error("eof when trying to read a necessary frame")]
    UnexpectedEof,

    #[error("protocol version mismatch: host version {this}, user version {received}")]
    VersionMismatch { this: u32, received: u32 },

    #[error("cannot open the record store: {0}")]
    StoreOpen(#[source] std::io::Error),

    #[error("cannot initialize the session: {0}")]
    Session(#[source] crate::error::Error),
}
