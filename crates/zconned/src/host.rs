use tap::Pipe as _;
use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio::time::{Duration, sleep};

use zconned_io_link::{
    ReadLink, WriteLink,
    protobuf::{Error as ProtobufLinkError, LinkStruct as ProtobufLink},
};
use zconned_stdio_types::{Handshake, IncomingFrame, OutgoingFrame, PROTOCOL_VERSION};

const ECHO_DELAY: Duration = Duration::from_secs(1);

pub async fn run<R, W>(stdin: &mut R, stdout: &mut W) -> crate::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut stdio_link = ProtobufLink::new(stdin, stdout);

    // Handshake with user via stdio
    let Handshake {
        version: user_version,
    } = stdio_link
        .read_frame()
        .await
        .map_err(StdioHostError::from)?
        .ok_or(StdioHostError::UnexpectedEof)?;
    if user_version != PROTOCOL_VERSION {
        StdioHostError::VersionMismatch {
            this: PROTOCOL_VERSION,
            received: user_version,
        }
        .pipe(Err)?;
    }

    Handshake {
        version: PROTOCOL_VERSION,
    }
    .pipe_ref(|m| stdio_link.write_frame(m))
    .await
    .map_err(StdioHostError::from)?;
    log::info!("handshake with user ok (version {PROTOCOL_VERSION})");

    while let Some(incoming_frame) = stdio_link
        .read_frame::<IncomingFrame>()
        .await
        .map_err(StdioHostError::from)?
    {
        let outgoing_frame = response(incoming_frame).await;
        stdio_link
            .write_frame(&outgoing_frame)
            .await
            .map_err(StdioHostError::from)?;
    }
    log::info!("user disconnected (eof)");
    Ok(())
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
}

async fn response(incoming_frame: IncomingFrame) -> OutgoingFrame {
    sleep(ECHO_DELAY).await; // the 1s echo contract
    OutgoingFrame {
        text: format!("hello {}", incoming_frame.text),
    }
}
