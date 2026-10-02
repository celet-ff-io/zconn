use std::process::Stdio;

use bytes::BytesMut;
use prost::Message;
use protobuf_varint_deframer::Deframer;
use serde_jsonlines::{AsyncJsonLinesReader, AsyncJsonLinesWriter};
use tap::Pipe as _;
use tokio::{
    io::{AsyncBufRead, AsyncWrite, BufReader},
    process::{Child, Command},
};
use zconned_types::{Handshake, IncomingFrame, OutgoingFrame, PROTOCOL_VERSION};

use crate::{
    Result,
    error::{self, client::Error as ClientError, core::Error as CoreError},
};

pub async fn run<R, W>(zconned_bin: &str, client_in: &mut R, client_out: &mut W) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let core_process = spawn_core(zconned_bin)?;
    let mut core_link = core::Link::new(
        take_stdio(core_process.stdout, "stdout")?.pipe(BufReader::new),
        take_stdio(core_process.stdin, "stdin")?,
    );

    // Handshake with core: translator - hs -> core
    Handshake { version: 1 }
        .pipe_ref(|m| core_link.write_frame(m))
        .await?;

    let Handshake {
        version: core_version,
    } = core_link.read_exact_frame().await?;
    if core_version != PROTOCOL_VERSION {
        CoreError::VersionMismatch {
            this: PROTOCOL_VERSION,
            received: core_version,
        }
        .pipe(Err)?;
    }

    // Handshake with client: client - hs -> translator
    let mut client_link = client::Link::new(
        AsyncJsonLinesReader::new(client_in),
        AsyncJsonLinesWriter::new(client_out),
    );
    let Handshake {
        version: client_version,
    } = client_link.read_exact_frame().await?;
    if client_version != PROTOCOL_VERSION {
        ClientError::VersionMismatch {
            this: PROTOCOL_VERSION,
            received: client_version,
        }
        .pipe(Err)?;
    }

    while let Some(frame_from_client) = client_link.read_frame::<IncomingFrame>().await? {
        core_link.write_frame(&frame_from_client).await?;

        let frame_from_core: OutgoingFrame = core_link.read_exact_frame().await?;
        client_link.write_frame(&frame_from_core).await?;
    }

    Ok(())
}

#[inline]
fn spawn_core(core: &str) -> error::core::Result<Child> {
    Command::new(core)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(CoreError::ProcessSpawnFailed)
}

fn take_stdio<T>(mut opt: Option<T>, name: &str) -> Result<T> {
    opt.take()
        .ok_or_else(|| CoreError::ProcessStdioPipeConsumed {
            name: name.to_owned(),
        })?
        .pipe(Ok)
}

mod core {
    use protobuf_varint_deframer::UNLIMITED_MAX_PAYLOAD_LENGTH;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    use crate::error::core::{Error, Result};

    pub struct Link<R, W> {
        framer: Deframer,
        reader: R,
        writer: W,
    }

    impl<R, W> Link<R, W>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        pub fn new(reader: R, writer: W) -> Self {
            Self {
                framer: Deframer::builder()
                    .max_payload_length(UNLIMITED_MAX_PAYLOAD_LENGTH)
                    .build(),
                reader,
                writer,
            }
        }

        #[inline]
        pub async fn read_exact_frame<T: Message + Default>(&mut self) -> Result<T> {
            self.read_frame().await?.ok_or(Error::UnexpectedEOF)
        }

        /// Read a frame from core.
        pub async fn read_frame<T: Message + Default>(&mut self) -> Result<Option<T>> {
            loop {
                let mut chunk = BytesMut::new();
                if self
                    .reader
                    .read_buf(&mut chunk)
                    .await
                    .map_err(Error::PipeIOError)?
                    == 0
                {
                    // EOF
                    return if self.framer.is_idle() {
                        Ok(None)
                    } else {
                        Error::TruncatedFrame.pipe(Err)
                    };
                }
                if let Some(payload) = self
                    .framer
                    .feed(&mut chunk)
                    .map_err(Error::FrameDeframeFailed)?
                {
                    return payload.pipe(T::decode)?.pipe(Some).pipe(Ok);
                }
            }
        }

        pub async fn write_frame<T: Message>(&mut self, message: &T) -> Result<()> {
            message
                .encode_length_delimited_to_vec()
                .pipe(async |buf| {
                    let writer = &mut self.writer;
                    writer.write_all(&buf).await?;
                    writer.flush().await?;
                    Ok(())
                })
                .await
                .map_err(Error::PipeIOError)?
                .pipe(Ok)
        }
    }
}

mod client {
    use super::*;

    use serde::{Serialize, de::DeserializeOwned};
    use tokio::io::{AsyncBufRead, AsyncWrite};

    use crate::error::client::{Error, Result};

    pub struct Link<R, W> {
        reader: AsyncJsonLinesReader<R>,
        writer: AsyncJsonLinesWriter<W>,
    }

    impl<R, W> Link<R, W>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        pub fn new(reader: AsyncJsonLinesReader<R>, writer: AsyncJsonLinesWriter<W>) -> Self {
            Self { reader, writer }
        }

        #[inline]
        pub async fn read_exact_frame<T: DeserializeOwned>(&mut self) -> Result<T> {
            self.read_frame().await?.ok_or(Error::UnexpectedEOF)
        }

        pub async fn read_frame<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
            self.reader.read::<T>().await?.pipe(Ok)
        }

        pub async fn write_frame<T: Serialize>(&mut self, message: &T) -> Result<()> {
            self.writer.write(message).await.map_err(Error::from)
        }
    }
}
