use bytes::BytesMut;
use prost::Message;
use protobuf_varint_deframer::{Deframer, UNLIMITED_MAX_PAYLOAD_LENGTH};
use tap::Pipe as _;
use tokio::io::{AsyncBufRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::{ReadCodec, ReadLink, WriteCodec, WriteLink};

pub struct CodecStruct<'a, R, W> {
    deframer: &'a mut Deframer,
    buf: &'a mut BytesMut,
    reader: R,
    writer: W,
}

impl<'a, R, W> From<&'a mut LinkStruct<R, W>> for CodecStruct<'a, &'a mut R, &'a mut W>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn from(link: &'a mut LinkStruct<R, W>) -> Self {
        Self {
            deframer: &mut link.deframer,
            buf: &mut link.buf,
            reader: &mut link.reader,
            writer: &mut link.writer,
        }
    }
}

impl<'a, T, R, W> ReadCodec<T> for CodecStruct<'a, R, W>
where
    T: Message + Default,
    R: AsyncBufRead + Unpin,
{
    type Error = Error;

    async fn read_frame(&mut self) -> Result<Option<T>> {
        loop {
            if let Some(record) = self.deframer.feed(&mut self.buf)? {
                return T::decode(record).map(Some)?.pipe(Ok);
            }
            if self.reader.read_buf(&mut self.buf).await? == 0 {
                return if self.deframer.is_idle() {
                    Ok(None)
                } else {
                    Err(Error::TruncatedFrame)
                };
            }
        }
    }
}

impl<'a, T, R, W> WriteCodec<T> for CodecStruct<'a, R, W>
where
    T: Message,
    W: AsyncWrite + Unpin,
{
    type Error = Error;

    async fn write_frame(&mut self, frame: &T) -> Result<()> {
        frame
            .encode_length_delimited_to_vec()
            .pipe(async |buf| {
                let writer = &mut self.writer;
                writer.write_all(&buf).await?;
                writer.flush().await?;
                Ok(())
            })
            .await
    }
}

pub struct LinkStruct<R, W> {
    deframer: Deframer,
    buf: BytesMut,
    reader: R,
    writer: W,
}

impl<R, W> LinkStruct<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            deframer: Deframer::builder()
                .max_payload_length(UNLIMITED_MAX_PAYLOAD_LENGTH)
                .build(),
            buf: BytesMut::new(),
            reader,
            writer,
        }
    }
}

impl<R, W> ReadLink for LinkStruct<R, W>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    type Codec<'a>
        = CodecStruct<'a, &'a mut R, &'a mut W>
    where
        Self: 'a;

    type Error = Error;

    async fn read_frame<'a, T>(&'a mut self) -> Result<Option<T>>
    where
        Self::Codec<'a>: ReadCodec<T, Error = Self::Error>,
    {
        self.pipe(CodecStruct::from).read_frame().await
    }
}

impl<R, W> WriteLink for LinkStruct<R, W>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    type Codec<'a>
        = CodecStruct<'a, &'a mut R, &'a mut W>
    where
        Self: 'a;

    type Error = Error;

    async fn write_frame<'a, T>(&'a mut self, frame: &T) -> Result<()>
    where
        Self::Codec<'a>: WriteCodec<T, Error = Self::Error>,
    {
        self.pipe(CodecStruct::from).write_frame(frame).await
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to deframe frame: {0}")]
    FrameDeframeFailed(#[from] protobuf_varint_deframer::Error),

    #[error("eof truncates frame")]
    TruncatedFrame,

    #[error("failed to decode frame: {0}")]
    FrameDecodeFailed(#[from] prost::DecodeError),
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use zconned_stdio_types::{IncomingFrame, MsgDraftCommit, MsgThreadsGet, incoming_frame::Method};

    use super::LinkStruct;

    /// When a single `read_buf` delivers more than one complete frame,
    /// `Deframer::feed` returns after the first one and leaves the rest
    /// in the caller's buffer; a per-call chunk drops them. Frames must
    /// survive in a persistent buffer.
    #[tokio::test]
    async fn multiple_frames_in_one_read_buf_are_not_lost() {
        let encode = |frame: IncomingFrame| frame.encode_length_delimited_to_vec();
        let data = [
            encode(IncomingFrame {
                method: Some(Method::MsgThreadsGet(MsgThreadsGet {})),
            }),
            encode(IncomingFrame {
                method: Some(Method::MsgDraftCommit(MsgDraftCommit {})),
            }),
        ]
        .concat();
        // `&[u8]` hands its whole content over in a single `read_buf`.
        let mut link = LinkStruct::new(&data[..], tokio::io::sink());

        let first: IncomingFrame = link.read_frame().await.unwrap().unwrap();
        assert!(matches!(first.method, Some(Method::MsgThreadsGet(_))));

        let second: IncomingFrame = link.read_frame().await.unwrap().unwrap();
        assert!(matches!(second.method, Some(Method::MsgDraftCommit(_))));

        // Both frames consumed: EOF on an idle deframer is a clean end.
        let eof: Option<IncomingFrame> = link.read_frame().await.unwrap();
        assert!(eof.is_none());
    }
}
