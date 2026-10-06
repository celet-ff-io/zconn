use bytes::BytesMut;
use prost::Message;
use tap::Pipe as _;

pub trait ReadLink {
    type Codec<'a>
    where
        Self: 'a;

    type Error;

    async fn read_frame<'a, T>(&'a mut self) -> Result<Option<T>, Self::Error>
    where
        Self: 'a,
        Self::Codec<'a>: ReadCodec<T, Error = Self::Error>;
}

pub trait WriteLink {
    type Codec<'a>
    where
        Self: 'a;

    type Error;

    async fn write_frame<'a, T>(&'a mut self, frame: &T) -> Result<(), Self::Error>
    where
        Self: 'a,
        Self::Codec<'a>: WriteCodec<T, Error = Self::Error>;
}

pub trait ReadCodec<T> {
    type Error;

    async fn read_frame(&mut self) -> Result<Option<T>, Self::Error>;
}

pub trait WriteCodec<T> {
    type Error;

    async fn write_frame(&mut self, frame: &T) -> Result<(), Self::Error>;
}

pub mod protobuf {
    use super::*;

    use protobuf_varint_deframer::{Deframer, UNLIMITED_MAX_PAYLOAD_LENGTH};
    use tokio::io::{AsyncBufRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

    pub struct CodecStruct<'a, R, W> {
        deframer: &'a mut Deframer,
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
                let mut chunk = BytesMut::new();
                if self.reader.read_buf(&mut chunk).await? == 0 {
                    return if self.deframer.is_idle() {
                        Ok(None)
                    } else {
                        Err(Error::TruncatedFrame)
                    };
                }
                if let Some(record) = self.deframer.feed(&mut chunk)? {
                    return T::decode(record).map(Some)?.pipe(Ok);
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
        reader: R,
        writer: W,
    }

    impl<R, W> LinkStruct<R, W> {
        pub fn new(reader: R, writer: W) -> Self {
            Self {
                deframer: Deframer::builder()
                    .max_payload_length(UNLIMITED_MAX_PAYLOAD_LENGTH)
                    .build(),
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
    pub enum Error {
        #[error("io error: {0}")]
        Io(#[from] std::io::Error),

        #[error("failed to deframe frame: {0}")]
        FrameDeframeFailed(#[from] protobuf_varint_deframer::Error),

        #[error("eof truncates frame")]
        TruncatedFrame,

        #[error("eof when trying to read a necessary frame")]
        UnexpectedEof,

        #[error("failed to decode frame: {0}")]
        FrameDecodeFailed(#[from] prost::DecodeError),
    }

    pub type Result<T> = core::result::Result<T, Error>;
}

pub mod jsonl {
    use super::*;

    use serde::{Serialize, de::DeserializeOwned};
    use serde_jsonlines::{AsyncJsonLinesReader, AsyncJsonLinesWriter};
    use tokio::io::{AsyncBufRead, AsyncWrite};

    pub struct CodecStruct<'a, R, W> {
        reader: &'a mut AsyncJsonLinesReader<R>,
        writer: &'a mut AsyncJsonLinesWriter<W>,
    }

    impl<'a, R, W> From<&'a mut LinkStruct<R, W>> for CodecStruct<'a, R, W>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        fn from(link: &'a mut LinkStruct<R, W>) -> Self {
            Self {
                reader: &mut link.reader,
                writer: &mut link.writer,
            }
        }
    }

    impl<'a, T, R, W> ReadCodec<T> for CodecStruct<'a, R, W>
    where
        T: DeserializeOwned,
        R: AsyncBufRead + Unpin,
    {
        type Error = Error;

        async fn read_frame(&mut self) -> Result<Option<T>> {
            self.reader
                .read::<T>()
                .await
                .map_err(Error::FrameDecodeFailed)
        }
    }

    impl<'a, T, R, W> WriteCodec<T> for CodecStruct<'a, R, W>
    where
        T: Serialize,
        W: AsyncWrite + Unpin,
    {
        type Error = Error;
        async fn write_frame(&mut self, frame: &T) -> Result<()> {
            self.writer.write(frame).await.map_err(Error::from)
        }
    }

    pub struct LinkStruct<R, W> {
        reader: AsyncJsonLinesReader<R>,
        writer: AsyncJsonLinesWriter<W>,
    }

    impl<R, W> LinkStruct<R, W> {
        pub fn new(reader: R, writer: W) -> Self {
            Self {
                reader: reader.pipe(AsyncJsonLinesReader::new),
                writer: writer.pipe(AsyncJsonLinesWriter::new),
            }
        }
    }

    impl<R, W> ReadLink for LinkStruct<R, W>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        type Codec<'a>
            = CodecStruct<'a, R, W>
        where
            Self: 'a;

        type Error = Error;

        async fn read_frame<'a, T>(&'a mut self) -> Result<Option<T>>
        where
            Self: 'a,
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
            = CodecStruct<'a, R, W>
        where
            Self: 'a;
        type Error = Error;

        async fn write_frame<'a, T>(&'a mut self, frame: &T) -> Result<()>
        where
            Self: 'a,
            Self::Codec<'a>: WriteCodec<T, Error = Self::Error>,
        {
            self.pipe(CodecStruct::from).write_frame(frame).await
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        #[error("io error: {0}")]
        Io(#[from] std::io::Error),

        #[error("eof truncates frame")]
        TruncatedFrame,

        #[error("eof when trying to read a necessary frame")]
        UnexpectedEof,

        #[error("failed to decode frame: {0}")]
        FrameDecodeFailed(#[source] std::io::Error),
    }

    pub type Result<T> = core::result::Result<T, Error>;
}
