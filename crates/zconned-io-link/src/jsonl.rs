use serde::{Serialize, de::DeserializeOwned};
use serde_jsonlines::{AsyncJsonLinesReader, AsyncJsonLinesWriter};
use tap::Pipe as _;
use tokio::io::{AsyncBufRead, AsyncWrite};
use typed_builder::TypedBuilder;

use crate::{ReadCodec, ReadLink, WriteCodec, WriteLink};

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
        let writer = &mut self.writer;
        writer.write(frame).await?;
        writer.flush().await?;
        Ok(())
    }
}

#[derive(TypedBuilder)]
pub struct LinkStruct<R, W> {
    #[builder(setter(transform = |reader: R| reader.pipe(AsyncJsonLinesReader::new)))]
    reader: AsyncJsonLinesReader<R>,

    #[builder(setter(transform = |writer: W| writer.pipe(AsyncJsonLinesWriter::new)))]
    writer: AsyncJsonLinesWriter<W>,
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
#[non_exhaustive]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to decode frame: {0}")]
    FrameDecodeFailed(#[source] std::io::Error),
}

pub type Result<T> = core::result::Result<T, Error>;
