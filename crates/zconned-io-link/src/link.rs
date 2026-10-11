pub trait ReadLink {
    type Codec<'a>
    where
        Self: 'a;

    type Error;

    #[expect(async_fn_in_trait)]
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

    #[expect(async_fn_in_trait)]
    async fn write_frame<'a, T>(&'a mut self, frame: &T) -> Result<(), Self::Error>
    where
        Self: 'a,
        Self::Codec<'a>: WriteCodec<T, Error = Self::Error>;
}

pub trait ReadCodec<T> {
    type Error;

    #[expect(async_fn_in_trait)]
    async fn read_frame(&mut self) -> Result<Option<T>, Self::Error>;
}

pub trait WriteCodec<T> {
    type Error;

    #[expect(async_fn_in_trait)]
    async fn write_frame(&mut self, frame: &T) -> Result<(), Self::Error>;
}
