use crate::host::StdioHostError;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("stdio host error: {0}")]
    StdioHost(#[from] StdioHostError),
}
