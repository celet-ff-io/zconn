use crate::host::StdioHostError;

pub type Result<T> = core::result::Result<T, Error>;

/// Top-level error of the zconned core host.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("stdio host error: {0}")]
    StdioHost(#[from] StdioHostError),
}
