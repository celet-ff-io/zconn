use std::fmt::{Display, Formatter};

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Payload length exceeds the maximum allowed value.
    ///
    /// Big payload may raise this error unexpectedly,
    /// so it is recommended to set a reasonable maximum payload length
    /// according to your application scenario and memory size.
    #[error("payload length {actual} exceeds maximum {max}")]
    PayloadLengthTooLarge { actual: usize, max: usize },

    #[error("{actual} exceeds maximum {max} in protocol")]
    LengthDelimiterExceedsProtocolMax {
        actual: LengthDelimiterExcess,
        max: u64,
    },

    #[error("prost decode length delimiter error: {0}")]
    ProstDecodeLengthDelimiterError(#[from] prost::DecodeError),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum LengthDelimiterExcess {
    Declared(u64),
    Unknown,
}

impl From<u64> for LengthDelimiterExcess {
    fn from(value: u64) -> Self {
        LengthDelimiterExcess::Declared(value)
    }
}

impl Display for LengthDelimiterExcess {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LengthDelimiterExcess::Declared(len) => write!(f, "length delimiter {len}"),
            LengthDelimiterExcess::Unknown => write!(f, "unknown length delimiter"),
        }
    }
}

pub type FrameResult<T> = Result<T, FrameError>;
