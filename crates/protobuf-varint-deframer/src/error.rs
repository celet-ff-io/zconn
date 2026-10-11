use core::fmt::{Display, Formatter};

/// Terminal errors of the deframer state machine.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
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

/// The offending length-delimiter value, as declared by the wire or
/// reported as unknowable.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[non_exhaustive]
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

pub type Result<T> = core::result::Result<T, Error>;
