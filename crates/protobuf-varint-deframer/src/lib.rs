mod deframe;
mod error;

pub use deframe::{
    DEFAULT_MAX_PAYLOAD_LENGTH, Deframer, MAX_LENGTH_DELIMITER, UNLIMITED_MAX_PAYLOAD_LENGTH,
};
pub use error::{Error, LengthDelimiterExcess, Result};
