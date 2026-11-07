//! Serialization views for zconned types (JSON and text forms).
//! At-rest record forms live here too (transcript rows).

mod error;
mod peer;
mod transcript;

pub use error::CodecError;
pub use peer::PublicKeySetJson;
pub use transcript::{ResourceRow, Row, RowClaim, RowMeta, RowMsg, RowMsgRef, RowResourceRef};
