//! The at-rest record layer: rendering received messages into
//! transcript rows and validating rows (fsck — file system check,
//! here: read-only row consistency checking).
//!
//! File-free by contract: appending and storing transcript.jsonl
//! belongs to the consuming CLI (persistence = interface layer).

mod error;
mod fsck;
mod render;

pub use error::{Error, Result};
pub use fsck::fsck_row;
pub use render::render_row;
