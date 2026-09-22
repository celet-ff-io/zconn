mod error;
mod server;

pub use error::{ZconnedError, ZconnedResult};
pub use server::run;
