/// Errors surfaced by the crypto crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    #[error("malformed master encoding: expected {expected} bytes of raw master, found {found}")]
    InvalidMasterFormat { expected: usize, found: usize },

    #[error("os entropy failure: {0}")]
    Entropy(#[from] getrandom::Error),
}
