extern crate alloc;

mod api;
pub mod ed25519_program;
#[cfg(not(feature = "lib"))]
mod program;
mod stdx;
#[cfg(feature = "lib")]
mod verifier;

pub use api::{SigHash, SignaturesAccount};
#[cfg(feature = "lib")]
pub use verifier::Verifier;
