extern crate alloc;

mod api;
pub mod ed25519_program;
#[cfg(not(feature = "library"))]
mod program;
mod stdx;
#[cfg(feature = "library")]
mod verifier;

pub use api::{SignatureHash, SignaturesAccount};
#[cfg(feature = "library")]
pub use verifier::Verifier;
