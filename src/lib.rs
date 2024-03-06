extern crate alloc;

mod api;
pub mod ed25519_program;
#[cfg(not(feature = "library"))]
mod program;
mod stdx;

pub use api::{SignatureHash, SignaturesAccount};
