extern crate alloc;

mod api;
#[cfg(not(feature = "library"))]
mod program;
mod stdx;

pub use api::{SigEntryError, SignatureHash, SignaturesAccount};
