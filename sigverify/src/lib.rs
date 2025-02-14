extern crate alloc;

pub mod algo;
mod api;
#[cfg(feature = "client")]
pub mod instruction;
#[cfg(not(any(feature = "client", feature = "lib")))]
mod program;
mod stdx;
#[cfg(feature = "lib")]
mod verifier;

pub use api::{SigHash, SignaturesAccount};
#[cfg(feature = "lib")]
pub use verifier::{
    Ed25519Verifier, Secp256k1Verifier, Secp256r1Verifier, Verifier,
};
