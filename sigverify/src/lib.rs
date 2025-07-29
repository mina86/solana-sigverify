// solana-sigverify — Solana program and library for dealing with aggregating
//                    signature verification.
// © 2024 by Composable Foundation
// © 2025 by Michał Nazarewicz <mina86@mina86.com>
//
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation; either version 2 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, see <https://www.gnu.org/licenses/>.

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
