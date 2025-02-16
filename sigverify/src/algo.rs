use core::num::NonZeroU32;

use solana_program::pubkey::Pubkey;

use crate::SigHash;


/// An opaque magic token used to identify different signature types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Magic(core::num::NonZeroU32);

impl Magic {
    pub(crate) fn to_bytes(self) -> [u8; 4] { self.0.get().to_le_bytes() }
}


/// Specifies a signature algorithm.
pub trait Algorithm {
    /// Magic used for this algorithm when constructing [`SigHash`].
    fn magic() -> Magic;

    /// Address of the native program verifying signatures of this type.
    fn program_id() -> Pubkey;

    /// Checks whether given program ID corresponds to the native program
    /// verifying signatures of this type.
    fn check_id(id: Pubkey) -> bool { id == Self::program_id() }

    /// Calculates a [`SigHash`] for signature of this algorithm.
    fn sighash(
        pubkey: &[u8; 32],
        signature: &[u8; 64],
        message: &[u8],
    ) -> SigHash {
        SigHash::new(Self::magic(), pubkey, signature, message)
    }

    /// Calculates a [`SigHash`] for signature of this algorithm.
    fn sighash_entry(entry: solana_native_sigverify::Entry) -> SigHash {
        SigHash::from_entry(Self::magic(), entry)
    }

    /// Creates an instruction calling a native signature verification program.
    ///
    /// This is a wrapper around [`solana_native_sigverify::new_instruction`].
    fn new_instruction(
        entries: &[solana_native_sigverify::Entry],
    ) -> Option<solana_program::instruction::Instruction> {
        solana_native_sigverify::new_instruction(Self::program_id(), entries)
    }
}


macro_rules! define {
    ($($name:ident, $magic:expr, $id:ident;)*) => {
        $(
            #[doc = concat!("Specification for the ", stringify!($name), " algorithm.")]
            pub struct $name;

            impl $name {
                /// Magic used for this algorithm when constructing [`SigHash`].
                pub const MAGIC: Magic = match NonZeroU32::new(u32::from_le_bytes(*$magic)) {
                    Some(magic) => Magic(magic),
                    None => unreachable!(),
                };

                /// Address of the native program verifying signatures of this type.
                pub const ID: Pubkey = solana_native_sigverify::$id;
            }

            impl Algorithm for $name {
                fn magic() -> Magic { Self::MAGIC }
                fn program_id() -> Pubkey { Self::ID }
            }
        )*

        #[test]
        fn test_unique_magic() {
            let magic = [
                $( (stringify!($name), $name::MAGIC), )*
            ];
            for (i, this) in magic.iter().enumerate() {
                for other in magic[..i].iter() {
                    assert_ne!(other.1, this.1, "{} same as {}", other.0, this.0);
                }
            }
        }

        /// Identifies algorithm from ID of the native program verifying
        /// signatures of that algorithm.
        ///
        /// Returns a magic token used in [`SigHash`] or `None` if the algorithm
        /// cannot be identified.
        ///
        /// # Example
        ///
        /// ```
        /// use solana_sigverify::algo;
        ///
        /// assert_eq!(Some(algo::Ed25519::MAGIC),
        ///            algo::from_id(algo::Ed25519::ID));
        /// ```
        pub fn from_id(id: Pubkey) -> Option<Magic> {
            $(
                if $name::ID == id {
                    return Some($name::MAGIC)
                }
            )*
            None
        }

        #[test]
        fn test_from_id() {
            $( assert_eq!(Some($name::MAGIC), from_id($name::ID)); )*
            assert_eq!(None, from_id(solana_program::system_program::ID));
        }
    }
}

define! {
    Ed25519, b"ed\xff\x13", ED25519_PROGRAM_ID;

    // See https://www.secg.org/sec2-v2.pdf for different sec algorithms.  The
    // magic format chosen is 's', followed by number in the algorithm mod 256
    // and then 'k#' or 'r#'.  Most of the algorithms won’t be supported by
    // Solana but this scheme allows for all of them to be used.
    Secp256k1, b"s\x00k1", SECP256K1_PROGRAM_ID;
    Secp256r1, b"s\x00r1", SECP256R1_PROGRAM_ID;
}
