//! Utilities for creating and parsing native signature verification program
//! instruction data.
//!
//! Solana runtime provides native programs for performing signature
//! verification (henceforth referred to as native signature verification
//! programs).  Unfortunately, interface for interfacing with those programs is
//! rather lacking.
//!
//! This crate offers functions for creating instruction calling the native
//! signature verification programs as well as parsing their instruction data.

use solana_program::instruction::Instruction;
use solana_program::pubkey::Pubkey;

mod stdx;


/// Offsets used in instruction data of native signature verification programs.
///
/// This is a low-level structure.  Typically you’d want to use higher level
/// interface: [`new_instruction`] for creating instruction calling the native
/// signature verification program or [`parse_data`] for parsing its instruction
/// data.
///
/// All integers are stored as little-endian.
// Copied from but we’re using
// https://github.com/solana-labs/solana/blob/master/sdk/src/ed25519_instruction.rs
#[derive(Copy, Clone, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
pub struct SignatureOffsets {
    pub signature_offset: u16, // offset to ed25519 signature of 64 bytes
    pub signature_instruction_index: u16, // instruction index to find signature
    pub pubkey_offset: u16,    // offset to public key of 32 bytes
    pub pubkey_instruction_index: u16, // instruction index to find public key
    pub message_offset: u16,   // offset to start of message data
    pub message_size: u16,     // size of message data
    pub message_instruction_index: u16, // index of instruction data to get message data
}

const OFF_SIZE: usize = core::mem::size_of::<SignatureOffsets>();


/// A parse signature from the Ed25519 native program.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Entry<'a> {
    pub signature: &'a [u8; 64],
    pub pubkey: &'a [u8; 32],
    pub message: &'a [u8],
}


/// Address of the Ed25519 native program.
pub const ED25519_PROGRAM_ID: Pubkey = solana_program::ed25519_program::ID;
/// Address of the Secp255k1 native program.
pub const SECP256K1_PROGRAM_ID: Pubkey = solana_program::secp256k1_program::ID;
/// Address of the Secp255r1 native program.
// This isn’t defined in solana-program 1.18 but documentation lists it, see
// <https://solana.com/docs/core/programs#secp256r1-program>.
pub const SECP256R1_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("Secp256r1SigVerify1111111111111111111111111");


/// Creates an instruction calling a native signature verification program.
///
/// `program_id` specifies the address of the signature verification program and
/// typically is one of [`ED25519_PROGRAM_ID`], [`SECP256K1_PROGRAM_ID`] or
/// [`SECP256R1_PROGRAM_ID`].  The function can be used for other signature
/// verification programs so long as they use the same calling convention.
///
/// See [`new_instruction_data`] for possible error conditions and notes about
/// space optimisation.
pub fn new_instruction(
    program_id: Pubkey,
    entries: &[Entry],
) -> Option<Instruction> {
    let data = new_instruction_data(entries)?;
    Some(Instruction { program_id, accounts: Vec::new(), data })
}


/// Creates instruction data for a call of a native signature verification
/// program.
///
/// Returns `None` if there are more than 255 entries or message length of any
/// entry is longer than 65535 bytes.  However, observe that Solana upper limit
/// for instruction data is about 1100 (lower in practice).  This function does
/// not check this size limit and may return instruction data which don’t fit in
/// a Solana transaction.
///
/// Tries to conserve space by reusing messages and public keys if possible.  In
/// current implementation this is done in two ways.  Firstly, if the same
/// public key is used for multiple signatures, that public key is included in
/// instruction data only once.  Secondly, if a later message is a prefix of an
/// earlier one, the message isn’t included for the second time.
///
/// The second optimisation doesn’t work if signature for a prefix is earlier in
/// the `entries` than the full message.  Depending on the nature of the
/// entries, it may be useful to sort them by the message length (starting from
/// the longest message) to maximise space optimisation potential.
pub fn new_instruction_data(entries: &[Entry]) -> Option<Vec<u8>> {
    u8::try_from(entries.len()).ok()?;

    // Calculate the length of the instruction.  If we manage to deduplicate
    // messages we may end up with something shorter.  This is the largest we
    // may possibly use.
    let mut capacity = (2 + (OFF_SIZE + 64 + 32) * entries.len()) as u16;
    for entry in entries {
        let len = u16::try_from(entry.message.len()).ok()?;
        capacity = capacity.checked_add(len)?;
    }

    let mut data = Vec::with_capacity(usize::from(capacity));
    let len = write_instruction_data(data.spare_capacity_mut(), entries);
    // SAFETY: Per interface of write_instruction_data, all data up to len bytes
    // have been initialised.
    unsafe { data.set_len(len) };

    Some(data)
}

fn write_instruction_data(
    dst: &mut [core::mem::MaybeUninit<u8>],
    entries: &[Entry],
) -> usize {
    // The structure of the instruction data is:
    //   count:   u8
    //   zero:    u8
    //   entries: [SignatureOffsets; count]
    //   data:    [u8]
    dst[0].write(entries.len() as u8);
    dst[1].write(0);

    let mut len = 2 + entries.len() * OFF_SIZE;
    let (head, mut dst) = dst.split_at_mut(len);
    let (entries_dst, rest) =
        stdx::as_chunks_mut::<{ OFF_SIZE }, _>(&mut head[2..]);
    assert_eq!((entries.len(), 0), (entries_dst.len(), rest.len()));

    macro_rules! append {
        ($slice:expr) => {{
            let (head, tail) = dst.split_at_mut($slice.len());
            stdx::write_slice(head, $slice);
            dst = tail;
            let ret = len;
            len += $slice.len();
            ret as u16
        }};
    }

    for idx in 0..entries.len() {
        let Entry { signature, pubkey, message } = entries[idx];

        // Append message but deduplicate if the message has already been used
        // or the message is prefix of a message which has already been used.
        let pos = entries[..idx]
            .iter()
            .position(|ent| ent.message.starts_with(message));
        let message_offset = if let Some(pos) = pos {
            let offsets = &entries_dst[pos];
            // SAFETY: All offsets prior to idx have been initialised.
            u16::from_le_bytes(unsafe {
                [offsets[8].assume_init(), offsets[9].assume_init()]
            })
        } else {
            append!(message)
        };

        // Append signature.
        let signature_offset = append!(signature);

        // Append pubkey, but deduplicate if the key has already been used.
        let pos = entries[..idx].iter().position(|ent| ent.pubkey == pubkey);
        let pubkey_offset = if let Some(pos) = pos {
            let offsets = &entries_dst[pos];
            // SAFETY: All offsets prior to idx have been initialised.
            u16::from_le_bytes(unsafe {
                [offsets[4].assume_init(), offsets[5].assume_init()]
            })
        } else {
            append!(pubkey)
        };

        // Fill in the entry.
        let offsets = SignatureOffsets {
            signature_offset: u16::from_le(signature_offset),
            signature_instruction_index: u16::MAX,
            pubkey_offset: u16::from_le(pubkey_offset),
            pubkey_instruction_index: u16::MAX,
            message_offset: u16::from_le(message_offset),
            message_size: message.len() as u16,
            message_instruction_index: u16::MAX,
        };
        stdx::write_slice(&mut entries_dst[idx], bytemuck::bytes_of(&offsets));
    }

    len
}


/// Creates a new iterator over signatures in given native signature
/// verification program instruction data.
///
/// `data` is the instruction data for the program call.  This is typically
/// fetched from the instructions sysvar account.  The format of the data is:
///
/// ```ignore
/// count:   u8
/// unused:  u8
/// offsets: [SignatureOffsets; count]
/// rest:    [u8]
/// ```
///
/// The way to parse the instruction data is to read count from the first byte,
/// verify the second byte is zero and then iterate over the next count 14-byte
/// blocks passing them to this method.
///
/// The iterator does *not* support fetching keys, signatures or messages from
/// other instructions (which is something native signature verification
/// programs support) and if that feature is used such entries will be reported
/// as [`Error::UnsupportedFeature`] errors.
///
/// Returns [`Error::BadData`] if the data is malformed.
pub fn parse_data(data: &[u8]) -> Result<Iter, BadData> {
    match stdx::split_at::<2, u8>(data) {
        Some(([count, 0], rest)) => {
            stdx::as_chunks::<14, u8>(rest).0.get(..usize::from(*count))
        }
        _ => None,
    }
    .map(|entries| Iter { entries: entries.iter(), data })
    .ok_or(BadData)
}

/// Iterator over signatures present in native signature verification program
/// instruction data.
#[derive(Clone, Debug)]
pub struct Iter<'a> {
    entries: core::slice::Iter<'a, [u8; 14]>,
    data: &'a [u8],
}

impl<'a> core::iter::Iterator for Iter<'a> {
    type Item = Result<Entry<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entries.next()?;
        Some(decode_entry(self.data, entry))
    }

    fn last(self) -> Option<Self::Item> {
        let entry = self.entries.last()?;
        Some(decode_entry(self.data, entry))
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        let entry = self.entries.nth(n)?;
        Some(decode_entry(self.data, entry))
    }

    fn size_hint(&self) -> (usize, Option<usize>) { self.entries.size_hint() }
    fn count(self) -> usize { self.entries.count() }
}

impl core::iter::ExactSizeIterator for Iter<'_> {
    fn len(&self) -> usize { self.entries.len() }
}

impl core::iter::DoubleEndedIterator for Iter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let entry = self.entries.next_back()?;
        Some(decode_entry(self.data, entry))
    }

    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        let entry = self.entries.nth_back(n)?;
        Some(decode_entry(self.data, entry))
    }
}


/// Error when parsing a signature.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Error {
    /// Signature entry references data from other instructions which is
    /// currently unsupported.
    UnsupportedFeature,

    /// Signature entry is malformed.
    ///
    /// Such entries should cause the native signature verification program
    /// instruction to fail so this should never happen when parsing past
    /// instructions of current transaction.
    BadData,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BadData;

impl From<BadData> for Error {
    fn from(_: BadData) -> Self { Self::BadData }
}

impl From<BadData> for solana_program::program_error::ProgramError {
    fn from(_: BadData) -> Self { Self::InvalidInstructionData }
}

impl From<Error> for solana_program::program_error::ProgramError {
    fn from(_: Error) -> Self { Self::InvalidInstructionData }
}


/// Decodes signature entry from the instruction data.
///
/// `data` is the entire instruction data for the native signature verification
/// program call and `entry` is one of the signature offsets entry from that
/// instruction data.
fn decode_entry<'a>(
    data: &'a [u8],
    entry: &'a [u8; 14],
) -> Result<Entry<'a>, Error> {
    let entry: &[[u8; 2]; 7] = bytemuck::must_cast_ref(entry);
    let entry = entry.map(u16::from_le_bytes);
    let entry: SignatureOffsets = bytemuck::must_cast(entry);

    if entry.signature_instruction_index != u16::MAX ||
        entry.pubkey_instruction_index != u16::MAX ||
        entry.message_instruction_index != u16::MAX
    {
        return Err(Error::UnsupportedFeature);
    }

    fn get_array<const N: usize>(data: &[u8], offset: u16) -> Option<&[u8; N]> {
        Some(stdx::split_at::<N, u8>(data.get(usize::from(offset)..)?)?.0)
    }

    (|| {
        let signature = get_array::<64>(data, entry.signature_offset)?;
        let pubkey = get_array::<32>(data, entry.pubkey_offset)?;
        let message = data
            .get(usize::from(entry.message_offset)..)?
            .get(..usize::from(entry.message_size))?;
        Some(Entry { signature, pubkey, message })
    })()
    .ok_or(Error::BadData)
}


#[cfg(test)]
mod test {
    use ed25519_dalek::{Keypair, Signer};
    use solana_sdk::ed25519_instruction::new_ed25519_instruction;

    use super::*;

    macro_rules! make_test {
        ($name:ident;
         let $ctx:ident = $prepare:expr;
         $make_data:expr;
         $($entry:expr),* $(,)?
        ) => {
            mod $name {
                use super::*;

                #[test]
                fn test_iter() {
                    let $ctx = $prepare;
                    let entries = [$($entry),*];
                    let data = $make_data;
                    let mut iter = parse_data(data.as_slice()).unwrap();
                    for want in entries {
                        assert_eq!(Some(Ok(want)), iter.next());
                    }
                    assert_eq!(None, iter.next());
                }

                #[test]
                fn test_iter_new_instruction() {
                    let $ctx = $prepare;
                    let entries = [$($entry),*];
                    let data = new_instruction_data(&entries).unwrap();

                    let mut iter = parse_data(data.as_slice()).unwrap();
                    for want in entries {
                        assert_eq!(Some(Ok(want)), iter.next());
                    }
                    assert_eq!(None, iter.next());
                }

                #[test]
                fn test_verify_new_instruction() {
                    let $ctx = $prepare;
                    let entries = [$($entry),*];
                    let mut data = new_instruction_data(&entries).unwrap();

                    // solana_sdk::ed25519_instruction::verify requires data to
                    // be aligned to two bytes.  data is Vec<u8> so we can’t
                    // control alignment but we can pad to get alignment we
                    // need.
                    let data = if data.as_ptr() as usize % 2 == 0 {
                        data.as_slice()
                    } else {
                        data.insert(0, 0);
                        &data[1..]
                    };

                    // Verify
                    solana_sdk::ed25519_instruction::verify(
                        data,
                        &[data],
                        &Default::default(),
                    ).unwrap();
                }

                #[test]
                #[cfg(not(miri))]
                fn test_new_instruction_snapshot() {
                    let $ctx = $prepare;
                    let entries = [$($entry),*];
                    let data = new_instruction_data(&entries).unwrap();
                    insta::assert_debug_snapshot!(data.as_slice());
                }
            }
        }
    }

    const KEYPAIR1: [u8; 64] = [
        99, 241, 33, 162, 28, 57, 15, 190, 246, 156, 30, 188, 100, 125, 110,
        174, 37, 123, 198, 137, 90, 220, 247, 230, 191, 238, 71, 217, 207, 176,
        67, 112, 18, 10, 242, 85, 239, 109, 138, 32, 37, 117, 17, 6, 184, 125,
        216, 16, 222, 201, 241, 41, 225, 95, 171, 115, 85, 114, 249, 152, 205,
        71, 25, 89,
    ];

    fn make_signature(
        message: &[u8],
        keypair: &[u8; 64],
    ) -> ([u8; 64], [u8; 32], Keypair) {
        let keypair = ed25519_dalek::Keypair::from_bytes(keypair).unwrap();
        let signature = keypair.sign(message).to_bytes();
        let pubkey = keypair.public.to_bytes();
        (signature, pubkey, keypair)
    }

    make_test! {
        single_signature;
        let ctx = make_signature(b"message", &KEYPAIR1);
        new_ed25519_instruction(&ctx.2, b"message").data;
        Entry { signature: &ctx.0, pubkey: &ctx.1, message: b"message" }
    }

    fn prepare_two_signatures_test(
        msg1: &[u8],
        msg2: &[u8],
        keypair2: &[u8; 64],
    ) -> ([u8; 64], [u8; 32], [u8; 64], [u8; 32], Vec<u8>) {
        const SIG_SIZE: u16 = 64;
        const KEY_SIZE: u16 = 32;
        const HEADER_SIZE: u16 = 2 + 2 * 14;
        let first_offset = HEADER_SIZE;
        let second_offset =
            HEADER_SIZE + SIG_SIZE + KEY_SIZE + msg1.len() as u16;

        #[rustfmt::skip]
        let header = [
            2,

            /* sig offset: */ first_offset,
            /* sig_ix_idx: */ u16::MAX,
            /* key_offset: */ first_offset + SIG_SIZE,
            /* key_ix_idx: */ u16::MAX,
            /* msg_offset: */ first_offset + SIG_SIZE + KEY_SIZE,
            /* msg_size:   */ msg1.len() as u16,
            /* msg_ix_idx: */ u16::MAX,

            /* sig offset: */ second_offset,
            /* sig_ix_idx: */ u16::MAX,
            /* key_offset: */ second_offset + SIG_SIZE,
            /* key_ix_idx: */ u16::MAX,
            /* msg_offset: */ second_offset + SIG_SIZE + KEY_SIZE,
            /* msg_size:   */ msg2.len() as u16,
            /* msg_ix_idx: */ u16::MAX,
        ];

        let (sig1, pubkey1, _) = make_signature(msg1, &KEYPAIR1);
        let (sig2, pubkey2, _) = make_signature(msg2, &keypair2);

        let data = [
            bytemuck::bytes_of(&header),
            sig1.as_ref(),
            pubkey1.as_ref(),
            msg1,
            sig2.as_ref(),
            pubkey2.as_ref(),
            msg2,
        ]
        .concat();

        (sig1, pubkey1, sig2, pubkey2, data)
    }

    make_test! {
        two_signatures;
        let ctx = prepare_two_signatures_test(b"foo", b"bar", &KEYPAIR1);
        ctx.4;
        Entry { signature: &ctx.0, pubkey: &ctx.1, message: b"foo" },
        Entry { signature: &ctx.2, pubkey: &ctx.3, message: b"bar" }
    }

    make_test! {
        two_signatures_same_message;
        let ctx = prepare_two_signatures_test(b"foo", b"foo", &KEYPAIR1);
        ctx.4;
        Entry { signature: &ctx.0, pubkey: &ctx.1, message: b"foo" },
        Entry { signature: &ctx.2, pubkey: &ctx.3, message: b"foo" }
    }

    make_test! {
        two_signatures_prefix_message;
        let ctx = prepare_two_signatures_test(b"foo", b"fo", &KEYPAIR1);
        ctx.4;
        Entry { signature: &ctx.0, pubkey: &ctx.1, message: b"foo" },
        Entry { signature: &ctx.2, pubkey: &ctx.3, message: b"fo" }
    }

    const KEYPAIR2: [u8; 64] = [
        157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44,
        196, 68, 73, 197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127,
        96, 215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7,
        58, 14, 225, 114, 243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81,
        26,
    ];

    make_test! {
        two_signatures_diff_keys;
        let ctx = prepare_two_signatures_test(b"foo", b"bar", &KEYPAIR2);
        ctx.4;
        Entry { signature: &ctx.0, pubkey: &ctx.1, message: b"foo" },
        Entry { signature: &ctx.2, pubkey: &ctx.3, message: b"bar" }
    }

    make_test! {
        two_signatures_same_message_diff_keys;
        let ctx = prepare_two_signatures_test(b"foo", b"foo", &KEYPAIR2);
        ctx.4;
        Entry { signature: &ctx.0, pubkey: &ctx.1, message: b"foo" },
        Entry { signature: &ctx.2, pubkey: &ctx.3, message: b"foo" }
    }

    make_test! {
        two_signatures_prefix_message_diff_keys;
        let ctx = prepare_two_signatures_test(b"foo", b"fo", &KEYPAIR2);
        ctx.4;
        Entry { signature: &ctx.0, pubkey: &ctx.1, message: b"foo" },
        Entry { signature: &ctx.2, pubkey: &ctx.3, message: b"fo" }
    }
}
