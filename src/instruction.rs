use core::num::NonZeroU16;

use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

type Result<T = (), E = ProgramError> = core::result::Result<T, E>;


/// Creates an instruction calling Update operation of the sigverify program.
///
/// For the instruction to work, it must be executed in a transaction with call
/// to native signature verification program *directly* preceding it.  To create
/// such instruction use [`crate::verify_program::new_instruction`].
///
/// Together with the instruction, returns the signatures account address and
/// bump.  The account is where the program will collect all the signatures.
/// Note that the signatures accounts are per-`payer`.  `seed` can be at most 31
/// bytes and allows the payer to maintain multiple accounts.
///
/// `epoch`, if specifies, allows to clear out all the old signatures from the
/// account without having to serialise a separate clear call to the sigverify
/// program.  It can be ignored if caller doesn’t reuse the signatures account
/// (e.g. always frees them after use).  Otherwise, each time a series of
/// signatures are collected, a different epoch should be used for that series
/// of signatures.
pub fn update(
    sigverify_program: Pubkey,
    payer: Pubkey,
    seed: &[u8],
    epoch: Option<u64>,
) -> Result<(Instruction, Pubkey, u8)> {
    let (account, bump) = Pubkey::find_program_address(
        &[payer.as_ref(), seed],
        &sigverify_program,
    );

    let data = {
        let mut buf = [0; 40];
        buf[1] = check_seed(seed)?;
        buf[2..2 + seed.len()].copy_from_slice(seed);
        buf[2 + seed.len()] = bump;
        let mut len = 2 + seed.len() + 1;
        if let Some(epoch) = epoch {
            buf[len..len + 8].copy_from_slice(&epoch.to_le_bytes());
            len += 8;
        }
        buf[..len].to_vec()
    };

    let instruction = Instruction {
        program_id: sigverify_program,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(account, false),
            AccountMeta::new(solana_program::sysvar::instructions::ID, false),
            AccountMeta::new(solana_program::system_program::ID, false),
        ],
        data,
    };

    Ok((instruction, account, bump))
}


/// Iterator generating Solana instructions calling the sigverify program
/// filling given account with given data.
pub struct UpdateIter<'a> {
    native_program: &'a Pubkey,
    sigverify_instruction: Instruction,
    entries: &'a [crate::verify_program::Entry<'a>],
    seed_len: u8,
    max_data_size: NonZeroU16,
}

impl<'a> UpdateIter<'a> {
    pub fn new(
        native_program: &'a Pubkey,
        sigverify_program: Pubkey,
        payer: Pubkey,
        seed: &[u8],
        epoch: Option<u64>,
        entries: &'a [crate::verify_program::Entry],
    ) -> Result<(Self, Pubkey, u8)> {
        let seed_len = check_seed(seed)?;
        let (sigverify_instruction, account, bump) =
            update(sigverify_program, payer, seed, epoch)?;

        let mut this = Self {
            native_program,
            sigverify_instruction,
            entries,
            seed_len,
            max_data_size: NonZeroU16::MIN,
        };
        this.max_data_size(800);
        Ok((this, account, bump))
    }

    /// Sets maximum signature verification native program instruction data
    /// size.
    ///
    /// When construction instructions, the iterator tries to collect as many
    /// signatures as possible in each Update to minimise total number of
    /// instructions.  The maximum data size limits how large each instruction
    /// can be.
    ///
    /// The default value is on the safe side leaving enough space in the
    /// transaction to include Update instruction and additional instructions.
    ///
    /// Note that the iterate will always output instruction with at least one
    /// signature, even if that exceeds the limit.
    pub fn max_data_size(&mut self, max_data_size: usize) {
        let size = u16::try_from(max_data_size)
            .unwrap_or(u16::MAX)
            .saturating_sub(u16::from(self.seed_len));
        self.max_data_size = NonZeroU16::new(size).unwrap_or(NonZeroU16::MIN);
    }
}

impl core::iter::Iterator for UpdateIter<'_> {
    type Item = (
        solana_program::instruction::Instruction,
        solana_program::instruction::Instruction,
    );

    fn next(&mut self) -> Option<Self::Item> {
        if self.entries.is_empty() {
            return None;
        }

        let mut limit = usize::from(self.max_data_size.get()).saturating_sub(2);
        let count = self
            .entries
            .iter()
            .take_while(|entry| {
                let size = 14 + 64 + 32 + entry.message.len();
                if size > limit {
                    return false;
                }
                limit -= size;
                true
            })
            .count();
        let count = count.max(1);

        let native_instruction = crate::verify_program::new_instruction(
            *self.native_program,
            &self.entries[..count],
        )
        .unwrap();
        self.entries = &self.entries[count..];
        Some((native_instruction, self.sigverify_instruction.clone()))
    }
}

/// Generates instruction data for Free operation.
///
/// `seed` and `bump` specifies seed and bump of the signatures PDA.  Note that
/// the actual seed used to create the PDA is `[payer.key, seed]` rather than
/// just `seed`.
///
/// If `signatures_account` is not given, it’s going to be generated from
/// provided sigverify program id, Payer account, seed and bump.
pub fn free(
    sigverify_program: Pubkey,
    payer: Pubkey,
    signatures_account: Option<Pubkey>,
    seed: &[u8],
    bump: u8,
) -> Result<Instruction> {
    let mut buf = [0; { solana_program::pubkey::MAX_SEED_LEN + 2 }];
    buf[0] = 1;
    buf[1] = check_seed(seed)?;
    buf[2..seed.len() + 2].copy_from_slice(seed);
    buf[seed.len() + 2] = bump;
    let data = &buf[..seed.len() + 3];

    let account = if let Some(acc) = signatures_account {
        acc
    } else {
        Pubkey::create_program_address(
            &[payer.as_ref(), seed, &[bump]],
            &sigverify_program,
        )?
    };

    Ok(Instruction {
        program_id: sigverify_program,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(account, false),
            AccountMeta::new(solana_program::system_program::ID, false),
        ],
        data: data.to_vec(),
    })
}

/// Checks that seed is below the maximum length; returns length cast to `u8`.
fn check_seed(seed: &[u8]) -> Result<u8> {
    if seed.len() < solana_program::pubkey::MAX_SEED_LEN {
        Ok(seed.len() as u8)
    } else {
        Err(ProgramError::MaxSeedLengthExceeded)
    }
}
