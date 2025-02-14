// Solana has a weird way of customising the `entrypoint` macro.  Disable
// warnings when `cfg` checks for an undefined feature.
#![allow(unexpected_cfgs)]

use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

solana_program::entrypoint!(process_instruction);

/// Hard-coded address of the solana-sigverify program.
///
/// This is necessary so that the smart contract isn’t tricked into reading
/// signatures from attacker-controlled account.  This must be the address of
/// a trusted solana-sigverify program which was used to create the signatures
/// account.
const SIGVERIFY_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("4VEPe5EMrGkcucbmZXYRSGBKAGt8eXfJYQtMtu2cP3he");

fn process_instruction<'a>(
    _program_id: &'a Pubkey,
    accounts: &'a [AccountInfo],
    _instruction: &'a [u8],
) -> Result<(), ProgramError> {
    let mut verifier = solana_sigverify::Ed25519Verifier::default();
    for account in accounts {
        if solana_program::sysvar::instructions::check_id(account.key) {
            verifier.set_ix_sysvar(account)?;
        } else {
            verifier.set_sigverify_account(account, &SIGVERIFY_PROGRAM_ID)?;
        }
    }

    for (i, (key, sig, msg)) in sig_data::ENTRIES.iter().enumerate() {
        let ok = verifier.verify(msg, key, sig)?;
        let ok = if ok { "signed" } else { "err" };
        solana_program::msg!("Entry #{}: {}", i, ok);
    }

    for (i, (key, sig, msg)) in sig_data::TESTS.iter().enumerate() {
        let ok = verifier.verify(msg, key, sig)?;
        let ok = if ok { "signed" } else { "err" };
        solana_program::msg!("Test #{}: {}", i, ok);
    }
    Ok(())
}
