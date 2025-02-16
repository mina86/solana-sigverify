use core::str::FromStr;
use std::process::ExitCode;

use solana_client::rpc_client::RpcClient;
use solana_native_sigverify::Entry;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::Message;
use solana_sdk::program_error::ProgramError;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::transaction::Transaction;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::UiTransactionEncoding;

/// Hard-coded address of the chsum program.
const PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("BeWjq8LPtjXZPtz7aXA21HfmTCY5hBjBtNQdXGzkVaBr");

/// Hard-coded address of the sigverify program.
const SIGVERIFY_PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("4VEPe5EMrGkcucbmZXYRSGBKAGt8eXfJYQtMtu2cP3he");

/// Seed to use for the instruction data PDA.  Can be at most
/// 31-byte long.
const SEED: &[u8] = b"";


type Result<T = (), E = Error> = core::result::Result<T, E>;


/// `usage: sig-client [<prob>]
fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("{err}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Executes the program.
fn run() -> Result {
    let keypair = read_keypair()?;
    let client = RpcClient::new("http://127.0.0.1:8899");

    // Parse command line arguments and prepare list of entries.
    let count = std::env::args()
        .nth(1)
        .map(|arg| usize::from_str(arg.as_str()))
        .transpose()
        .map_err(|_| Error::Msg("usage: sig-client [<count>]"))?;
    let mut entries: Vec<Entry> = sig_data::ENTRIES
        .iter()
        .map(|entry| Entry {
            pubkey: &entry.0,
            signature: &entry.1,
            message: &entry.2,
        })
        .collect();
    if let Some(count) = count.filter(|&count| count < entries.len()) {
        use rand::seq::SliceRandom;
        entries.shuffle(&mut rand::rng());
        entries.truncate(count);
        entries.sort_unstable();
    }


    // If the signatures account is not being reused, epoch can be sot to None.
    // For demonstration purposes, initialise epoch to a unique value to show
    // how it can be used if the account is reused.
    //
    // The caller must guarantee that the epoch is set to a different value for
    // each set of accounts that need to be collect.  One way to do it is by
    // using a nanosecond-precision timestamp.
    //
    // Calling solana-sigverify with a different epoch clears the signatures
    // account.
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let epoch = Some(epoch);


    // Generate all necessary instructions and send them to Solana.  UpdateIter
    // groups signatures together and calls solana-sigverify to collect all the
    // signatures.
    let (iter, account, bump) = solana_sigverify::instruction::UpdateIter::new(
        &solana_sigverify::algo::Ed25519::ID,
        SIGVERIFY_PROGRAM_ID,
        keypair.pubkey(),
        SEED,
        epoch,
        &entries,
    )?;

    eprintln!("Aggregating {} signatures", entries.len());
    for insts in iter {
        eprintln!("Sending transaction to {}…", insts[1].program_id);
        let blockhash = client.get_latest_blockhash()?;
        let message = Message::new_with_blockhash(
            &insts,
            Some(&keypair.pubkey()),
            &blockhash,
        );
        send_and_confirm_message(&client, &keypair, blockhash, message)?;
        eprintln!();
    }


    // Call the test program
    eprintln!("Calling sigtest program…");
    call_sigtest_program(&client, &keypair, account)?;


    // Free the account.  This is optional.  Depending on usage, the account can
    // be kept around and reused with a new epoch as described at the top of
    // this function.  Reusing the account saves minor amount of gas fees.
    eprintln!();
    eprintln!("Freeing signatures account…");
    let instruction = solana_sigverify::instruction::free(
        SIGVERIFY_PROGRAM_ID,
        keypair.pubkey(),
        Some(account),
        SEED,
        bump,
    )?;
    send_and_confirm_instruction(&client, &keypair, instruction)
}


/// Reads keypair from a hard-coded location.
fn read_keypair() -> Result<Keypair> {
    let home = std::env::var_os("HOME").unwrap();
    let mut path = std::path::PathBuf::from(home);
    path.push(".config/solana/id.json");
    solana_sdk::signer::keypair::read_keypair_file(path).map_err(Error::from)
}


/// Call the sig test program.
fn call_sigtest_program(
    client: &RpcClient,
    keypair: &Keypair,
    signatures_account: Pubkey,
) -> Result {
    // For demonstration, execute sigtest program together with call to Ed25519
    // program to show that solana_sigverify::Verifier is capable of checking
    // signatures from signatures account as well as from the native signature
    // verification program invocation.
    let entries: Vec<Entry> = sig_data::TESTS
        .iter()
        .map(|entry| Entry {
            pubkey: &entry.0,
            signature: &entry.1,
            message: entry.2,
        })
        .collect();
    let sig_instruction = solana_native_sigverify::new_instruction(
        solana_native_sigverify::ED25519_PROGRAM_ID,
        &entries,
    )
    .unwrap();

    let test_instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            // Pass the signatures account so the program can test signatures
            // collected inside of it.
            AccountMeta::new_readonly(signatures_account, false),
            // Pass the Instructions sysvar so the program can test signatures
            // tested within this transaction in
            AccountMeta::new(solana_sdk::sysvar::instructions::ID, false),
        ],
        data: Vec::new(),
    };

    eprintln!("Sending transaction to {}…", test_instruction.program_id);
    let blockhash = client.get_latest_blockhash()?;
    let message = Message::new_with_blockhash(
        &[sig_instruction, test_instruction],
        Some(&keypair.pubkey()),
        &blockhash,
    );
    send_and_confirm_message(client, keypair, blockhash, message)
}


/// Sends transaction with given instruction and logs result.
fn send_and_confirm_instruction(
    client: &RpcClient,
    keypair: &Keypair,
    instruction: Instruction,
) -> Result {
    eprintln!("Sending transaction to {}…", instruction.program_id);
    let blockhash = client.get_latest_blockhash()?;
    let message = Message::new_with_blockhash(
        core::slice::from_ref(&instruction),
        Some(&keypair.pubkey()),
        &blockhash,
    );
    send_and_confirm_message(client, keypair, blockhash, message)
}

/// Sends transaction and logs result.
fn send_and_confirm_message(
    client: &RpcClient,
    keypair: &Keypair,
    blockhash: solana_sdk::hash::Hash,
    message: Message,
) -> Result {
    let mut tx = Transaction::new_unsigned(message);
    tx.sign(&[&keypair], blockhash);

    let sig = client.send_and_confirm_transaction(&tx)?;
    eprintln!("Signature: {sig}");

    let encoding = UiTransactionEncoding::Binary;
    let resp = client.get_transaction(&sig, encoding)?;
    let (slot, tx) = (resp.slot, resp.transaction);
    eprintln!("Executed in slot: {slot}");

    // Print log messages
    let log_messages = tx
        .meta
        .map(|meta| meta.log_messages)
        .ok_or(Error::Msg("No transaction metadata"))?;
    if let OptionSerializer::Some(messages) = log_messages {
        for msg in messages {
            println!("{msg}");
        }
        Ok(())
    } else {
        Err(Error::Msg("No log message"))
    }
}


#[derive(derive_more::From, derive_more::Display)]
enum Error {
    Msg(&'static str),
    Prog(ProgramError),
    Box(Box<dyn std::error::Error>),
}

impl From<solana_client::client_error::ClientError> for Error {
    fn from(err: solana_client::client_error::ClientError) -> Self {
        Self::Box(Box::new(err))
    }
}
