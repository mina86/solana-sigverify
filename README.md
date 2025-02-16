# Solana Signature Verifier

Solana runtime contains [native programs] for verification of
cryptographic signatures such as Ed25519 (henceforth collectively
called native signature verification programs).  However, those
features face two issues.


## `solana-native-sigverify`

Firstly, neither `solana-program` nor `solana-sdk` offer satisfactory
interfaces for interacting with those native signature verification
programs.

The SDK has `new_ed25519_instruction` for creating calls to the
Ed25519 native program (and analogous function for Secp256k1), but it
allows verification of only one signature and requires caller to hold
the secret key (i.e. it’s not possible to construct an instruction
which verifies an existing signature).

Furthermore, there are no functions for parsing the instruction data
which is required inside of the smart contract to verify signatures.

This repository includes `solana-native-sigverify` crate with helper
functions for interacting with the native signature verification
programs.  It includes functions for constructing calls to the native
programs as well as interpreting their instruction data.

The `new_instruction` function constructs instructions for executing
native signature verification functions.  It does not require the
caller to hold the secret key and allows passing multiple signatures
in a single call.

The `parse_data` function parses instruction data of a call to native
signature verification program returning an iterator which can be used
to read all the signatures verified by the native program.


## `solana-sigverify`

Secondly, since call to the native signature verification programs
must be performed through an instruction in a Solana transaction, they
are subject to the Solana transaction size limit of 1232 bytes.  The
consequence of it is that there’s a limited number of signatures that
can be verified in a single transaction.

To address this problem, this repository includes a `solana-sigverify`
crate which offers a way to spread signature verification through
multiple transactions.  The crate defines:
* a smart contract which aggregates verified signatures into an
  account,
* RPC client library functions facilitating invocation of that smart
  contract (requires `client` Cargo feature), and
* smart contract library functions which enable target smart contract
  to check signatures against signatures aggregated in the account.

A more detailed description of the approach is available in [Solana
signature count
limit](https://mina86.com/2025/solana-signatures-count-limit/)
article.

Furthermore, this repository has an `examples` directory with example
smart contract and RPC client which take advantage of the signature
aggregation.
