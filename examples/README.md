# Solana `sigverify` examples

Example code using the `solana-sigverify` crate to implement signature
aggregation in a smart contract.  To test in localnet, in a background
terminal execute `solana-test-validator` and then run:

```shell
$ cd ..
$ cargo build-sbf
$ solana -u localhost program deploy \
      ./target/deploy/solana_sigverify.so
# Make note of the program id

$ solana -u localhost program deploy \
      ./target/deploy/sigtest.so
# Make note of the program id
```

Now, modify `sig-client/src/main.rs` file by updating
`SIGVERIFY_PROGRAM_ID` and `PROGRAM_ID` addresses to the ones noted
above.  With that change done, you can test working of the `sigtest`
program by executing the `sig-client`:

```shell
$ cargo build -r -p sig-client

$ ./target/release/sig-client
Aggregating 20 signatures
⋮
Calling sigtest program…
⋮
Program log: Entry #0: signed
⋮
Program log: Entry #19: signed
Program log: Test #0: signed
⋮
Program log: Test #3: signed
⋮

$ ./target/release/sig-client 5
Aggregating 3 signatures
⋮
Calling sigtest program…
⋮
Program log: Entry #0: signed
Program log: Entry #1: err
⋮
```

A more detailed description of the approach is available in [Solana
signature count
limit](https://mina86.com/2025/solana-signatures-count-limit/)
article.
