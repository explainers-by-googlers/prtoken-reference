# Probabilistic Reveal Tokens

Probabilistic Reveal Tokens allow a client to limit the disclosure of a signal
to a predetermined probability and prove adherence to this probability. This
repository contains the [description of the protocol](protocol.md) as well as a
reference implementation.

## Overview of components

+   prtoken/
    +   token.{h,cc,proto} - Implementation of the token itself.
    +   issuer.{h,cc} - Token issuance
    +   client.{h,cc} - Re-randomization of ciphertext
    +   verifier.{h, cc} - Verification of token contents and reveal rate.
    +   main.cc - Command interface to issue/verify tokens for IP.
+   protocol.md - Description of the protocol
+   README.md - This file

## How to compile the protocol source

1.  Install [Bazelisk](https://github.com/bazelbuild/bazelisk)
2.  Build the libraries: `bazelisk build prtoken:all`

## How to run

Issue tokens for IP:

```
bazel run //prtoken:prtoken issue -- \
    --custom_db_filename=test.db \
    --custom_key_filename=test_key.json \
    --output_dir=${SOME_PATH} \
    --num_tokens=10 \
    --ip=1.2.3.4
```

Verify tokens:

```
bazel run //prtoken:prtoken verify -- \
    --token_db "${SOME_PATH}/test.db" \
    --private_key "${SOME_PATH}/test_key.json" \
    --result_table RESULTS
```

The above command will create a new table `RESULTS` in the same db file to
store the decryptions. Try below to query the results.

```sql
SELECT t.e, r.m, r.ordinal
FROM tokens AS t JOIN RESULTS AS r WHERE
t.e = r.e
```

In the column `r.m`, there should be one row showing the decrypted IP,
`::ffff:1.2.3.4` which is padded IPv4-mapped address.
