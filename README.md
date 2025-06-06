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

Export `PRT_OUTPUT_DIR` to an existing directory, or manually edit the paths in the commands below:
```
export PRT_OUTPUT_DIR=/tmp
```
### Issue tokens for IP

```
bazelisk run //prtoken:prtoken issue -- \
    --custom_db_filename=test.db \
    --custom_key_filename=test_key.json \
    --output_dir=${PRT_OUTPUT_DIR} \
    --num_tokens=10 \
    --ip=1.2.3.4
```

### Verify tokens

```
bazelisk run //prtoken:prtoken verify -- \
    --token_db "${PRT_OUTPUT_DIR}/test.db" \
    --private_key "${PRT_OUTPUT_DIR}/test_key.json" \
    --result_table RESULTS
```

The above command will create a new table `RESULTS` in the same db file to
store the decrypted tokens.

### Query the results

Use the sqlite command to open the 'test.db' database file within the `PRT_OUTPUT_DIR` directory.
```
sqlite3 test.db
```

```sql
SELECT t.e, r.m, r.ordinal
FROM tokens AS t JOIN RESULTS AS r WHERE
t.e = r.e;
```

In the column `r.m`, there should be one row showing the decrypted IP,
`::ffff:1.2.3.4` which is padded IPv4-mapped address.

## PRT Headers

A PRT header is the value that Chrome attaches to the
`Sec-Probabilistic-Reveal-Token` request header for proxied requests. It is a
base64 encoded string that includes the encrypted token data, the token version,
and the epoch ID. Below are a few tools for extracting the data contained in a
PRT header.

### Get Epoch ID from PRT header

```
bazelisk run //prtoken:prtoken epoch -- \
    --prt={prt_header_value}
```
The above will print the epoch ID of the given token to std out.

### Decrypt PRT header

```
bazelisk run //prtoken:prtoken decrypt -- \
    --prt={prt_header_value}
```
The above will print the contents of the decrypted PRT to std out. This includes
the epoch ID, the token version, the token ordinal, the IP (either empty or
populated), and whether the token HMAC value was valid.

Decryption will fail if the keys for the associated epoch have not yet been
published.

Alternatively, you can decrypt multiple PRTs at once by putting them in a file
(one PRT value per line) and using the following:

```
bazelisk run //prtoken:prtoken decrypt -- \
    --prt_filename={prt_file.txt}
```
By default, the above will print the results of decrypting each PRT to std out
in CSV format. You can provide an optional `--output_filename` flag to write the
results to a file instead.

The schema of the output CSV is as follows:\
`PRT, Epoch ID, Version, Ordinal, IP, HMAC Valid, Error`

Here `PRT` is the original encrypted token value from the input file and `Error`
will be populated with a message if decryption fails for a particular token (for
example if the keys for that token have not been published).
