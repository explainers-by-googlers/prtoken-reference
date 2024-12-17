# Probabilistic Reveal Tokens

Probabilistic Reveal Tokens allow a client to limit the disclosure of a signal
to a predetermined probability and prove adherence to this probability.
This repository contains the
[description of the protocol](protocol.md) as well as a reference
implementation.

## Overview of components

+ prtoken/
  +   token.{h,cc,proto} - Implementation of the token itself.
  +   issuer.{h,cc} - Token issuance
  +   client.{h,cc} - Re-randomization of ciphertext
  +   verifier{h, cc} - Token verification on the server
+   protocol.md - Description of the protocol
+  README.md - This file

## How to compile the protocol source
1. Install [Bazelisk](https://github.com/bazelbuild/bazelisk)
2. Build the libraries: `bazelisk build prtoken:all`

