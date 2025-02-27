# Probabilistic Reveal Tokens

Authors: Philipp Pfeiffenberger (philippp@google.com); Jonathan Katz
(jkcrypto@google.com); Scott Hendrickson (shendrick@google.com); Theodore
Olsauskus-Warren (sauski@google.com)

## Motivation

Fraud detection often relies on high-entropy signals that can also be used to
track users across sites. A uniformly selected sample of high-entropy signals
can be applied to some scenarios to accurately measure fraud rates and to build
denylists that can be used to block fraud. Probabilistic Reveal Tokens (PRTs)
attempt to balance the needs of fraud detection and tracking prevention by
sampling at a rate that is too low for scaled cross-site tracking, but
sufficient for fraud detection in aggregate scenarios.

PRTs allow for the gradual introduction of privacy-enhancing technologies by
moderating access to sensitive signals. For example, instead of an IP proxy that
either hides or reveals the pre-proxy IP all of the time, PRTs can reduce access
to the pre-proxy IP to an extent that prevents cross site tracking, while
preserving enough pre-proxy IP signal to allow for fraud detection in aggregate.

Browsers can use PRTs to reveal a sensitive signal on a per-site basis with
provable probability `p_reveal`, while websites can use PRTs to measure traffic
quality for some entity or combinations of entities (e.g. some specific platform
on a specific publisher) and update denylists.

## Overview of Probabilistic Reveal Tokens

We propose a new protocol called Probabilistic Reveal Tokens (PRTs) to
probabilistically share signals that would present a tracking risk when shared
deterministically. PRTs provide a verifiable reveal rate: browsers cannot
inspect whether a given token will reveal any signal prior to spending it, but
users can validate the reveal rate after the tokens have been spent. Tokens are
unlinkable beyond the probabilistically-included high-entropy signals,
unforgeable while they are eligible to be spent, and refutable after the
spending period (i.e. the epoch) is over. Browsers should always give users full
control over whether or not they use PRTs. It should be possible for users to
opt-out of PRT usage.

The PRT protocol introduces a key coordinator and issuer that generates tokens
which contain a given signal with `p_reveal` probability. The contents of the
tokens remain opaque to the browser as well as websites while the tokens are
eligible to be spent. Once this period ends, the key material needed to decrypt
and validate integrity of these tokens is released, and users and websites can
validate their integrity. Users are able to validate that the tokens' privacy
properties are true, and websites can use the sampled signal to evaluate quality
of traffic slices, discounting traffic that appears fraudulent.

### Terminology

**Epoch**\
A token is eligible to be spent by a browser during an epoch. After the epoch
ends, key material to decrypt and verify the tokens is released. This key
material also allows anyone to generate tokens of this now-revealed epoch,
creating deniability for token bearers: After an epoch ends, a token does not
provide any proof that a given IP visited a website.

**Key Coordinator**\
The key coordinator generates the cryptographic keypair necessary for token
encryption and decryption, and is responsible for keeping the secret key
material secret while tokens are eligible to be spent. This may be implemented
as part of the issuer.

**Issuer**\
The issuer is an internet-facing service from which the browser fetches PRTs.
The issuer computes an array of `N = N_signal + N_NULL` tokens (where `N_signal`
tokens contain the signal, and `N_NULL` tokens do not) so that `p_reveal =
N_signal/N`. The issuer shuffles these tokens and passes them to the browser. \
The issuer privately generates an HMAC key for message validation and keeps it
secret during the epoch. When the epoch ends, the issuer collects the secret key
from the key coordinator and publishes it along with its HMAC key for token
validation.

**Browser**\
The browser fetches tokens from the issuer, re-randomizes them to prevent
linkability, and sends the tokens to websites. After the key material is
published, the browser helps the user validate the privacy properties of the
tokens.

**Websites**\
Receive tokens from the browser. After the key material is published, websites
validate the legitimacy of the tokens and leverage sampled signals. \
We assume that the browser allocates tokens in a way that prevents the website
from fetching multiple tokens from the same epoch, otherwise the browser's
`p_reveal` for this website is compromised.

### Trust Model

-   Websites need to trust that the issuer is writing the correct signal
    into the token.
-   The issuer needs to independently establish trust in the signal.
-   Browsers must trust the issuer to correctly mint tokens for the duration
    of the epoch (i.e. until validation).

### Requirements

-   Ratio Inspection: Users must be able to verify the token reveal rate
    (`p_reveal`).
-   Content Inspection: Users must be able to verify after-the-fact that the
    tokens do not contain additional identifying information beyond an IP
    address.
-   The website and issuer must not be able to re-identify the user (e.g.,
    by colluding and matching tokens).
-   Robustness
    -   Browsers must not be able to intentionally reduce their
        aggregate token reveal rate below `p_reveal`.
    -   Websites must not be able to increase the likelihood of a
        browser revealing its signal.

### Implementation Considerations

-   Epoch length: The window of token eligibility (the epoch) should not be
    so large that the signal is likely to be outdated while tokens are being
    spent. The epoch must also be large enough to prevent websites from
    collecting multiple tokens they are able to identify as coming from the
    same user (e.g., through a cookie identifier). Browsers will enforce
    reasonable bounds on the epoch to ensure that it meets these criteria to
    preserve privacy.
-   Privacy: Tokens from the same browser must not be joinable by the
    website. If the receiving party can link multiple tokens from the same
    browser (e.g., through storing them in partitioned storage on the browser),
    the website's chance of recovering the signal increases beyond `p_reveal`.

## Protocol Description

### Token Scope

PRTs reduce access to re-identifiable information in the absence of other
cross-visit identifiers. PRT implementations must allocate only one token to
each website during a visit, where a visit is defined as a period during which
the user expects to be re-identified by a website (e.g., a sequence of
navigations or a cookied session). If this requirement is not met, a website
could collect multiple tokens for the same user and the same signal, and
increase their chance of recovering the signal beyond `p_reveal`.

### Epochs and sequencing

We expect epochs to be about one day, but do not require this in the protocol.
In practice, epochs should be long enough to avoid leakage through, e.g., user
re-identification through link decoration within a browsing session, and short
enough that the signal in the token is still likely to be valid, and for clients
to verify that the issuer is behaving correctly and p_reveal is as expected. In
practice, we recommend a minimum epoch length of four hours.

Each epoch must end after the following epoch has started. This allows browsers
to start using tokens from the new epoch before the current epoch ends, avoiding
both a lapse in the availability of valid tokens and a thundering herd problem
when new tokens become available.

### Token Generation by the Key Coordinator and Issuer

The key coordinator generates an asymmetric keypair (`pk_e`, `sk_e`) to be
rotated every epoch `E`, with `sk_e` published to all participants after the
epoch has ended. `pk_e` is shared as a JSON web key (JWK: see Figure 1). An
issuer receives `pk_e` and generates an epoch-scoped secret `S_e` that ensures
only this issuer can mint tokens.

<table>
    <tr>
      <pre>
{
  "kty": "EC",
  "crv": "P-256",
  "x": "DROn9TZojl70_6lhtcLxItT2qskNDGk97wjz0N5qdiE",
  "y": "k6EtdGm_jW3b7Le9zM2LgcO7b9Q_qwjS2jL0MFn6V4",
}
</pre>
    </tr>
    <tr>
      <td>
Figure 1. Sample <code>pk_e</code> as a JWK</td>
    </tr>
</table>

*Note: The key coordinator may be run by the same party as the issuer, but does
not have to be.*

The browser can now request batches of `N` tokens from the issuer. N is fixed by
the issuer, and remains constant within each epoch. The issuer receives the
signal to be encrypted into the token from the browser (e.g., by observing the
browser's IP address from the inbound connection) and represents the signal as a
big-endian byte array for token generation.\
The issuer then generates an array of messages `[M_0, M_1, M_2, .., M_idx, ..,
M_N]` to be encrypted into tokens `[T_0, T_1, T_2, .., T_idx, .., T_N]`. For
each message `M_idx`, the issuer chooses a distinct value from the integer
interval `[1, 2, … N]` and includes it as the per-token ordinal `t_ord`. This
per-token ordinal hardens against duplication of tokens via ciphertext
re-randomization by the browser, while limiting risk of side-channel leakage
from the issuer by being deterministically allocated within each batch. Each
message `M_idx` also contains a `Version` field that is initially set to 1 and a
signal value that is either `NULL` (with 1 - `p_reveal` probability) or the
actual signal (with `p_reveal` probability). Finally, the token contains the
first 8
bytes[^whyhmacshort]
of the HMAC value `H := HMAC-SHA256(S_e, Version || t_ord || signal)` to prevent
the browser from generating its own tokens.

Prior to encryption, `M_idx` is a byte array with the following structure:

<table>
  <thead>
    <tr>
      <th>Field Name</th>
      <th>Version</th>
      <th>t_ord</th>
      <th>signal</th>
      <th>H</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Field Size (bits)</td>
      <td>8</td>
      <td>8</td>
      <td>128</td>
      <td>64</td>
    </tr>
    <tr>
      <td>Byte Indices</td>
      <td>[0]</td>
      <td>[1]</td>
      <td>[2..17]</td>
      <td>[18..25]</td>
    </tr>
  </tbody>
</table>

The issuer computes the token ciphertext `T_idx` as the ElGamal encryption of
`M_idx` with curve secp256r1 and `pk_e`, padding the message with three bytes of
data so that the padded message is a valid point on the curve. The issuer
provides the browser with an array of ciphertexts `[T_0, T_1, …, T_N]` and the
public key `pk_e` needed for re-encryption. The browser can learn the time at
which this epoch will end (`t_epoch_end`), at which point `sk_e` and `S_e` will
be published by the coordinator/issuer. The browser also learns the start of the
next epoch (`t_next_epoch_start`), when it can start fetching new tokens.

### Token re-randomization and spending on the browser

The browser can validate `p_reveal` and the ordinal assignment when `sk_e` is
published, but the browser cannot verify that the issuer did not hide
information in the ciphertext (e.g., the issuer could have chosen a valid
ciphertext in which the first byte matches the first byte of the signal).
Furthermore, a constant ciphertext would allow the issuer and website to
conspire and recover all browser signals by correlating ciphertexts, which
breaks our privacy model.

The browser defends against this by re-randomizing the ciphertexts before
sending the token to a website. The browser re-randomizes the ciphertext under
ElGamal encryption by choosing a random integer `z` between `1` and `n - 1` and
computing `C' = C_1', C_2' ← C_1 + zP, C_2 + zQ` (where `n` is the prime order
of the group, `P` is the generator point, and `Q` is the public key of the
recipient).

The browser will re-randomize each token before it is used, and each time the
token is re-used to defend against linkability attacks.

The browser writes its tokens and their metadata into a local database. This
database also includes a string field `context_id`, which defaults to `NULL` for
new tokens and is set to an identifier of the context (e.g., the domain name) in
which the token has been spent. This defends against a token recipient attacking
the browser by requesting tokens until the signal is revealed: Fixing a token to
a given context allows the browser to only ever reveal at most one token to a
given recipient, limiting the reveal probability to `p_reveal`. The browser
retains the following information in its database:

<table>
  <thead>
    <tr>
      <th>Field Name</th>
      <th>Token</th>
      <th>pk_e</th>
      <th>t_epoch_end</th>
      <th>context_1p</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Field Type</td>
      <td>bytes</td>
      <td>bytes</td>
      <td>timestamp</td>
      <td>string</td>
    </tr>
  </tbody>
</table>

When the browser wishes to assert its willingness to probabilistically reveal a
signal, it refers to the context of the requesting party and SELECTs any token
that has been assigned to this context, and whose `t_epoch_end` has not passed.
If such a token is found, the browser will re-randomize it and re-use it for
this connection. If no such token exists, the browser assigns a non-spent,
current-epoch token to the context of the requesting party by writing its value
to the `context_id` field. This token is now considered "spent" and can be
re-randomized and sent to the relevant party.

*Note: Websites can use local storage to track the browser over multiple
epochs. We can compute the likelihood that the signal has been revealed after
`N` epochs as `P(reveal) = 1 - (1 - p_reveal)^N`. With `p_reveal = 0.1`, there
is a 34% chance that the signal will have been disclosed after four epochs.
Epochs must thus be sized to match the duration of expected re-identifiability
of the browser, see Epochs and Sequencing above.*

### Token Validation: Key formats and secret sharing

At the end of the epoch, the issuer will publish (`pk_e`, `sk_e`, `S_e`) as
JSON web keys (JWKs). The ElGamal key will be stored as `eg` with `x` and `y`
holding the public key (`pk_e`) and `d` the secret key (`sk_e`). The HMAC secret
`Se` is stored as `hm`. All values converted to big-endian byte-arrays that are
then base64url-encoded into strings. Timestamps are ISO 8601 timestamps UTC.

<table>
    <tr>
      <pre>
{
  "epoch_id": 12,
  "epoch_start_time" : "20241125T10:00:00",
  "epoch_end_time" : "20241126T12:00:00",
  "invalidated_at" : NULL,
  "eg" : {
    "kty": "EC",
    "crv": "P-256",
    "x": "DROn9TZojl70_6lhtcLxItT2qskNDGk97wjz0N5qdiE",
    "y": "k6EtdGm_jW3b7Le9zM2LgcO7b9Q_qwjS2jL0MFn6V4",
    "d": "S7_oLScyL_W2ob71hx6kHFv5nTmAt2CvqzmKeF7lLGA"
  },
  "hmac" : {
    "kty": "oct",
    "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    "alg": "HS256"
  }
}
</pre>
    </tr>
    <tr>
      <td>Figure 2. Secret disclosure from the Issuer</td>
    </tr>
</table>

### Token Validation by the user

Users can save and validate tokens against the stated `p_reveal` and expected
token ordinal assignment. The browser may choose to persist the following
details for validation:

<table>
  <thead>
    <tr>
      <th>Field Name</th>
      <th>Token</th>
      <th>pk_e</th>
      <th>t_epoch_end</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Field Type</td>
      <td>bytes</td>
      <td>bytes</td>
      <td>timestamp</td>
    </tr>
  </tbody>
</table>

The user may run the validation script with a directory containing one or more
of these sqlite files. For each row for which `t_epoch_end` has passed, the
script fetches the `sk_e` and `S_e` associated with `pk_e` from a well-known
location at issuer I. The script can now decrypt tokens and populate a table of
per-token validation results with the following schema:

<table>
  <thead>
    <tr>
      <th>Field Name</th>
      <th>Token</th>
      <th>pk_e</th>
      <th>validation_failed_ts</th>
      <th>has_signal</th>
      <th>t_ord</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Field Type</td>
      <td>bytes</td>
      <td>bytes</td>
      <td>timestamp</td>
      <td>boolean</td>
      <td>uint8</td>
    </tr>
  </tbody>
</table>

The script decrypts `T` and recovers `Version`, signal (which may be `NULL` or
the actual signal), `H_idx`, and `t_ord`. The script computes `HMAC-SHA-256(S_e,
Version || t_ord || signal)`, and sets the `validation_failed_ts` field for the
row to the current time if this value does not match `H_idx`. The script also
sets `has_signal` to `true` if the token specified the signal, and `false` if it
did not.

The user can now validate the rate of signal reveal, as well as the assignment
of `t_ord` values across all decrypted tokens. This makes it possible for
external auditors to detect any issuers that may be colluding with websites to
increase `p_reveal`.

### Token use by websites

Websites store each token as part of the request for eventual decryption after
the epoch ends. Once a new epoch `(e+1)` starts, the browser will begin fetching
tokens encrypted with `pk_{e+1}` and continue as before. The browser is
configured to cease spending epoch e tokens when epoch e ends, and the website
can assume that all legitimate browsers have transitioned to generate tokens for
epoch `e+1` at this point. The issuer can now reveal `(pk_e, sk_e, S_e)` to all
parties, allowing the browser to verify privacy properties and the website to
make use of the sampled signal.

Once `(pk_e, sk_e, S_e)` have been revealed to all parties, websites use `sk_e`
to decrypt tokens that were shared with `pk_e`. The website discards the final
padding bytes that were added by the issuer, leaving the pre-encryption message.
The website can now verify the following:

1.  For each token, the first eight bytes of `HMAC-SHA-256(S_e, Version ||
    t_ord || signal) == H_idx`. This proves that the browser did not generate
    their own tokens.
1.  The distribution of `t_ord` over a given entity (e.g., top-level domain
    name) should be uniformly distributed, without outlier spikes. This gives
    confidence that a browser did not send the same token many times over.

[^whyhmacshort]: Keeping only the first eight bytes allows us to use a smaller
 curve while limiting the probability of guessing a valid token to 2^-64.
