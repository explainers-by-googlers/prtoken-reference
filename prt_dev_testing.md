# PRT Dev Testing Instructions

## Context

In order to support local testing of Probabilistic Reveal Tokens (PRTs), we have
implemented a set of feature flags that affect how PRTs are attached to
requests. In particular these flags can create a configuration where PRTs are
attached to every request for a given list of domains, regardless of whether the
request is proxied or whether the user is in an incognito session.

## Setup

The following
[Chrome features](https://chromium.googlesource.com/chromium/src/+/main/docs/configuration.md#Features)
are used to enable PRTs:

*   `EnableIpPrivacyProxy`
*   `MaskedDomainList`
*   `EnableProbabilisticRevealTokens`

Additionally we can modify the default behavior of PRTs by setting the following
parameters of the `EnableProbabilisticRevealTokens` feature:

*   `ProbabilisticRevealTokensAddHeaderToProxiedRequests = true`
    *   If true, Chrome will attach PRTs to the request headers of eligible
        requests (by default “eligible” here means that the request is being
        proxied due to the IP Protection feature, and the request is being sent
        to a domain that has registered to receive PRTs - the next few params
        can be used to modify that behavior).
*   `EnableProbabilisticRevealTokensForNonProxiedRequests = true`
    *   If true, PRTs can be attached to non-proxied requests as well. This will
        also allow first-party requests to receive PRTs (instead of just
        third-party requests).
*   `UseCustomProbabilisticRevealTokenRegistry = true`
    *   If true, Chrome will use the user-specified PRT registry (the following
        param) instead of the standard registry. This means you can test PRTs
        locally without needing to register your domain through the official
        registration process.
*   `CustomProbabilisticRevealTokenRegistry = "some,eTLD+1,csv,string"`
    *   This is a comma-separated list of domains (eTLD+1) which will be
        considered eligible to receive PRTs. This value requires special
        characters to be URL escaped (see below for more detail). A few
        examples:
        *   `google%2Ecom (google.com)`
        *   `google%2Ecom%2Cyoutube%2Ecom (google.com,youtube.com)`

You can
[look here](https://www.chromium.org/developers/how-tos/run-chromium-with-flags/)
to see how to start Chrome with command-line flags on each operating system. On
Linux, for example, that might look like this:

```
/opt/google/chrome/chrome --some-command-line-flag
```

If you want to run Chrome Beta you can replace `Google\ Chrome` with `Google\
Chrome\ Beta` i.e.:

```
/opt/google/chrome-beta/chrome --some-command-line-flag
```

You can make similar replacements to run Chrome Dev or Chrome Canary (just make
sure you have downloaded the relevant Chrome build).

In our case we want to set the `--enable-features` command line flag with the
features from above:

```
--enable-features="EnableIpPrivacyProxy,MaskedDomainList,EnableProbabilisticRevealTokens"
```

And we want to set the testing feature parameters for
`EnableProbabilisticRevealTokens`. Feature parameters are set with a `key/value`
syntax like follows:

```
--enable-features="MyFeature:k1/v1/k2/v2"
```

Note: In param values, special characters like `[%:/.,]` all need to be
URL-escaped. For example, the string `"my.value"` will be written as
`"my%2Evalue"`. This is needed when setting the custom registry, which is
expected to be a comma-separated list of domains. One way to get the URL-escaped
version of a domain-list string is with the following JavaScript snippet:

```
const domainListString = 'a.example,b.example,c.example';
encodeURIComponent(domainListString).replace(/\./g, '%2E').replace(/\-/g, '%2D');

==> 'a%2Eexample%2Cb%2Eexample%2Cc%2Eexample'
```

Note: The values in the custom registry should be registrable domains (eTLD+1).
You can find the registrable domain of a URL using this
[URL Analyzer](https://web.dev/articles/url-parts#url_analyzer) tool.

## Example

Combining all the steps from above, an example of starting Chrome Canary on
linux with the testing features and using `[google.com, youtube.com]` as the
custom registry list would look like:

```
/opt/google/chrome/chrome --enable-features=" \
    EnableIpPrivacyProxy, \
    MaskedDomainList, \
    EnableProbabilisticRevealTokens: \
      ProbabilisticRevealTokensAddHeaderToProxiedRequests/true/ \
      EnableProbabilisticRevealTokensForNonProxiedRequests/true/ \
      UseCustomProbabilisticRevealTokenRegistry/true/ \
      CustomProbabilisticRevealTokenRegistry/ \
      google%2Ecom%2Cyoutube%2Ecom"
```

Here you can replace the `google%2Ecom%2Cyoutube%2Ecom` value with your chosen
list of domains to perform testing on other sites.

## Testing

### Getting a token

Once you have launched Chrome with the feature flags above, you can navigate to
a page which is sending requests to one of the domains in your custom registry.
By opening the Network tab of the Chrome Devtools you can check the headers of
those requests. You should see a PRT set in the following request header:

```
Sec-Probabilistic-Reveal-Token
```

Alternatively, if you are sending the requests to a server you own, you can log
the tokens from your server.

Note: when attaching token headers to requests, Chrome will cache and reuse
tokens for a given first-party / third-party pair (i.e. top level site /
embedded site), as long as the token is not expired. That means if a given user
loads the same page multiple times during a single session, and PRTs are being
sent to some domain on that page, Chrome will attach the same token value to the
requests for that domain. If you want to get distinct token values for testing,
you can reset the session (i.e. close and reopen the browser), or load pages
with different top-level sites or different embedded sites.

The value of the PRT header will be base64 encoded bytes representing the
following struct:

```
PRT {
  uint8 version;
  opaque u;
  opaque e;
  opaque epoch_id;
}
```

Here `u` and `e` are used to generate the ciphertext of the token, and
`epoch_id` is used to identify the associated keys for decrypting the token.

### Decrypting a token

Tokens can be decrypted and validated using our
[developer library](https://github.com/explainers-by-googlers/prtoken-reference/).
You can clone that repo and follow the instructions in the README on how to
build and run commands. The following commands are useful for decrypting and
validating tokens:

*   `epoch`
*   `decrypt`

`epoch` outputs the epoch ID of a given token, without attempting to decrypt the
token. Tokens can only be decrypted once the encryption keys for that epoch have
been published. Token keys are typically published 24 hours after an epoch ends.
To see if the keys for an epoch have been published you can check for an entry
in the
[epochs.csv](https://github.com/explainers-by-googlers/prtoken-reference/blob/main/published_keys/epochs.csv)
file. If there is no entry for the given epoch ID, then those tokens cannot be
decrypted yet.

Note: given an epoch ID, you can fetch the keys for an epoch with the following
url template:

```
https://raw.githubusercontent.com/explainers-by-googlers/prtoken-reference/refs/heads/main/published_keys/{epoch_id}.json
```

Example:

```
bazelisk run //prtoken:prtoken epoch -- --prt=AQAhAynlOiG0DOYkZlMuAexBokZwjaqXmYmC2BP4fI9vUHhFACEChAGuFovnbJL7rgEFC5sKt7OOWd2KvSi2qk79VdKtcG0F9BAgFHhO+A==

==> epoch_id: BfQQIBR4Tvg
```

`decrypt` will attempt to fetch the keys for the relevant epoch and decrypt the
given token. If the keys for the epoch have not been published, this operation
will fail. On success, this will output the decrypted token contents.

Example:

```
bazelisk run //prtoken:prtoken decrypt -- --prt=AQAhAynlOiG0DOYkZlMuAexBokZwjaqXmYmC2BP4fI9vUHhFACEChAGuFovnbJL7rgEFC5sKt7OOWd2KvSi2qk79VdKtcG0F9BAgFHhO+A==

==> PRT:
==> epoch_id: BfQQIBR4Tvg
==> version: 1
==> ordinal: 2
==> ip: ::ffff:104.197.188.2
==> hmac_valid: true
```

In the example above, the IP address is populated. This will only be the case
for a small percentage of tokens. For most tokens the IP field will be blank.

Since tokens can only be decrypted after the epoch embargo period ends, it is
recommended to collect several tokens for an epoch if you want to test with
tokens that contain an IP address. At a 10% reveal rate, collecting 20 tokens
will give you ~88% chance of having at least one token with an IP.

The `decrypt` command can also be used to decrypt several tokens at once. To do
this, write the tokens to a file with one token value per line and set the
`--prt_filename` flag:

Example:

```
bazelisk run //prtoken:prtoken decrypt -- --prt_filename=/data/prts.txt
```

This will attempt to decrypt all of the tokens in the input file and print the
results to stdout in CSV format. You can provide an optional `--output_filename`
flag to write the results to a file instead.

The schema of the output CSV file is:

```
PRT, Epoch ID, Version, Ordinal, IP, HMAC Valid, Error
```

Here `PRT` is the original encrypted token value from the input file and `Error`
will be populated with a message if decryption fails for a particular token (for
example if the keys for that token have not been published).

## Additional Flags

Here are some additional feature params for the
`EnableProbabilisticRevealTokens` feature that may be useful for testing:

*   `ProbabilisticRevealTokenServer`(string)
    *   You can set this param if you want to override the host of the PRT
        issuer server. This could be useful if you would like to run your own
        test server that issues PRTs using a known private-key. This would allow
        you to decrypt and validate the tokens immediately, as well as allow you
        to change the IP reveal rate. Without overriding this, the default
        Google-run issuer server will be used, and you will have to wait for the
        keys to be published in order to decrypt the PRT headers.
*   `ProbabilisticRevealTokenServerPath`(string)
    *   This is used to override the path of the PRT issuance endpoint.
*   `BypassProbabilisticRevealTokenRegistry`(boolean)
    *   If true, the PRT registration check will be skipped altogether and we
        will consider every domain as being eligible to receive PRTs. This can
        be used in place of `UseCustomProbabilisticRevealTokenRegistry` &
        `CustomProbabilisticRevealTokenRegistry`. Just be aware that this will
        cause Chrome to attach PRTs to all requests (not just to requests for
        your chosen list of domains).

The full list of PRT feature params and descriptions is
[defined here](https://source.chromium.org/chromium/chromium/src/+/main:net/base/features.h;l=370?q=kEnableProbabilisticRevealTokens&ss=chromium%2Fchromium%2Fsrc)
under the `kEnableProbabilisticRevealTokens` feature.

For faster dev testing, override the ProbabilisticRevealTokenServerPath:

```
/opt/google/chrome/chrome --enable-features=" \
    EnableIpPrivacyProxy, \
    MaskedDomainList, \
    EnableProbabilisticRevealTokens: \
      ProbabilisticRevealTokensAddHeaderToProxiedRequests/true/ \
      EnableProbabilisticRevealTokensForNonProxiedRequests/true/ \
      UseCustomProbabilisticRevealTokenRegistry/true/ \
      ProbabilisticRevealTokenServerPath/%2Fv1%2Ftestissueprts%2F/
      CustomProbabilisticRevealTokenRegistry/ \
      google%2Ecom%2Cyoutube%2Ecom" --store-probabilistic-reveal-tokens
```

The /v1/testissueprts endpoint uses a revealed set of keys to mint PRTs.
This allows immediate token decryption for faster testing.

The keys used are from /published_keys/5Y8CIWJwNmE.json:
{
    "eg": {
        "crv": "P-256",
        "d": "Pq4R2aXEDtAkY4VOLNCIxzI_XI7i8iAd-M_Xy-s20Hs",
        "g": "A2sX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW",
        "kty": "EC",
        "x": "PePsOzwzLYu0K_PCRalWuFbUm7pGbjWPVDngp8Dsuj4",
        "y": "BiYMu6-ifC_w6egQEPEKALcu9Q4Q0Xw3LmMZxliNhl4"
    },
    "epoch_end_time": "2025-06-09T13:14:18+00:00",
    "epoch_id": "5Y8CIWJwNmE",
    "epoch_start_time": "2025-06-08T01:14:18+00:00",
    "hmac": {
        "alg": "HS256",
        "k": "Xb5MHBvuLztWWsdrA8Q_uNJdVLFWmXX-QigIMQV_B9E",
        "kty": "HMAC"
    }
}

### Storing PRTs to disk

Additionally, there is a separate command-line flag that can be used to store
PRTs to disk:

```
--store-probabilistic-reveal-tokens
```

Specifically, this flag writes all tokens received from the issuer server to a
file named `ProbabilisticRevealTokens` in the
[user-data directory](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md)
of the current profile. This file is a sqlite database file, which can be
manually queried from the command-line or validated with our
[developer library](https://github.com/explainers-by-googlers/prtoken-reference/)
(see the `verify` command in the README). This can be used to verify the IP
reveal rate by decrypting all tokens received from the issuer server once the
issuance keys are published.

Note: the tokens stored in the database file are not in the same format as the
PRT headers which are attached to requests. There is some additional
serialization and encoding (as well as cryptographic re-randomization) that
occurs when we attach PRT headers to requests. But the token ciphertexts in the
database file and the token ciphertexts that are attached to request headers
will decrypt to the same underlying plaintext values.

It is not advised to run Chrome with this command-line flag outside of testing,
as it will write PRTs to disk even in Incognito mode (Chrome typically does not
write anything to the user-data directory in Incognito mode, so this flag
enables some non-standard behavior).

## Troubleshooting

If you are failing to see PRTs in the request headers after following the
instructions above, you can try some of the following methods to fix the issue.

*   Quit all running instances of Chrome by navigating to `chrome://quit` in a
    browser window and restart Chrome by launching from the command-line with
    the feature flags above.
    *   This can fix issues where the feature params were not set properly
        because there was already an instance of Chrome running with the default
        feature state.
*   Double check your value for the `CustomProbabilisticRevealTokenRegistry`
    feature param to make sure all special characters were properly url-escaped
    (it’s possible that the JS snippet given above does not escape all special
    characters).
    *   Alternatively, you can try replacing the
        `CustomProbabilisticRevealTokenRegistry` param with
        `BypassProbabilisticRevealTokenRegistry`, which will cause Chrome to
        skip the registration check altogether. Just be aware that this will
        cause Chrome to attach PRTs to all requests (not just to requests for
        your chosen list of domains).
*   You can check the result of the PRT issuance request by navigating to
    `chrome://histograms/#NetworkService.IpProtection.GetProbabilisticRevealTokensResult`
    and looking at the values logged for the metric (they will be numbers
    between 0 and 15). If you see results other than 0, that means either the
    issue request failed or the subsequent validation checks failed. You can
    match the logged error codes with the definitions in the
    [source-code](https://source.chromium.org/chromium/chromium/src/+/main:components/ip_protection/common/ip_protection_data_types.h;l=170)
    to see what is failing.
    *   This is more likely to occur if you are running your own issuer server
        and return a malformed token, an invalid public key, or invalid token
        expiration times.
