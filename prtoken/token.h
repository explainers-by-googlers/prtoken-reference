/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRTOKEN_TOKEN_H_
#define PRTOKEN_TOKEN_H_

#include <sys/types.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "private_join_and_compute/crypto/elgamal.pb.h"
#include "prtoken/token.pb.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/nid.h"

namespace prtoken {

// All _size and _offset fields are in bytes.
struct VersionedTokenStructure {
  size_t version_value;
  size_t version_size;
  size_t bucket_offset;
  size_t bucket_size;
  size_t signal_offset;
  size_t signal_size;
  size_t hmac_offset;
  size_t hmac_size;
  size_t padding_size;
  constexpr size_t token_size() const {
    return version_size + bucket_size + signal_size + hmac_size + padding_size;
  };
};

constexpr VersionedTokenStructure token_structure_v1 = {
    .version_value = 1,
    .version_size = 1,
    .bucket_offset = 1,
    .bucket_size = 1,
    .signal_offset = 2,
    .signal_size = 16,
    .hmac_offset = 18,
    .hmac_size = 8,
    .padding_size = 3,
};

constexpr VersionedTokenStructure token_structure = token_structure_v1;
using PlaintextTokenBytes = std::array<uint8_t, token_structure.token_size()>;

// The # of buckets we can choose for a token. Note that this number must fit
// into the bucket_size parameter for the token.
static const size_t kTokenBucketsCount = 100;
static constexpr int kCurveId = NID_X9_62_prime256v1;  // aka secp256r1
static const uint8_t kBitsPerByte = 8;
static const uint8_t kHMACSecretSizeBytes = 32;

struct ElGamalProtoKeypair {
  private_join_and_compute::ElGamalPublicKey public_key;
  private_join_and_compute::ElGamalSecretKey secret_key;
};

// Generates the plaintext of a probabilistic reveal token.
class PlaintextTokenGenerator {
 public:
  explicit PlaintextTokenGenerator(absl::string_view hmac_key);
  // Build the plaintext of a probabilistic reveal token for a given signal.
  virtual absl::Status Generate(
      const std::array<uint8_t, token_structure.signal_size>& signal,
      int bucket_id,
      PlaintextTokenBytes& message);
  virtual ~PlaintextTokenGenerator() = default;

 private:
  // Bit generator for uniformly random bucket assignment.
  std::unique_ptr<absl::BitGen> gen_;
  std::string hmac_key_;
};

class PlaintextTokenValidator {
 public:
  explicit PlaintextTokenValidator(absl::string_view hmac_secret);
  // Validates the HMAC of the message and exports a proto of relevant fields.
  absl::StatusOr<proto::PlaintextToken> ToProto(absl::string_view message);
  absl::StatusOr<proto::PlaintextToken> ToProto(
      PlaintextTokenBytes message_bytes);
 private:
  absl::StatusOr<bool> IsHMACValid(absl::string_view message);
  std::string hmac_key_;
};

absl::StatusOr<std::string> HMAC_SHA256(
    absl::string_view key,
    absl::string_view message);

}  // namespace prtoken

#endif  // PRTOKEN_TOKEN_H_
