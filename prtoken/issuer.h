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

#ifndef PRTOKEN_ISSUER_H_
#define PRTOKEN_ISSUER_H_
#include <sys/types.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "private_join_and_compute/crypto/elgamal.pb.h"
#include "prtoken/token.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace prtoken {

using KeySet = std::pair<std::unique_ptr<private_join_and_compute::elgamal::PublicKey>,
                         std::unique_ptr<private_join_and_compute::elgamal::PrivateKey>>;

absl::StatusOr<proto::ElGamalKeyMaterial> GenerateElGamalKeypair();

// Convenience function to generate a secret key for HMAC.
std::string GenerateSecretKeyHMAC();

// Encrypts a probabilistic reveal token.
// Creates and holds its own context and ECGroup, which are NOT thread-safe.
// Consider creating a single encrypter per thread.
class Encrypter {
 public:
  Encrypter() = default;
  // Initialize the encrypter with the public key.
  virtual absl::Status Init(const private_join_and_compute::ElGamalPublicKey& public_key);
  // Encrypt a message using the public key.
  virtual absl::StatusOr<private_join_and_compute::ElGamalCiphertext> Encrypt(
      absl::string_view message);
  virtual ~Encrypter() = default;

 private:
  std::unique_ptr<private_join_and_compute::Context> blinders_context_;
  std::unique_ptr<private_join_and_compute::ECGroup> ec_group_;
  std::unique_ptr<private_join_and_compute::ElGamalEncrypter> encrypter_;
  private_join_and_compute::ElGamalPublicKey public_key_el_gamal_;
};

// Issues PRTs using a PlaintextTokenGenerator and Encrypter.
class Issuer {
 public:
  // Create an issuer with a given number of tokens that can reveal the signal
  // per batch.
  static absl::StatusOr<std::unique_ptr<Issuer>> Create(
      absl::string_view hmac_key, const private_join_and_compute::ElGamalPublicKey& public_key);
  virtual ~Issuer() = default;

  // Generate `num_total_tokens` tokens for the given signal and append these to
  // the `tokens` vector.
  absl::Status IssueTokens(
      const std::array<uint8_t, token_structure.signal_size>& signal,
      uint64_t num_signal_tokens, uint64_t num_total_tokens,
      std::vector<private_join_and_compute::ElGamalCiphertext>& tokens);

 protected:
  // Construct an issuer with a given number of tokens that can reveal the
  // signal.
  Issuer(std::unique_ptr<Encrypter> encrypter,
         std::unique_ptr<PlaintextTokenGenerator> generator);

 private:
  Issuer() = default;
  std::unique_ptr<PlaintextTokenGenerator> generator_;
  std::unique_ptr<Encrypter> encrypter_;
  std::array<uint8_t, token_structure.signal_size> null_signal_;
};

}  // namespace prtoken
#endif  // PRTOKEN_ISSUER_H_
