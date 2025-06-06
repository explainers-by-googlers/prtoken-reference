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

#ifndef PRTOKEN_VERIFIER_H_
#define PRTOKEN_VERIFIER_H_

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "private_join_and_compute/crypto/elgamal.pb.h"
#include "prtoken/token.h"
#include "prtoken/token.pb.h"

namespace prtoken {

enum VerificationError {
  VERIFICATION_ERROR_UNKNOWN,
  VERIFICATION_ERROR_DECRYPT_FAILED,
  VERIFICATION_ERROR_PARSE_FAILED,
  VERIFICATION_ERROR_INVALID_HMAC
};

using ::private_join_and_compute::BigNum;
using ::private_join_and_compute::Context;
using ::private_join_and_compute::ElGamalPublicKey;
using ::private_join_and_compute::ElGamalSecretKey;

using VerificationReport =
    std::vector<std::pair<size_t /** index */, VerificationError>>;

// Decrypts a probabilistic reveal token into a plaintext message.
// Creates and holds its own context and ECGroup, which are NOT thread-safe.
// Consider creating a single decrypter per thread.
class Decrypter {
 public:
  Decrypter() = default;
  void Init(
      const private_join_and_compute::ElGamalSecretKey &elgamal_secret_key);
  absl::StatusOr<std::string> Decrypt(
      const private_join_and_compute::ElGamalCiphertext &token) const;

 private:
  std::unique_ptr<private_join_and_compute::Context> blinders_context_;
  std::unique_ptr<private_join_and_compute::ECGroup> ec_group_;
  std::unique_ptr<private_join_and_compute::ElGamalDecrypter> decrypter_;
};

class Verifier {
 public:
  static absl::StatusOr<std::unique_ptr<Verifier>> Create(
      const private_join_and_compute::ElGamalSecretKey &elgamal_secret_key,
      absl::string_view hmac_secret);

  absl::Status DecryptTokens(
      absl::Span<const private_join_and_compute::ElGamalCiphertext> tokens,
      std::vector<proto::PlaintextToken> &messages,
      std::vector<proto::VerificationErrorReport> &reports);
  // Returns true if successfully decrypted a token.
  bool DecryptToken(const private_join_and_compute::ElGamalCiphertext &token,
                    std::vector<proto::PlaintextToken> &messages,
                    std::vector<proto::VerificationErrorReport> &reports);

  std::map<uint8_t, size_t> GetOrdinalHistogram(
      const std::vector<proto::PlaintextToken> &tokens);

  absl::Status VerifyEquivalentOrdinalCounts(
      const std::vector<proto::PlaintextToken> &tokens);

  absl::Status VerifyRevealRate(absl::Span<const proto::PlaintextToken> tokens,
                                float p_reveal);

 private:
  explicit Verifier(std::unique_ptr<Decrypter> decrypter,
                    std::unique_ptr<PlaintextTokenValidator> validator)
      : validator_(std::move(validator)), decrypter_(std::move(decrypter)) {}

  private_join_and_compute::ElGamalSecretKey elgamal_secret_key_;
  std::unique_ptr<PlaintextTokenValidator> validator_;
  std::unique_ptr<Decrypter> decrypter_;
  constexpr static float kRevealRateTolerance = 0.001;  // 0.1% tolerance.
};
}  // namespace prtoken

#endif  // PRTOKEN_VERIFIER_H_
