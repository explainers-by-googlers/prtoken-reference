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

#ifndef PRTOKEN_CLIENT_H_
#define PRTOKEN_CLIENT_H_

#include <memory>

#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "private_join_and_compute/crypto/elgamal.pb.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace prtoken {

// Re-randomizes a probabilistic reveal token, as would be done by a client.
// Creates and holds its own context and ECGroup, which are NOT thread-safe.
// Consider creating a single Rerandomizer per thread.
class Rerandomizer {
 public:
  Rerandomizer() = default;
  // Initialize the Rerandomizer with the public key.
  virtual absl::Status Init(const private_join_and_compute::ElGamalPublicKey& public_key);
  // Encrypt a message using the public key.
  virtual absl::StatusOr<private_join_and_compute::ElGamalCiphertext> Rerandomize(
      private_join_and_compute::ElGamalCiphertext original_ciphertext);
  virtual ~Rerandomizer() = default;

 private:
  std::unique_ptr<private_join_and_compute::Context> blinders_context_;
  std::unique_ptr<private_join_and_compute::ECGroup> ec_group_;
  std::unique_ptr<private_join_and_compute::ElGamalEncrypter> encrypter_;
  private_join_and_compute::ElGamalPublicKey public_key_el_gamal_;
};

}  // namespace prtoken
#endif  // PRTOKEN_CLIENT_H_
