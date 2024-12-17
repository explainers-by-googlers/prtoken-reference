// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "prtoken/verifier.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "prtoken/token.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "private_join_and_compute/util/status_macros.h"

namespace prtoken {

using ::private_join_and_compute::BigNum;
using ::private_join_and_compute::ECPoint;
using ::private_join_and_compute::ElGamalCiphertext;
using ::private_join_and_compute::elgamal::PrivateKey;

void Decrypter::Init(const private_join_and_compute::ElGamalSecretKey& elgamal_secret_key) {
  blinders_context_ = std::make_unique<private_join_and_compute::Context>();
  ec_group_ = std::make_unique<private_join_and_compute::ECGroup>(
      private_join_and_compute::ECGroup::Create(kCurveId, blinders_context_.get()).value());

  // Note: Although PrivateKey is an aggregate type, some compilers do not
  // allow passing a BigNum directly, hence we do this {} instantiation.
  std::unique_ptr<PrivateKey> private_key(
      new PrivateKey({blinders_context_->CreateBigNum(
          elgamal_secret_key.x())}));

  decrypter_ =
      std::make_unique<private_join_and_compute::ElGamalDecrypter>(std::move(private_key));
}

absl::StatusOr<std::string> Decrypter::Decrypt(
    const private_join_and_compute::ElGamalCiphertext& token) const {
  ASSIGN_OR_RETURN(ECPoint point_u, ec_group_->CreateECPoint(token.u()));
  ASSIGN_OR_RETURN(ECPoint point_e, ec_group_->CreateECPoint(token.e()));
  private_join_and_compute::elgamal::Ciphertext ciphertext = {std::move(point_u),
                                              std::move(point_e)};
  ASSIGN_OR_RETURN(ECPoint decrypted_token, decrypter_->Decrypt(ciphertext));
  ASSIGN_OR_RETURN(
      BigNum x_recovered,
      ec_group_->RecoverXFromPaddedPoint(
          decrypted_token,
          /*padding_bit_count=*/token_structure.padding_size * kBitsPerByte));
  return x_recovered.ToBytes();
}

absl::Status Verifier::DecryptTokens(
    absl::Span<const ElGamalCiphertext> tokens,
    std::vector<proto::PlaintextToken>& messages) {
  for (const private_join_and_compute::ElGamalCiphertext& token : tokens) {
    ASSIGN_OR_RETURN(std::string message, decrypter_->Decrypt(token));
    ASSIGN_OR_RETURN(proto::PlaintextToken parsed_message,
                    validator_->ToProto(message));
    messages.push_back(parsed_message);
  }
  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<Verifier>> Verifier::Create(
    const private_join_and_compute::ElGamalSecretKey& elgamal_secret_key,
    absl::string_view hmac_secret) {
  auto decrypter = std::make_unique<Decrypter>();
  decrypter->Init(elgamal_secret_key);
  auto validator = std::make_unique<PlaintextTokenValidator>(hmac_secret);
  return std::unique_ptr<Verifier>(
      new Verifier(std::move(decrypter), std::move(validator)));
}
}  // namespace prtoken
