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

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "prtoken/token.h"
#include "prtoken/token.pb.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
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
    absl::Span<const private_join_and_compute::ElGamalCiphertext> tokens,
    std::vector<proto::PlaintextToken>& messages,
    std::vector<proto::VerificationErrorReport>& reports) {
  for (size_t i = 0; i < tokens.size(); ++i) {
    const private_join_and_compute::ElGamalCiphertext& token = tokens[i];
    absl::StatusOr<std::string> message_or = decrypter_->Decrypt(token);
    if (!message_or.ok()) {
      std::string error_message = absl::StrCat(
          "Failed to decrypt token at index=", i, " with error ",
          message_or.status().message());
      LOG(INFO) << error_message;
      proto::VerificationErrorReport report;
      report.set_index(i);
      report.set_error(proto::VERIFICATION_ERROR_DECRYPT_FAILED);
      report.set_error_message(error_message);
      reports.push_back(report);
      continue;
    }
    absl::StatusOr<proto::PlaintextToken> parsed_message_or =
        validator_->ToProto(*message_or);
    if (!parsed_message_or.ok()) {
      std::string error_message = absl::StrCat(
          "Failed to parse token at index=", i, " with error ",
          parsed_message_or.status().message());
      LOG(INFO) << error_message;
      proto::VerificationErrorReport report;
      report.set_index(i);
      report.set_error(proto::VERIFICATION_ERROR_PARSE_FAILED);
      report.set_error_message(error_message);
      reports.push_back(report);
      continue;
    }
    if (!parsed_message_or->hmac_valid()) {
      std::string error_message = absl::StrCat(
          "Token at index=", i, " has invalid HMAC");
      LOG(INFO) << error_message;
      proto::VerificationErrorReport report;
      report.set_index(i);
      report.set_error(proto::VERIFICATION_ERROR_INVALID_HMAC);
      report.set_error_message(error_message);
      reports.push_back(report);
      continue;
    }
    messages.push_back(*parsed_message_or);
  }
  if (!reports.empty()) {
    return absl::InternalError(
        absl::StrCat(reports.size(), " tokens had errors."));
  }
  return absl::OkStatus();
}


std::map<uint8_t, size_t> Verifier::GetOrdinalHistogram(
    const std::vector<proto::PlaintextToken>& tokens) {
  std::map<uint8_t, size_t> ordinal_counts;
  for (const proto::PlaintextToken& token : tokens) {
    ordinal_counts[token.ordinal()]++;
  }
  return ordinal_counts;
}

absl::Status Verifier::VerifyEquivalentOrdinalCounts(
    const std::vector<proto::PlaintextToken>& tokens) {
  // Create a map of ordinals to counts.
  const std::map<uint8_t, size_t> ordinal_counts = GetOrdinalHistogram(tokens);
  // Check that the counts are all the same value.
  for (const auto& [ordinal, count] : ordinal_counts) {
    if (count != ordinal_counts.begin()->second) {
      return absl::InvalidArgumentError(
          absl::StrCat("Ordinal ", ordinal, " appears ", count,
                       " times, but is expected to appear ",
                       ordinal_counts.begin()->second, " times."));
    }
  }
  return absl::OkStatus();
}

absl::Status Verifier::VerifyRevealRate(
    absl::Span<const proto::PlaintextToken> tokens, float p_reveal) {
  int num_revealed = 0;
  for (const proto::PlaintextToken& token : tokens) {
    if (!IsTokenSignalEmpty(token)) {
      num_revealed++;
    }
  }
  float actual_reveal_rate =
      static_cast<float>(num_revealed) / tokens.size();
  if (abs(actual_reveal_rate - p_reveal) > kRevealRateTolerance) {
    return absl::InvalidArgumentError(
        absl::StrCat("Actual reveal rate ", actual_reveal_rate,
                     " is not within ", kRevealRateTolerance,
                     " of the expected reveal rate ", p_reveal));
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
