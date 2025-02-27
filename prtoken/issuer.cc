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

#include "prtoken/issuer.h"

#include <sys/types.h>

#include <algorithm>
#include <array>
#include <cstddef>
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
#include "private_join_and_compute/crypto/openssl.inc"
#include "prtoken/token.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/rand.h"
#include "private_join_and_compute/util/status_macros.h"

namespace prtoken {

using ::private_join_and_compute::Context;
using ::private_join_and_compute::ECGroup;
using ::private_join_and_compute::ECPoint;
using ::private_join_and_compute::ElGamalCiphertext;
using ::private_join_and_compute::ElGamalEncrypter;
using ::private_join_and_compute::ElGamalPublicKey;
using ::private_join_and_compute::elgamal::Ciphertext;
using ::private_join_and_compute::elgamal::GenerateKeyPair;
using ::private_join_and_compute::elgamal::PublicKey;

absl::Status ShuffleVector(std::vector<private_join_and_compute::ElGamalCiphertext>& tokens) {
  uint32_t randomValue;
  for (size_t i = tokens.size() - 1; i > 0; --i) {
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&randomValue),
                   sizeof(randomValue)) != 1) {
      return absl::InternalError("Failed to generate random value");
    }
    size_t j = randomValue % (i + 1);
    std::swap(tokens[i], tokens[j]);
  }
  return absl::OkStatus();
}

absl::Status Encrypter::Init(const ElGamalPublicKey& public_key) {
  blinders_context_ = std::make_unique<Context>();
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(kCurveId, blinders_context_.get()));
  ec_group_ = std::make_unique<private_join_and_compute::ECGroup>(std::move(ec_group));
  ASSIGN_OR_RETURN(ECPoint point_g, ec_group_->CreateECPoint(public_key.g()));
  ASSIGN_OR_RETURN(ECPoint point_y, ec_group_->CreateECPoint(public_key.y()));
  std::unique_ptr<PublicKey> public_key_eg(
      new PublicKey({std::move(point_g), std::move(point_y)}));
  encrypter_ = std::make_unique<ElGamalEncrypter>(ec_group_.get(),
                                                  std::move(public_key_eg));
  return absl::OkStatus();
}

absl::StatusOr<ElGamalCiphertext> Encrypter::Encrypt(
    absl::string_view message) {
  ASSIGN_OR_RETURN(
      ECPoint message_point,
      ec_group_->GetPointByPaddingX(
          blinders_context_->CreateBigNum(message),
          /*padding_bit_count=*/token_structure.padding_size * kBitsPerByte));
  ASSIGN_OR_RETURN(const Ciphertext ciphertext,
                   encrypter_->Encrypt(message_point));
  private_join_and_compute::ElGamalCiphertext ciphertext_proto;
  ASSIGN_OR_RETURN(const std::string u_bytes, ciphertext.u.ToBytesCompressed());
  ASSIGN_OR_RETURN(const std::string e_bytes, ciphertext.e.ToBytesCompressed());
  ciphertext_proto.set_u(u_bytes);
  ciphertext_proto.set_e(e_bytes);
  return ciphertext_proto;
}

Issuer::Issuer(std::unique_ptr<Encrypter> encrypter,
               std::unique_ptr<PlaintextTokenGenerator> generator)
    : generator_(std::move(generator)), encrypter_(std::move(encrypter)) {
  null_signal_.fill(0);
};

absl::Status Issuer::IssueTokens(
    const std::array<uint8_t, token_structure.signal_size>& signal,
    uint64_t num_signal_tokens, uint64_t num_total_tokens,
    std::vector<private_join_and_compute::ElGamalCiphertext>& tokens) {
  if (num_signal_tokens > num_total_tokens) {
    return absl::InvalidArgumentError(
        "Number of signal tokens cannot be greater than the total number of "
        "tokens.");
  }
  for (uint64_t i = 0; i < num_total_tokens; ++i) {
    PlaintextTokenBytes message;
    if (i < num_signal_tokens) {
      RETURN_IF_ERROR(generator_->Generate(signal, i + 1, message));
    } else {
      RETURN_IF_ERROR(generator_->Generate(null_signal_, i + 1, message));
    }
    absl::string_view message_str(reinterpret_cast<char*>(message.data()),
                                  token_structure.token_size());
    ASSIGN_OR_RETURN(ElGamalCiphertext ciphertext_proto,
                     encrypter_->Encrypt(message_str));
    tokens.push_back(ciphertext_proto);
  }
  RETURN_IF_ERROR(ShuffleVector(tokens));
  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<Issuer>> Issuer::Create(
    absl::string_view hmac_key, const private_join_and_compute::ElGamalPublicKey& public_key) {
  auto encrypter = std::make_unique<Encrypter>();
  RETURN_IF_ERROR(encrypter->Init(public_key));
  auto generator = std::make_unique<PlaintextTokenGenerator>(hmac_key);
  return std::unique_ptr<Issuer>(
      new Issuer(std::move(encrypter), std::move(generator)));
}

std::string GenerateSecretKeyHMAC() {
  auto context = std::make_unique<private_join_and_compute::Context>();
  return context->GenerateRandomBytes(kHMACSecretSizeBytes);
}

absl::StatusOr<proto::ElGamalKeyMaterial> GenerateElGamalKeypair() {
  proto::ElGamalKeyMaterial proto_key_pair;
  auto context = std::make_unique<private_join_and_compute::Context>();
  ASSIGN_OR_RETURN(const ECGroup ec_group,
                   ECGroup::Create(kCurveId, context.get()));
  ASSIGN_OR_RETURN(const KeySet key_pair, GenerateKeyPair(ec_group));
  ASSIGN_OR_RETURN(const std::string g_bytes,
                   key_pair.first->g.ToBytesUnCompressed());
  ASSIGN_OR_RETURN(const std::string y_bytes,
                   key_pair.first->y.ToBytesUnCompressed());
  proto_key_pair.mutable_public_key()->mutable_g()->assign(g_bytes);
  proto_key_pair.mutable_public_key()->mutable_y()->assign(y_bytes);
  proto_key_pair.mutable_secret_key()->mutable_x()->assign(
      key_pair.second->x.ToBytes());
  return proto_key_pair;
}

}  // namespace prtoken
