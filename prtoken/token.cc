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

#include "prtoken/token.h"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/digest.h"
#include "openssl/hmac.h"
#include "private_join_and_compute/util/status_macros.h"

namespace prtoken {

PlaintextTokenGenerator::PlaintextTokenGenerator(absl::string_view hmac_key) {
  gen_ = std::make_unique<absl::BitGen>();
  hmac_key_ = hmac_key;
}

absl::Status PlaintextTokenGenerator::Generate(
    const std::array<uint8_t, token_structure.signal_size>& signal,
    int ordinal,
    PlaintextTokenBytes& message) {
  message.fill(0);
  message[0] = token_structure.version_value;
  message[token_structure.ordinal_offset] = ordinal;
  for (size_t i = 0; i < token_structure.signal_size; ++i) {
    message[token_structure.signal_offset + i] = signal[i];
  }
  std::string message_hmac(reinterpret_cast<const char*>(message.data()),
                           token_structure.hmac_offset);
  ASSIGN_OR_RETURN(const std::string hmac_val,
                   HMAC_SHA256(hmac_key_,
                               message_hmac));
  for (size_t i = 0; i < token_structure.hmac_size; ++i) {
    message[token_structure.hmac_offset + i] = hmac_val[i];
  }
  return absl::OkStatus();
}

PlaintextTokenValidator::PlaintextTokenValidator(
    absl::string_view hmac_secret) {
  hmac_key_ = hmac_secret;
}

absl::StatusOr<proto::PlaintextToken> PlaintextTokenValidator::ToProto(
    PlaintextTokenBytes message_bytes) {
      return ToProto(std::string(message_bytes.begin(), message_bytes.end()));
}

absl::StatusOr<proto::PlaintextToken> PlaintextTokenValidator::ToProto(
    absl::string_view message) {
  if (message.size() != token_structure.token_size()) {
    return absl::InvalidArgumentError("Invalid message size");
  }
  absl::string_view signal_str =
      message.substr(token_structure.signal_offset,
                     token_structure.signal_size);
  proto::PlaintextToken plaintext;
  plaintext.set_version(message[0]);
  plaintext.set_ordinal(message[token_structure.ordinal_offset]);
  // Explicit cast from a string_view to a string for compiler compatibility.
  plaintext.set_signal(std::string(signal_str));
  ASSIGN_OR_RETURN(const bool hmac_valid, IsHMACValid(message));
  plaintext.set_hmac_valid(hmac_valid);
  return plaintext;
}

absl::StatusOr<bool> PlaintextTokenValidator::IsHMACValid(
    absl::string_view message) {
  std::array<uint8_t, token_structure.hmac_size> observed_hmac;
  auto hmac_start_iter = message.begin() + token_structure.hmac_offset;
  std::copy(hmac_start_iter, hmac_start_iter + token_structure.hmac_size,
            observed_hmac.begin());
  std::string observed_hmac_str(reinterpret_cast<char*>(observed_hmac.data()),
                                token_structure.hmac_size);
  std::string message_hmac(reinterpret_cast<const char*>(message.data()),
                           token_structure.hmac_offset);
  std::string computed_hmac;
  ASSIGN_OR_RETURN(computed_hmac, HMAC_SHA256(hmac_key_, message_hmac));
  return observed_hmac_str == computed_hmac.substr(
      0, token_structure.hmac_size);
}

bool IsTokenSignalEmpty(const proto::PlaintextToken& token) {
  for (const uint8_t byte : token.signal()) {
    if (byte != 0) {
      return false;
    }
  }
  return true;
}

absl::StatusOr<std::string> HMAC_SHA256(
    absl::string_view key,
    absl::string_view message) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int resultLen = 0;
    const unsigned char* hmacResult = HMAC(
        EVP_sha256(),
        key.data(),
        key.size(),
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size(),
        result,
        &resultLen
    );
  if (hmacResult == nullptr) {
      return absl::InternalError("HMAC failed");
  }
  return std::string(reinterpret_cast<const char*>(hmacResult), resultLen);
}

};  // namespace prtoken
