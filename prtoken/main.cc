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

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "ortools/base/init_google.h"
#include "ortools/base/path.h"
#include "prtoken/issuer.h"
#include "prtoken/storage.h"
#include "prtoken/token.h"
#include "prtoken/token.pb.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"

ABSL_FLAG(int, num_tokens, 100, "How many tokens to generate.");
ABSL_FLAG(float, p_reveal, 0.1, "p_reveal value.");
ABSL_FLAG(std::string, signal_b64, "", "URI-safe Base64 encoded signal "
          "(max 128 bits).");
ABSL_FLAG(std::string, output_dir, "/tmp/", "Where to store output data.");
ABSL_FLAG(std::string, custom_db_filename, "",
          "Append to this file in the output_dir instead of a per-epoch DB.");

namespace {

constexpr int kErrorKeyGeneration = 1;
constexpr int kErrorSignalParsing = 2;
constexpr int kErrorTokenIssuance = 3;
constexpr int kErrorKeyWrite = 4;
constexpr int kErrorTokenWrite = 5;

// This is an alias to aid readability.
constexpr size_t SignalSizeLimit =
    prtoken::token_structure.signal_size;

absl::StatusOr<std::array<uint8_t, SignalSizeLimit>> ParseSignal(
    const std::string& signal_b64) {
  std::array<uint8_t, SignalSizeLimit> signal;
  std::string unescaped_str = "";
  if (!absl::WebSafeBase64Unescape(signal_b64, &unescaped_str)) {
    return absl::InternalError("Failed to parse signal.");
  }
  if (unescaped_str.size() > SignalSizeLimit) {
    return absl::InternalError("Signal is too long.");
  }
  std::memcpy(signal.data(), unescaped_str.data(), unescaped_str.size());
  return signal;
}
}  // namespace

int main(int argc, char** argv) {
  InitGoogle(argv[0], &argc, &argv, true);

  // Generate secrets and instantiate an issuer.
  absl::StatusOr<prtoken::proto::ElGamalKeyMaterial>
      keypair_or = prtoken::GenerateElGamalKeypair();
  if (!keypair_or.ok()) {
    return kErrorKeyGeneration;
  }
  const prtoken::proto::ElGamalKeyMaterial& keypair =
      *keypair_or;
  const std::string secret_key_hmac =
      prtoken::GenerateSecretKeyHMAC();
  const float p_reveal = absl::GetFlag(FLAGS_p_reveal);
  absl::StatusOr<std::unique_ptr<prtoken::Issuer>>
      issuer_status = prtoken::Issuer::Create(
          secret_key_hmac, keypair.public_key());
  std::unique_ptr<prtoken::Issuer> issuer(
      std::move(issuer_status.value()));

  // Mint tokens.
  std::vector<private_join_and_compute::ElGamalCiphertext> tokens;
  std::string signal_b64 = absl::GetFlag(FLAGS_signal_b64);
  absl::StatusOr<std::array<uint8_t, SignalSizeLimit>> signal_or =
      ParseSignal(signal_b64);
  if (!signal_or.ok()) {
    return kErrorSignalParsing;
  }
  std::array<uint8_t, SignalSizeLimit> signal = *signal_or;
  int num_tokens = absl::GetFlag(FLAGS_num_tokens);
  absl::Status status = issuer->IssueTokens(
      signal, static_cast<int>(p_reveal * num_tokens), num_tokens, tokens);
  if (!status.ok()) {
    return kErrorTokenIssuance;
  }

  const absl::Time epoch_start_time = absl::Now();
  const absl::Time epoch_end_time = absl::Now() + absl::Hours(24);
  // Format epoch_end_time as a string in ISO 8601 UST format YYYYMMDDHHMMSS.
  std::string epoch_end_time_str =
      absl::FormatTime("%Y%m%d%H%M%S", epoch_end_time, absl::UTCTimeZone());
  const std::string key_file = file::JoinPath(
      absl::GetFlag(FLAGS_output_dir),
      absl::StrCat("keys-", epoch_end_time_str, ".json"));
  std::string tokens_db_file;
  if (!absl::GetFlag(FLAGS_custom_db_filename).empty()) {
    tokens_db_file.assign(
        file::JoinPath(absl::GetFlag(FLAGS_output_dir),
                     absl::GetFlag(FLAGS_custom_db_filename)));
  } else {
    tokens_db_file = absl::StrCat(absl::GetFlag(FLAGS_output_dir), "/tokens-",
                                  epoch_end_time_str, ".db");
  }
  // Write keys and tokens.
  if (!prtoken::WriteKeysToFile(
           keypair, secret_key_hmac, key_file, epoch_start_time, epoch_end_time)
           .ok()) {
    return kErrorKeyWrite;
  }
  if (!prtoken::WriteTokensToFile(
           tokens, keypair.public_key(), absl::GetFlag(FLAGS_p_reveal),
           epoch_end_time, tokens_db_file)
           .ok()) {
    return kErrorTokenWrite;
  }
  return 0;
}
