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

#include <arpa/inet.h>
#include <netinet/in.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "ortools/base/path.h"
#include "prtoken/issuer.h"
#include "prtoken/storage.h"
#include "prtoken/token.h"
#include "prtoken/token.pb.h"
#include "prtoken/verifier.h"

// For token issuance.
ABSL_FLAG(int, num_tokens, 100, "How many tokens to generate.");
ABSL_FLAG(float, p_reveal, 0.1, "p_reveal value.");
ABSL_FLAG(std::string, ip, "", "IPv4 or v6 address in string");
ABSL_FLAG(std::string, output_dir, "/tmp/", "Where to store output data.");
ABSL_FLAG(std::string, custom_db_filename, "",
          "Append to this file in the output_dir instead of a per-epoch DB.");
ABSL_FLAG(std::string, custom_key_filename, "",
          "The json file to store the keys. If empty, default is "
          "keys-[epoch_second].json");

// For token decryption.
ABSL_FLAG(std::string, private_key, "",
          "Required string for path of the private key json.");
ABSL_FLAG(std::string, token_db, "",
          "Required string for the path to the token db file.");
ABSL_FLAG(std::string, table_name, "tokens",
          "The table that stores the tokens.");

namespace {

constexpr int kErrorKeyGeneration = 1;
constexpr int kErrorSignalParsing = 2;
constexpr int kErrorTokenIssuance = 3;
constexpr int kErrorKeyWrite = 4;
constexpr int kErrorTokenWrite = 5;

// This is an alias to aid readability.
constexpr size_t SignalSizeLimit = prtoken::token_structure.signal_size;

// Helper to check if the input is a valid IP address.
bool IsValidIPAddress(absl::string_view ip_string) {
  struct in_addr ip4_addr;
  struct in6_addr ip6_addr;
  return (inet_pton(AF_INET, ip_string.data(), &ip4_addr) == 1 ||
          inet_pton(AF_INET6, ip_string.data(), &ip6_addr) == 1);
}

// Transform IP string into byte array. V4 address is padded
// to IPv4-mapped address, see
// http://tools.ietf.org/html/rfc3493#section-3.7.
absl::StatusOr<std::array<uint8_t, SignalSizeLimit>> IPStringToByteArray(
    std::string_view ip_string) {
  std::array<uint8_t, SignalSizeLimit> ipv6_bytes;
  struct in6_addr ip6_addr;
  if (inet_pton(AF_INET6, ip_string.data(), &ip6_addr) == 1) {
    std::memcpy(ipv6_bytes.data(), &ip6_addr, SignalSizeLimit);
    return ipv6_bytes;
  }
  struct in_addr ipv4_addr;
  if (inet_pton(AF_INET, ip_string.data(), &ipv4_addr) == 1) {
    // IPv4-mapped IPv6 format: ::ffff:IPv4
    // First 10 bytes are 0, next 2 bytes are 0xff, then the IPv4 address.
    std::memset(ipv6_bytes.data(), 0, 10);
    ipv6_bytes[10] = 0xff;
    ipv6_bytes[11] = 0xff;
    std::memcpy(ipv6_bytes.data() + 12, &ipv4_addr, 4);
    return ipv6_bytes;
  }
  return absl::InvalidArgumentError("Invalid IPv4 or IPv6 address.");
}

// Transform IPv6 byte array into string.
absl::StatusOr<std::string> IPv6ByteArrayToString(
    const std::string_view ip_string) {
  struct in6_addr ip6_addr;
  std::memcpy(&ip6_addr, ip_string.data(), sizeof(ip6_addr));
  char ip6_str[INET6_ADDRSTRLEN];
  if (inet_ntop(AF_INET6, &ip6_addr, ip6_str, INET6_ADDRSTRLEN) == nullptr) {
    return absl::InternalError("Failed to convert IPv6 address to string.");
  }
  return std::string(ip6_str);
}

// Function to generate and store tokens
absl::Status GenerateAndStoreTokens() {
  std::string ip = absl::GetFlag(FLAGS_ip);
  if (!IsValidIPAddress(ip)) {
    return absl::InvalidArgumentError("Invalid IP address.");
  }
  int num_tokens = absl::GetFlag(FLAGS_num_tokens);
  float p_reveal = absl::GetFlag(FLAGS_p_reveal);
  std::string output_dir = absl::GetFlag(FLAGS_output_dir);
  std::string custom_db_filename = absl::GetFlag(FLAGS_custom_db_filename);
  std::string custom_key_filename = absl::GetFlag(FLAGS_custom_key_filename);

  // Generate secrets and instantiate an issuer.
  absl::StatusOr<prtoken::proto::ElGamalKeyMaterial> keypair_or =
      prtoken::GenerateElGamalKeypair();
  if (!keypair_or.ok()) {
    return absl::InternalError("Failed to generate ElGamal keypair.");
  }
  const prtoken::proto::ElGamalKeyMaterial &keypair = *keypair_or;
  const std::string secret_key_hmac = prtoken::GenerateSecretKeyHMAC();
  absl::StatusOr<std::unique_ptr<prtoken::Issuer>> issuer_status =
      prtoken::Issuer::Create(secret_key_hmac, keypair.public_key());
  if (!issuer_status.ok()) {
    return absl::InternalError("Failed to create issuer.");
  }
  std::unique_ptr<prtoken::Issuer> issuer(std::move(issuer_status.value()));

  // Mint tokens.
  std::vector<private_join_and_compute::ElGamalCiphertext> tokens;
  absl::StatusOr<std::array<uint8_t, SignalSizeLimit>> signal_or =
      IPStringToByteArray(ip);
  if (!signal_or.ok()) {
    return signal_or.status();
  }
  std::array<uint8_t, SignalSizeLimit> signal = *signal_or;
  absl::Status status = issuer->IssueTokens(
      signal, static_cast<int>(p_reveal * num_tokens), num_tokens, tokens);
  if (!status.ok()) {
    return absl::InternalError("Failed to issue tokens.");
  }

  const absl::Time epoch_start_time = absl::Now();
  const absl::Time epoch_end_time = absl::Now() + absl::Hours(24);
  // Format epoch_end_time as a string in ISO 8601 UST format YYYYMMDDHHMMSS.
  std::string epoch_end_time_str =
      absl::FormatTime("%Y%m%d%H%M%S", epoch_end_time, absl::UTCTimeZone());

  std::string key_file;
  if (!custom_key_filename.empty()) {
    key_file.assign(file::JoinPath(output_dir, custom_key_filename));
  } else {
    key_file = absl::StrCat(output_dir, "/keys-", epoch_end_time_str, ".json");
  }

  std::string tokens_db_file;
  if (!custom_db_filename.empty()) {
    tokens_db_file.assign(file::JoinPath(output_dir, custom_db_filename));
  } else {
    tokens_db_file =
        absl::StrCat(output_dir, "/tokens-", epoch_end_time_str, ".db");
  }
  // Write keys and tokens.
  if (!prtoken::WriteKeysToFile(keypair, secret_key_hmac, key_file,
                                epoch_start_time, epoch_end_time)
           .ok()) {
    return absl::InternalError("Failed to write keys to file.");
  }
  if (!prtoken::WriteTokensToFile(tokens, keypair.public_key(), p_reveal,
                                  epoch_end_time, tokens_db_file)
           .ok()) {
    return absl::InternalError("Failed to write tokens to file.");
  }
  return absl::OkStatus();
}

// Function to decrypt tokens.
absl::Status DecryptTokens() {
  std::string private_key = absl::GetFlag(FLAGS_private_key);
  std::string token_db = absl::GetFlag(FLAGS_token_db);

  if (private_key.empty()) {
    return absl::InvalidArgumentError(
        "--private_key is required for decryption");
  }
  if (!std::filesystem::exists(private_key)) {
    return absl::InvalidArgumentError("private key file does not exist");
  }

  if (token_db.empty()) {
    return absl::InvalidArgumentError("--token_db is required for decryption");
  }
  if (!std::filesystem::exists(token_db)) {
    return absl::InvalidArgumentError("token file does not exist");
  }

  absl::StatusOr<prtoken::EpochKeyMaterials> key_materials_or =
      prtoken::LoadKeysFromFile(private_key);
  if (!key_materials_or.ok()) {
    return absl::InternalError("Failed to load keys from file.");
  }
  const prtoken::EpochKeyMaterials &key_materials = *key_materials_or;
  std::string y_escaped, ciphertext;
  absl::WebSafeBase64Escape(key_materials.eg().public_key().y(), &y_escaped);
  absl::StatusOr<std::vector<prtoken::ValidationToken>> tokens_or =
      prtoken::LoadTokensFromFile(y_escaped, absl::GetFlag(FLAGS_table_name),
                                  token_db);
  if (!tokens_or.ok()) {
    return absl::InternalError("Failed to load tokens from file.");
  }
  const std::vector<prtoken::ValidationToken> &tokens = *tokens_or;
  LOG(INFO) << "Tokens Loaded: " << tokens.size();

  absl::StatusOr<std::unique_ptr<prtoken::Verifier>> verifier =
      prtoken::Verifier::Create(key_materials.eg().secret_key(),
                                key_materials.hmac_key());
  if (!verifier.ok()) {
    return absl::InternalError("Failed to materialize secret keys.");
  }
  std::unique_ptr<prtoken::Verifier> verifier_ptr(std::move(verifier.value()));
  std::vector<prtoken::proto::PlaintextToken> decrypted_tokens;
  std::vector<prtoken::proto::VerificationErrorReport> reports;
  auto status = verifier_ptr->DecryptTokens(tokens, decrypted_tokens, reports);
  if (!status.ok()) {
    return absl::InternalError("Failed to decrypt tokens.");
  }
  for (long unsigned i = 0; i < decrypted_tokens.size(); i++) {
    absl::StatusOr<std::string> result =
        IPv6ByteArrayToString(std::string(decrypted_tokens[i].signal().begin(),
                                          decrypted_tokens[i].signal().end()));
    // This is not perfectly correct. Following CLs will remove this and expose
    // errors in Verifier::DecryptTokens() method.
    if (!result.ok()) {
      LOG(ERROR) << "Failed to decrypt tokens: " << tokens[i];
      continue;
    }
    std::string decrypted_str = *result;
    // TODO(b/400517728): Inject the the result back to the DB file.
    std::cout << "IP: " << ((decrypted_str == "::") ? "null" : decrypted_str)
              << ", validation: " << decrypted_tokens[i].hmac_valid()
              << std::endl;
  }
  return absl::OkStatus();
}
}  // namespace

int main(int argc, char **argv) {
  absl::InitializeLog();

  // For Positional Arguments.
  std::vector<char *> pop_args = absl::ParseCommandLine(argc, argv);
  if (pop_args.size() < 2) {
    LOG(ERROR) << "Usage: " << argv[0] << " <issue|verify> [options]\n";
    return 1;
  }

  std::string command = pop_args[1];
  absl::Status status;
  if (command == "issue") {
    status = GenerateAndStoreTokens();
  } else if (command == "verify") {
    status = DecryptTokens();
  } else {
    status =
        absl::InvalidArgumentError("Wrong command-line argument: " + command);
  }
  if (status.ok()) return 0;
  LOG(ERROR) << status.message();
  return 1;
}
