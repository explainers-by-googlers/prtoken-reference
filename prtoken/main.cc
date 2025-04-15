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

// The main function issues and verifies PRTokens for IP addresses.
//
// Usage:
//   prtoken issue --ip=1.2.3.4 --num_tokens=100 --p_reveal=0.1
//   --output_dir=/tmp/ --custom_db_filename=tokens.db
//   --custom_key_filename=keys.json
//
//   prtoken verify --private_key=keys.json --token_db=tokens.db
//   --table_name=tokens --result_table=results
//
// The issue subcommand generates a set of tokens and stores them in a SQLite
// database file.
// The verify subcommand decrypts/verify the tokens and stores them to a new
// table in the same SQLite database file.

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
#include "ortools/base/path.h"
#include "prtoken/command.h"
#include "prtoken/issuer.h"
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
ABSL_FLAG(std::string, result_table, "",
          "The table name to store the decryptions. If empty, default is "
          "results_[epoch_second].");

namespace {

// Function to generate and store tokens
absl::Status GenerateAndStoreTokens() {
  std::string ip = absl::GetFlag(FLAGS_ip);
  if (!prtoken::IsValidIPAddress(ip)) {
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
  absl::StatusOr<std::array<uint8_t, prtoken::SignalSizeLimit>> signal_or =
      prtoken::IPStringToByteArray(ip);
  if (!signal_or.ok()) {
    return signal_or.status();
  }
  std::array<uint8_t, prtoken::SignalSizeLimit> signal = *signal_or;
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
  absl::StatusOr<std::unique_ptr<prtoken::Verifier>> verifier =
      prtoken::Verifier::Create(key_materials.eg().secret_key(),
                                key_materials.hmac_key());
  if (!verifier.ok()) {
    return absl::InternalError("Failed to materialize secret keys.");
  }

  prtoken::TokensDBWithIPVerifier db(std::move(verifier.value()),
                                     absl::GetFlag(FLAGS_table_name),
                                     absl::GetFlag(FLAGS_result_table));
  absl::Status status = db.Open(token_db);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to open tokens database: " << status.message();
    return status;
  }
  status = db.CreateResultTable();
  if (!status.ok()) {
    LOG(ERROR) << "Failed to create result table: " << status.message();
    return status;
  }
  status = db.ProcessTokens(y_escaped);
  db.close();
  if (status.ok()) {
    return db.report();
  }
  return status;
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
