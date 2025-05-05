/*
 * Copyright 2025 Google LLC
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

#include "prtoken/token_header.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "openssl/bytestring.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "private_join_and_compute/crypto/elgamal.pb.h"
#include "private_join_and_compute/util/status_macros.h"
#include "prtoken/command.h"
#include "prtoken/issuer.h"
#include "prtoken/storage.h"
#include "prtoken/verifier.h"

const std::string kPublishedKeysDir = "published_keys";

namespace prtoken {

using ::private_join_and_compute::ElGamalCiphertext;

namespace {

// Size of a PRT when TLS serialized, before base64 encoding.
constexpr size_t kPRTSize = 79;
constexpr size_t kPRTPointSize = 33;
constexpr size_t kEpochIdSize = 8;

// Struct representing an encrypted PRT header.
struct ProbabilisticRevealToken {
  std::int32_t version = 0;
  std::string u = "";
  std::string e = "";
  std::string epoch_id = "";

  std::string prt_header = "";  // The original PRT header string.
  std::string epoch_id_base64 = "";
};

// Deserializes a PRT bytestring that was serialized by Chrome.
bool DeserializePrt(const std::string &serialized_prt,
                    ProbabilisticRevealToken &out) {
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t *>(serialized_prt.data()),
           serialized_prt.size());
  if (CBS_len(&cbs) != kPRTSize) {
    return false;
  }
  uint8_t version;
  uint16_t u_size;
  uint16_t e_size;
  std::string u(kPRTPointSize, '0');
  std::string e(kPRTPointSize, '0');
  std::string epoch_id(kEpochIdSize, '0');
  if (!CBS_get_u8(&cbs, &version) || !CBS_get_u16(&cbs, &u_size) ||
      u_size != kPRTPointSize ||
      !CBS_copy_bytes(&cbs, reinterpret_cast<uint8_t *>(u.data()), u_size) ||
      !CBS_get_u16(&cbs, &e_size) || e_size != kPRTPointSize ||
      !CBS_copy_bytes(&cbs, reinterpret_cast<uint8_t *>(e.data()), e_size) ||
      !CBS_copy_bytes(&cbs, reinterpret_cast<uint8_t *>(epoch_id.data()),
                      kEpochIdSize)) {
    return false;
  }
  out.version = version;
  out.u = std::move(u);
  out.e = std::move(e);
  out.epoch_id = std::move(epoch_id);
  return true;
}

// A PRT header is serialized and base64 encoded. In order to build the token
// struct from the header string, we need to first base64 decode the string,
// then deserialize the bytes into the PRT struct.
absl::StatusOr<ProbabilisticRevealToken> GetTokenFromHeaderString(
    std::string prt_header) {
  // Remove padding colons if necessary.
  if (prt_header[0] == ':') {
    prt_header = prt_header.substr(1, prt_header.length());
  }
  if (prt_header[prt_header.length() - 1] == ':') {
    prt_header = prt_header.substr(0, prt_header.length() - 1);
  }

  std::string prt_bytes;
  if (!absl::Base64Unescape(prt_header, &prt_bytes)) {
    return absl::InternalError("Decoding prt failed.");
  }

  ProbabilisticRevealToken prt;
  if (!DeserializePrt(prt_bytes, prt)) {
    return absl::InternalError("Deserializing prt failed.");
  }
  prt.prt_header = prt_header;
  absl::WebSafeBase64Escape(prt.epoch_id, &prt.epoch_id_base64);
  return prt;
}

// Read the key file from the published_keys directory.
absl::StatusOr<std::string> GetKeyFileForEpoch(const std::string &epoch_id) {
  std::string private_key_file = epoch_id + ".json";
  std::filesystem::path filePath(std::filesystem::current_path() /
                                 kPublishedKeysDir / private_key_file);
  if (!std::filesystem::exists(filePath)) {
    return absl::InternalError(absl::StrCat(
        "Failed to find the key file for epoch: ", private_key_file,
        ". Try `git pull` and check published_keys/epochs.csv "
        "to see if the epoch keys have been published."));
  }

  std::ifstream fileStream(filePath);
  if (!fileStream.is_open()) {
    return absl::InternalError(absl::StrCat(
        "Failed to open ", kPublishedKeysDir, "/", private_key_file));
  }
  std::stringstream key_file_buffer;
  key_file_buffer << fileStream.rdbuf();
  fileStream.close();
  return key_file_buffer.str();
}

absl::StatusOr<std::unique_ptr<prtoken::Verifier>> BuildVerifierFromKeyFile(
    const std::string &key_file_json) {
  absl::StatusOr<prtoken::EpochKeyMaterials> key_materials_or =
      prtoken::LoadKeysFromJson(key_file_json);
  if (!key_materials_or.ok()) {
    return absl::InternalError("Failed to load keys from json.");
  }
  const prtoken::EpochKeyMaterials &key_materials = *key_materials_or;
  std::string y_escaped;
  absl::WebSafeBase64Escape(key_materials.eg().public_key().y(), &y_escaped);
  return prtoken::Verifier::Create(key_materials.eg().secret_key(),
                                   key_materials.hmac_key());
}

absl::StatusOr<prtoken::proto::PlaintextToken> DecryptToken(
    const ProbabilisticRevealToken &prt, prtoken::Verifier *verifier) {
  ElGamalCiphertext prt_ciphertext;
  prt_ciphertext.set_e(prt.e);
  prt_ciphertext.set_u(prt.u);
  std::vector<prtoken::proto::PlaintextToken> plaintext_tokens;
  std::vector<prtoken::proto::VerificationErrorReport> reports;
  if (!verifier->DecryptToken(prt_ciphertext, plaintext_tokens, reports)) {
    std::string error_message;
    if (reports.size() > 0) {
      error_message = reports[0].error_message();
    }
    return absl::InternalError(
        absl::StrCat("Failed to decrypt token. ", error_message));
  }
  return plaintext_tokens[0];
}

}  // namespace

absl::Status GetEpochIdFromTokenHeader(const std::string &prt_header) {
  ASSIGN_OR_RETURN(ProbabilisticRevealToken prt,
                   GetTokenFromHeaderString(prt_header));
  std::cout << "epoch_id: " << prt.epoch_id_base64 << std::endl;
  return absl::OkStatus();
}

absl::Status DecryptTokenHeader(const std::string &prt_header) {
  ASSIGN_OR_RETURN(ProbabilisticRevealToken prt,
                   GetTokenFromHeaderString(prt_header));

  // Load the keys for the epoch and create a token verifier.
  ASSIGN_OR_RETURN(std::string key_file_json,
                   GetKeyFileForEpoch(prt.epoch_id_base64));
  absl::StatusOr<std::unique_ptr<prtoken::Verifier>> verifier =
      BuildVerifierFromKeyFile(key_file_json);
  if (!verifier.ok()) {
    return absl::InternalError("Failed to materialize secret keys.");
  }

  // Decrypt the token.
  ASSIGN_OR_RETURN(prtoken::proto::PlaintextToken plaintext_token,
                   DecryptToken(prt, verifier.value().get()));
  absl::StatusOr<std::string> ip_string =
      prtoken::IPv6ByteArrayToString(std::string(
          plaintext_token.signal().begin(), plaintext_token.signal().end()));
  if (!ip_string.ok()) {
    return absl::InternalError("Failed to deserialize ip bytes.");
  }

  // Print the decrypted token contents.
  std::cout << "PRT:" << std::endl;
  std::cout << "epoch_id: " << prt.epoch_id_base64 << std::endl;
  std::cout << "version: " << plaintext_token.version() << std::endl;
  std::cout << "ordinal: " << plaintext_token.ordinal() << std::endl;
  std::cout << "ip: " << ip_string.value() << std::endl;
  std::cout << "hmac_valid: "
            << (plaintext_token.hmac_valid() ? "true" : "false") << std::endl;

  return absl::OkStatus();
}

absl::Status DecryptTokenHeaderFile(const std::string &prt_file,
                                    std::optional<std::string> output_file) {
  // Read input file into a vector of PRT headers.
  std::ifstream prt_file_stream(prt_file);
  std::string prt_header;
  std::vector<std::string> prt_headers;
  if (prt_file_stream.is_open()) {
    while (std::getline(prt_file_stream, prt_header)) {
      prt_headers.push_back(prt_header);
    }
    prt_file_stream.close();
  } else {
    return absl::InternalError("Failed to open prt file.");
  }

  // Parse the PRT headers into a vector of token structs, and get the set of
  // unique epoch IDs.
  std::vector<ProbabilisticRevealToken> prts;
  std::set<std::string> epoch_ids;
  for (const std::string &prt_header : prt_headers) {
    ASSIGN_OR_RETURN(ProbabilisticRevealToken prt,
                     GetTokenFromHeaderString(prt_header));
    prts.push_back(prt);
    epoch_ids.insert(prt.epoch_id_base64);
  }

  // A map of epoch_id to verifier.
  std::map<std::string, std::unique_ptr<prtoken::Verifier>> verifiers;
  // A map of epoch_id to error message.
  std::map<std::string, std::string> verifier_errors;
  // Load the keys for each epoch and create a token verifier.
  for (const std::string &epoch_id : epoch_ids) {
    absl::StatusOr<std::string> key_file_json = GetKeyFileForEpoch(epoch_id);
    if (!key_file_json.ok()) {
      verifier_errors[epoch_id] = key_file_json.status().message();
      continue;
    }
    absl::StatusOr<std::unique_ptr<prtoken::Verifier>> verifier =
        BuildVerifierFromKeyFile(key_file_json.value());
    if (!verifier.ok()) {
      verifier_errors[epoch_id] = verifier.status().message();
      continue;
    }
    verifiers[epoch_id] = std::move(verifier.value());
  }

  // Build the output lines.
  std::vector<std::string> out_lines;
  out_lines.push_back("prt,epoch_id,version,ordinal,ip,hmac_valid,error");

  for (const ProbabilisticRevealToken &prt : prts) {
    std::string epoch_id = prt.epoch_id_base64;
    // Get the verifier for the epoch, or the error message if the verifier
    // failed to be created.
    auto verifier_iterator = verifiers.find(epoch_id);
    if (verifier_iterator == verifiers.end()) {
      std::string error_message = verifier_errors[epoch_id];
      out_lines.push_back(absl::StrFormat("%s,%s,,,,,%s", prt.prt_header,
                                          epoch_id, error_message));
      continue;
    }
    prtoken::Verifier *verifier = verifier_iterator->second.get();

    // Decrypt the token.
    absl::StatusOr<prtoken::proto::PlaintextToken> maybe_plaintext_token =
        DecryptToken(prt, verifier);
    if (!maybe_plaintext_token.ok()) {
      out_lines.push_back(
          absl::StrFormat("%s,%s,,,,,%s", prt.prt_header, epoch_id,
                          maybe_plaintext_token.status().message()));
      continue;
    }
    prtoken::proto::PlaintextToken plaintext_token =
        maybe_plaintext_token.value();
    absl::StatusOr<std::string> ip_string =
        prtoken::IPv6ByteArrayToString(std::string(
            plaintext_token.signal().begin(), plaintext_token.signal().end()));
    if (!ip_string.ok()) {
      out_lines.push_back(absl::StrFormat("%s,%s,,,,,%s", prt.prt_header,
                                          epoch_id,
                                          "Failed to deserialize ip bytes."));
      continue;
    }

    // Add the decrypted token contents to the output CSV file.
    std::string out_line = absl::StrFormat(
        "%s,%s,%d,%d,%s,%s,%s", prt.prt_header, epoch_id,
        plaintext_token.version(), plaintext_token.ordinal(), ip_string.value(),
        (plaintext_token.hmac_valid() ? "true" : "false"), "");
    out_lines.push_back(out_line);
  }

  // Write the results to the given output file, or stdout if none is provided.
  if (output_file.has_value()) {
    std::ofstream outputFile(output_file.value());
    if (outputFile.is_open()) {
      for (const std::string &line : out_lines) {
        outputFile << line << std::endl;
      }
      outputFile.close();
    } else {
      return absl::InternalError("Error opening output file.");
    }
  } else {
    for (const std::string &line : out_lines) {
      std::cout << line << std::endl;
    }
  }

  return absl::OkStatus();
}

}  // namespace prtoken
