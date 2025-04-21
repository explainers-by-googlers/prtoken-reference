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

#include <curl/curl.h>

#include <cstddef>
#include <cstdint>
#include <fstream>
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
  return prt;
}

// A callback function for curl to write the response to a string.
size_t CurlWriteCallback(char *contents, size_t size, size_t nmemb,
                         std::string *response) {
  size_t total_size = size * nmemb;
  response->append(contents, total_size);
  return total_size;
}

}  // namespace

absl::Status GetEpochIdFromTokenHeader(const std::string &prt_header) {
  ASSIGN_OR_RETURN(ProbabilisticRevealToken prt,
                   GetTokenFromHeaderString(prt_header));
  std::string epoch_id_base64;
  absl::WebSafeBase64Escape(prt.epoch_id, &epoch_id_base64);
  std::cout << "epoch_id: " << epoch_id_base64 << std::endl;
  return absl::OkStatus();
}

absl::Status DecryptTokenHeader(const std::string &prt_header) {
  ASSIGN_OR_RETURN(ProbabilisticRevealToken prt,
                   GetTokenFromHeaderString(prt_header));
  std::string epoch_id_base64;
  absl::WebSafeBase64Escape(prt.epoch_id, &epoch_id_base64);

  // Fetch the key file from the published_keys directory in github.
  CURL *curl;
  CURLcode res;
  std::string key_file_buffer;
  std::string key_file_url = absl::StrCat(
      "https://raw.githubusercontent.com/explainers-by-googlers/"
      "prtoken-reference/refs/heads/main/published_keys/",
      epoch_id_base64, ".json");

  curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, key_file_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &key_file_buffer);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
      return absl::InternalError(
          absl::StrCat("Failed to fetch key file for epoch: ", epoch_id_base64,
                       ". Check "
                       "https://github.com/explainers-by-googlers/"
                       "prtoken-reference/blob/main/published_keys/epochs.csv "
                       "too see if the epoch keys have been published."));
    }
    curl_easy_cleanup(curl);
  } else {
    return absl::InternalError("Failed to initialize curl.");
  }

  // Load the keys and create a token verifier.
  absl::StatusOr<prtoken::EpochKeyMaterials> key_materials_or =
      prtoken::LoadKeysFromJson(key_file_buffer);
  if (!key_materials_or.ok()) {
    return absl::InternalError("Failed to load keys from json.");
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

  // Decrypt the token.
  ElGamalCiphertext prt_ciphertext;
  prt_ciphertext.set_e(prt.e);
  prt_ciphertext.set_u(prt.u);
  std::vector<prtoken::proto::PlaintextToken> plaintext_tokens;
  std::vector<prtoken::proto::VerificationErrorReport> reports;
  if (!verifier.value()->DecryptToken(prt_ciphertext, plaintext_tokens,
                                      reports)) {
    std::string error_message;
    if (reports.size() > 0) {
      error_message = reports[0].error_message();
    }
    return absl::InternalError(
        absl::StrCat("Failed to decrypt token. ", error_message));
  }
  prtoken::proto::PlaintextToken plaintext_token = plaintext_tokens[0];
  absl::StatusOr<std::string> ip_string =
      prtoken::IPv6ByteArrayToString(std::string(
          plaintext_token.signal().begin(), plaintext_token.signal().end()));
  if (!ip_string.ok()) {
    return absl::InternalError("Failed to deserialize ip bytes.");
  }

  // Print the decrypted token contents.
  std::cout << "PRT:" << std::endl;
  std::cout << "epoch_id: " << epoch_id_base64 << std::endl;
  std::cout << "version: " << plaintext_token.version() << std::endl;
  std::cout << "ordinal: " << plaintext_token.ordinal() << std::endl;
  std::cout << "ip: " << ip_string.value() << std::endl;
  std::cout << "hmac_valid: "
            << (plaintext_token.hmac_valid() ? "true" : "false") << std::endl;

  return absl::OkStatus();
}

}  // namespace prtoken
