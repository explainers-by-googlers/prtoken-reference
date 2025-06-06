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

#ifndef PRTOKEN_STORAGE_H_
#define PRTOKEN_STORAGE_H_

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "include/nlohmann/json_fwd.hpp"
#include "ortools/base/types.h"
#include "private_join_and_compute/crypto/elgamal.pb.h"
#include "prtoken/token.pb.h"
#include "sqlite3.h"

namespace prtoken {

using private_join_and_compute::ElGamalCiphertext;
using prtoken::proto::EpochKeyMaterials;
using prtoken::proto::ValidationToken;

constexpr uint32_t kValidationBucketCount = 10000;

// Validating aggregate properties of tokens makes most sense in the context
// of the same num_tokens_with_signal and epoch_id, which we refer to as a
// validation bucket.
using ValidationBucket =
    std::pair<uint64_t /** num_tokens_with_signal */, uint64_t /** epoch_id */>;

// Singular Token database file.
class TokensDB {
 public:
  explicit TokensDB(std::string token_table) : token_table_(token_table) {};
  TokensDB() : token_table_("tokens") {};
  absl::Status Open(const std::string &db_path);
  absl::Status Insert(
      absl::Span<const ElGamalCiphertext> tokens,
      const private_join_and_compute::ElGamalPublicKey &public_key,
      uint64_t num_tokens_with_signal, absl::Time expiration_time);
  absl::Status GetValidationBuckets(std::set<ValidationBucket> &buckets);
  // Process tokens found in rows matching the given public key.
  // It calls OnFinishGetToken() after each token is read.
  // ProcessTokens() fails if OnFinishGetToken() returns any error status.
  absl::Status ProcessTokens(const std::string &public_key);
  // A hook for subclasses to perform additional token processing.
  // The implementation decides what error to raise. If OnFinishGetToken()
  // fails, ProcessTokens() stops and returns that error.
  virtual absl::Status OnFinishGetToken(const ValidationToken &token);
  // Populate a vector of tokens found in rows that match the given bucket.
  absl::Status GetTokensForValidationBucket(
      const ValidationBucket &bucket, std::vector<ValidationToken> &tokens);
  void close();
  virtual ~TokensDB();

 protected:
    sqlite3 *get_db() { return db_; };

 private:
  absl::Status readTokenFromStatement(sqlite3_stmt *stmt,
                                      ValidationToken &token);
  sqlite3 *db_;
  std::string db_path_;
  std::string token_table_;
  constexpr static char kBase64URIEncodedG[] =\
    "A2sX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW";

};

// Store containing multiple token databases.
class TokenStore {
 public:
  absl::Status LoadFile(std::string_view file_path);
  absl::Status LoadFilesMatchingPattern(const std::string &file_pattern);
  absl::Status GetValidationBuckets(std::set<ValidationBucket> &buckets);
  absl::Status GetTokensForValidationBucket(
      const ValidationBucket &bucket, std::vector<ValidationToken> &tokens);

 private:
  std::map<std::string, std::unique_ptr<TokensDB>> tokens_dbs_;
};

class EpochKeyMaterialStore {
 public:
  absl::Status LoadFilesMatchingPattern(absl::string_view file_pattern);
  absl::Status LoadFile(const std::string &file_path);
  absl::StatusOr<EpochKeyMaterials> GetEpochKeyMaterials(uint64_t epoch_id);

 private:
  std::map<uint64_t, EpochKeyMaterials> epoch_keys_;
};

absl::StatusOr<nlohmann::json> EpochKeysToJson(
    const proto::ElGamalKeyMaterial& elgamal_keypair,
    absl::string_view secret_key_hmac, uint64_t epoch_id,
    absl::Time epoch_start, absl::Time epoch_end);

// Helper function to write a JSON file containing the given key material.
absl::Status WriteKeysToFile(const proto::ElGamalKeyMaterial &elgamal_keypair,
                             absl::string_view secret_key_hmac,
                             absl::string_view output_file_name,
                             absl::Time epoch_start, absl::Time epoch_end);

absl::StatusOr<EpochKeyMaterials> LoadKeysFromFile(
    const std::string &file_path);

absl::StatusOr<EpochKeyMaterials> LoadKeysFromJson(
    const std::string &json_string);

// Helper function to write a sqlite3 file containing the given tokens.
absl::Status WriteTokensToFile(
    const std::vector<ElGamalCiphertext> &tokens,
    const private_join_and_compute::ElGamalPublicKey &public_key,
    uint64_t num_tokens_with_signal, absl::Time expiration_time,
    absl::string_view output_file_name);

std::string TokenToTLS(const private_join_and_compute::ElGamalCiphertext &token,
                       uint64_t epoch_id);
}  // namespace prtoken

#endif  // PRTOKEN_STORAGE_H_
