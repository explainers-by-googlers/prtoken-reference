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

#include "prtoken/storage.h"

#include <sys/types.h>

#include <array>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/base/internal/endian.h"
#include "absl/cleanup/cleanup.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "include/nlohmann/json.hpp"
#include "ortools/base/file.h"
#include "ortools/base/filesystem.h"
#include "ortools/base/helpers.h"
#include "ortools/base/options.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/elgamal.pb.h"
#include "private_join_and_compute/util/status_macros.h"
#include "prtoken/token.h"
#include "prtoken/verifier.h"
#include "sqlite3.h"

using private_join_and_compute::ECGroup;
using private_join_and_compute::ECPoint;
using private_join_and_compute::ElGamalCiphertext;
using private_join_and_compute::ElGamalPublicKey;
using prtoken::token_structure;

using TokenBytes = std::array<uint8_t, token_structure.signal_size>;
constexpr absl::string_view kEpochIDDateFormat = "%Y%m%d%H%M%S";

namespace prtoken {

/**
 * TokensDB is a wrapper around a single SQLite database containing tokens.
 */
absl::Status TokensDB::Open(const std::string &db_path) {
  db_path_ = db_path;
  if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
    return absl::UnavailableError(
        absl::StrCat("Failed to open database: ", sqlite3_errmsg(db_)));
  }
  char *errmsg = nullptr;

  // SQL command to create a table with the given schema
  const char *sql_create = R"sql(
      CREATE TABLE IF NOT EXISTS tokens (
      version INTEGER,
      u BLOB,
      e BLOB,
      expiration INTEGER,
      num_tokens_with_signal INTEGER,
      epoch_id INTEGER,
      public_key TEXT);
    )sql";

  // Execute the create table statement
  if (sqlite3_exec(db_, sql_create, nullptr, nullptr, &errmsg) != SQLITE_OK) {
    absl::Status status = absl::UnavailableError(
        absl::StrCat("Failed to create table: ", errmsg));
    sqlite3_free(errmsg);
    sqlite3_close(db_);
    return status;
  }
  return absl::OkStatus();
}

absl::Status TokensDB::GetValidationBuckets(
    std::set<ValidationBucket> &buckets) {
  sqlite3_stmt *stmt;
  absl::Cleanup cleanup = [&stmt] { sqlite3_finalize(stmt); };
  std::string sql_select = absl::StrFormat(
      "SELECT num_tokens_with_signal, epoch_id FROM %s GROUP BY "
      "num_tokens_with_signal, epoch_id;",
      token_table_);
  if (sqlite3_prepare_v2(db_, sql_select.c_str(), -1, &stmt, nullptr) !=
      SQLITE_OK) {
    return absl::UnavailableError(
        absl::StrCat("Failed to prepare statement: ", sqlite3_errmsg(db_)));
  }
  // Now read the results.
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    uint64_t num_tokens_with_signal = sqlite3_column_int(stmt, 0);
    // Read the epoch ID string from the database and convert it to an integer.
    const unsigned char *id_str = sqlite3_column_text(stmt, 1);
    std::string id_unescaped;
    if (!absl::WebSafeBase64Unescape(
            std::string(reinterpret_cast<const char *>(id_str)),
            &id_unescaped)) {
      return absl::UnavailableError(
          absl::StrCat("Failed to unescape epoch_id: ", sqlite3_errmsg(db_)));
    }
    uint64_t epoch_id;
    if (!absl::SimpleAtoi(id_unescaped, &epoch_id)) {
      absl::Status status = absl::InternalError(absl::StrCat(
          "Failed to convert epoch_id string to integer: ", id_unescaped));
      return status;
    }
    buckets.insert(std::make_pair(num_tokens_with_signal, epoch_id));
  }
  return absl::OkStatus();
}

absl::Status TokensDB::Insert(
    absl::Span<const ElGamalCiphertext> tokens,
    const private_join_and_compute::ElGamalPublicKey &public_key,
    uint64_t num_tokens_with_signal, absl::Time expiration_time) {
  // Compute an ISO8601 YYYYMMDDHHMMSS integer from the epoch end time.
  std::string expiration_time_str = absl::FormatTime(
      kEpochIDDateFormat, expiration_time, absl::UTCTimeZone());
  LOG(INFO) << "Epoch ID (string): " << expiration_time_str;
  for (const ElGamalCiphertext &token : tokens) {
    sqlite3_stmt *stmt;
    const char *sql_insert = R"sql(
        INSERT INTO tokens (u, e, expiration, num_tokens_with_signal, public_key, epoch_id)
        VALUES (?, ?, ?, ?, ?, ?);
    )sql";
    if (sqlite3_prepare_v2(db_, sql_insert, -1, &stmt, nullptr) != SQLITE_OK) {
      absl::Status status = absl::UnavailableError(
          absl::StrCat("Failed to prepare statement: ", sqlite3_errmsg(db_)));
      sqlite3_finalize(stmt);
      return status;
    }
    // Store the expiration_time_str as a YYYYMMDDHHMMSS integer.
    uint64_t expiration_time_int;
    if (!absl::SimpleAtoi(expiration_time_str, &expiration_time_int)) {
      absl::Status status = absl::InternalError(
          absl::StrCat("Failed to convert expiration_time string to integer: ",
                       expiration_time_str));
      sqlite3_finalize(stmt);
      return status;
    }
    std::string y_escaped, id_escaped;
    absl::WebSafeBase64Escape(public_key.y(), &y_escaped);
    sqlite3_bind_text(stmt, 5, y_escaped.c_str(), y_escaped.size(),
                      SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, expiration_time_int);
    sqlite3_bind_int(stmt, 4, num_tokens_with_signal);
    sqlite3_bind_blob(stmt, 1, token.u().data(), token.u().size(),
                      SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, token.e().data(), token.e().size(),
                      SQLITE_STATIC);
    absl::WebSafeBase64Escape(expiration_time_str, &id_escaped);
    sqlite3_bind_text(stmt, 6, id_escaped.c_str(), id_escaped.size(),
                      SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
      absl::Status status = absl::UnavailableError(
          absl::StrCat("Failed to insert token: ", sqlite3_errmsg(db_)));
      sqlite3_finalize(stmt);
      return status;
    }
    sqlite3_finalize(stmt);
  }
  return absl::OkStatus();
}

// Helper function to read a single token from the result set.
absl::Status TokensDB::readTokenFromStatement(sqlite3_stmt *stmt,
                                              ValidationToken &token) {
  ElGamalCiphertext ciphertext;
  const char *u_str =
      reinterpret_cast<const char *>(sqlite3_column_blob(stmt, 0));
  ciphertext.mutable_u()->assign(u_str, sqlite3_column_bytes(stmt, 0));

  const char *e_str =
      reinterpret_cast<const char *>(sqlite3_column_blob(stmt, 1));
  ciphertext.mutable_e()->assign(e_str, sqlite3_column_bytes(stmt, 1));

  ElGamalPublicKey public_key;

  const unsigned char *y_str = sqlite3_column_text(stmt, 2);
  std::string y_unescaped;
  if (!absl::WebSafeBase64Unescape(
          std::string(reinterpret_cast<const char *>(y_str)), &y_unescaped)) {
    return absl::UnavailableError("Failed to unescape public_key");
  }
  std::string g_unescaped;
  if (!absl::WebSafeBase64Unescape(
          std::string(reinterpret_cast<const char *>(kBase64URIEncodedG)),
          &g_unescaped)) {
    return absl::UnavailableError("Failed to unescape g");
  }
  public_key.mutable_g()->assign(g_unescaped);
  public_key.mutable_y()->assign(y_unescaped);

  *token.mutable_eg_ciphertext() = ciphertext;
  *token.mutable_public_key() = public_key;
  token.set_filename(db_path_);
  return absl::OkStatus();
}

absl::Status TokensDB::GetTokensForValidationBucket(
    const ValidationBucket &bucket, std::vector<ValidationToken> &tokens) {
  sqlite3_stmt *stmt;
  std::string sql_select = absl::StrFormat(
      "SELECT u, e, public_key FROM %s WHERE num_tokens_with_signal = ? AND "
      "epoch_id = ?;",
      token_table_);
  if (sqlite3_prepare_v2(db_, sql_select.c_str(), -1, &stmt, nullptr) !=
      SQLITE_OK) {
    absl::Status status = absl::UnavailableError(
        absl::StrCat("Failed to prepare statement: ", sqlite3_errmsg(db_)));
    sqlite3_finalize(stmt);
    return status;
  }
  sqlite3_bind_int(stmt, 1, bucket.first);
  // Escape the epoch ID string and bind it to the statement.
  std::string id_escaped;
  absl::WebSafeBase64Escape(absl::StrCat(bucket.second), &id_escaped);
  sqlite3_bind_text(stmt, 2, id_escaped.c_str(), id_escaped.size(),
                    SQLITE_STATIC);
  // Now read the results.
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    ValidationToken token;
    RETURN_IF_ERROR(readTokenFromStatement(stmt, token));
    token.set_epoch_id(bucket.second);
    token.set_num_tokens_with_signal(bucket.first);
    tokens.push_back(token);
  }
  sqlite3_finalize(stmt);
  return absl::OkStatus();
}

absl::Status TokensDB::ProcessTokens(const std::string &public_key) {
  sqlite3_stmt *stmt;
  std::string sql_select = absl::StrFormat(
      "SELECT u, e, public_key FROM %s WHERE public_key = \"%s\"", token_table_,
      public_key);

  if (sqlite3_prepare_v2(db_, sql_select.c_str(), -1, &stmt, nullptr) !=
      SQLITE_OK) {
    absl::Status status = absl::UnavailableError(
        absl::StrCat("Failed to prepare statement: ", sqlite3_errmsg(db_)));
    sqlite3_finalize(stmt);
    return status;
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    ValidationToken token;
    RETURN_IF_ERROR(readTokenFromStatement(stmt, token));
    // Probably we could batch token processing to save some I/O operations.
    absl::Status status = OnFinishGetToken(token);
    // Ignore single token error. Only return for I/O errors, e.g. failed
    // to store the decrypted result.
    if (!status.ok()) {
      sqlite3_finalize(stmt);
      return status;
    }
  }
  sqlite3_finalize(stmt);
  return absl::OkStatus();
}

absl::Status TokensDB::OnFinishGetToken(const ValidationToken &token) {
  return absl::UnimplementedError("OnFinishGetToken is not implemented.");
}

void TokensDB::close() {
  if (db_ != nullptr) {
    sqlite3_close(db_);
  }
  db_ = nullptr;
}
TokensDB::~TokensDB() { close(); };

// TokenStore contains multiple TokensDBs and allows for unified querying.

absl::Status TokenStore::LoadFile(std::string_view file_path) {
  auto tokens_db = std::make_unique<TokensDB>();
  LOG(INFO) << "Opening " << file_path;
  CHECK_OK(tokens_db->Open(std::string(file_path)));
  tokens_dbs_[std::string(file_path)] = std::move(tokens_db);
  return absl::OkStatus();
}

absl::Status TokenStore::LoadFilesMatchingPattern(
    const std::string &file_pattern) {
  std::vector<std::string> filenames;
  CHECK_OK(file::Match(file_pattern, &filenames, file::Defaults()));
  for (const std::string &filename : filenames) {
    CHECK_OK(LoadFile(filename));
  }
  return absl::OkStatus();
}

// Get the distinct validation buckets across all token databases.
absl::Status TokenStore::GetValidationBuckets(
    std::set<ValidationBucket> &buckets) {
  for (const auto &[file_path, tokens_db] : tokens_dbs_) {
    std::set<ValidationBucket> buckets_db;
    absl::Status status = tokens_db->GetValidationBuckets(buckets_db);
    if (!status.ok()) {
      return status;
    }
    buckets.insert(buckets_db.begin(), buckets_db.end());
  }
  return absl::OkStatus();
}

// Get the tokens for a given validation bucket.
absl::Status TokenStore::GetTokensForValidationBucket(
    const ValidationBucket &bucket, std::vector<ValidationToken> &tokens) {
  for (const auto &[file_path, tokens_db] : tokens_dbs_) {
    std::vector<ValidationToken> bucket_tokens;
    absl::Status status =
        tokens_db->GetTokensForValidationBucket(bucket, bucket_tokens);
    if (!status.ok()) {
      return status;
    }
    tokens.insert(tokens.end(), bucket_tokens.begin(), bucket_tokens.end());
  }
  LOG(INFO) << "Found " << tokens.size() << " tokens for bucket "
            << bucket.first << "," << bucket.second;
  return absl::OkStatus();
}

/**
 * EpochKeyMaterialstore contains multiple EpochKeyMaterials.
 */
absl::Status EpochKeyMaterialStore::LoadFile(const std::string &file_path) {
  absl::StatusOr<EpochKeyMaterials> epoch_keys = LoadKeysFromFile(file_path);
  if (!epoch_keys.ok()) {
    LOG(ERROR) << "Failed to load keys from " << file_path;
    return epoch_keys.status();
  }
  epoch_keys_[epoch_keys->epoch_id()] = *epoch_keys;
  LOG(INFO) << "Loaded keys from " << file_path << " for epoch "
            << epoch_keys->epoch_id();
  return absl::OkStatus();
}

absl::Status EpochKeyMaterialStore::LoadFilesMatchingPattern(
    absl::string_view file_pattern) {
  std::vector<std::string> filenames;
  CHECK_OK(file::Match(file_pattern, &filenames, file::Defaults()));
  for (const std::string &filename : filenames) {
    CHECK_OK(LoadFile(filename));
    LOG(INFO) << "Read " << filename;
  }
  return absl::OkStatus();
}

absl::StatusOr<EpochKeyMaterials> EpochKeyMaterialStore::GetEpochKeyMaterials(
    uint64_t epoch_id) {
  auto it = epoch_keys_.find(epoch_id);
  if (it == epoch_keys_.end()) {
    return absl::NotFoundError(absl::StrCat("Epoch ", epoch_id, " not found"));
  }
  return it->second;
}

absl::StatusOr<nlohmann::json> EpochKeysToJson(
    const proto::ElGamalKeyMaterial &elgamal_keypair,
    absl::string_view secret_key_hmac, uint64_t epoch_id,
    absl::Time epoch_start, absl::Time epoch_end) {
  /**
   * {
   *   epoch_id: <integer>
   *   epoch_start_time: <string ISO 8601 UTC>
   *   epoch_end_time: <string ISO 8601 UTC>
   *   invalidated_at: <null | string ISO 8601 UTC>
   *   eg: <jwk>
   *   hmac: <null | jwk>
   * }
   */
  auto blinders_context_ = std::make_unique<Context>();
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(kCurveId, blinders_context_.get()));
  nlohmann::json j;
  // Epoch Metadata.
  char epoch_id_buf[sizeof(uint64_t)];
  absl::big_endian::Store64(epoch_id_buf, epoch_id);

  j["epoch_id"] = absl::WebSafeBase64Escape(
      std::string(epoch_id_buf, sizeof(epoch_id_buf)));
  std::string epoch_start_time_str =
      absl::FormatTime(absl::RFC3339_sec, epoch_start, absl::UTCTimeZone());
  j["epoch_start_time"] = epoch_start_time_str;
  std::string epoch_end_time_str =
      absl::FormatTime(absl::RFC3339_sec, epoch_end, absl::UTCTimeZone());
  j["epoch_end_time"] = epoch_end_time_str;
  // ElGamal key material.
  j["eg"] = nlohmann::json::object();
  j["eg"]["kty"] = "EC";
  j["eg"]["crv"] = "P-256";
  // Decompose the Y point into its affine coordinates by calling the
  // EC point's GetAffineCoordinates function.
  ASSIGN_OR_RETURN(private_join_and_compute::ECPoint point_public_key,
                   ec_group.CreateECPoint(elgamal_keypair.public_key().y()));
  BigNum::BignumPtr x_coord_ptr, y_coord_ptr;
  ASSIGN_OR_RETURN(auto affine_coords, point_public_key.GetAffineCoordinates());
  BigNum x_coord =
      blinders_context_->CreateBigNum(std::move(affine_coords.first));
  BigNum y_coord =
      blinders_context_->CreateBigNum(std::move(affine_coords.second));
  std::string x_coord_escaped, y_coord_escaped;
  absl::WebSafeBase64Escape(x_coord.ToBytes(), &x_coord_escaped);
  absl::WebSafeBase64Escape(y_coord.ToBytes(), &y_coord_escaped);
  j["eg"]["x"] = x_coord_escaped;
  j["eg"]["y"] = y_coord_escaped;
  std::string d_escaped, g_escaped;
  absl::WebSafeBase64Escape(elgamal_keypair.public_key().g(), &g_escaped);
  absl::WebSafeBase64Escape(elgamal_keypair.secret_key().x(), &d_escaped);
  j["eg"]["d"] = d_escaped;
  j["eg"]["g"] = g_escaped;
  // HMAC key material.
  j["hmac"] = nlohmann::json::object();
  j["hmac"]["kty"] = "HMAC";
  j["hmac"]["alg"] = "HS256";
  std::string hmac_escaped;
  absl::WebSafeBase64Escape(secret_key_hmac, &hmac_escaped);
  j["hmac"]["k"] = hmac_escaped;
  return j;
};

absl::Status WriteKeysToFile(const proto::ElGamalKeyMaterial &elgamal_keypair,
                             absl::string_view secret_key_hmac,
                             absl::string_view output_file_name,
                             const absl::Time epoch_start,
                             const absl::Time epoch_end) {
  // In this module, epoch end time is used as epoch ID, but in production the
  // epoch ID is generated by the rekey/clark job with a different convention.
  std::string epoch_id_str =
      absl::FormatTime(kEpochIDDateFormat, epoch_end, absl::UTCTimeZone());
  uint64_t epoch_id;
  if (!absl::SimpleAtoi(epoch_id_str, &epoch_id)) {
    return absl::InternalError("Failed to convert epoch_id string to integer");
  }
  ASSIGN_OR_RETURN(nlohmann::json j,
                   EpochKeysToJson(elgamal_keypair, secret_key_hmac, epoch_id,
                                   epoch_start, epoch_end));

  // Serialize the JSON object to a formatted string
  std::string json_str = j.dump(4);  // 4 is the indentation level
  File *my_file = file::OpenOrDie(output_file_name, "w", file::Defaults());
  CHECK_OK(file::WriteString(my_file, json_str, file::Defaults()));
  CHECK_OK(my_file->Close(file::Defaults()));
  return absl::OkStatus();
}

absl::StatusOr<EpochKeyMaterials> LoadKeysFromFile(
    const std::string &file_path) {
  auto blinders_context_ = std::make_unique<Context>();
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(kCurveId, blinders_context_.get()));
  std::string json_str;
  CHECK_OK(file::GetContents(file_path, &json_str, file::Defaults()))
      << absl::StrCat("Failed to read file: ", file_path);
  nlohmann::json j = nlohmann::json::parse(json_str);
  if (j.is_discarded()) {
    return absl::InternalError("Failed to parse JSON file");
  }
  for (std::string key : {"epoch_id", "epoch_start_time", "epoch_end_time"}) {
    if (!j.contains(key)) {
      return absl::InternalError(
          absl::StrCat("JSON file does not contain ", key));
    }
  }
  EpochKeyMaterials epoch_keys;
  std::string epoch_id_unescaped;
  if (!absl::WebSafeBase64Unescape(std::string(j["epoch_id"]),
                                   &epoch_id_unescaped)) {
    return absl::InternalError("Failed to unescape epoch_id");
  }
  uint64_t epoch_id = absl::big_endian::Load64(epoch_id_unescaped.c_str());
  epoch_keys.set_epoch_id(epoch_id);
  epoch_keys.set_epoch_start_time(j["epoch_start_time"]);
  epoch_keys.set_epoch_end_time(j["epoch_end_time"]);
  if (!j.contains("eg")) {
    return absl::InternalError("JSON file does not contain eg");
  }
  for (std::string key : {"x", "y", "g"}) {
    if (!j["eg"].contains(key)) {
      return absl::InternalError(
          absl::StrCat("JSON file does not contain eg.", key));
    }
  }
  // ElGamal key material.
  proto::ElGamalKeyMaterial *eg = epoch_keys.mutable_eg();
  if (j["eg"].contains("d")) {
    std::string d_unescaped;
    if (!absl::WebSafeBase64Unescape(std::string(j["eg"]["d"]), &d_unescaped)) {
      return absl::InternalError("Failed to unescape eg.d");
    }
    eg->mutable_secret_key()->mutable_x()->assign(d_unescaped);
  }
  std::string public_key_unescaped;
  std::string y_affine_bytes;
  std::string x_affine_bytes;
  if (!absl::WebSafeBase64Unescape(std::string(j["eg"]["y"]),
                                   &y_affine_bytes)) {
    return absl::InternalError("Failed to unescape eg.y");
  }
  if (!absl::WebSafeBase64Unescape(std::string(j["eg"]["x"]),
                                   &x_affine_bytes)) {
    return absl::InternalError("Failed to unescape eg.x");
  }
  ASSIGN_OR_RETURN(
      ECPoint public_point,
      ec_group.CreateECPoint(blinders_context_->CreateBigNum(x_affine_bytes),
                             blinders_context_->CreateBigNum(y_affine_bytes)));
  // In the public key representation, Y is the point composed of x and y
  // affine coordinates.
  ASSIGN_OR_RETURN(public_key_unescaped, public_point.ToBytesCompressed());
  eg->mutable_public_key()->set_y(public_key_unescaped);
  std::string g_unescaped;
  if (!absl::WebSafeBase64Unescape(std::string(j["eg"]["g"]), &g_unescaped)) {
    return absl::InternalError("Failed to unescape eg.g");
  }
  eg->mutable_public_key()->set_g(g_unescaped);
  if (!j.contains("hmac")) {
    return absl::InternalError("JSON file does not contain hmac");
  }
  if (!j["hmac"].contains("k")) {
    return absl::InternalError("JSON file does not contain hmac.k");
  }
  // HMAC key material.
  std::string hmac_unescaped;
  if (!absl::WebSafeBase64Unescape(std::string(j["hmac"]["k"]),
                                   &hmac_unescaped)) {
    return absl::InternalError("Failed to unescape hmac key");
  }
  epoch_keys.mutable_hmac_key()->assign(hmac_unescaped);
  return epoch_keys;
}

absl::Status WriteTokensToFile(
    const std::vector<ElGamalCiphertext> &tokens,
    const private_join_and_compute::ElGamalPublicKey &public_key,
    uint64_t num_tokens_with_signal, absl::Time expiration_time,
    absl::string_view output_file_name) {
  TokensDB tokens_db;
  RETURN_IF_ERROR(tokens_db.Open(std::string(output_file_name)));
  RETURN_IF_ERROR(tokens_db.Insert(tokens, public_key, num_tokens_with_signal,
                                   expiration_time));
  tokens_db.close();
  return absl::OkStatus();
}
}  // namespace prtoken
