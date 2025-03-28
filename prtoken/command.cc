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

#include "prtoken/command.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "prtoken/token.pb.h"
#include "prtoken/verifier.h"

namespace prtoken {

TokensDBWithIPVerifier::TokensDBWithIPVerifier(
    std::unique_ptr<Verifier> verifier_ptr, std::string token_table,
    std::string result_table)
    : TokensDB(token_table), verifier_ptr_(std::move(verifier_ptr)) {
  result_table_ =
      result_table.empty()
          ? absl::StrCat("results_",
                         absl::FormatTime("%Y%m%d%H%M%S", absl::Now(),
                                          absl::UTCTimeZone()))
          : result_table;
}

TokensDBWithIPVerifier::~TokensDBWithIPVerifier() = default;

absl::Status TokensDBWithIPVerifier::CreateResultTable() {
  char *errmsg = nullptr;
  // Create a table for decryption results.
  std::cout << "table name:" << result_table_ << std::endl;
  std::string sql_create = absl::StrFormat(
      "CREATE TABLE IF NOT EXISTS \"%s\" (e BLOB, ordinal INTEGER, m TEXT, "
      "error TEXT);",
      result_table_);
  // Execute the create table statement.
  if (sqlite3_exec(get_db(), sql_create.c_str(), nullptr, nullptr, &errmsg) !=
      SQLITE_OK) {
    absl::Status status = absl::UnavailableError(
        absl::StrCat("Failed to create table: ", errmsg));
    sqlite3_free(errmsg);
    sqlite3_close(get_db());
    return status;
  }
  return absl::OkStatus();
}

absl::Status TokensDBWithIPVerifier::CommitResult(sqlite3_stmt *stmt) {
  absl::Status status = absl::OkStatus();
  if (sqlite3_step(stmt) != SQLITE_DONE) {
    status = absl::UnavailableError(
        absl::StrCat("Failed to insert token: ", sqlite3_errmsg(get_db())));
  }
  sqlite3_finalize(stmt);
  return status;
}

absl::Status TokensDBWithIPVerifier::OnFinishGetToken(
    const ValidationToken &token) {
  std::vector<proto::PlaintextToken> decrypted_tokens;
  std::vector<proto::VerificationErrorReport> reports;

  processed_++;
  sqlite3_stmt *stmt;
  std::string sql_insert = absl::StrFormat(
      "INSERT INTO %s (e, ordinal, m, error) VALUES (?, ?, ?, ?);",
      result_table_);

  if (sqlite3_prepare_v2(get_db(), sql_insert.c_str(), -1, &stmt, nullptr) !=
      SQLITE_OK) {
    absl::Status status = absl::UnavailableError(absl::StrCat(
        "Failed to prepare statement: ", sqlite3_errmsg(get_db())));
    sqlite3_finalize(stmt);
    return status;
  }

  sqlite3_bind_blob(stmt, 1, token.eg_ciphertext().e().data(),
                    token.eg_ciphertext().e().size(), SQLITE_STATIC);
  if (!verifier_ptr_->DecryptToken(token.eg_ciphertext(), decrypted_tokens,
                                   reports)) {
    errors_++;
    auto report = reports.back();
    sqlite3_bind_text(stmt, 3, "", 0, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, report.error_message().c_str(),
                      report.error_message().size(), SQLITE_STATIC);
    // As long as we can store the error report, not stop the token
    // processing.
    return CommitResult(stmt);
  };

  proto::PlaintextToken decrypted_token = decrypted_tokens.back();
  absl::StatusOr<std::string> result = IPv6ByteArrayToString(std::string(
      decrypted_token.signal().begin(), decrypted_token.signal().end()));
  if (!result.ok()) {
    errors_++;
    sqlite3_bind_text(stmt, 3, "", 0, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, "Failed to parse decrypted token to IP", -1,
                      SQLITE_STATIC);
    return CommitResult(stmt);
  }

  std::string decrypted_str = ((*result == "::") ? "null" : *result);
  sqlite3_bind_int(stmt, 2, decrypted_token.ordinal());
  sqlite3_bind_text(stmt, 3, decrypted_str.c_str(), decrypted_str.size(),
                    SQLITE_STATIC);
  sqlite3_bind_text(stmt, 4, "", 0, SQLITE_STATIC);
  return CommitResult(stmt);
}

absl::Status TokensDBWithIPVerifier::report() {
  if (processed_ == 0) {
    return absl::NotFoundError("No tokens were processed.");
  }
  std::cout
      << "Try query results by: "
      << absl::StrFormat(
             "select t.e, r.m from tokens as t join %s as r where t.e = r.e;",
             result_table_)
      << std::endl;
  if (errors_ == 0 && processed_ > 0) {
    std::cout << "Successfully Processed " << processed_
              << " tokens with no errors." << std::endl;
    return absl::OkStatus();
  }
  return absl::InvalidArgumentError(
      absl::StrCat("Processed ", processed_, " tokens, ", errors_, " failed."));
}

bool IsValidIPAddress(absl::string_view ip_string) {
  struct in_addr ip4_addr;
  struct in6_addr ip6_addr;
  return (inet_pton(AF_INET, ip_string.data(), &ip4_addr) == 1 ||
          inet_pton(AF_INET6, ip_string.data(), &ip6_addr) == 1);
}

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

}  // namespace prtoken
