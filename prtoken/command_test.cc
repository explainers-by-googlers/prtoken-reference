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

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/status/status_matchers.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "ortools/base/path.h"
#include "ortools/base/status_matchers.h"
#include "prtoken/issuer_test_lib.h"
#include "prtoken/storage.h"
#include "prtoken/token.h"
#include "prtoken/token.pb.h"
#include "prtoken/verifier.h"

namespace prtoken {
namespace {

using ::testing::internal::CaptureStdout;
using ::testing::internal::GetCapturedStdout;

TEST_F(PRTokenTest, ValidIPStringTest) {
  EXPECT_TRUE(IsValidIPAddress("1.2.3.4"));
  EXPECT_TRUE(IsValidIPAddress("fe80::202:b3ff:fe1e:8329"));
  EXPECT_TRUE(IsValidIPAddress("::ffff:1.2.3.4"));
  EXPECT_FALSE(IsValidIPAddress("invalid"));
}

TEST_F(PRTokenTest, IPv6StringToByteArrayTest) {
  std::vector<std::string> expected_ipv6_strings = {
      "fe80::202:b3ff:fe1e:8329",
      "::1",
      "::ffff:1.2.3.4",
  };
  for (const std::string& expected_ipv6_string : expected_ipv6_strings) {
    absl::StatusOr<std::array<uint8_t, SignalSizeLimit>> ip_byte_array =
        IPStringToByteArray(expected_ipv6_string);
    EXPECT_OK(ip_byte_array);
    std::string ip_byte_string(ip_byte_array->begin(), ip_byte_array->end());
    absl::StatusOr<std::string> got_ip_string =
        IPv6ByteArrayToString(ip_byte_string);
    EXPECT_OK(got_ip_string);
    EXPECT_EQ(*got_ip_string, expected_ipv6_string);
  }
}

TEST_F(PRTokenTest, IPv4StringToByteArrayTest) {
  absl::StatusOr<std::array<uint8_t, SignalSizeLimit>> ip_byte_array =
      IPStringToByteArray("1.2.3.4");
  EXPECT_OK(ip_byte_array);
  std::string ip_byte_string(ip_byte_array->begin(), ip_byte_array->end());
  absl::StatusOr<std::string> got_ip_string =
      IPv6ByteArrayToString(ip_byte_string);
  EXPECT_OK(got_ip_string);
  EXPECT_EQ(*got_ip_string, "::ffff:1.2.3.4");
}

TEST_F(PRTokenTest, DecryptTokenTestSuccess) {
  const char* output_dir = getenv("TEST_UNDECLARED_OUTPUTS_DIR");
  EXPECT_NE(output_dir, nullptr);
  const std::string output_file =
      file::JoinPath(output_dir, "DecryptTokenTest.sqlite3");
  const absl::Time expiration_time = absl::Now() + absl::Hours(24);
  std::vector<ElGamalCiphertext> original_tokens;
  float p_reveal = 0.1;
  absl::StatusOr<std::array<uint8_t, prtoken::SignalSizeLimit>> signal_or =
      prtoken::IPStringToByteArray("1.1.1.1");
  EXPECT_OK(signal_or);
  std::array<uint8_t, prtoken::SignalSizeLimit> signal = *signal_or;
  ASSERT_THAT(issuer_->IssueTokens(signal, 10, 100, original_tokens),
              absl_testing::IsOk());
  {
    TokensDB tokens_db;
    EXPECT_OK(tokens_db.Open(output_file));
    EXPECT_OK(tokens_db.Insert(original_tokens, key_pair_.public_key(),
                               p_reveal, expiration_time));
    tokens_db.close();
  }
  TokensDBWithIPVerifier db(std::move(verifier_), "tokens", "results");
  EXPECT_OK(db.Open(output_file));
  EXPECT_OK(db.CreateResultTable());
  std::string y_escaped;
  absl::WebSafeBase64Escape(key_pair_.public_key().y(), &y_escaped);
  EXPECT_OK(db.ProcessTokens(y_escaped));
  CaptureStdout();
  absl::Status status = db.report();
  EXPECT_OK(status);
  std::string report_output = GetCapturedStdout();
  EXPECT_THAT(report_output, testing::HasSubstr("Try query results by:"));
  EXPECT_THAT(
      report_output,
      testing::HasSubstr("Successfully Processed 100 tokens with no errors."));
  db.close();

  // Verify the result table has one row with the correct IP.
  sqlite3* db_ptr;
  int rc = sqlite3_open(output_file.c_str(), &db_ptr);
  ASSERT_EQ(rc, SQLITE_OK);
  sqlite3_stmt* stmt;
  const char* sql = "SELECT m FROM results WHERE m != 'null'";
  rc = sqlite3_prepare_v2(db_ptr, sql, -1, &stmt, nullptr);
  ASSERT_EQ(rc, SQLITE_OK);

  int row_count = 0;
  std::string decrypted_ip;
  while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    row_count++;
    const unsigned char* ip_str = sqlite3_column_text(stmt, 0);
    decrypted_ip = reinterpret_cast<const char*>(ip_str);
  }
  ASSERT_EQ(rc, SQLITE_DONE);
  sqlite3_finalize(stmt);
  sqlite3_close(db_ptr);

  EXPECT_EQ(row_count, 10);
  EXPECT_EQ(decrypted_ip, "::ffff:1.1.1.1");
}

TEST_F(PRTokenTest, DecryptTokenTestWithFailure) {
  const char* output_dir = getenv("TEST_UNDECLARED_OUTPUTS_DIR");
  EXPECT_NE(output_dir, nullptr);
  const std::string output_file =
      file::JoinPath(output_dir, "DecryptTokenTest.sqlite3");
  const absl::Time expiration_time = absl::Now() + absl::Hours(24);
  std::vector<ElGamalCiphertext> original_tokens;
  float p_reveal = 0.2;
  absl::StatusOr<std::array<uint8_t, prtoken::SignalSizeLimit>> signal_or =
      prtoken::IPStringToByteArray("1.1.1.1");
  EXPECT_OK(signal_or);
  std::array<uint8_t, prtoken::SignalSizeLimit> signal = *signal_or;
  ASSERT_THAT(issuer_->IssueTokens(signal, 20, 100, original_tokens),
              absl_testing::IsOk());
  // Add a dummy token.
  original_tokens.push_back(ElGamalCiphertext());
  {
    TokensDB tokens_db;
    EXPECT_OK(tokens_db.Open(output_file));
    EXPECT_OK(tokens_db.Insert(original_tokens, key_pair_.public_key(),
                               p_reveal, expiration_time));
    tokens_db.close();
  }
  TokensDBWithIPVerifier db(std::move(verifier_), "tokens", "results");
  EXPECT_OK(db.Open(output_file));
  EXPECT_OK(db.CreateResultTable());
  std::string y_escaped;
  absl::WebSafeBase64Escape(key_pair_.public_key().y(), &y_escaped);
  EXPECT_OK(db.ProcessTokens(y_escaped));
  CaptureStdout();
  absl::Status status = db.report();
  EXPECT_THAT(status,
              absl_testing::StatusIs(absl::StatusCode::kInvalidArgument,
                                     "Processed 101 tokens, 1 failed."));
  EXPECT_THAT(GetCapturedStdout(), testing::HasSubstr("Try query results by:"));
  db.close();
}

}  // namespace
}  // namespace prtoken
