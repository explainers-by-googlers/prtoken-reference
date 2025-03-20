/*
 * Copyright 2024 Google LLC
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

#include "prtoken/storage.h"

#include <stdlib.h>  // for getenv()

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "absl/log/log.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "ortools/base/path.h"
#include "ortools/base/status_matchers.h"
#include "prtoken/issuer_test_lib.h"

namespace prtoken {
namespace {

uint64_t EpochIDFromEndTime(absl::Time epoch_end_time) {
  uint64_t epoch_id;
  EXPECT_TRUE(absl::SimpleAtoi(
      absl::FormatTime("%Y%m%d%H%M%S", epoch_end_time, absl::UTCTimeZone()),
      &epoch_id));
  return epoch_id;
}

TEST_F(PRTokenTest, KeyFileRoundTrip) {
  const char* output_dir = getenv("TEST_UNDECLARED_OUTPUTS_DIR");
  EXPECT_NE(output_dir, nullptr);
  const std::string output_file =
      file::JoinPath(output_dir, "KeyFileRoundTrip.json");
  const absl::Time epoch_start_time = absl::Now();
  const absl::Time epoch_end_time = absl::Now() + absl::Hours(24);
  EXPECT_OK(WriteKeysToFile(key_pair_, secret_key_hmac_, output_file,
                            epoch_start_time, epoch_end_time));
  absl::StatusOr<EpochKeyMaterials> epoch_keys_or =
      LoadKeysFromFile(output_file);
  EXPECT_OK(epoch_keys_or);
  EpochKeyMaterials epoch_keys = *std::move(epoch_keys_or);

  EXPECT_EQ(epoch_keys.epoch_id(), EpochIDFromEndTime(epoch_end_time));
  EXPECT_EQ(epoch_keys.epoch_start_time(),
            absl::FormatTime(absl::RFC3339_sec, epoch_start_time,
                             absl::UTCTimeZone()));
  EXPECT_EQ(
      epoch_keys.epoch_end_time(),
      absl::FormatTime(absl::RFC3339_sec, epoch_end_time, absl::UTCTimeZone()));
  EXPECT_EQ(epoch_keys.eg().secret_key().x(), key_pair_.secret_key().x());
  EXPECT_EQ(epoch_keys.eg().public_key().y(), key_pair_.public_key().y());
  EXPECT_EQ(epoch_keys.eg().public_key().g(), key_pair_.public_key().g());
  EXPECT_EQ(epoch_keys.hmac_key(), secret_key_hmac_);
}

TEST_F(PRTokenTest, TokenFileRoundTrip) {
  const char* output_dir = getenv("TEST_UNDECLARED_OUTPUTS_DIR");
  EXPECT_NE(output_dir, nullptr);
  const std::string output_file =
      file::JoinPath(output_dir, "TokenFileRoundTrip.sqlite3");
  const absl::Time expiration_time = absl::Now() + absl::Hours(24);
  std::vector<ElGamalCiphertext> original_tokens;
  float p_reveal = 0.2;
  ASSERT_THAT(issuer_->IssueTokens({1, 1, 1}, 20, 100, original_tokens),
              absl_testing::IsOk());
  {
    TokensDB tokens_db;
    EXPECT_OK(tokens_db.Open(output_file));
    EXPECT_OK(tokens_db.Insert(original_tokens, key_pair_.public_key(),
                               p_reveal, expiration_time));
    tokens_db.close();
  }
  TokensDB tokens_db;
  EXPECT_OK(tokens_db.Open(output_file));
  std::set<ValidationBucket> buckets;
  EXPECT_OK(tokens_db.GetValidationBuckets(buckets));
  EXPECT_EQ(buckets.size(), 1);
  std::vector<ValidationToken> tokens;
  EXPECT_OK(tokens_db.GetTokensForValidationBucket(*buckets.begin(), tokens));
  EXPECT_EQ(tokens.size(), 100);
  // Make sure the tokens are the same as the original tokens.
  for (size_t i = 0; i < tokens.size(); ++i) {
    EXPECT_EQ(tokens[i].eg_ciphertext().u(), original_tokens[i].u());
    EXPECT_EQ(tokens[i].eg_ciphertext().e(), original_tokens[i].e());
    EXPECT_EQ(tokens[i].p_reveal(), p_reveal);
    EXPECT_EQ(tokens[i].filename(), output_file);
    EXPECT_EQ(tokens[i].epoch_id(), EpochIDFromEndTime(expiration_time));
    EXPECT_EQ(tokens[i].public_key().y(), key_pair_.public_key().y());
    EXPECT_EQ(tokens[i].public_key().g(), key_pair_.public_key().g());
  }
  tokens_db.close();
}

TEST_F(PRTokenTest, TokenStoreMultipleDatabasesTest) {
  const char* output_dir = getenv("TEST_UNDECLARED_OUTPUTS_DIR");
  const std::string output_file_prefix = "TokenStoreMultipleDatabasesTest";
  const int num_databases = 5;
  EXPECT_NE(output_dir, nullptr);
  for (size_t db_idx = 0; db_idx < num_databases; ++db_idx) {
    const std::string output_file = file::JoinPath(
        output_dir,
        absl::StrCat("TokenStoreMultipleDatabasesTest", db_idx, ".sqlite3"));
    const absl::Time expiration_time =
        absl::Now() + absl::Hours(24 * (db_idx + 1));
    std::vector<ElGamalCiphertext> tokens;
    float p_reveal = 0.2;
    ASSERT_OK(issuer_->IssueTokens({1, 1, 1}, 2, 10, tokens));
    TokensDB tokens_db;
    EXPECT_OK(tokens_db.Open(output_file));
    EXPECT_OK(tokens_db.Insert(tokens, key_pair_.public_key(), p_reveal,
                               expiration_time));
    tokens_db.close();
  }
  const std::string output_file_pattern =
      file::JoinPath(output_dir, absl::StrCat(output_file_prefix, "*.sqlite3"));
  // Create a TokenStore and load all the databases.
  TokenStore token_store;
  EXPECT_OK(token_store.LoadFilesMatchingPattern(output_file_pattern));
  std::set<ValidationBucket> buckets;
  EXPECT_OK(token_store.GetValidationBuckets(buckets));
  EXPECT_EQ(buckets.size(), num_databases);
  for (const ValidationBucket& bucket : buckets) {
    std::vector<ValidationToken> tokens;
    EXPECT_OK(token_store.GetTokensForValidationBucket(bucket, tokens));
    EXPECT_EQ(tokens.size(), 10);
  }
}

TEST_F(PRTokenTest, EpochKeyMaterialStoreTest) {
  const char* output_dir = getenv("TEST_UNDECLARED_OUTPUTS_DIR");
  EXPECT_NE(output_dir, nullptr);
  const std::string output_file_prefix = "EpochKeyMaterialStoreTest";
  const int num_epochs = 5;
  for (size_t epoch_idx = 0; epoch_idx < num_epochs; ++epoch_idx) {
    const absl::Time epoch_start_time =
        absl::Now() + absl::Hours(24 * epoch_idx);
    const absl::Time epoch_end_time =
        absl::Now() + absl::Hours(24 * (1 + epoch_idx));
    const std::string output_file = file::JoinPath(
        output_dir,
        absl::StrCat("EpochKeyMaterialStoreTest", epoch_idx, ".json"));
    EXPECT_OK(WriteKeysToFile(key_pair_, secret_key_hmac_, output_file,
                              epoch_start_time, epoch_end_time));
  }
  EpochKeyMaterialStore epoch_key_store;
  EXPECT_OK(epoch_key_store.LoadFilesMatchingPattern(
      file::JoinPath(output_dir, absl::StrCat(output_file_prefix, "*.json"))));
  for (size_t epoch_idx = 0; epoch_idx < num_epochs; ++epoch_idx) {
    const absl::Time epoch_start_time =
        absl::Now() + absl::Hours(24 * epoch_idx);
    const absl::Time epoch_end_time =
        absl::Now() + absl::Hours(24 * (1 + epoch_idx));
    LOG(INFO) << "Epoch Index: " << epoch_idx;
    LOG(INFO) << "Epoch start time: " << epoch_start_time;
    LOG(INFO) << "Epoch end time: " << epoch_end_time;
    LOG(INFO) << "Epoch ID: " << EpochIDFromEndTime(epoch_end_time);
    absl::StatusOr<EpochKeyMaterials> epoch_keys_or =
        epoch_key_store.GetEpochKeyMaterials(
            EpochIDFromEndTime(epoch_end_time));
    EXPECT_OK(epoch_keys_or);
    EpochKeyMaterials epoch_keys = *std::move(epoch_keys_or);

    EXPECT_EQ(epoch_keys.epoch_id(), EpochIDFromEndTime(epoch_end_time));
    EXPECT_EQ(epoch_keys.epoch_start_time(),
              absl::FormatTime(absl::RFC3339_sec, epoch_start_time,
                               absl::UTCTimeZone()));
    EXPECT_EQ(epoch_keys.epoch_end_time(),
              absl::FormatTime(absl::RFC3339_sec, epoch_end_time,
                               absl::UTCTimeZone()));
    EXPECT_EQ(epoch_keys.eg().secret_key().x(), key_pair_.secret_key().x());
    EXPECT_EQ(epoch_keys.eg().public_key().y(), key_pair_.public_key().y());
    EXPECT_EQ(epoch_keys.eg().public_key().g(), key_pair_.public_key().g());
    EXPECT_EQ(epoch_keys.hmac_key(), secret_key_hmac_);
  }
}
}  // namespace
}  // namespace prtoken
