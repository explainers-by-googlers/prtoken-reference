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

#include "prtoken/issuer_test_lib.h"

#include <memory>
#include <utility>

#include "absl/log/check.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "prtoken/issuer.h"
#include "prtoken/token.h"
#include "prtoken/verifier.h"

namespace prtoken {
absl::StatusOr<std::unique_ptr<IssuerUnderTest>> IssuerUnderTest::Create(
    absl::string_view secret_key_hmac,
    const private_join_and_compute::ElGamalPublicKey& public_key) {
  auto encrypter = std::make_unique<Encrypter>();
  CHECK_OK(encrypter->Init(public_key));
  auto generator = std::make_unique<PlaintextTokenGenerator>(secret_key_hmac);
  return std::unique_ptr<IssuerUnderTest>(
      new IssuerUnderTest(std::move(encrypter), std::move(generator)));
}

void PRTokenTest::SetUp() {
  // ASSERT_OK_AND_ASSIGN(key_pair_, GenerateElGamalKeypair());
  absl::StatusOr<proto::ElGamalKeyMaterial> key_pair = GenerateElGamalKeypair();
  EXPECT_THAT(key_pair, absl_testing::IsOk());
  key_pair_ = *std::move(key_pair);

  private_join_and_compute::ElGamalPublicKey public_key =
      key_pair_.public_key();
  absl::StatusOr<std::unique_ptr<IssuerUnderTest>> issuer =
      IssuerUnderTest::Create(secret_key_hmac_, public_key);
  EXPECT_THAT(issuer, absl_testing::IsOk());
  issuer_ = *std::move(issuer);
  CHECK_NE(issuer_.get(), nullptr);

  absl::StatusOr<std::unique_ptr<Verifier>> verifier =
      Verifier::Create(key_pair_.secret_key(), secret_key_hmac_);
  EXPECT_THAT(verifier, absl_testing::IsOk());
  verifier_ = *std::move(verifier);
  CHECK_NE(verifier_.get(), nullptr);
}
}  // namespace prtoken
