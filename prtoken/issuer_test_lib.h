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

#ifndef PRTOKEN_ISSUER_TEST_LIB_H_
#define PRTOKEN_ISSUER_TEST_LIB_H_

#include <memory>
#include <string>

#include "absl/log/check.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "prtoken/issuer.h"
#include "prtoken/token.pb.h"
#include "prtoken/verifier.h"

namespace prtoken {

class IssuerUnderTest : public Issuer {
  using Issuer::Issuer;

 public:
  static absl::StatusOr<std::unique_ptr<IssuerUnderTest>> Create(
      absl::string_view secret_key_hmac,
      const private_join_and_compute::ElGamalPublicKey& public_key);
};

class PRTokenTest : public ::testing::Test {
 protected:
  void SetUp() override;
  std::string secret_key_hmac_;
  proto::ElGamalKeyMaterial key_pair_;
  std::unique_ptr<Verifier> verifier_;
  std::unique_ptr<IssuerUnderTest> issuer_;
};
}  // namespace prtoken

#endif  // PRTOKEN_ISSUER_TEST_LIB_H_
