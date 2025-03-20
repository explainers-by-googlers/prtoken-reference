// Copyright 2025 Google LLC
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

#include <sys/types.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "benchmark/benchmark.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "ortools/base/path.h"
#include "ortools/base/status_matchers.h"
#include "private_join_and_compute/crypto/elgamal.pb.h"
#include "prtoken/client.h"
#include "prtoken/command.h"
#include "prtoken/issuer.h"
#include "prtoken/issuer_test_lib.h"
#include "prtoken/token.h"
#include "prtoken/token.pb.h"
#include "prtoken/verifier.h"

namespace prtoken {
namespace {

constexpr absl::string_view kSecretKeyHMAC = "foobar";
using private_join_and_compute::ElGamalCiphertext;

class IssuerUnderTest : public Issuer {
  using Issuer::Issuer;

 public:
  static absl::StatusOr<std::unique_ptr<IssuerUnderTest>> Create(
      absl::string_view secret_key_hmac,
      const private_join_and_compute::ElGamalPublicKey& public_key) {
    auto encrypter = std::make_unique<Encrypter>();
    CHECK_OK(encrypter->Init(public_key));
    auto generator = std::make_unique<PlaintextTokenGenerator>(secret_key_hmac);
    return std::unique_ptr<IssuerUnderTest>(
        new IssuerUnderTest(std::move(encrypter), std::move(generator)));
  }
};

class IssuerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(key_pair_, GenerateElGamalKeypair());
    private_join_and_compute::ElGamalPublicKey public_key =
        key_pair_.public_key();
    secret_key_hmac_ = GenerateSecretKeyHMAC();
    ASSERT_OK_AND_ASSIGN(issuer_,
                         IssuerUnderTest::Create(secret_key_hmac_, public_key));
    CHECK_NE(issuer_.get(), nullptr);
    ASSERT_OK_AND_ASSIGN(
        verifier_, Verifier::Create(key_pair_.secret_key(), secret_key_hmac_));
  }
  std::string secret_key_hmac_;
  proto::ElGamalKeyMaterial key_pair_;
  std::unique_ptr<Verifier> verifier_;
  std::unique_ptr<IssuerUnderTest> issuer_;
};

TEST_F(IssuerTest, IssueIPV4Token) {
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes;
  ASSERT_OK_AND_ASSIGN(ip_address_bytes, IPStringToByteArray("1.2.3.4"));
  std::vector<ElGamalCiphertext> tokens;
  ASSERT_OK(issuer_->IssueTokens(ip_address_bytes, /*num_signal_tokens=*/1,
                                 /*num_total_tokens=*/1, tokens));
  EXPECT_EQ(tokens.size(), 1);
  std::vector<proto::PlaintextToken> decrypted_tokens;
  std::vector<proto::VerificationErrorReport> reports;
  ASSERT_OK(verifier_->DecryptTokens(tokens, decrypted_tokens, reports));
  EXPECT_EQ(decrypted_tokens.size(), 1);
  EXPECT_TRUE(decrypted_tokens[0].hmac_valid());
  std::string ip_address_str;
  ASSERT_OK_AND_ASSIGN(ip_address_str,
                       IPv6ByteArrayToString(decrypted_tokens[0].signal()));
  EXPECT_EQ(ip_address_str, "::ffff:1.2.3.4");
}

TEST_F(IssuerTest, IssueIPV6Token) {
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes;
  ASSERT_OK_AND_ASSIGN(ip_address_bytes, IPStringToByteArray("2001:0000:130F:0000:0000:09C0:876A:130B"));
  std::vector<ElGamalCiphertext> tokens;
  ASSERT_OK(issuer_->IssueTokens(ip_address_bytes, /*num_signal_tokens=*/1,
                                 /*num_total_tokens=*/1, tokens));
  EXPECT_EQ(tokens.size(), 1);
  std::vector<proto::PlaintextToken> decrypted_tokens;
  std::vector<proto::VerificationErrorReport> reports;
  ASSERT_OK(verifier_->DecryptTokens(tokens, decrypted_tokens, reports));
  EXPECT_TRUE(decrypted_tokens[0].hmac_valid());
  std::string ip_address_str;
  ASSERT_OK_AND_ASSIGN(ip_address_str,
                       IPv6ByteArrayToString(decrypted_tokens[0].signal()));
  EXPECT_EQ(ip_address_str, "2001:0:130f::9c0:876a:130b");
}

TEST_F(IssuerTest, ValidateRevealRate) {
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes;
  ASSERT_OK_AND_ASSIGN(
      ip_address_bytes,
      IPStringToByteArray("2001:0000:130F:0000:0000:09C0:876A:130B"));
  std::vector<ElGamalCiphertext> tokens;
  ASSERT_OK(issuer_->IssueTokens(ip_address_bytes, /*num_signal_tokens=*/20,
                                 /*num_total_tokens=*/100, tokens));
  EXPECT_EQ(tokens.size(), 100);
  std::vector<proto::PlaintextToken> messages;
  std::vector<proto::VerificationErrorReport> reports;
  EXPECT_OK(verifier_->DecryptTokens(tokens, messages, reports));
  EXPECT_EQ(messages.size(), 100);
  int num_revealed = 0;
  std::string ip_address_str;
  for (const proto::PlaintextToken& message : messages) {
    ASSERT_OK_AND_ASSIGN(ip_address_str,
                         IPv6ByteArrayToString(message.signal()));
    if (ip_address_str != "::") {
      ++num_revealed;
    }
  }
  EXPECT_EQ(num_revealed, 20);
  EXPECT_OK(verifier_->VerifyRevealRate(messages, 0.2));
}

TEST_F(PRTokenTest, ValidateZeroRevealRate) {
  // Note: Validation is done by checking that the number of tokens with IP
  // addresses is within 10% of the expected number.
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes;
  ASSERT_OK_AND_ASSIGN(
      ip_address_bytes,
      IPStringToByteArray("2001:0000:130F:0000:0000:09C0:876A:130B"));
  std::vector<ElGamalCiphertext> tokens;
  ASSERT_OK(issuer_->IssueTokens(ip_address_bytes, /*num_signal_tokens=*/0,
                                 /*num_total_tokens=*/100, tokens));
  EXPECT_EQ(tokens.size(), 100);
  std::vector<proto::PlaintextToken> messages;
  std::vector<proto::VerificationErrorReport> reports;
  EXPECT_OK(verifier_->DecryptTokens(tokens, messages, reports));
  EXPECT_EQ(messages.size(), 100);
  int num_revealed = 0;
  std::string ip_address_str;
  for (const proto::PlaintextToken& message : messages) {
    ASSERT_OK_AND_ASSIGN(ip_address_str,
                         IPv6ByteArrayToString(message.signal()));
    if (ip_address_str != "::") {
      ++num_revealed;
    }
  }
  EXPECT_EQ(num_revealed, 0);
  EXPECT_OK(verifier_->VerifyRevealRate(messages, 0));
}

TEST_F(PRTokenTest, ValidateOrdinalDiversity) {
  // Note: Validation checks that each token has a distinct ordinal ID.
  auto ip_address_bytes_or = IPStringToByteArray("8.8.8.8");
  ASSERT_OK(ip_address_bytes_or);
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes =
      *ip_address_bytes_or;
  std::vector<ElGamalCiphertext> tokens;
  ASSERT_OK(issuer_->IssueTokens(ip_address_bytes, /*num_signal_tokens=*/10,
                                 /*num_total_tokens=*/100, tokens));
  EXPECT_EQ(tokens.size(), 100);
  std::vector<proto::PlaintextToken> messages;
  std::vector<proto::VerificationErrorReport> reports;
  EXPECT_OK(verifier_->DecryptTokens(tokens, messages, reports));
  std::set<int32_t> ordinals;
  for (const proto::PlaintextToken& message : messages) {
    ordinals.insert(message.ordinal());
  }
  EXPECT_EQ(ordinals.size(), 100);
  EXPECT_OK(verifier_->VerifyEquivalentOrdinalCounts(messages));
}

TEST(PlaintextGeneratorValidatorTest, BuildIPv4Plaintext) {
  PlaintextTokenGenerator generator(kSecretKeyHMAC);
  auto ip_address_bytes_or = IPStringToByteArray("1.2.3.4");
  ASSERT_OK(ip_address_bytes_or);
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes =
      *ip_address_bytes_or;
  PlaintextTokenBytes message;
  EXPECT_OK(generator.Generate(ip_address_bytes, 5, message));
  EXPECT_EQ(message[0], 1);
  /**
   *    https://datatracker.ietf.org/doc/html/rfc4291 ____________________
   *    |                80 bits               | 16 |      32 bits        |
        +--------------------------------------+--------------------------+
        |0000..............................0000|FFFF|    IPv4 address     |
        +--------------------------------------+----+---------------------+
   */
  for (size_t i = 0; i < 10; ++i) {
    // Expect 10 zero-bytes in IPv4-Mapped IPv6 Address.
    EXPECT_EQ(message[2 + i], 0);
  }
  for (size_t i = 0; i < 2; ++i) {
    // Expect 2 high bytes in IPv4-Mapped IPv6 Address.
    EXPECT_EQ(message[2 + 10 + i], 255);
  }
  EXPECT_EQ(message[14], 1);
  EXPECT_EQ(message[15], 2);
  EXPECT_EQ(message[16], 3);
  EXPECT_EQ(message[17], 4);
  PlaintextTokenValidator validator(kSecretKeyHMAC);
  ASSERT_OK_AND_ASSIGN(proto::PlaintextToken token, validator.ToProto(message));
  std::string ip_address_str;
  ASSERT_OK_AND_ASSIGN(ip_address_str, IPv6ByteArrayToString(token.signal()));
  EXPECT_EQ(ip_address_str, "::ffff:1.2.3.4");
  EXPECT_TRUE(token.hmac_valid());
  EXPECT_EQ(token.ordinal(), message[1]);
  EXPECT_EQ(token.version(), message[0]);
}

TEST(PlaintextGeneratorValidatorTest, BuildIPv6Plaintext) {
  PlaintextTokenGenerator generator(kSecretKeyHMAC);
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes;
  ASSERT_OK_AND_ASSIGN(ip_address_bytes, IPStringToByteArray("2001:db8:3333:4444:5555:6666:7777:8888"));
  PlaintextTokenBytes message;
  EXPECT_OK(generator.Generate(ip_address_bytes, 5, message));
  EXPECT_EQ(message[0], 1);
  EXPECT_EQ(message[1], 5);
  EXPECT_EQ(message[2], 0x20);
  EXPECT_EQ(message[3], 0x1);
  EXPECT_EQ(message[4], 0xd);
  EXPECT_EQ(message[5], 0xb8);
  EXPECT_EQ(message[6], 0x33);
  EXPECT_EQ(message[7], 0x33);
  EXPECT_EQ(message[8], 0x44);
  EXPECT_EQ(message[9], 0x44);
  EXPECT_EQ(message[10], 0x55);
  EXPECT_EQ(message[11], 0x55);
  EXPECT_EQ(message[12], 0x66);
  EXPECT_EQ(message[13], 0x66);
  EXPECT_EQ(message[14], 0x77);
  EXPECT_EQ(message[15], 0x77);
  EXPECT_EQ(message[16], 0x88);
  EXPECT_EQ(message[17], 0x88);
  PlaintextTokenValidator validator(kSecretKeyHMAC);
  ASSERT_OK_AND_ASSIGN(proto::PlaintextToken token, validator.ToProto(message));
  std::string ip_address_str;
  ASSERT_OK_AND_ASSIGN(ip_address_str, IPv6ByteArrayToString(token.signal()));
  EXPECT_EQ(ip_address_str, "2001:db8:3333:4444:5555:6666:7777:8888");
  EXPECT_TRUE(token.hmac_valid());
  EXPECT_EQ(token.ordinal(), message[1]);
  EXPECT_EQ(token.version(), message[0]);
}

TEST(PlaintextGeneratorValidatorTest, ValidateHMACCorruption) {
  PlaintextTokenGenerator generator(kSecretKeyHMAC);
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes;
  ASSERT_OK_AND_ASSIGN(ip_address_bytes, IPStringToByteArray("1.2.3.4"));
  PlaintextTokenBytes message;
  EXPECT_OK(generator.Generate(ip_address_bytes, 5, message));
  // Modify the message to inject a different IP address.
  message[14] = 5;
  message[15] = 6;
  message[16] = 7;
  message[17] = 8;
  std::string_view message_str(reinterpret_cast<char*>(message.data()),
                               token_structure.token_size());
  PlaintextTokenValidator validator(kSecretKeyHMAC);
  ASSERT_OK_AND_ASSIGN(proto::PlaintextToken token,
                       validator.ToProto(message_str));
  std::string ip_address_str;
  ASSERT_OK_AND_ASSIGN(ip_address_str, IPv6ByteArrayToString(token.signal()));
  EXPECT_EQ(ip_address_str, "::ffff:5.6.7.8");
  EXPECT_FALSE(token.hmac_valid());
}

TEST(PlaintextGeneratorValidatorTest, InvalidHMACDoesNotValidate) {
  PlaintextTokenGenerator generator(kSecretKeyHMAC);
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes;
  ASSERT_OK_AND_ASSIGN(ip_address_bytes, IPStringToByteArray("1.2.3.4"));
  PlaintextTokenBytes message;
  EXPECT_OK(generator.Generate(ip_address_bytes, 5, message));
  PlaintextTokenValidator validator("now for something completely different!");
  ASSERT_OK_AND_ASSIGN(proto::PlaintextToken token, validator.ToProto(message));
  std::string ip_address_str;
  ASSERT_OK_AND_ASSIGN(ip_address_str, IPv6ByteArrayToString(token.signal()));
  EXPECT_EQ(ip_address_str, "::ffff:1.2.3.4");
  EXPECT_FALSE(token.hmac_valid());
}

TEST_F(IssuerTest, InvalidKeyDoesNotDecrypt) {
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes;
  ASSERT_OK_AND_ASSIGN(ip_address_bytes, IPStringToByteArray("1.2.3.4"));
  std::vector<ElGamalCiphertext> tokens;
  ASSERT_OK(issuer_->IssueTokens(ip_address_bytes, /*num_signal_tokens=*/1,
                                 /*num_total_tokens=*/1, tokens));
  EXPECT_EQ(tokens.size(), 1);
  std::vector<proto::PlaintextToken> decrypted_tokens;
  ASSERT_OK_AND_ASSIGN(proto::ElGamalKeyMaterial alt_key_pair,
                       GenerateElGamalKeypair());
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Verifier> alt_verifier,
      Verifier::Create(alt_key_pair.secret_key(), secret_key_hmac_));
  std::vector<proto::VerificationErrorReport> reports;
  absl::Status status =
      alt_verifier->DecryptTokens(tokens, decrypted_tokens, reports);
  EXPECT_EQ(status.code(), absl::StatusCode::kInternal);
  EXPECT_EQ(reports.size(), 1);
}

TEST_F(IssuerTest, ReRandomizedTokensAreDifferent) {
  constexpr absl::string_view kIPAddressString = "2001:0:130f::9c0:876a:130b";
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes;
  ASSERT_OK_AND_ASSIGN(ip_address_bytes, IPStringToByteArray(kIPAddressString));
  std::vector<ElGamalCiphertext> tokens;
  ASSERT_OK(issuer_->IssueTokens(ip_address_bytes, /*num_signal_tokens=*/1,
                                 /*num_total_tokens=*/1, tokens));
  Rerandomizer rerand = Rerandomizer();
  ASSERT_OK(rerand.Init(key_pair_.public_key()));
  ASSERT_OK_AND_ASSIGN(ElGamalCiphertext rerandomized_token,
                       rerand.Rerandomize(tokens[0]));
  ASSERT_NE(tokens[0].e(), rerandomized_token.e());
  std::vector<proto::PlaintextToken> decrypted_tokens;
  std::vector<proto::VerificationErrorReport> reports;
  ASSERT_OK(verifier_->DecryptTokens({rerandomized_token}, decrypted_tokens,
                                     reports));
  EXPECT_TRUE(decrypted_tokens[0].hmac_valid());
  std::string ip_address_str;
  ASSERT_OK_AND_ASSIGN(ip_address_str,
                       IPv6ByteArrayToString(decrypted_tokens[0].signal()));
  EXPECT_EQ(ip_address_str, kIPAddressString);
}

/*
Benchmark for rerandomizing a token.
To test:
  bazel test --config=benchmark prtoken:issuance_verification_test \
      --test_arg=--benchmark_filter=all
*/
void BM_Rerandomize(benchmark::State& state) {
  std::string secret_key_hmac;
  proto::ElGamalKeyMaterial key_pair;
  std::unique_ptr<IssuerUnderTest> issuer;
  ASSERT_OK_AND_ASSIGN(key_pair, GenerateElGamalKeypair());
  private_join_and_compute::ElGamalPublicKey public_key = key_pair.public_key();
  secret_key_hmac = GenerateSecretKeyHMAC();
  ASSERT_OK_AND_ASSIGN(issuer,
                       IssuerUnderTest::Create(secret_key_hmac, public_key));
  CHECK_NE(issuer.get(), nullptr);
  constexpr absl::string_view kIPAddressString = "2001:0:130f::9c0:876a:130b";
  std::array<uint8_t, prtoken::SignalSizeLimit> ip_address_bytes;
  ASSERT_OK_AND_ASSIGN(ip_address_bytes, IPStringToByteArray(kIPAddressString));
  std::vector<ElGamalCiphertext> tokens;
  ASSERT_OK(issuer->IssueTokens(ip_address_bytes, /*num_signal_tokens=*/10,
                                /*num_total_tokens=*/1, tokens));
  Rerandomizer rerand = Rerandomizer();
  ASSERT_OK(rerand.Init(key_pair.public_key()));
  for (auto _ : state) {
    ASSERT_OK_AND_ASSIGN(ElGamalCiphertext token,
                         rerand.Rerandomize(tokens[0]));
  }
}
BENCHMARK(BM_Rerandomize);

}  // namespace
}  // namespace prtoken
