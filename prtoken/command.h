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

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "prtoken/storage.h"
#include "prtoken/token.pb.h"
#include "prtoken/verifier.h"

namespace prtoken {

// This is an alias to aid readability.
constexpr size_t SignalSizeLimit = prtoken::token_structure.signal_size;

// Read tokens from a DB and decrypt them to IP strings.
class TokensDBWithIPVerifier : public TokensDB {
 public:
  TokensDBWithIPVerifier(std::unique_ptr<Verifier> verifier_ptr,
                         std::string token_table, std::string result_table);
  ~TokensDBWithIPVerifier() override;

  absl::Status CreateResultTable();
  absl::Status CommitResult(sqlite3_stmt *stmt);
  absl::Status OnFinishGetToken(const ValidationToken &token) override;
  absl::Status report();

 private:
  uint16_t processed_ = 0;
  uint16_t errors_ = 0;
  std::string result_table_;
  std::unique_ptr<Verifier> verifier_ptr_;
};

// Helper to check if the input is a valid IP address.
bool IsValidIPAddress(absl::string_view ip_string);

// Transform IP string into byte array. V4 address is padded
// to IPv4-mapped address, see
// http://tools.ietf.org/html/rfc3493#section-3.7.
absl::StatusOr<std::array<uint8_t, SignalSizeLimit>> IPStringToByteArray(
    std::string_view ip_string);

// Transform IPv6 byte array into string.
absl::StatusOr<std::string> IPv6ByteArrayToString(
    const std::string_view ip_string);
}  // namespace prtoken
