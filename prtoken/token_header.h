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

#ifndef PRTOKEN_TOKEN_HEADER_H_
#define PRTOKEN_TOKEN_HEADER_H_

#include <string>

#include "absl/status/status.h"

namespace prtoken {

// Prints the epoch id from the given token header.
absl::Status GetEpochIdFromTokenHeader(const std::string &prt_header);

// Decrypts the given token header and prints the decrypted contents.
// This gets the epoch ID from the token and fetches the key file from
// https://github.com/explainers-by-googlers/prtoken-reference/blob/main/published_keys/
// for decryption. This will fail if the keys have not yet been published for
// the associated epoch.
absl::Status DecryptTokenHeader(const std::string &prt_header);

}  // namespace prtoken

#endif  // PRTOKEN_TOKEN_HEADER_H_
