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

#include "prtoken/client.h"

#include <memory>
#include <string>
#include <utility>

#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "private_join_and_compute/crypto/elgamal.pb.h"
#include "prtoken/token.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "private_join_and_compute/util/status_macros.h"

namespace prtoken {

using ::private_join_and_compute::Context;
using ::private_join_and_compute::ECGroup;
using ::private_join_and_compute::ECPoint;
using ::private_join_and_compute::ElGamalCiphertext;
using ::private_join_and_compute::ElGamalEncrypter;
using ::private_join_and_compute::ElGamalPublicKey;
using ::private_join_and_compute::elgamal::PublicKey;
using ::private_join_and_compute::elgamal::Ciphertext;

absl::Status Rerandomizer::Init(const ElGamalPublicKey& public_key) {
  blinders_context_ = std::make_unique<Context>();
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(kCurveId, blinders_context_.get()));
  ec_group_ = std::make_unique<private_join_and_compute::ECGroup>(std::move(ec_group));
  ASSIGN_OR_RETURN(ECPoint point_g, ec_group_->CreateECPoint(public_key.g()));
  ASSIGN_OR_RETURN(ECPoint point_y, ec_group_->CreateECPoint(public_key.y()));
  std::unique_ptr<PublicKey> public_key_eg(
      new PublicKey({std::move(point_g), std::move(point_y)}));
  encrypter_ = std::make_unique<ElGamalEncrypter>(ec_group_.get(),
                                                  std::move(public_key_eg));
  return absl::OkStatus();
}

absl::StatusOr<ElGamalCiphertext> Rerandomizer::Rerandomize(
    const ElGamalCiphertext original_ciphertext) {
  ASSIGN_OR_RETURN(ECPoint point_u,
                   ec_group_->CreateECPoint(original_ciphertext.u()));
  ASSIGN_OR_RETURN(ECPoint point_e,
                   ec_group_->CreateECPoint(original_ciphertext.e()));
  Ciphertext ciphertext = {std::move(point_u),
                                              std::move(point_e)};
  ASSIGN_OR_RETURN(Ciphertext ciphertext_new,
                   encrypter_->ReRandomize(ciphertext));
  private_join_and_compute::ElGamalCiphertext ciphertext_proto_new;
  ASSIGN_OR_RETURN(const std::string u_bytes,
                   ciphertext_new.u.ToBytesCompressed());
  ciphertext_proto_new.set_u(u_bytes);
  ASSIGN_OR_RETURN(const std::string e_bytes,
                   ciphertext_new.e.ToBytesCompressed());
  ciphertext_proto_new.set_e(e_bytes);
  return ciphertext_proto_new;
}
}  // namespace prtoken
