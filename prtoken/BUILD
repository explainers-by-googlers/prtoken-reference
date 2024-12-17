# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "token",
    srcs = ["token.cc"],
    hdrs = ["token.h"],
    deps = [
        ":token_cc_proto",
        "@boringssl//:crypto",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:string_view",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal_proto",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
    ],
)

cc_library(
    name = "issuer",
    srcs = ["issuer.cc"],
    hdrs = ["issuer.h"],
    deps = [
        ":token",
        "@boringssl//:crypto",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:string_view",
        "@private_join_and_compute//private_join_and_compute/crypto:bn_util",
        "@private_join_and_compute//private_join_and_compute/crypto:ec_util",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal_proto",
        "@private_join_and_compute//private_join_and_compute/crypto:openssl_includes",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
    ],
)

cc_library(
    name = "client",
    srcs = ["client.cc"],
    hdrs = ["client.h"],
    deps = [
        ":token",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@private_join_and_compute//private_join_and_compute/crypto:bn_util",
        "@private_join_and_compute//private_join_and_compute/crypto:ec_util",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal_proto",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
    ],
)

cc_library(
    name = "verifier",
    srcs = ["verifier.cc"],
    hdrs = ["verifier.h"],
    deps = [
        ":token",
        ":token_cc_proto",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:string_view",
        "@com_google_absl//absl/types:span",
        "@private_join_and_compute//private_join_and_compute/crypto:bn_util",
        "@private_join_and_compute//private_join_and_compute/crypto:ec_util",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal_proto",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
    ],
)

proto_library(
    name = "token_proto",
    srcs = ["token.proto"],
)

cc_proto_library(
    name = "token_cc_proto",
    deps = [":token_proto"],
)
