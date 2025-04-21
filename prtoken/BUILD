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

load("@com_github_grpc_grpc//bazel:grpc_build_system.bzl", "grpc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "token",
    srcs = ["token.cc"],
    hdrs = ["token.h"],
    deps = [
        ":token_proto",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings:string_view",
        "@boringssl//:crypto",
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
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings:string_view",
        "@boringssl//:crypto",
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
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
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
        ":token_proto",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/types:span",
        "@private_join_and_compute//private_join_and_compute/crypto:bn_util",
        "@private_join_and_compute//private_join_and_compute/crypto:ec_util",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal_proto",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
    ],
)

grpc_proto_library(
    name = "token_proto",
    srcs = ["token.proto"],
    deps = ["@private_join_and_compute//private_join_and_compute/crypto:elgamal_proto"],
)

# Command tool to issue and verify probabilistic reveal tokens for IP address.
cc_library(
    name = "command",
    srcs = ["command.cc"],
    hdrs = ["command.h"],
    deps = [
        ":token",
        ":token_proto",
        ":storage",
        ":verifier",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
    ],
)

cc_library(
    name = "storage",
    srcs = ["storage.cc"],
    hdrs = ["storage.h"],
    deps = [
        ":token",
        ":token_proto",
        ":verifier",
        "@abseil-cpp//absl/cleanup",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
        "@nlohmann_json//:json",
        "@or-tools//ortools/base:file",
        "@private_join_and_compute//private_join_and_compute/crypto:bn_util",
        "@private_join_and_compute//private_join_and_compute/crypto:ec_util",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal_proto",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
        "@sqlite3",
    ],
)

cc_library(
    name = "token_header",
    srcs = ["token_header.cc"],
    hdrs = ["token_header.h"],
    deps = [
        ":issuer",
        ":command",
        ":verifier",
        ":storage",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@curl",
        "@private_join_and_compute//private_join_and_compute/crypto:bn_util",
        "@private_join_and_compute//private_join_and_compute/crypto:ec_util",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal_proto",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
    ],
)

cc_binary(
    name = "prtoken",
    srcs = ["main.cc"],
    deps = [
        ":issuer",
        ":command",
        ":token_header",
        ":verifier",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@or-tools//ortools/base:path",
    ],
)

cc_library(
    name = "issuer_test_lib",
    testonly = 1,
    srcs = ["issuer_test_lib.cc"],
    hdrs = ["issuer_test_lib.h"],
    deps = [
        ":issuer",
        ":token",
        ":token_proto",
        ":verifier",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/status:status_matchers",
        "@abseil-cpp//absl/strings:string_view",
    ],
)

cc_test(
    name = "command_test",
    srcs = ["command_test.cc"],
    deps = [
        ":issuer_test_lib",
        ":storage",
        ":command",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@or-tools//ortools/base:path",
        "@or-tools//ortools/base:status_matchers",
    ],
)

cc_test(
    name = "storage_test",
    srcs = ["storage_test.cc"],
    deps = [
        ":issuer_test_lib",
        ":storage",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@or-tools//ortools/base:path",
        "@or-tools//ortools/base:status_matchers",
    ],
)

cc_test(
    name = "issuance_verification_test",
    srcs = ["issuance_verification_test.cc"],
    deps = [
        ":client",
        ":issuer",
        ":issuer_test_lib",
        ":token",
        ":token_proto",
        ":verifier",
        ":command",
        "@or-tools//ortools/base:path",
        "@or-tools//ortools/base:status_matchers",
        "@google_benchmark//:benchmark",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings:string_view",
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal_proto",
    ],
)