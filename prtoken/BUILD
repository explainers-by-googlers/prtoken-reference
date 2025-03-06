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

cc_binary(
    name = "prtoken",
    srcs = ["main.cc"],
    deps = [
        ":issuer",
        ":storage",
        ":token",
        ":token_proto",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@or-tools//ortools/base:path",
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
        "@private_join_and_compute//private_join_and_compute/crypto:elgamal_proto",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
        "@sqlite3",
    ],
)
