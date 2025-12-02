# Copyright 2025 Google LLC
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

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")
load("@protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
load("@protobuf//bazel:proto_library.bzl", "proto_library")
load("@protobuf//rust:defs.bzl", "rust_proto_library")

package(
    default_applicable_licenses = [
    ],
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "willow_api_common",
    srcs = [
        "common.rs",
    ],
    deps = [
        "//shell_wrapper:status",
    ],
)

rust_library(
    name = "client",
    srcs = [
        "client.rs",
    ],
    deps = [
        ":willow_api_common",
        ":willow_api_common_rust_proto",
        "//shell_wrapper:status",
    ],
)

rust_library(
    name = "decryptor",
    srcs = [
        "decryptor.rs",
    ],
    deps = [
        ":willow_api_common",
        ":willow_api_common_rust_proto",
        "//shell_wrapper:status",
    ],
)

rust_library(
    name = "server",
    srcs = [
        "server.rs",
    ],
    deps = [
        ":willow_api_common",
        ":willow_api_common_rust_proto",
        "//shell_wrapper:status",
    ],
)

rust_library(
    name = "verifier",
    srcs = [
        "verifier.rs",
    ],
    deps = [
        ":willow_api_common",
        ":willow_api_common_rust_proto",
        "//shell_wrapper:status",
    ],
)

# Common proto
proto_library(
    name = "willow_api_common_proto",
    srcs = ["common.proto"],
    deps = [
        "//willow/proto/shell:shell_ciphertexts_proto",
        "//willow/proto/zk:proofs_proto",
    ],
)

cc_proto_library(
    name = "willow_api_common_cc_proto",
    deps = [":willow_api_common_proto"],
)

rust_proto_library(
    name = "willow_api_common_rust_proto",
    deps = [":willow_api_common_proto"],
)

rust_library(
    name = "willow_api_common_serialization",
    srcs = [
        "common_serialization.rs",
    ],
    deps = [
        ":willow_api_common",
        ":willow_api_common_rust_proto",
        "@protobuf//rust:protobuf",
    ],
)

rust_test(
    name = "willow_api_common_serialization_test",
    crate = ":willow_api_common_serialization",
    deps = [
        ":willow_api_common_serialization",
        "@crate_index//:googletest",
        "//willow/src/testing_utils",
    ],
)
