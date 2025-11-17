# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
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
    default_visibility = ["//visibility:public"],
)

# Parameters proto
proto_library(
    name = "shell_parameters_proto",
    srcs = ["parameters.proto"],
)

cc_proto_library(
    name = "shell_parameters_cc_proto",
    deps = [":shell_parameters_proto"],
)

rust_proto_library(
    name = "shell_parameters_rust_proto",
    deps = [":shell_parameters_proto"],
)

# Utilities for parameters proto (e.g. conversion between rust structs and protos)
rust_library(
    name = "shell_parameters_proto_utils",
    srcs = ["parameters_proto_utils.rs"],
    crate_root = "parameters_proto_utils.rs",
    deps = [
        ":shell_parameters_rust_proto",
        "@protobuf//rust:protobuf",
        "//shell_wrapper:kahe",
        "//shell_wrapper:status",
        "//willow/src/shell:kahe_shell",
    ],
)

rust_test(
    name = "shell_parameters_proto_utils_test",
    crate = ":shell_parameters_proto_utils",
    deps = [
        ":shell_parameters_proto_utils",
        "@crate_index//:googletest",
        "@protobuf//rust:protobuf_gtest_matchers",
        "//shell_wrapper:status",
    ],
)
