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

load("@cxx.rs//tools/bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_applicable_licenses = [
    ],
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "aggregation_config",
    srcs = [
        "aggregation_config.rs",
    ],
    deps = [
        "@protobuf//rust:protobuf",
        "//ffi_utils:status",
        "//willow/proto/willow:aggregation_config_rust_proto",
        "//willow/src/shell:single_thread_hkdf",
        "//willow/src/traits:proto_serialization_traits",
    ],
)

rust_test(
    name = "aggregation_config_test",
    crate = ":aggregation_config",
    deps = [
        ":aggregation_config",
        "@crate_index//:googletest",
        "//willow/src/testing_utils",
    ],
)

cc_library(
    name = "server_accumulator",
    srcs = ["server_accumulator.cc"],
    hdrs = ["server_accumulator.h"],
    deps = [
        ":server_accumulator_cxx/include",  # fixdeps: keep
        ":server_accumulator_rust",  # fixdeps: keep
        "@abseil-cpp//absl/memory",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@cxx.rs//:core",
        "//willow/proto/willow:aggregation_config_cc_proto",
        "//willow/proto/willow:messages_cc_proto",
        "//willow/proto/willow:server_accumulator_cc_proto",
        "//willow/src/input_encoding:codec",
    ],
)

cc_test(
    name = "server_accumulator_test",
    srcs = ["server_accumulator_test.cc"],
    deps = [
        ":client_cc",
        ":server_accumulator",
        ":server_accumulator_cxx",  # fixdeps: keep
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "//ffi_utils:status_matchers",
        "//willow/proto/willow:aggregation_config_cc_proto",
        "//willow/proto/willow:messages_cc_proto",
        "//willow/proto/willow:server_accumulator_cc_proto",
        "//willow/src/input_encoding:codec",
        "//willow/src/testing_utils:shell_testing_decryptor_cc",
    ],
)

rust_cxx_bridge(
    name = "server_accumulator_cxx",
    src = "server_accumulator.rs",
    deps = [
        ":server_accumulator",
    ],
)

rust_library(
    name = "server_accumulator_rust",
    srcs = ["server_accumulator.rs"],
    deps = [
        ":aggregation_config",
        "@protobuf//rust:protobuf",
        "@cxx.rs//:cxx",
        "@crate_index//:rangemap",
        "//ffi_utils:status",
        "//willow/proto/willow:aggregation_config_rust_proto",
        "//willow/proto/willow:server_accumulator_rust_proto",
        "//willow/proto/willow:messages_rust_proto",
        "//willow/src/shell:kahe_shell",
        "//willow/src/shell:parameters_shell",
        "//willow/src/shell:vahe_shell",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:kahe_traits",
        "//willow/src/traits:messages",
        "//willow/src/traits:proto_serialization_traits",
        "//willow/src/traits:server_traits",
        "//willow/src/traits:vahe_traits",
        "//willow/src/traits:verifier_traits",
        "//willow/src/willow_v1:willow_v1_server",
        "//willow/src/willow_v1:willow_v1_verifier",
    ],
)

rust_library(
    name = "client",
    srcs = ["client.rs"],
    deps = [
        ":aggregation_config",
        "@protobuf//rust:protobuf",
        "@cxx.rs//:cxx",
        "//ffi_utils:status",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "//willow/proto/willow:aggregation_config_rust_proto",
        "//willow/proto/willow:messages_rust_proto",
        "//willow/src/shell:ahe_shell",
        "//willow/src/shell:kahe_shell",
        "//willow/src/shell:parameters_shell",
        "//willow/src/shell:single_thread_hkdf",
        "//willow/src/shell:vahe_shell",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:client_traits",
        "//willow/src/traits:kahe_traits",
        "//willow/src/traits:messages",
        "//willow/src/traits:prng_traits",
        "//willow/src/traits:proto_serialization_traits",
        "//willow/src/traits:vahe_traits",
        "//willow/src/willow_v1:willow_v1_client",
        "//willow/src/willow_v1:willow_v1_server",
    ],
)

rust_cxx_bridge(
    name = "client_cxx",
    src = "client.rs",
    deps = [
        ":client",
    ],
)

cc_library(
    name = "client_cc",
    srcs = ["client.cc"],
    hdrs = ["client.h"],
    deps = [
        ":client_cxx",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@cxx.rs//:core",
        "//shell_wrapper:shell_types_cc",
        "//willow/proto/shell:shell_ciphertexts_cc_proto",
        "//willow/proto/willow:aggregation_config_cc_proto",
        "//willow/proto/willow:messages_cc_proto",
        "//willow/proto/willow:server_accumulator_cc_proto",
        "//willow/src/input_encoding:codec",
    ],
)

cc_test(
    name = "client_test_cc",
    srcs = ["client_test.cc"],
    deps = [
        ":client_cc",
        ":client_cxx",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/status",
        "@cxx.rs//:core",
        "//ffi_utils:status_matchers",
        "//willow/proto/willow:aggregation_config_cc_proto",
        "//willow/proto/willow:input_spec_cc_proto",
        "//willow/src/input_encoding:codec",
        "//willow/src/testing_utils:shell_testing_decryptor_cc",
    ],
)
