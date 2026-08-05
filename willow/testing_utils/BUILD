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
    default_visibility = ["//:internal"],
)

# PRNG
rust_library(
    name = "fake_prng",
    testonly = 1,
    srcs = [
        "fake_prng.rs",
    ],
    deps = [
        "//ffi_utils:status",
        "//willow/crypto:prng_traits",
    ],
)

rust_test(
    name = "fake_prng_test",
    crate = ":fake_prng",
    deps = [
        "@crate_index//:googletest",
    ],
)

# Configuration builder and default testing_parameters for AHE and KAHE.
rust_library(
    name = "shell_testing_parameters",
    testonly = 1,
    srcs = ["shell_testing_parameters.rs"],
    deps = [
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//willow/api:aggregation_config",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:shell_ahe",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters_generation",
    ],
)

# Testing utilities.
rust_library(
    name = "testing_utils",
    testonly = 1,
    srcs = [
        "testing_utils.rs",
    ],
    deps = [
        ":shell_testing_parameters",
        "@crate_index//:rand",
        "//ffi_utils:status",
        "//willow/api:aggregation_config",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:vahe_traits",
        "//willow/protocol:default_client",
        "//willow/protocol:messages",
    ],
)

rust_test(
    name = "testing_utils_test",
    crate = ":testing_utils",
    deps = [
        "@crate_index//:googletest",
    ],
)

rust_cxx_bridge(
    name = "shell_testing_decryptor_cxx",
    src = "shell_testing_decryptor.rs",
    deps = [
        ":shell_testing_decryptor",
        "//ffi_utils:status_cxx",
        "//willow/crypto:vahe_traits",
    ],
)

rust_library(
    name = "shell_testing_decryptor",
    srcs = [
        "shell_testing_decryptor.rs",
    ],
    deps = [
        "@protobuf//rust:protobuf",
        "@cxx.rs//:cxx",
        "//ffi_utils:status",
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:shell_ahe",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:vahe_traits",
        "//willow/proto/willow:aggregation_config_rust_proto",
        "//willow/proto/willow:messages_rust_proto",
        "//willow/protocol:decryptor",
        "//willow/protocol:messages",
    ],
)

cc_library(
    name = "shell_testing_decryptor_cc",
    srcs = ["shell_testing_decryptor.cc"],
    hdrs = ["shell_testing_decryptor.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":shell_testing_decryptor_cxx",
        "@abseil-cpp//absl/memory",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "//ffi_utils:cxx_utils",
        "//ffi_utils:status_macros",
        "//willow/input_encoding:codec",
        "//willow/proto/shell:shell_ciphertexts_cc_proto",
        "//willow/proto/willow:aggregation_config_cc_proto",
        "//willow/proto/willow:messages_cc_proto",
    ],
)

cc_test(
    name = "shell_testing_decryptor_test",
    srcs = ["shell_testing_decryptor_test.cc"],
    deps = [
        ":shell_testing_decryptor_cc",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/status",
        "//ffi_utils:status_matchers",
        "//willow/proto/willow:aggregation_config_cc_proto",
    ],
)

cc_library(
    name = "testing_utils_cc",
    srcs = ["testing_utils.cc"],
    hdrs = ["testing_utils.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//willow/input_encoding:codec",
        "//willow/proto/willow:aggregation_config_cc_proto",
        "//willow/proto/willow:input_spec_cc_proto",
    ],
)
