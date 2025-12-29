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
        "//shell_wrapper:status",
        "//willow/src/traits:prng_traits",
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
        "//shell_wrapper:kahe",
        "//shell_wrapper:status",
        "//willow/src/api:aggregation_config",
        "//willow/src/shell:ahe_shell",
        "//willow/src/shell:kahe_shell",
        "//willow/src/shell:shell_parameters_generation",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:kahe_traits",
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
        "//shell_wrapper:status",
        "//willow/src/api:aggregation_config",
        "//willow/src/shell:kahe_shell",
        "//willow/src/shell:vahe_shell",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:kahe_traits",
        "//willow/src/traits:messages",
        "//willow/src/traits:prng_traits",
        "//willow/src/traits:vahe_traits",
        "//willow/src/willow_v1:willow_v1_client",
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
        "//shell_wrapper:shell_types_cc",
        "//shell_wrapper:status",
        "//willow/proto/willow:aggregation_config_rust_proto",
        "//willow/proto/willow:messages_rust_proto",
        "//willow/src/api:aggregation_config",
        "//willow/src/shell:ahe_shell",
        "//willow/src/shell:kahe_shell",
        "//willow/src/shell:parameters_shell",
        "//willow/src/shell:single_thread_hkdf",
        "//willow/src/shell:vahe_shell",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:kahe_traits",
        "//willow/src/traits:messages",
        "//willow/src/traits:prng_traits",
        "//willow/src/traits:proto_serialization_traits",
        "//willow/src/traits:vahe_traits",
    ],
)

cc_library(
    name = "shell_testing_decryptor_cc",
    srcs = ["shell_testing_decryptor.cc"],
    hdrs = ["shell_testing_decryptor.h"],
    deps = [
        ":shell_testing_decryptor_cxx",
        "@abseil-cpp//absl/memory",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "//shell_wrapper:shell_types_cc",
        "//willow/proto/shell:shell_ciphertexts_cc_proto",
        "//willow/proto/willow:aggregation_config_cc_proto",
        "//willow/proto/willow:messages_cc_proto",
        "//willow/src/input_encoding:codec",
    ],
)

cc_test(
    name = "shell_testing_decryptor_test",
    srcs = ["shell_testing_decryptor_test.cc"],
    deps = [
        ":shell_testing_decryptor_cc",
        "@googletest//:gtest_main",
        "//shell_wrapper:status_matchers",
        "//willow/proto/willow:aggregation_config_cc_proto",
    ],
)
