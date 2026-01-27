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
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_applicable_licenses = [
    ],
    default_visibility = ["//visibility:public"],
)

# AHE
rust_library(
    name = "ahe_shell",
    srcs = [
        "ahe.rs",
    ],
    crate_root = "ahe.rs",
    deps = [
        ":single_thread_hkdf",
        "@protobuf//rust:protobuf",
        "//ffi_utils:status",
        "//shell_wrapper:ahe",
        "//shell_wrapper:ahe_cxx",  # fixdeps: keep
        "//shell_wrapper:shell_serialization",
        "//shell_wrapper:shell_serialization_cxx",  # fixdeps: keep
        "//shell_wrapper:shell_types",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:prng_traits",
        "//willow/src/traits:proto_serialization_traits",
    ],
)

rust_test(
    name = "ahe_shell_test",
    crate = ":ahe_shell",
    deps = [
        ":ahe_shell",
        ":single_thread_hkdf",
        "@crate_index//:googletest",
        "//ffi_utils:status",
        "//ffi_utils:status_matchers_rs",
        "//willow/src/testing_utils",
        "//willow/src/testing_utils:shell_testing_parameters",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:prng_traits",
    ],
)

# KAHE
rust_library(
    name = "kahe_shell",
    srcs = ["kahe.rs"],
    deps = [
        ":single_thread_hkdf",
        "@protobuf//rust:protobuf",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//shell_wrapper:kahe_cxx",
        "//shell_wrapper:shell_serialization",
        "//shell_wrapper:shell_serialization_cxx",  # fixdeps: keep
        "//shell_wrapper:shell_types",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "//willow/src/traits:kahe_traits",
        "//willow/src/traits:prng_traits",
        "//willow/src/traits:proto_serialization_traits",
    ],
)

rust_test(
    name = "kahe_shell_test",
    crate = ":kahe_shell",
    deps = [
        ":kahe_shell",
        "@crate_index//:googletest",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//willow/src/testing_utils",
        "//willow/src/testing_utils:shell_testing_parameters",
    ],
)

# Parameters of the underlying RLWE systems
rust_library(
    name = "parameters_shell",
    srcs = ["parameters.rs"],
    crate_root = "parameters.rs",
    deps = [
        ":ahe_shell",
        ":kahe_shell",
        ":shell_parameters_generation",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//willow/src/api:aggregation_config",
    ],
)

# Utilities for parameters proto (e.g. conversion between rust structs and protos)
rust_library(
    name = "shell_parameters_utils",
    srcs = ["parameters_utils.rs"],
    crate_root = "parameters_utils.rs",
    deps = [
        ":kahe_shell",
        ":parameters_shell",
        "@protobuf//rust:protobuf",
        "@cxx.rs//:cxx",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//willow/proto/shell:shell_parameters_rust_proto",
        "//willow/proto/willow:aggregation_config_rust_proto",
        "//willow/src/api:aggregation_config",
        "//willow/src/traits:proto_serialization_traits",
    ],
)

rust_cxx_bridge(
    name = "shell_parameters_utils_cxx",
    src = "parameters_utils.rs",
    deps = [
        ":shell_parameters_utils",
        "//ffi_utils:status_cxx",
    ],
)

cc_library(
    name = "shell_parameters_utils_cc",
    srcs = ["parameters_utils.cc"],
    hdrs = ["parameters_utils.h"],
    deps = [
        ":shell_parameters_utils_cxx",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@cxx.rs//:core",
        "//ffi_utils:status_cc",
        "//ffi_utils:status_macros",
        "//willow/proto/willow:aggregation_config_cc_proto",
    ],
)

cc_test(
    name = "parameters_utils_test",
    srcs = ["parameters_utils_test.cc"],
    deps = [
        ":shell_parameters_utils_cc",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/status",
        "//willow/proto/willow:aggregation_config_cc_proto",
    ],
)

rust_test(
    name = "shell_parameters_utils_test",
    crate = ":shell_parameters_utils",
    deps = [
        ":shell_parameters_utils",
        "@crate_index//:googletest",
        "@protobuf//rust:protobuf_gtest_matchers",
        "//ffi_utils:status",
    ],
)

# Parameter generation
rust_library(
    name = "shell_parameters_generation",
    srcs = ["parameters_generation.rs"],
    crate_root = "parameters_generation.rs",
    deps = [
        ":kahe_shell",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//willow/src/api:aggregation_config",
    ],
)

rust_test(
    name = "shell_parameters_generation_test",
    crate = ":shell_parameters_generation",
    deps = [
        ":shell_parameters_generation",
        "@crate_index//:googletest",
        "@protobuf//rust:protobuf_gtest_matchers",
        "//ffi_utils:status",
    ],
)

# PRNG
rust_library(
    name = "single_thread_hkdf",
    srcs = [
        "single_thread_hkdf.rs",
    ],
    deps = [
        "//ffi_utils:status",
        "//shell_wrapper:single_thread_hkdf",
        "//shell_wrapper:single_thread_hkdf_cxx",  # fixdeps: keep
        "//willow/src/traits:prng_traits",
    ],
)

rust_test(
    name = "single_thread_hkdf_test",
    crate = ":single_thread_hkdf",
    deps = [
        "@crate_index//:googletest",
    ],
)

rust_library(
    name = "vahe_shell",
    srcs = ["vahe.rs"],
    deps = [
        ":ahe_shell",
        ":single_thread_hkdf",
        "@protobuf//rust:protobuf",
        "@crate_index//:merlin",
        "//ffi_utils:status",
        "//shell_wrapper:ahe",
        "//shell_wrapper:ahe_cxx",  # fixdeps: keep
        "//shell_wrapper:shell_types",
        "//willow/proto/zk:proofs_rust_proto",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:proto_serialization_traits",
        "//willow/src/traits:vahe_traits",
        "//willow/src/traits:zk_traits",
        "//willow/src/zk:rlwe_relation",
        "//willow/src/zk:rlwe_relation_serialization",
    ],
)

rust_test(
    name = "vahe_shell_test",
    crate = ":vahe_shell",
    deps = [
        ":vahe_shell",
        "@crate_index//:googletest",
        "@crate_index//:merlin",
        "//ffi_utils:status",
        "//willow/src/testing_utils",
        "//willow/src/testing_utils:shell_testing_parameters",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:prng_traits",
        "//willow/src/traits:proto_serialization_traits",
        "//willow/src/traits:vahe_traits",
        "//willow/src/traits:zk_traits",
        "//willow/src/zk:rlwe_relation",
    ],
)
