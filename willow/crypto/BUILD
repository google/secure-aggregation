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

# Cryptographic primitives traits

rust_library(
    name = "prng_traits",
    srcs = [
        "prng_traits.rs",
    ],
    deps = [
        "//ffi_utils:status",
    ],
)

rust_library(
    name = "kahe_traits",
    srcs = [
        "kahe_traits.rs",
    ],
    deps = [
        ":prng_traits",
        "//ffi_utils:status",
    ],
)

rust_library(
    name = "ahe_traits",
    srcs = [
        "ahe_traits.rs",
    ],
    deps = [
        ":prng_traits",
        "//ffi_utils:status",
    ],
)

rust_library(
    name = "vahe_traits",
    srcs = [
        "vahe_traits.rs",
    ],
    deps = [
        ":ahe_traits",
        "//ffi_utils:status",
    ],
)

# KAHE, AHE and VAHE implementations using Shell

rust_library(
    name = "shell_kahe",
    srcs = ["shell_kahe.rs"],
    deps = [
        ":kahe_traits",
        ":prng_traits",
        ":single_thread_hkdf",
        "@protobuf//rust:protobuf",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//shell_wrapper:shell_serialization",
        "//shell_wrapper:shell_serialization_cxx",  # fixdeps: keep
        "//shell_wrapper:shell_types",
        "//willow/api:proto_serialization_traits",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
    ],
)

rust_test(
    name = "shell_kahe_test",
    crate = ":shell_kahe",
    deps = [
        ":shell_kahe",
        "@crate_index//:googletest",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//willow/testing_utils",
        "//willow/testing_utils:shell_testing_parameters",
    ],
)

rust_library(
    name = "shell_ahe",
    srcs = [
        "shell_ahe.rs",
    ],
    deps = [
        ":ahe_traits",
        ":prng_traits",
        ":single_thread_hkdf",
        "@protobuf//rust:protobuf",
        "//ffi_utils:status",
        "//shell_wrapper:ahe",
        "//shell_wrapper:ahe_cxx",  # fixdeps: keep
        "//shell_wrapper:shell_serialization",
        "//shell_wrapper:shell_serialization_cxx",  # fixdeps: keep
        "//shell_wrapper:shell_types",
        "//willow/api:proto_serialization_traits",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
    ],
)

rust_test(
    name = "shell_ahe_test",
    crate = ":shell_ahe",
    deps = [
        ":ahe_traits",
        ":prng_traits",
        ":shell_ahe",
        ":single_thread_hkdf",
        "@crate_index//:googletest",
        "//ffi_utils:status",
        "//ffi_utils:status_matchers_rs",
        "//willow/testing_utils",
        "//willow/testing_utils:shell_testing_parameters",
    ],
)

rust_library(
    name = "shell_vahe",
    srcs = ["shell_vahe.rs"],
    deps = [
        ":ahe_traits",
        ":rlwe_relation_serialization",
        ":shell_ahe",
        ":single_thread_hkdf",
        ":vahe_traits",
        ":zk_rlwe_relation",
        ":zk_traits",
        "@protobuf//rust:protobuf",
        "@crate_index//:merlin",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//shell_wrapper:kahe_cxx",
        "//shell_wrapper:shell_serialization",
        "//shell_wrapper:shell_serialization_cxx",  # fixdeps: keep
        "//shell_wrapper:shell_types",
        "//willow/api:proto_serialization_traits",
        "//willow/proto/zk:proofs_rust_proto",
    ],
)

rust_test(
    name = "shell_vahe_test",
    crate = ":shell_vahe",
    deps = [
        ":ahe_traits",
        ":prng_traits",
        ":shell_vahe",
        ":vahe_traits",
        ":zk_rlwe_relation",
        ":zk_traits",
        "@crate_index//:googletest",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//willow/testing_utils",
        "//willow/testing_utils:shell_testing_parameters",
    ],
)

# Parameters of the underlying RLWE systems
rust_library(
    name = "shell_parameters",
    srcs = ["shell_parameters.rs"],
    deps = [
        ":shell_ahe",
        ":shell_kahe",
        ":shell_parameters_generation",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//willow/api:aggregation_config",
    ],
)

# Utilities for parameters proto (e.g. conversion between rust structs and protos)
rust_library(
    name = "shell_parameters_utils",
    srcs = ["shell_parameters_utils.rs"],
    deps = [
        ":shell_kahe",
        ":shell_parameters",
        "@protobuf//rust:protobuf",
        "@cxx.rs//:cxx",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/proto/shell:shell_parameters_rust_proto",
        "//willow/proto/willow:aggregation_config_rust_proto",
    ],
)

rust_cxx_bridge(
    name = "shell_parameters_utils_cxx",
    src = "shell_parameters_utils.rs",
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
        "@abseil-cpp//absl/status:statusor",
        "@cxx.rs//:core",
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
    srcs = ["shell_parameters_generation.rs"],
    deps = [
        ":shell_kahe",
        "//ffi_utils:status",
        "//shell_wrapper:kahe",
        "//willow/api:aggregation_config",
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
        ":prng_traits",
        "//ffi_utils:status",
        "//shell_wrapper:single_thread_hkdf",
        "//shell_wrapper:single_thread_hkdf_cxx",  # fixdeps: keep
    ],
)

rust_test(
    name = "single_thread_hkdf_test",
    crate = ":single_thread_hkdf",
    deps = [
        "@crate_index//:googletest",
    ],
)

# Zero knowledge

rust_library(
    name = "zk_traits",
    srcs = [
        "zk_traits.rs",
    ],
    visibility = ["//visibility:private"],
    deps = [
        ":ahe_traits",
        ":shell_ahe",
        ":single_thread_hkdf",
        "@protobuf//rust:protobuf",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:merlin",
        "//ffi_utils:status",
        "//shell_wrapper:shell_types",
    ],
)

rust_library(
    name = "zk_linear_innerproduct",
    srcs = ["zk_linear_ip.rs"],
    deps = [
        ":prng_traits",
        ":zk_traits",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:merlin",
        "@crate_index//:rand",
        "@crate_index//:sha3",
        "@crate_index//:thiserror",
        "//ffi_utils:status",
        "//willow/proto/zk:proofs_rust_proto",
    ],
)

rust_test(
    name = "zk_linear_innerproduct_test",
    crate = ":zk_linear_innerproduct",
    deps = [
        "@crate_index//:googletest",
        "//ffi_utils:status_matchers_rs",
    ],
)

rust_library(
    name = "linear_ip_serialization",
    srcs = ["linear_ip_serialization.rs"],
    deps = [
        ":zk_linear_innerproduct",
        ":zk_traits",
        "@protobuf//rust:protobuf",
        "@crate_index//:curve25519-dalek",
        "//ffi_utils:status",
        "//willow/proto/zk:proofs_rust_proto",
    ],
)

rust_test(
    name = "linear_ip_serialization_test",
    crate = ":linear_ip_serialization",
    deps = [
        ":zk_linear_innerproduct",
        ":zk_traits",
        "@crate_index//:googletest",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:merlin",
        "@crate_index//:rand",
    ],
)

# RLWE relation zero-knowledge proof.
rust_library(
    name = "zk_rlwe_relation",
    srcs = ["zk_rlwe_relation.rs"],
    visibility = ["//visibility:private"],
    deps = [
        ":zk_linear_innerproduct",
        ":zk_traits",
        "@protobuf//rust:protobuf",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:merlin",
        "@crate_index//:rand",
        "//ffi_utils:status",
        "//shell_wrapper:shell_types",
        "//willow/proto/zk:proofs_rust_proto",
    ],
)

rust_test(
    name = "zk_rlwe_relation_test",
    crate = ":zk_rlwe_relation",
    deps = [
        ":shell_ahe",
        "@crate_index//:googletest",
        "@crate_index//:sha3",
        "//ffi_utils:status_matchers_rs",
        "//shell_wrapper:ahe",
        "//shell_wrapper:ahe_cxx",  # fixdeps: keep
        "//shell_wrapper:single_thread_hkdf",
        "//shell_wrapper:single_thread_hkdf_cxx",
        "//willow/testing_utils:shell_testing_parameters",
    ],
)

rust_library(
    name = "rlwe_relation_serialization",
    srcs = ["rlwe_relation_serialization.rs"],
    deps = [
        ":linear_ip_serialization",
        ":zk_linear_innerproduct",
        ":zk_rlwe_relation",
        "@protobuf//rust:protobuf",
        "@crate_index//:curve25519-dalek",
        "//ffi_utils:status",
        "//willow/proto/zk:proofs_rust_proto",
    ],
)

rust_test(
    name = "rlwe_relation_serialization_test",
    crate = ":rlwe_relation_serialization",
    deps = [
        ":rlwe_relation_serialization",
        ":shell_ahe",
        ":zk_traits",
        "@crate_index//:googletest",
        "@protobuf//rust:protobuf",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:merlin",
        "@crate_index//:sha3",
        "//ffi_utils:status_matchers_rs",
        "//shell_wrapper:ahe",
        "//shell_wrapper:ahe_cxx",
        "//shell_wrapper:shell_types",
        "//shell_wrapper:single_thread_hkdf",
        "//shell_wrapper:single_thread_hkdf_cxx",
        "//willow/proto/zk:proofs_rust_proto",
        "//willow/testing_utils:shell_testing_parameters",
    ],
)
