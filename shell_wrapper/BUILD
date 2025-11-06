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

rust_library(
    name = "status",
    srcs = ["status.rs"],
    deps = [
        ":status_cc",
        ":status_cxx",  # fixdeps: keep
        "@cxx.rs//:cxx",
    ],
)

rust_cxx_bridge(
    name = "status_cxx",
    src = "status.rs",
    deps = [":status_cc"],
)

rust_test(
    name = "status_test",
    crate = ":status",
    deps = [
        "@crate_index//:googletest",
    ],
)

cc_library(
    name = "status_cc",
    srcs = ["status.cc"],
    hdrs = ["status.h"],
    deps = [
        ":status_cxx/include",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings:string_view",
        "@cxx.rs//:cxx",  # fixdeps: keep
        "@cxx.rs//:core",
    ],
)

rust_library(
    name = "status_matchers_rs",
    testonly = 1,
    srcs = ["status_matchers.rs"],
    deps = [
        ":status",
        "@crate_index//:googletest",
    ],
)

# Shared functionality
cc_library(
    name = "shell_types_cc",
    srcs = ["shell_types.cc"],
    hdrs = [
        "shell_aliases.h",
        "shell_types.h",
    ],
    deps = [
        ":shell_types_cxx/include",
        ":status_cc",
        ":status_cxx",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/numeric:int128",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/types:span",
        "@shell-encryption//shell_encryption:int256",
        "@shell-encryption//shell_encryption:integral_types",
        "@shell-encryption//shell_encryption:montgomery",
        "@shell-encryption//shell_encryption/prng:single_thread_hkdf_prng",
        "@shell-encryption//shell_encryption/rns:crt_interpolation",
        "@shell-encryption//shell_encryption/rns:rns_context",
        "@shell-encryption//shell_encryption/rns:rns_integer",
        "@shell-encryption//shell_encryption/rns:rns_modulus",
        "@shell-encryption//shell_encryption/rns:rns_polynomial",
        "@cxx.rs//:core",
    ],
)

cc_test(
    name = "shell_types_test",
    srcs = ["shell_types_test.cc"],
    deps = [
        ":kahe_cc",
        ":kahe_cxx/include",
        ":shell_types_cc",
        ":shell_types_cxx",
        ":single_thread_hkdf_cc",
        ":status_cc",
        ":status_cxx",
        ":status_matchers",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/algorithm:container",
        "@abseil-cpp//absl/numeric:int128",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/types:span",
        "@shell-encryption//shell_encryption/rns:error_distribution",
        "@shell-encryption//shell_encryption/rns:rns_modulus",
        "@shell-encryption//shell_encryption/sampler:discrete_gaussian",
        "@shell-encryption//shell_encryption/testing:testing_prng",
        "@cxx.rs//:core",
    ],
)

rust_library(
    name = "shell_types",
    srcs = ["shell_types.rs"],
    deps = [
        ":shell_types_cc",
        ":status",
        "@cxx.rs//:cxx",
    ],
)

rust_cxx_bridge(
    name = "shell_types_cxx",
    src = "shell_types.rs",
    deps = [":shell_types_cc"],
)

cc_library(
    name = "testing_utils",
    testonly = 1,
    hdrs = ["testing_utils.h"],
    deps = [
        "@abseil-cpp//absl/numeric:int128",
        "@abseil-cpp//absl/random",
        "@shell-encryption//shell_encryption:int256",
    ],
)

# KAHE
rust_cxx_bridge(
    name = "kahe_cxx",
    src = "kahe.rs",
    deps = [
        ":kahe_cc",
        ":shell_types_cc",
    ],
)

cc_library(
    name = "kahe_cc",
    srcs = ["kahe.cc"],
    hdrs = ["kahe.h"],
    deps = [
        ":kahe_cxx/include",
        ":shell_types_cc",
        ":shell_types_cxx/include",
        ":single_thread_hkdf_cc",
        ":single_thread_hkdf_cxx",
        ":status_cc",
        ":status_cxx",
        ":status_macros",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/types:span",
        "@shell-encryption//shell_encryption/rns:coefficient_encoder",
        "@shell-encryption//shell_encryption/rns:crt_interpolation",
        "@shell-encryption//shell_encryption/rns:error_distribution",
        "@shell-encryption//shell_encryption/rns:message_packing",
        "@shell-encryption//shell_encryption/rns:rns_modulus",
        "@shell-encryption//shell_encryption/sampler:discrete_gaussian",
        "@cxx.rs//:core",
    ],
)

cc_test(
    name = "kahe_test",
    srcs = ["kahe_test.cc"],
    deps = [
        ":kahe_cc",
        ":kahe_cxx/include",
        ":shell_types_cc",
        ":shell_types_cxx/include",
        ":single_thread_hkdf_cc",
        ":single_thread_hkdf_cxx/include",
        ":status_cc",
        ":status_cxx",
        ":status_matchers",
        ":testing_utils",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/types:span",
        "@shell-encryption//shell_encryption/rns:error_distribution",
        "@shell-encryption//shell_encryption/rns:message_packing",
        "@shell-encryption//shell_encryption/rns/testing:testing_utils",
        "@shell-encryption//shell_encryption/sampler:discrete_gaussian",
        "@cxx.rs//:core",
    ],
)

rust_library(
    name = "kahe",
    srcs = ["kahe.rs"],
    deps = [
        ":kahe_cc",
        ":kahe_cxx",  # fixdeps: keep
        ":shell_types",
        ":shell_types_cxx",  # fixdeps: keep
        ":single_thread_hkdf",
        ":status",
        "@cxx.rs//:cxx",
    ],
)

rust_test(
    name = "kahe_test_rs",
    srcs = ["kahe_test.rs"],
    deps = [
        ":kahe",
        ":single_thread_hkdf",
        ":single_thread_hkdf_cxx",  # fixdeps: keep
        ":status",
        ":status_matchers_rs",
        "@crate_index//:googletest",
        "@crate_index//:rand",
    ],
)

# AHE
cc_library(
    name = "ahe_cc",
    srcs = ["ahe.cc"],
    hdrs = [
        "ahe.h",
        "ahe_aliases.h",
    ],
    deps = [
        ":ahe_cxx/include",
        ":shell_types_cc",
        ":shell_types_cxx/include",
        ":single_thread_hkdf_cc",
        ":status_macros",
        "@abseil-cpp//absl/numeric:int128",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:span",
        "@shell-encryption//shell_encryption:int256",
        "@shell-encryption//shell_encryption/multi_party:public_key",
        "@shell-encryption//shell_encryption/multi_party:public_key_share",
        "@shell-encryption//shell_encryption/multi_party:public_parameter",
        "@shell-encryption//shell_encryption/multi_party:recovery",
        "@shell-encryption//shell_encryption/multi_party:secret_key_share",
        "@shell-encryption//shell_encryption/rns:coefficient_encoder",
        "@shell-encryption//shell_encryption/rns:crt_interpolation",
        "@shell-encryption//shell_encryption/rns:rns_error_params",
        "@shell-encryption//shell_encryption/rns:rns_modulus",
        "@shell-encryption//shell_encryption/rns:rns_polynomial",
        "@shell-encryption//shell_encryption/sampler:discrete_gaussian",
        "@cxx.rs//:core",
    ],
)

rust_cxx_bridge(
    name = "ahe_cxx",
    src = "ahe.rs",
    deps = [
        ":ahe_cc",
        ":shell_types_cc",
        ":single_thread_hkdf_cc",
    ],
)

cc_test(
    name = "ahe_test",
    srcs = ["ahe_test.cc"],
    deps = [
        ":ahe_cc",
        ":ahe_cxx",
        ":shell_types_cc",
        ":shell_types_cxx",
        ":single_thread_hkdf_cc",
        ":single_thread_hkdf_cxx",  # fixdeps: keep
        ":status_cc",
        ":status_matchers",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/strings:string_view",
        "@shell-encryption//shell_encryption/rns/testing:testing_utils",
    ],
)

rust_library(
    name = "ahe",
    srcs = ["ahe.rs"],
    deps = [
        ":ahe_cc",
        ":ahe_cxx",  # fixdeps: keep
        ":shell_types",
        ":shell_types_cxx",  # fixdeps: keep
        ":single_thread_hkdf",
        ":status",
        "@cxx.rs//:cxx",
        "@cxx.rs//:core",
    ],
)

rust_test(
    name = "ahe_test_rs",
    srcs = ["ahe_test.rs"],
    deps = [
        ":ahe",
        ":ahe_cxx",  # fixdeps: keep
        ":shell_types",
        ":shell_types_cxx",  # fixdeps: keep
        ":single_thread_hkdf",
        ":single_thread_hkdf_cxx",  # fixdeps: keep
        ":status",
        ":status_matchers_rs",
        "@crate_index//:googletest",
        "@crate_index//:rand",
    ],
)

# PRNG
cc_library(
    name = "single_thread_hkdf_cc",
    srcs = ["single_thread_hkdf.cc"],
    hdrs = ["single_thread_hkdf.h"],
    deps = [
        ":shell_types_cc",
        ":single_thread_hkdf_cxx/include",
        ":status_cxx",
        ":status_macros",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings:string_view",
        "@shell-encryption//shell_encryption/prng:single_thread_hkdf_prng",
        "@cxx.rs//:core",
        "@tink_cc//tink/subtle",
    ],
)

rust_cxx_bridge(
    name = "single_thread_hkdf_cxx",
    src = "single_thread_hkdf.rs",
    deps = [
        ":shell_types_cc",
        ":shell_types_cxx",
        ":single_thread_hkdf_cc",
        "@shell-encryption//shell_encryption/prng:single_thread_hkdf_prng",
    ],
)

rust_library(
    name = "single_thread_hkdf",
    srcs = ["single_thread_hkdf.rs"],
    deps = [
        ":shell_types",
        ":status",
        "@cxx.rs//:cxx",
    ],
)

cc_library(
    name = "status_macros",
    hdrs = ["status_macros.h"],
)

cc_library(
    name = "status_matchers",
    testonly = 1,
    srcs = ["status_matchers.cc"],
    hdrs = ["status_matchers.h"],
    deps = [
        ":status_macros",
        "@googletest//:gtest",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
    ],
)
