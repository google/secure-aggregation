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
        "//shell_wrapper:ahe",
        "//shell_wrapper:ahe_cxx",  # fixdeps: keep
        "//shell_wrapper:shell_types",
        "//shell_wrapper:status",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:prng_traits",
    ],
)

rust_test(
    name = "ahe_shell_test",
    crate = ":ahe_shell",
    deps = [
        ":ahe_shell",
        ":single_thread_hkdf",
        "@crate_index//:googletest",
        "//shell_wrapper:status",
        "//shell_wrapper:status_matchers_rs",
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
        "//shell_wrapper:kahe",
        "//shell_wrapper:shell_types",
        "//shell_wrapper:status",
        "//willow/src/traits:kahe_traits",
        "//willow/src/traits:prng_traits",
    ],
)

rust_test(
    name = "kahe_shell_test",
    crate = ":kahe_shell",
    deps = [
        ":kahe_shell",
        "@crate_index//:googletest",
        "//shell_wrapper:kahe",
        "//shell_wrapper:status",
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
        "//shell_wrapper:kahe",
        "//shell_wrapper:status",
        "//willow/src/api:willow_api_common",
    ],
)

# Utilities for parameters proto (e.g. conversion between rust structs and protos)
rust_library(
    name = "shell_parameters_utils",
    srcs = ["parameters_utils.rs"],
    crate_root = "parameters_utils.rs",
    deps = [
        ":kahe_shell",
        "@protobuf//rust:protobuf",
        "//shell_wrapper:kahe",
        "//shell_wrapper:status",
        "//willow/proto/shell:shell_parameters_rust_proto",
    ],
)

rust_test(
    name = "shell_parameters_utils_test",
    crate = ":shell_parameters_utils",
    deps = [
        ":shell_parameters_utils",
        "@crate_index//:googletest",
        "@protobuf//rust:protobuf_gtest_matchers",
        "//shell_wrapper:status",
    ],
)

# Parameter generation
rust_library(
    name = "shell_parameters_generation",
    srcs = ["parameters_generation.rs"],
    crate_root = "parameters_generation.rs",
    deps = [
        ":kahe_shell",
        "//shell_wrapper:kahe",
        "//shell_wrapper:status",
        "//willow/src/api:willow_api_common",
    ],
)

rust_test(
    name = "shell_parameters_generation_test",
    crate = ":shell_parameters_generation",
    deps = [
        ":shell_parameters_generation",
        "@crate_index//:googletest",
        "@protobuf//rust:protobuf_gtest_matchers",
        "//shell_wrapper:status",
    ],
)

# PRNG
rust_library(
    name = "single_thread_hkdf",
    srcs = [
        "single_thread_hkdf.rs",
    ],
    deps = [
        "//shell_wrapper:single_thread_hkdf",
        "//shell_wrapper:single_thread_hkdf_cxx",  # fixdeps: keep
        "//shell_wrapper:status",
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
        "@crate_index//:merlin",
        "//shell_wrapper:ahe",
        "//shell_wrapper:ahe_cxx",  # fixdeps: keep
        "//shell_wrapper:shell_types",
        "//shell_wrapper:status",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:vahe_traits",
        "//willow/src/traits:zk_traits",
        "//willow/src/zk:rlwe_relation",
    ],
)

rust_test(
    name = "vahe_shell_test",
    crate = ":vahe_shell",
    deps = [
        ":vahe_shell",
        "@crate_index//:googletest",
        "@crate_index//:merlin",
        "//shell_wrapper:status",
        "//willow/src/testing_utils",
        "//willow/src/testing_utils:shell_testing_parameters",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:prng_traits",
        "//willow/src/traits:vahe_traits",
        "//willow/src/traits:zk_traits",
        "//willow/src/zk:rlwe_relation",
    ],
)
