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
    default_visibility = ["//:internal"],
)

rust_library(
    name = "linear_innerproduct",
    srcs = ["linear_ip.rs"],
    deps = [
        "@crate_index//:curve25519-dalek",
        "@crate_index//:merlin",
        "@crate_index//:rand",
        "@crate_index//:sha3",
        "@crate_index//:thiserror",
        "//ffi_utils:status",
        "//willow/src/traits:prng_traits",
        "//willow/src/traits:zk_traits",
    ],
)

rust_test(
    name = "linear_innerproduct_test",
    crate = ":linear_innerproduct",
    deps = [
        "@crate_index//:googletest",
        "//ffi_utils:status_matchers_rs",
    ],
)

rust_library(
    name = "linear_ip_serialization",
    srcs = ["linear_ip_serialization.rs"],
    deps = [
        ":linear_innerproduct",
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
        ":linear_innerproduct",
        "@crate_index//:googletest",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:merlin",
        "@crate_index//:rand",
        "//willow/src/traits:zk_traits",
    ],
)

# quadratic inner product zero-knowledge proof.
rust_library(
    name = "quadratic_innerproduct",
    testonly = 1,
    srcs = ["quadratic_ip.rs"],
    deps = [
        "@crate_index//:curve25519-dalek",
        "@crate_index//:merlin",
        "@crate_index//:rand",
        "@crate_index//:sha3",
        "@crate_index//:thiserror",
        "//ffi_utils:status",
        "//willow/src/traits:prng_traits",
        "//willow/src/traits:zk_traits",
    ],
)

rust_test(
    name = "quadratic_innerproduct_test",
    crate = ":quadratic_innerproduct",
    deps = [
        "@crate_index//:googletest",
        "//ffi_utils:status_matchers_rs",
    ],
)

# RLWE relation zero-knowledge proof.
rust_library(
    name = "rlwe_relation",
    srcs = ["rlwe_relation.rs"],
    deps = [
        ":linear_innerproduct",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:merlin",
        "@crate_index//:rand",
        "//ffi_utils:status",
        "//shell_wrapper:shell_types",
        "//willow/src/traits:zk_traits",
    ],
)

rust_test(
    name = "rlwe_relation_test",
    crate = ":rlwe_relation",
    deps = [
        "@crate_index//:googletest",
        "@crate_index//:sha3",
        "//ffi_utils:status_matchers_rs",
        "//shell_wrapper:ahe",
        "//shell_wrapper:ahe_cxx",  # fixdeps: keep
        "//shell_wrapper:single_thread_hkdf",
        "//shell_wrapper:single_thread_hkdf_cxx",
        "//willow/src/shell:ahe_shell",
        "//willow/src/testing_utils:shell_testing_parameters",
    ],
)

rust_library(
    name = "rlwe_relation_serialization",
    srcs = ["rlwe_relation_serialization.rs"],
    deps = [
        ":linear_innerproduct",
        ":linear_ip_serialization",
        ":rlwe_relation",
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
        "@crate_index//:googletest",
        "@protobuf//rust:protobuf",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:merlin",
        "@crate_index//:sha3",
        "//ffi_utils:status_matchers_rs",
        "//shell_wrapper:ahe",
        "//shell_wrapper:ahe_cxx",  # fixdeps: keep
        "//shell_wrapper:shell_types",
        "//shell_wrapper:single_thread_hkdf",
        "//shell_wrapper:single_thread_hkdf_cxx",
        "//willow/proto/zk:proofs_rust_proto",
        "//willow/src/shell:ahe_shell",
        "//willow/src/testing_utils:shell_testing_parameters",
        "//willow/src/traits:zk_traits",
    ],
)
