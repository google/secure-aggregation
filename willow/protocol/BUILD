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

# Protocol level message types: Client, Server, Decryptor.
rust_library(
    name = "messages",
    srcs = [
        "messages.rs",
    ],
    deps = [
        "@protobuf//rust:protobuf",
        "//ffi_utils:status",
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:vahe_traits",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "//willow/proto/willow:aggregation_config_rust_proto",
        "//willow/proto/willow:messages_rust_proto",
        "//willow/proto/zk:proofs_rust_proto",
    ],
)

# Protocol level traits
rust_library(
    name = "client_traits",
    srcs = [
        "client_traits.rs",
    ],
    deps = [
        ":messages",
        "//ffi_utils:status",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:vahe_traits",
    ],
)

rust_library(
    name = "accumulator_traits",
    srcs = [
        "accumulator_traits.rs",
    ],
    deps = [
        ":messages",
        "//ffi_utils:status",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:vahe_traits",
    ],
)

rust_library(
    name = "verifier_traits",
    srcs = [
        "verifier_traits.rs",
    ],
    deps = [
        ":messages",
        "//ffi_utils:status",
        "//willow/crypto:vahe_traits",
    ],
)

# Protocol level implementations using Shell
rust_library(
    name = "willow_v1_client",
    srcs = [
        "willow_v1_client.rs",
    ],
    deps = [
        ":client_traits",
        ":messages",
        "//ffi_utils:status",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:vahe_traits",
    ],
)

rust_test(
    name = "willow_v1_client_test",
    crate = ":willow_v1_client",
    deps = [
        "@crate_index//:googletest",
        "//willow/api:aggregation_config",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/testing_utils",
        "//willow/testing_utils:shell_testing_decryptor",
        "//willow/testing_utils:shell_testing_parameters",
    ],
)

rust_test(
    name = "willow_v1_decryptor_test",
    crate = ":willow_v1_decryptor",
    deps = [
        ":messages",
        "@crate_index//:googletest",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:single_thread_hkdf",
        "//willow/crypto:vahe_traits",
        "//willow/testing_utils",
    ],
)

rust_library(
    name = "willow_v1_decryptor",
    srcs = [
        "willow_v1_decryptor.rs",
    ],
    deps = [
        ":messages",
        "@protobuf//rust:protobuf",
        "//ffi_utils:status",
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:vahe_traits",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "//willow/proto/willow:messages_rust_proto",
    ],
)

rust_test(
    name = "willow_v1_accumulator_test",
    crate = ":willow_v1_accumulator",
    deps = [
        ":accumulator_traits",
        ":client_traits",
        ":verifier_traits",
        ":willow_v1_client",
        ":willow_v1_decryptor",
        ":willow_v1_verifier",
        "@crate_index//:googletest",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:single_thread_hkdf",
        "//willow/testing_utils",
        "//willow/testing_utils:shell_testing_parameters",
    ],
)

rust_library(
    name = "willow_v1_accumulator",
    srcs = [
        "willow_v1_accumulator.rs",
    ],
    deps = [
        ":accumulator_traits",
        ":messages",
        "@protobuf//rust:protobuf",
        "//ffi_utils:status",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:vahe_traits",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "//willow/proto/willow:messages_rust_proto",
    ],
)

rust_library(
    name = "willow_v1_verifier",
    srcs = [
        "willow_v1_verifier.rs",
    ],
    deps = [
        ":messages",
        ":verifier_traits",
        "@protobuf//rust:protobuf",
        "//ffi_utils:status",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:vahe_traits",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "//willow/proto/willow:messages_rust_proto",
    ],
)

rust_test(
    name = "willow_v1_verifier_test",
    crate = ":willow_v1_verifier",
    deps = [
        ":accumulator_traits",
        ":client_traits",
        ":willow_v1_accumulator",
        ":willow_v1_client",
        ":willow_v1_decryptor",
        "@crate_index//:googletest",
        "//ffi_utils:status_matchers_rs",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:single_thread_hkdf",
        "//willow/crypto:vahe_traits",
        "//willow/testing_utils",
        "//willow/testing_utils:shell_testing_parameters",
    ],
)

# Multi-decryptor coordinator implementation.
rust_library(
    name = "willow_v1_coordinator",
    srcs = [
        "willow_v1_coordinator.rs",
    ],
    deps = [
        ":messages",
        "//ffi_utils:status",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:vahe_traits",
    ],
)

rust_test(
    name = "willow_v1_coordinator_test",
    crate = ":willow_v1_coordinator",
    deps = [
        ":messages",
        ":willow_v1_decryptor",
        "@crate_index//:googletest",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:single_thread_hkdf",
        "//willow/crypto:vahe_traits",
    ],
)
