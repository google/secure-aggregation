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

load("@rules_rust//rust:defs.bzl", "rust_test")

package(default_applicable_licenses = [
])

# Integration tests for Willow V1 with SHELL instantiation.
rust_test(
    name = "willow_v1_shell",
    srcs = [
        "willow_v1_shell.rs",
    ],
    deps = [
        "@crate_index//:googletest",
        "//ffi_utils:status",
        "//ffi_utils:status_matchers_rs",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_ahe",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:single_thread_hkdf",
        "//willow/crypto:vahe_traits",
        "//willow/protocol:accumulator_traits",
        "//willow/protocol:client_traits",
        "//willow/protocol:decryptor_traits",
        "//willow/protocol:messages",
        "//willow/protocol:verifier_traits",
        "//willow/protocol:willow_v1_accumulator",
        "//willow/protocol:willow_v1_client",
        "//willow/protocol:willow_v1_decryptor",
        "//willow/protocol:willow_v1_verifier",
        "//willow/testing_utils",
        "//willow/testing_utils:shell_testing_parameters",
    ],
)
