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

# Integration tests for Willow with SHELL instantiation.
rust_test(
    name = "e2e_shell",
    srcs = [
        "e2e_shell.rs",
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
        "//willow/protocol:coordinator",
        "//willow/protocol:decryptor",
        "//willow/protocol:default_accumulator",
        "//willow/protocol:default_client",
        "//willow/protocol:default_verifier",
        "//willow/protocol:messages",
        "//willow/protocol:single_decryptor",
        "//willow/protocol:verifier_traits",
        "//willow/testing_utils",
        "//willow/testing_utils:shell_testing_parameters",
    ],
)
