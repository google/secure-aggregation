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
        "//shell_wrapper:status",
        "//shell_wrapper:status_matchers_rs",
        "//willow/src/api:willow_api_common",
        "//willow/src/shell:ahe_shell",
        "//willow/src/shell:kahe_shell",
        "//willow/src/shell:parameters_shell",
        "//willow/src/shell:single_thread_hkdf",
        "//willow/src/shell:vahe_shell",
        "//willow/src/testing_utils",
        "//willow/src/testing_utils:shell_testing_parameters",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:client_traits",
        "//willow/src/traits:decryptor_traits",
        "//willow/src/traits:kahe_traits",
        "//willow/src/traits:prng_traits",
        "//willow/src/traits:server_traits",
        "//willow/src/traits:verifier_traits",
        "//willow/src/willow_v1:willow_v1_client",
        "//willow/src/willow_v1:willow_v1_common",
        "//willow/src/willow_v1:willow_v1_decryptor",
        "//willow/src/willow_v1:willow_v1_server",
        "//willow/src/willow_v1:willow_v1_verifier",
    ],
)

# Dummy KAHE test.
rust_library(
    name = "dummy_kahe",
    testonly = 1,
    srcs = ["dummy_kahe.rs"],
    deps = [
        "//shell_wrapper:status",
        "//willow/src/traits:kahe_traits",
    ],
)

rust_test(
    name = "dummy_kahe_test",
    crate = ":dummy_kahe",
    deps = [
        "@crate_index//:googletest",
        "//shell_wrapper:status_matchers",
    ],
)
