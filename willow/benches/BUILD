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

load(
    "@rules_rust//rust:defs.bzl",
    "rust_binary",
    "rust_library",
)

package(default_applicable_licenses = [
])

rust_library(
    name = "shell_benchmarks",
    testonly = 1,
    srcs = ["shell_benchmarks.rs"],
    deps = [
        "@crate_index//:clap",
        "//willow/src/api:willow_api_common",
        "//willow/src/shell:kahe_shell",
        "//willow/src/shell:shell_parameters_generation",
        "//willow/src/shell:single_thread_hkdf",
        "//willow/src/shell:vahe_shell",
        "//willow/src/testing_utils",
        "//willow/src/testing_utils:shell_testing_parameters",
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

rust_binary(
    name = "run_shell_benchmark",
    testonly = 1,
    srcs = ["run_shell_benchmark.rs"],
    deps = [
        ":shell_benchmarks",
        "@crate_index//:clap",
    ],
)
