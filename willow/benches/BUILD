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
        "//willow/api:aggregation_config",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:single_thread_hkdf",
        "//willow/crypto:vahe_traits",
        "//willow/protocol:accumulator_traits",
        "//willow/protocol:client_traits",
        "//willow/protocol:messages",
        "//willow/protocol:verifier_traits",
        "//willow/protocol:willow_v1_accumulator",
        "//willow/protocol:willow_v1_client",
        "//willow/protocol:willow_v1_decryptor",
        "//willow/protocol:willow_v1_single_decryptor",
        "//willow/protocol:willow_v1_verifier",
        "//willow/testing_utils",
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
