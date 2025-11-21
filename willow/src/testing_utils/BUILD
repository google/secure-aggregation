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

# PRNG
rust_library(
    name = "fake_prng",
    testonly = 1,
    srcs = [
        "fake_prng.rs",
    ],
    deps = [
        "//shell_wrapper:status",
        "//willow/src/traits:prng_traits",
    ],
)

rust_test(
    name = "fake_prng_test",
    crate = ":fake_prng",
    deps = [
        "@crate_index//:googletest",
    ],
)

# Configuration builder and default testing_parameters for AHE and KAHE.
rust_library(
    name = "shell_testing_parameters",
    testonly = 1,
    srcs = ["shell_testing_parameters.rs"],
    deps = [
        "//shell_wrapper:kahe",
        "//shell_wrapper:status",
        "//willow/src/api:willow_api_common",
        "//willow/src/shell:ahe_shell",
        "//willow/src/shell:kahe_shell",
        "//willow/src/shell:shell_parameters_generation",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:kahe_traits",
    ],
)

# Testing utilities.
rust_library(
    name = "testing_utils",
    testonly = 1,
    srcs = [
        "testing_utils.rs",
    ],
    deps = [
        ":shell_testing_parameters",
        "@crate_index//:rand",
        "//shell_wrapper:status",
        "//willow/src/api:willow_api_common",
        "//willow/src/shell:kahe_shell",
        "//willow/src/shell:single_thread_hkdf",
        "//willow/src/shell:vahe_shell",
        "//willow/src/traits:ahe_traits",
        "//willow/src/traits:kahe_traits",
        "//willow/src/traits:messages",
        "//willow/src/traits:prng_traits",
        "//willow/src/traits:vahe_traits",
        "//willow/src/willow_v1:willow_v1_client",
    ],
)

rust_test(
    name = "testing_utils_test",
    crate = ":testing_utils",
    deps = [
        "@crate_index//:googletest",
    ],
)
