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

load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_applicable_licenses = [
    ],
    default_visibility = ["//visibility:public"],
)

# Cryptographic primitives traits: PRNG, AHE, KAHE.

rust_library(
    name = "prng_traits",
    srcs = [
        "prng.rs",
    ],
    deps = [
        "//shell_wrapper:status",
    ],
)

rust_library(
    name = "kahe_traits",
    srcs = [
        "kahe.rs",
    ],
    deps = [
        ":prng_traits",
        "//shell_wrapper:status",
    ],
)

rust_library(
    name = "ahe_traits",
    srcs = [
        "ahe.rs",
    ],
    deps = [
        ":prng_traits",
        "//shell_wrapper:status",
    ],
)

rust_library(
    name = "vahe_traits",
    srcs = [
        "vahe.rs",
    ],
    deps = [
        ":ahe_traits",
        "//shell_wrapper:status",
    ],
)

# Protocol level message types: Client, Server, Decryptor.
rust_library(
    name = "messages",
    srcs = [
        "messages.rs",
    ],
    deps = [
        ":ahe_traits",
        ":kahe_traits",
        ":vahe_traits",
    ],
)

rust_library(
    name = "client_traits",
    srcs = [
        "client.rs",
    ],
    deps = [
        ":kahe_traits",
        ":messages",
        ":vahe_traits",
        "//shell_wrapper:status",
    ],
)

rust_library(
    name = "server_traits",
    srcs = [
        "server.rs",
    ],
    deps = [
        ":kahe_traits",
        ":messages",
        ":vahe_traits",
        "//shell_wrapper:status",
    ],
)

rust_library(
    name = "decryptor_traits",
    srcs = [
        "decryptor.rs",
    ],
    deps = [
        ":messages",
        ":vahe_traits",
        "//shell_wrapper:status",
    ],
)

rust_library(
    name = "verifier_traits",
    srcs = [
        "verifier.rs",
    ],
    deps = [
        ":messages",
        ":vahe_traits",
        "//shell_wrapper:status",
    ],
)

rust_library(
    name = "zk_traits",
    srcs = [
        "zk.rs",
    ],
    deps = [
        ":ahe_traits",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:merlin",
        "//shell_wrapper:shell_types",
        "//shell_wrapper:status",
    ],
)
