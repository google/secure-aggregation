# Copyright 2026 Google LLC
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

load("@cxx.rs//tools/bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_applicable_licenses = [
    ],
    default_visibility = ["//:internal"],
)

cc_library(
    name = "cxx_utils",
    hdrs = ["cxx_utils.h"],
    deps = [
        "@abseil-cpp//absl/strings:string_view",
        "@cxx.rs//:core",
    ],
)

rust_library(
    name = "status",
    srcs = ["status.rs"],
    deps = [
        ":status_cc",
        ":status_cxx",  # fixdeps: keep
        "@cxx.rs//:cxx",
    ],
)

rust_cxx_bridge(
    name = "status_cxx",
    src = "status.rs",
    deps = [
        ":status_cc",
        "@abseil-cpp//absl/status",
    ],
)

rust_test(
    name = "status_test",
    crate = ":status",
    deps = [
        "@crate_index//:googletest",
    ],
)

cc_library(
    name = "status_cc",
    srcs = ["status.cc"],
    hdrs = ["status.h"],
    deps = [
        ":cxx_utils",
        ":status_cxx/include",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings:string_view",
        "@cxx.rs//:cxx",  # fixdeps: keep
        "@cxx.rs//:core",
    ],
)

cc_library(
    name = "status_macros",
    hdrs = ["status_macros.h"],
)

cc_library(
    name = "status_matchers",
    testonly = 1,
    srcs = ["status_matchers.cc"],
    hdrs = ["status_matchers.h"],
    deps = [
        ":status_macros",
        "@googletest//:gtest",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
    ],
)

rust_library(
    name = "status_matchers_rs",
    testonly = 1,
    srcs = ["status_matchers.rs"],
    deps = [
        ":status",
        "@crate_index//:googletest",
    ],
)
