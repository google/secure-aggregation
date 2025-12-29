# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

package(
    default_applicable_licenses = [
    ],
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "codec",
    srcs = [
        "codec_factory.cc",
    ],
    hdrs = [
        "codec.h",
        "codec_factory.h",
    ],
    deps = [
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/memory",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "//willow/proto/willow:input_spec_cc_proto",
    ],
)

cc_test(
    name = "explicit_codec_test",
    srcs = ["explicit_codec_test.cc"],
    deps = [
        ":codec",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/status",
        "//shell_wrapper:status_matchers",
        "//willow/proto/willow:input_spec_cc_proto",
    ],
)
