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
)

cc_library(
    name = "willow_explicit_encoder",
    srcs = ["willow_explicit_encoder.cc"],
    hdrs = [
        "willow_encoder_factory.h",
        "willow_explicit_encoder.h",
    ],
    deps = [
        "@abseil-cpp//absl/memory",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "//willow/proto/willow:input_spec_cc_proto",
    ],
)

cc_test(
    name = "willow_explicit_encoder_test",
    srcs = ["willow_explicit_encoder_test.cc"],
    deps = [
        ":willow_explicit_encoder",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/status",
        "//willow/proto/willow:input_spec_cc_proto",
    ],
)
