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

load("@rules_python//python:defs.bzl", pytype_strict_contrib_test = "py_test")
load("@pybind11_bazel//:build_defs.bzl", pytype_pybind_extension = "pybind_extension")
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

package(
    default_applicable_licenses = [
    ],
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "time_utils",
    srcs = [
        "time_utils.cc",
    ],
    hdrs = [
        "time_utils.h",
    ],
    deps = [
        "@protobuf//:duration_cc_proto",
        "@protobuf//:timestamp_cc_proto",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "//willow/proto/willow:input_spec_cc_proto",
    ],
)

cc_library(
    name = "codec",
    srcs = [
        "codec.cc",
    ],
    hdrs = [
        "codec.h",
        "codec_factory.h",
    ],
    deps = [
        ":time_utils",
        "@abseil-cpp//absl/container:btree",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/memory",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "//ffi_utils:status_macros",
        "//willow/proto/willow:input_spec_cc_proto",
    ],
)

cc_test(
    name = "codec_test",
    srcs = ["codec_test.cc"],
    deps = [
        ":codec",
        ":time_utils",
        "@protobuf//:duration_cc_proto",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/time",
        "//ffi_utils:status_matchers",
        "//willow/proto/willow:input_spec_cc_proto",
        "//willow/testing_utils:testing_utils_cc",
    ],
)

cc_test(
    name = "time_utils_test",
    srcs = ["time_utils_test.cc"],
    deps = [
        ":time_utils",
        "@protobuf//:duration_cc_proto",
        "@protobuf//:timestamp_cc_proto",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/time",
        "//ffi_utils:status_matchers",
        "//willow/proto/willow:input_spec_cc_proto",
    ],
)

pytype_pybind_extension(
    name = "codec_bindings",
    srcs = ["codec_bindings.cc"],
    deps = [
        ":codec",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/time",
        "@pybind11_abseil//pybind11_abseil:status_casters",
        "//willow/proto/willow:input_spec_cc_proto",
    ],
)

pytype_strict_contrib_test(
    name = "codec_bindings_test",
    srcs = ["codec_bindings_test.py"],
    deps = [
        ":codec_bindings",
        "@pybind11_abseil//pybind11_abseil:status",
        "//willow/proto/willow:input_spec_py_pb2",
    ],
)
