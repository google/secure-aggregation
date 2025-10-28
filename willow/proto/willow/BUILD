# Copyright 2021 Google LLC
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

load("@protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
load("@protobuf//bazel:proto_library.bzl", "proto_library")

package(
    default_applicable_licenses = [
    ],
    default_visibility = ["//visibility:public"],
)

proto_library(
    name = "decryptor_proto",
    srcs = ["decryptor.proto"],
)

cc_proto_library(
    name = "decryptor_cc_proto",
    deps = [":decryptor_proto"],
)

proto_library(
    name = "key_proto",
    srcs = ["key.proto"],
)

cc_proto_library(
    name = "key_cc_proto",
    deps = [":key_proto"],
)
