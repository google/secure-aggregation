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

# TODO(itester): Consider hiding the micro_rpc targets from open source.
# Same as in https://source.corp.google.com/piper///depot/google3/third_party/fcp/protos/confidentialcompute/BUILD

load("//net/grpc:cc_grpc_library.bzl", "cc_grpc_library")
load("//net/proto2/compiler/stubby/cc:cc_stubby_library.bzl", "cc_stubby_library")
load("//security/oak/micro_rpc/codegen/build_defs:micro_rpc.bzl", "cc_micro_rpc_library")  # fcp:google-only(internal use only)
load("@protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
load("@protobuf//bazel:proto_library.bzl", "proto_library")
load("@protobuf//rust:defs.bzl", "rust_proto_library")

package(
    default_visibility = ["//visibility:public"],
)

proto_library(
    name = "aggregation_config_proto",
    srcs = ["aggregation_config.proto"],
    deps = [
        "//willow/proto/shell:shell_ciphertexts_proto",
        "//willow/proto/zk:proofs_proto",
    ],
)

cc_proto_library(
    name = "aggregation_config_cc_proto",
    deps = [":aggregation_config_proto"],
)

rust_proto_library(
    name = "aggregation_config_rust_proto",
    deps = [":aggregation_config_proto"],
)

proto_library(
    name = "decryptor_proto",
    srcs = ["decryptor.proto"],
    has_services = True,
    deps = ["//third_party/oak/proto/micro_rpc:options_proto"],
)

cc_proto_library(
    name = "decryptor_cc_proto",
    deps = [":decryptor_proto"],
)

cc_stubby_library(
    name = "decryptor_cc_stubby",
    srcs = [":decryptor_proto"],
    deps = [":decryptor_cc_proto"],
)

cc_grpc_library(
    name = "decryptor_cc_grpc_proto",
    srcs = [":decryptor_proto"],
    deps = [":decryptor_cc_proto"],
)

cc_micro_rpc_library(
    name = "decryptor_cc_micro_proto",
    srcs = [":decryptor_proto"],
    deps = [":decryptor_cc_proto"],
)

proto_library(
    name = "key_proto",
    srcs = ["key.proto"],
)

cc_proto_library(
    name = "key_cc_proto",
    deps = [":key_proto"],
)

proto_library(
    name = "input_spec_proto",
    srcs = ["input_spec.proto"],
)

cc_proto_library(
    name = "input_spec_cc_proto",
    deps = [":input_spec_proto"],
)

proto_library(
    name = "messages_proto",
    srcs = ["messages.proto"],
    deps = [
        "//willow/proto/shell:shell_ciphertexts_proto",
        "//willow/proto/zk:proofs_proto",
    ],
)

cc_proto_library(
    name = "messages_cc_proto",
    deps = [":messages_proto"],
)

rust_proto_library(
    name = "messages_rust_proto",
    deps = [":messages_proto"],
)

proto_library(
    name = "server_accumulator_proto",
    srcs = ["server_accumulator.proto"],
    deps = [
        ":aggregation_config_proto",
        ":messages_proto",
    ],
)

cc_proto_library(
    name = "server_accumulator_cc_proto",
    deps = [":server_accumulator_proto"],
)

rust_proto_library(
    name = "server_accumulator_rust_proto",
    deps = [":server_accumulator_proto"],
)
