// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "willow/src/api/server_accumulator.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "include/cxx.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/server_accumulator.pb.h"
#include "willow/src/api/server_accumulator.rs.h"

namespace secure_aggregation {

absl::StatusOr<std::unique_ptr<WillowShellServerAccumulator>>
WillowShellServerAccumulator::Create(
    const willow::AggregationConfigProto& aggregation_config) {
  secure_aggregation::ServerAccumulator* out;
  std::unique_ptr<std::string> status_message;
  int status_code =
      secure_aggregation::NewServerAccumulatorFromSerializedConfig(
          std::make_unique<std::string>(aggregation_config.SerializeAsString()),
          &out, &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }
  return absl::WrapUnique(new WillowShellServerAccumulator(IntoBox(out)));
}

absl::StatusOr<std::unique_ptr<WillowShellServerAccumulator>>
WillowShellServerAccumulator::CreateFromSerializedState(
    std::string serialized_state) {
  secure_aggregation::ServerAccumulator* out;
  std::unique_ptr<std::string> status_message;
  int status_code = secure_aggregation::NewServerAccumulatorFromSerializedState(
      std::make_unique<std::string>(std::move(serialized_state)), &out,
      &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }
  return absl::WrapUnique(new WillowShellServerAccumulator(IntoBox(out)));
}

absl::Status WillowShellServerAccumulator::ProcessClientMessages(
    willow::ClientMessageRange client_messages) {
  auto serialized_client_messages = client_messages.SerializeAsString();
  client_messages.Clear();
  return ProcessClientMessages(std::move(serialized_client_messages));
}

absl::Status WillowShellServerAccumulator::ProcessClientMessages(
    std::string serialized_client_messages) {
  std::unique_ptr<std::string> status_message;
  int status_code = accumulator_->ProcessClientMessages(
      std::make_unique<std::string>(std::move(serialized_client_messages)),
      &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }
  return absl::OkStatus();
}

absl::Status WillowShellServerAccumulator::Merge(
    std::unique_ptr<WillowShellServerAccumulator> other) {
  std::unique_ptr<std::string> status_message;
  int status_code =
      accumulator_->Merge(std::move(other->accumulator_), &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> WillowShellServerAccumulator::ToSerializedState() {
  rust::Vec<uint8_t> serialized_state;
  std::unique_ptr<std::string> status_message;
  int status_code =
      accumulator_->ToSerializedState(&serialized_state, &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }
  return std::string(reinterpret_cast<const char*>(serialized_state.data()),
                     serialized_state.size());
}

}  // namespace secure_aggregation