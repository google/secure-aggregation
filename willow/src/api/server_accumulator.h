/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SECURE_AGGREGATION_WILLOW_SRC_API_SERVER_ACCUMULATOR_H_
#define SECURE_AGGREGATION_WILLOW_SRC_API_SERVER_ACCUMULATOR_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "include/cxx.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/server_accumulator.pb.h"
#include "willow/src/api/server_accumulator.rs.h"

namespace secure_aggregation {

// Implements an accumulator class intended to be used by a batch processing
// system. Combines both the server and the verifier functionality of willow_v1,
// using SHELL for the underlying cryptography.
class WillowShellServerAccumulator {
 public:
  // Creates a new accumulator with the given aggregation_config and empty
  // state.
  static absl::StatusOr<std::unique_ptr<WillowShellServerAccumulator>> Create(
      const willow::AggregationConfigProto& aggregation_config);

  // Creates a new accumulator from the given serialized state, which must
  // correspond to a serialized ServerAccumulatorState proto.
  static absl::StatusOr<std::unique_ptr<WillowShellServerAccumulator>>
  CreateFromSerializedState(std::string serialized_state);

  // Processes a list of client messages. If an invalid message is encountered,
  // an error is logged and processing continues.
  absl::Status ProcessClientMessages(willow::ClientMessageList client_messages);

  // Processes a list of client messages, given as a serialized
  // ClientMessageList proto.
  absl::Status ProcessClientMessages(std::string serialized_client_messages);

  // Merges the state of `other` into the current accumulator.
  absl::Status Merge(std::unique_ptr<WillowShellServerAccumulator> other);

  // Converts the current state of the accumulator to a serialized
  // ServerAccumulatorState proto.
  absl::StatusOr<std::string> ToSerializedState();

 private:
  explicit WillowShellServerAccumulator(
      rust::Box<secure_aggregation::ServerAccumulator> accumulator)
      : accumulator_(std::move(accumulator)) {}

  rust::Box<secure_aggregation::ServerAccumulator> accumulator_;
};

}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_SRC_API_SERVER_ACCUMULATOR_H_
