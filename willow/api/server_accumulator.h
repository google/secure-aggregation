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

#ifndef SECURE_AGGREGATION_WILLOW_API_SERVER_ACCUMULATOR_H_
#define SECURE_AGGREGATION_WILLOW_API_SERVER_ACCUMULATOR_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "include/cxx.h"
#include "willow/api/server_accumulator.rs.h"
#include "willow/input_encoding/codec.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/messages.pb.h"
#include "willow/proto/willow/server_accumulator.pb.h"

namespace secure_aggregation {
namespace willow {

// Holds the relevant state from a finalized accumulation, and can decrypt the
// final result using the response from the decryptor service. Only works with
// a single decryptor, or if the response is already the sum of all partial
// decryptions, since it attempts to decrypt after receiving only a single
// partial decryption response.
class FinalResultDecryptor {
 public:
  // Creates a new final result decryptor from the given serialized
  // state, likely coming from a FinalizedAccumulatorResult.
  static absl::StatusOr<std::unique_ptr<FinalResultDecryptor>>
  CreateFromSerialized(std::string final_result_decryptor_state);

  // Decrypts final result using the given partial decryption
  // response.
  absl::StatusOr<EncodedData> Decrypt(
      std::string serialized_partial_decryption_response);

 private:
  explicit FinalResultDecryptor(
      rust::Box<secure_aggregation::FinalResultDecryptor>
          aggregated_ciphertexts)
      : aggregated_ciphertexts_(std::move(aggregated_ciphertexts)) {}

  rust::Box<secure_aggregation::FinalResultDecryptor> aggregated_ciphertexts_;
};

// Implements an accumulator class intended to be used by a batch processing
// system. Combines both the server and the verifier functionality of willow_v1,
// using SHELL for the underlying cryptography.
class ServerAccumulator {
 public:
  // Creates a new accumulator with the given aggregation_config and empty
  // state.
  static absl::StatusOr<std::unique_ptr<ServerAccumulator>> Create(
      const AggregationConfigProto& aggregation_config);

  // Creates a new accumulator from the given serialized state, which must
  // correspond to a serialized ServerAccumulatorState proto.
  static absl::StatusOr<std::unique_ptr<ServerAccumulator>>
  CreateFromSerializedState(std::string serialized_state);

  // Processes a list of client messages. If an invalid message is encountered,
  // an error is logged and processing continues.
  absl::Status ProcessClientMessages(ClientMessageRange client_messages);

  // Processes a list of client messages, given as a serialized
  // ClientMessageList proto.
  absl::Status ProcessClientMessages(std::string serialized_client_messages);

  // Merges the state of `other` into the current accumulator.
  absl::Status Merge(std::unique_ptr<ServerAccumulator> other);

  // Converts the current state of the accumulator to a serialized
  // ServerAccumulatorState proto.
  absl::StatusOr<std::string> ToSerializedState();

  // Finalizes the accumulator and returns a proto that holds the serialized
  // decryption request (to be sent to the decryptor service) and the
  // serialized decryptor state (to create a FinalResultDecryptor). This
  // consumes the accumulator.
  absl::StatusOr<FinalizedAccumulatorResult> Finalize() &&;

 private:
  explicit ServerAccumulator(
      rust::Box<secure_aggregation::ServerAccumulator> accumulator)
      : accumulator_(std::move(accumulator)) {}

  rust::Box<secure_aggregation::ServerAccumulator> accumulator_;
};

}  // namespace willow
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_API_SERVER_ACCUMULATOR_H_
