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
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "include/cxx.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/server_accumulator.pb.h"
#include "willow/src/api/server_accumulator.rs.h"
#include "willow/src/input_encoding/codec.h"

namespace secure_aggregation {
namespace willow {

absl::StatusOr<std::unique_ptr<ServerAccumulator>> ServerAccumulator::Create(
    const AggregationConfigProto& aggregation_config) {
  secure_aggregation::ServerAccumulator* out;
  std::unique_ptr<std::string> status_message;
  int status_code =
      secure_aggregation::NewServerAccumulatorFromSerializedConfig(
          std::make_unique<std::string>(aggregation_config.SerializeAsString()),
          &out, &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }
  return absl::WrapUnique(new ServerAccumulator(IntoBox(out)));
}

absl::StatusOr<std::unique_ptr<ServerAccumulator>>
ServerAccumulator::CreateFromSerializedState(std::string serialized_state) {
  secure_aggregation::ServerAccumulator* out;
  std::unique_ptr<std::string> status_message;
  int status_code = secure_aggregation::NewServerAccumulatorFromSerializedState(
      std::make_unique<std::string>(std::move(serialized_state)), &out,
      &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }
  return absl::WrapUnique(new ServerAccumulator(IntoBox(out)));
}

absl::Status ServerAccumulator::ProcessClientMessages(
    ClientMessageRange client_messages) {
  auto serialized_client_messages = client_messages.SerializeAsString();
  client_messages.Clear();
  return ProcessClientMessages(std::move(serialized_client_messages));
}

absl::Status ServerAccumulator::ProcessClientMessages(
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

absl::Status ServerAccumulator::Merge(
    std::unique_ptr<ServerAccumulator> other) {
  std::unique_ptr<std::string> status_message;
  int status_code =
      accumulator_->Merge(std::move(other->accumulator_), &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> ServerAccumulator::ToSerializedState() {
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

absl::StatusOr<FinalizedAccumulatorResult> ServerAccumulator::Finalize() && {
  // Finalize accumulator in Rust and store the serialized results.
  rust::Vec<uint8_t> decryption_request;
  rust::Vec<uint8_t> final_result_decryptor_state;
  std::unique_ptr<std::string> status_message;
  int status_code = secure_aggregation::FinalizeServerAccumulator(
      std::move(accumulator_), &decryption_request,
      &final_result_decryptor_state, &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }

  // Pack the two serialized results into a single proto.
  FinalizedAccumulatorResult result_proto;
  result_proto.set_decryption_request(
      std::string(reinterpret_cast<const char*>(decryption_request.data()),
                  decryption_request.size()));
  result_proto.set_final_result_decryptor_state(std::string(
      reinterpret_cast<const char*>(final_result_decryptor_state.data()),
      final_result_decryptor_state.size()));

  return result_proto;
}

absl::StatusOr<std::unique_ptr<FinalResultDecryptor>>
FinalResultDecryptor::CreateFromSerialized(
    std::string final_result_decryptor_state) {
  secure_aggregation::FinalResultDecryptor* out;
  std::unique_ptr<std::string> status_message;
  int status_code =
      secure_aggregation::CreateFinalResultDecryptorFromSerialized(
          std::make_unique<std::string>(
              std::move(final_result_decryptor_state)),
          &out, &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }
  return absl::WrapUnique(new FinalResultDecryptor(
      secure_aggregation::FinalResultDecryptorIntoBox(out)));
}

absl::StatusOr<EncodedData> FinalResultDecryptor::Decrypt(
    std::string serialized_partial_decryption_response) {
  rust::Vec<EncodedDataEntry> out;
  std::unique_ptr<std::string> status_message;
  int status_code = aggregated_ciphertexts_->Decrypt(
      std::make_unique<std::string>(
          std::move(serialized_partial_decryption_response)),
      &out, &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }
  EncodedData encoded_data;
  for (const auto& rust_entry : out) {
    std::string key(rust_entry.key);
    std::vector<int64_t> val;
    val.reserve(rust_entry.values.size());
    for (auto v : rust_entry.values) {
      val.push_back(static_cast<int64_t>(v));
    }
    encoded_data[std::move(key)] = std::move(val);
  }
  return encoded_data;
}

}  // namespace willow
}  // namespace secure_aggregation