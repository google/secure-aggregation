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

#include "willow/src/api/client.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "include/cxx.h"
#include "shell_wrapper/shell_types.h"
#include "willow/proto/shell/ciphertexts.pb.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/server_accumulator.pb.h"
#include "willow/src/api/client.rs.h"
#include "willow/src/input_encoding/codec.h"

namespace secure_aggregation {

absl::StatusOr<willow::ClientMessage> GenerateClientContribution(
    const willow::AggregationConfigProto& aggregation_config,
    const willow::EncodedData& encoded_data,
    const willow::ShellAhePublicKey& public_key, const std::string& nonce) {
  // Initialize client.
  std::string config_str = aggregation_config.SerializeAsString();
  auto config_ptr = std::make_unique<std::string>(std::move(config_str));
  secure_aggregation::WillowShellClient* client_ptr = nullptr;
  std::unique_ptr<std::string> status_message;
  int status_code =
      initialize_client(std::move(config_ptr), &client_ptr, &status_message);
  if (status_code != 0) {
    return absl::Status(absl::StatusCode(status_code), *status_message);
  }
  // Use `into_box` to avoid linker issues arising from rust::Box::from_raw.
  auto client = client_into_box(client_ptr);

  // Prepare arguments.
  std::vector<DataEntryView> entries;
  entries.reserve(encoded_data.size());
  for (const auto& [key, values] : encoded_data) {
    rust::Slice<const uint8_t> key_slice = ToRustSlice(key);
    // values.data() is currently a pointer to an int64_t array and not
    // uint64_t, so this performs an implicit cast (wrapping around if
    // necessary). Not using a ToRustSlice variant because this is a temporary
    // solution until the codec is updated to use uint64_t.
    rust::Slice<const uint64_t> values_slice(
        reinterpret_cast<const uint64_t*>(values.data()), values.size());
    entries.push_back(DataEntryView{key_slice, values_slice});
  }
  rust::Slice<const DataEntryView> entries_slice(entries.data(),
                                                 entries.size());

  std::string key_str = public_key.SerializeAsString();
  auto key_ptr = std::make_unique<std::string>(std::move(key_str));
  rust::Slice<const uint8_t> nonce_slice = ToRustSlice(nonce);
  rust::Vec<uint8_t> result_bytes;
  std::unique_ptr<std::string> status_message_gen;

  // Encrypt data.
  int status_code_gen =
      generate_contribution(client, entries_slice, std::move(key_ptr),
                            nonce_slice, &result_bytes, &status_message_gen);
  if (status_code_gen != 0) {
    return absl::Status(absl::StatusCode(status_code_gen), *status_message_gen);
  }

  // Parse string to ClientMessage.
  willow::ClientMessage client_message;
  std::string result_str(reinterpret_cast<const char*>(result_bytes.data()),
                         result_bytes.size());
  if (!client_message.ParseFromString(result_str)) {
    return absl::InternalError(
        "Failed to parse ClientMessage from Rust output.");
  }

  return client_message;
}

}  // namespace secure_aggregation
