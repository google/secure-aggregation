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

#include "willow/api/client.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "ffi_utils/cxx_utils.h"
#include "ffi_utils/status_macros.h"
#include "include/cxx.h"
#include "willow/api/client.rs.h"
#include "willow/input_encoding/codec.h"
#include "willow/proto/shell/ciphertexts.pb.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/input_spec.pb.h"
#include "willow/proto/willow/server_accumulator.pb.h"

namespace secure_aggregation {

absl::StatusOr<willow::AggregationConfigProto> CreateAggregationConfig(
    const willow::InputSpec& input_spec_proto, absl::string_view key_id,
    int64_t max_number_of_clients, int64_t max_number_of_decryptors,
    int64_t max_decryptor_dropouts, int64_t default_max_metric_value) {
  willow::AggregationConfigProto config_proto;
  config_proto.set_max_number_of_clients(max_number_of_clients);
  config_proto.set_max_number_of_decryptors(max_number_of_decryptors);
  config_proto.set_max_decryptor_dropouts(max_decryptor_dropouts);
  config_proto.set_key_id(std::string(key_id));
  // All metrics have same vector length, corresponding to the Cartesian product
  // of group-by domains.
  int64_t flattened_domain_size = 1;
  for (const auto& group_by_spec : input_spec_proto.group_by_vector_specs()) {
    if (group_by_spec.domain_spec().string_values().values_size() == 0) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Missing domain, invalid domain type (must be StringValues), or "
          "empty string_values for group by vector: ",
          group_by_spec.vector_name()));
    }
    flattened_domain_size *=
        group_by_spec.domain_spec().string_values().values_size();
  }
  // Build VectorConfig (length and bound) for each metric.
  for (const auto& metric_spec : input_spec_proto.metric_vector_specs()) {
    auto& vector_config =
        (*config_proto.mutable_vector_configs())[metric_spec.vector_name()];
    vector_config.set_length(flattened_domain_size);
    if (metric_spec.has_domain_spec() &&
        metric_spec.domain_spec().has_interval()) {
      vector_config.set_bound(
          static_cast<int64_t>(metric_spec.domain_spec().interval().max()));
    } else {
      vector_config.set_bound(default_max_metric_value);
    }
  }
  return config_proto;
}

absl::StatusOr<willow::ClientMessage> GenerateClientContribution(
    const willow::AggregationConfigProto& aggregation_config,
    const willow::EncodedData& encoded_data,
    const willow::ShellAhePublicKey& public_key, absl::string_view nonce) {
  // Initialize client.
  std::string config_str = aggregation_config.SerializeAsString();
  auto config_ptr = std::make_unique<std::string>(std::move(config_str));
  secure_aggregation::WillowShellClient* client_ptr = nullptr;
  SECAGG_RETURN_IF_FFI_ERROR(
      initialize_client(std::move(config_ptr), &client_ptr));
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
  // Encrypt data.
  SECAGG_RETURN_IF_FFI_ERROR(generate_contribution(
      client, entries_slice, std::move(key_ptr), nonce_slice, &result_bytes));

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
