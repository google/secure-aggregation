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

#ifndef SECURE_AGGREGATION_WILLOW_API_CLIENT_H_
#define SECURE_AGGREGATION_WILLOW_API_CLIENT_H_

#include <cstdint>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "willow/input_encoding/codec.h"
#include "willow/proto/shell/ciphertexts.pb.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/input_spec.pb.h"
#include "willow/proto/willow/messages.pb.h"
#include "willow/proto/willow/server_accumulator.pb.h"

namespace secure_aggregation {

// Default maximum bound for metric vector elements if not specified in the
// InputSpec and not passed to CreateAggregationConfig.
inline constexpr int64_t kDefaultMaxMetricValue = 1LL << 30;

// Default configuration for Willow clients and decryptors.
inline constexpr int64_t kDefaultMaxNumberOfClients = 10000000;
inline constexpr int64_t kDefaultMaxDecryptors = 1;
inline constexpr int64_t kDefaultMaxDecryptorDropouts = 0;

// Creates an AggregationConfigProto from the given InputSpec and other
// parameters. For each metric, it builds a willow.VectorConfig proto, where
// the length is the Cartesian product of the group-by vector domains, and the
// bound is the interval max if specified, or default_max_metric_value
// otherwise.
absl::StatusOr<willow::AggregationConfigProto> CreateAggregationConfig(
    const willow::InputSpec& input_spec, absl::string_view key_id,
    int64_t max_number_of_clients = kDefaultMaxNumberOfClients,
    int64_t max_number_of_decryptors = kDefaultMaxDecryptors,
    int64_t max_decryptor_dropouts = kDefaultMaxDecryptorDropouts,
    int64_t default_max_metric_value = kDefaultMaxMetricValue);

// Generates a client contribution by encrypting the encoded data with the
// provided AHE public key.
absl::StatusOr<willow::ClientMessage> GenerateClientContribution(
    const willow::AggregationConfigProto& aggregation_config,
    const willow::EncodedData& encoded_data,
    const willow::ShellAhePublicKey& public_key, absl::string_view nonce);

}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_API_CLIENT_H_
