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

#include <string>

#include "absl/status/statusor.h"
#include "willow/input_encoding/codec.h"
#include "willow/proto/shell/ciphertexts.pb.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/messages.pb.h"
#include "willow/proto/willow/server_accumulator.pb.h"

namespace secure_aggregation {

// Generates a client contribution by encrypting the encoded data with the
// provided AHE public key.
absl::StatusOr<willow::ClientMessage> GenerateClientContribution(
    const willow::AggregationConfigProto& aggregation_config,
    const willow::EncodedData& encoded_data,
    const willow::ShellAhePublicKey& public_key, const std::string& nonce);

}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_API_CLIENT_H_
