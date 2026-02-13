/*
 * Copyright 2026 Google LLC
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

#ifndef SECURE_AGGREGATION_WILLOW_CRYPTO_PARAMETERS_UTILS_H_
#define SECURE_AGGREGATION_WILLOW_CRYPTO_PARAMETERS_UTILS_H_

#include <string>

#include "absl/status/statusor.h"
#include "willow/proto/willow/aggregation_config.pb.h"

namespace secure_aggregation {
namespace willow {

// Returns the ShellKaheConfig and ShellAheConfig as a human-readable string,
// for the given AggregationConfigProto.
absl::StatusOr<std::string> CreateHumanReadableShellConfig(
    const AggregationConfigProto& config);

}  // namespace willow
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_CRYPTO_PARAMETERS_UTILS_H_
