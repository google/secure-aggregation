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

#include "willow/src/shell/parameters_utils.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "include/cxx.h"
#include "shell_wrapper/status_macros.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/src/shell/parameters_utils.rs.h"

namespace secure_aggregation {
namespace willow {

absl::StatusOr<std::string> CreateHumanReadableShellConfig(
    const AggregationConfigProto& config) {
  std::string serialized_config = config.SerializeAsString();
  rust::Vec<uint8_t> result;

  SECAGG_RETURN_IF_FFI_ERROR(
      secure_aggregation::create_human_readable_shell_config(
          std::make_unique<std::string>(std::move(serialized_config)),
          &result));

  return std::string(reinterpret_cast<const char*>(result.data()),
                     result.size());
}

}  // namespace willow
}  // namespace secure_aggregation
