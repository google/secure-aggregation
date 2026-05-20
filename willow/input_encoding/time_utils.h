// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_TIME_UTILS_H_
#define SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_TIME_UTILS_H_

#include <cstdint>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "willow/proto/willow/input_spec.pb.h"

namespace secure_aggregation {
namespace willow {

// A special string representation returned when decoding an invalid/stale
// modular timestamp bucket index.
inline constexpr absl::string_view kInvalidTimestamp = "INVALID_TIMESTAMP";

// Struct containing the parsed time domain parameters.
struct TimeDomainInfo {
  absl::Duration period_duration;
  int num_periods;
  std::string format;
  absl::TimeZone timezone;
  absl::Time origin_time;
  absl::Duration lookback_window;
};

// Parses a TimeDomain protobuf spec into a validated TimeDomainInfo struct.
// Returns an InvalidArgument status if spec fields (duration, periods,
// timezone) are invalid.
absl::StatusOr<TimeDomainInfo> ParseTimeDomain(
    const InputSpec::TimeDomain& proto);

// Encodes a parsed absl::Time into a modular bucket index in [0, num_periods).
// Returns num_periods (the invalid/stale bucket) if the event is in the future
// or older than the lookback window relative to `encoding_time`.
int64_t EncodeTime(absl::Time t, const TimeDomainInfo& info,
                   absl::Time encoding_time);

// Reconstructs the absolute start-of-period absl::Time from a bucket index.
// Expects bucket_index in [0, num_periods). Returns an InvalidArgument status
// if the bucket index is out of bounds.
absl::StatusOr<absl::Time> DecodeTime(int64_t bucket_index,
                                      const TimeDomainInfo& info,
                                      absl::Time decoding_anchor_time);

}  // namespace willow
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_TIME_UTILS_H_
