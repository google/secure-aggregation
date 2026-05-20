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

#include "willow/input_encoding/time_utils.h"

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "google/protobuf/duration.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include "willow/proto/willow/input_spec.pb.h"

namespace secure_aggregation {
namespace willow {
namespace {

absl::Duration DurationFromProto(const google::protobuf::Duration& proto) {
  return absl::Seconds(proto.seconds()) + absl::Nanoseconds(proto.nanos());
}

absl::Time TimeFromProto(const google::protobuf::Timestamp& proto) {
  return absl::FromUnixSeconds(proto.seconds()) +
         absl::Nanoseconds(proto.nanos());
}

int64_t GetPeriodIndex(absl::Time t, absl::Time origin_time,
                       absl::Duration period_duration) {
  // Calculate the exact duration elapsed since the time origin.
  absl::Duration elapsed = t - origin_time;

  // Round down to the nearest period multiple, even for negative elapsed times.
  // e.g. Floor(-12h, 24h) = -24h.
  absl::Duration floored_elapsed = absl::Floor(elapsed, period_duration);

  // Calculate the number of elapsed periods using integer division, since
  // floored_elapsed is an exact multiple of period_duration.
  absl::Duration unused_remainder;
  int64_t period_index =
      absl::IDivDuration(floored_elapsed, period_duration, &unused_remainder);

  return period_index;
}

}  // namespace

absl::StatusOr<TimeDomainInfo> ParseTimeDomain(
    const InputSpec::TimeDomain& proto) {
  absl::TimeZone tz;
  if (proto.timezone().empty()) {
    tz = absl::UTCTimeZone();
  } else if (!absl::LoadTimeZone(proto.timezone(), &tz)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid timezone: ", proto.timezone()));
  }

  absl::Duration period_duration = DurationFromProto(proto.period_duration());
  if (period_duration <= absl::ZeroDuration()) {
    return absl::InvalidArgumentError("period_duration must be > 0");
  }

  int32_t num_periods = proto.num_periods();
  if (num_periods <= 0) {
    return absl::InvalidArgumentError("num_periods must be > 0");
  }

  std::string format;
  if (proto.format().empty()) {
    format = absl::RFC3339_full;
  } else {
    format = proto.format();
  }

  absl::Time origin_time = absl::UnixEpoch();
  if (proto.has_origin_time()) {
    origin_time = TimeFromProto(proto.origin_time());
  }

  absl::Duration lookback_window;
  if (proto.has_lookback_window()) {
    lookback_window = DurationFromProto(proto.lookback_window());
    if (lookback_window <= absl::ZeroDuration()) {
      return absl::InvalidArgumentError("lookback_window must be > 0");
    }
  } else {
    lookback_window = period_duration * proto.num_periods() / 2;
  }

  return TimeDomainInfo{
      .period_duration = period_duration,
      .num_periods = num_periods,
      .format = format,
      .timezone = tz,
      .origin_time = origin_time,
      .lookback_window = lookback_window,
  };
}

int64_t EncodeTime(absl::Time t, const TimeDomainInfo& info,
                   absl::Time encoding_time) {
  // How many full periods have elapsed since origin_time, with handling for
  // negative times.
  int64_t period_index =
      GetPeriodIndex(t, info.origin_time, info.period_duration);

  // Correct negative remainder to positive modulo: bucket in [0, num_periods).
  int64_t bucket = period_index % info.num_periods;
  if (bucket < 0) {
    bucket += info.num_periods;
  }

  // Future events are always invalid.
  if (t > encoding_time) {
    return info.num_periods;  // Invalid bucket index (last index in domain)
  }

  // Any event older than lookback_window relative to now is marked invalid.
  // This filters out obsolete data and prevents wraparound collisions
  if (t < encoding_time - info.lookback_window) {
    return info.num_periods;  // Invalid bucket index
  }

  return bucket;
}

absl::StatusOr<absl::Time> DecodeTime(int64_t bucket_index,
                                      const TimeDomainInfo& info,
                                      absl::Time decoding_anchor_time) {
  if (bucket_index < 0 || bucket_index >= info.num_periods) {
    return absl::InvalidArgumentError(
        absl::StrCat("Bucket index out of range: ", bucket_index,
                     ", must be in [0, ", info.num_periods, ")"));
  }

  // anchor_period is the period index of anchor_time relative to origin_time.
  int64_t anchor_period = GetPeriodIndex(decoding_anchor_time, info.origin_time,
                                         info.period_duration);

  // We want to find k in [0, num_periods) such that:
  //   (anchor_period + k) mod num_periods = bucket_index
  int64_t k = (bucket_index - anchor_period) % info.num_periods;
  if (k < 0) {
    k += info.num_periods;  // Turn remainder into positive modulo
  }

  // Unique period start time t in [anchor_time, anchor_time + info.num_periods
  // * info.period_duration) that maps to bucket_index.
  return info.origin_time + (anchor_period + k) * info.period_duration;
}

}  // namespace willow
}  // namespace secure_aggregation
