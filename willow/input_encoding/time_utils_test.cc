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

#include "absl/status/status.h"
#include "absl/time/time.h"
#include "ffi_utils/status_matchers.h"
#include "gmock/gmock.h"
#include "google/protobuf/duration.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include "gtest/gtest.h"
#include "willow/proto/willow/input_spec.pb.h"

namespace secure_aggregation {
namespace willow {
namespace {

using ::secure_aggregation::secagg_internal::StatusIs;
using ::testing::HasSubstr;

TEST(TimeDomainHelperTest, ParseTimeDomainWithLookback) {
  InputSpec::TimeDomain proto;
  proto.mutable_period_duration()->set_seconds(86400);  // 1 day
  proto.set_num_periods(6);                             // 6 days
  proto.set_timezone("America/Los_Angeles");
  proto.set_format("%Y-%m-%d");
  proto.mutable_origin_time()->set_seconds(1234567890);
  proto.mutable_lookback_window()->set_seconds(7 * 24 * 3600);  // 7 days

  SECAGG_ASSERT_OK_AND_ASSIGN(TimeDomainInfo info, ParseTimeDomain(proto));

  EXPECT_EQ(info.period_duration, absl::Hours(24));
  EXPECT_EQ(info.num_periods, 6);
  EXPECT_EQ(info.format, "%Y-%m-%d");

  absl::TimeZone expected_tz;
  ASSERT_TRUE(absl::LoadTimeZone("America/Los_Angeles", &expected_tz));
  EXPECT_EQ(info.timezone, expected_tz);
  EXPECT_EQ(info.origin_time, absl::FromUnixSeconds(1234567890));
  EXPECT_EQ(info.lookback_window, absl::Hours(7 * 24));
}

TEST(TimeDomainHelperTest, ParseTimeDomainDefaultLookback) {
  InputSpec::TimeDomain proto;
  proto.mutable_period_duration()->set_seconds(86400);  // 1 day
  proto.set_num_periods(6);                             // 6 days
  proto.set_timezone("UTC");

  SECAGG_ASSERT_OK_AND_ASSIGN(TimeDomainInfo info, ParseTimeDomain(proto));
  // Default lookback is 6 * 1 day / 2 = 3 days (72 hours).
  EXPECT_EQ(info.lookback_window, absl::Hours(3 * 24));
}

TEST(TimeDomainHelperTest, ParseTimeDomainInvalid) {
  InputSpec::TimeDomain proto;
  // Missing period_duration (default 0)
  proto.set_num_periods(6);
  EXPECT_THAT(ParseTimeDomain(proto),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("period_duration must be > 0")));

  proto.mutable_period_duration()->set_seconds(86400);
  proto.set_num_periods(0);  // Invalid periods
  EXPECT_THAT(ParseTimeDomain(proto),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("num_periods must be > 0")));

  proto.set_num_periods(6);
  proto.set_timezone("Invalid/Timezone");
  EXPECT_THAT(ParseTimeDomain(proto),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid timezone")));
  proto.set_timezone("UTC");

  // Invalid lookback_window <= 0
  proto.mutable_lookback_window()->set_seconds(0);
  EXPECT_THAT(ParseTimeDomain(proto),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("lookback_window must be > 0")));
}

TEST(TimeDomainHelperTest, EncodeTimeWithCustomLookback) {
  TimeDomainInfo info{
      .period_duration = absl::Hours(24),
      .num_periods = 6,
      .format = "%Y-%m-%d",
      .timezone = absl::UTCTimeZone(),
      .origin_time = absl::UnixEpoch(),
      .lookback_window =
          absl::Hours(24 * 2),  // Events older than 2 days are stale
  };

  absl::Time encoding_time =
      absl::UnixEpoch() + absl::Hours(24 * 10);  // Day 10 (1970-01-11)

  // Valid event: 1 day ago
  absl::Time t1 = encoding_time - absl::Hours(24 * 1);
  EXPECT_EQ(EncodeTime(t1, info, encoding_time), 3);

  // Stale event: 3 days ago
  absl::Time t2 = encoding_time - absl::Hours(24 * 3);
  EXPECT_EQ(EncodeTime(t2, info, encoding_time), 6);  // Invalid bucket

  // Future event: 1 day in future.
  absl::Time t3 = encoding_time + absl::Hours(24 * 1);
  EXPECT_EQ(EncodeTime(t3, info, encoding_time), 6);  // Invalid bucket
}

TEST(TimeDomainHelperTest, DecodeTime) {
  TimeDomainInfo info{
      .period_duration = absl::Hours(24),
      .num_periods = 6,
      .format = "%Y-%m-%d",
      .timezone = absl::UTCTimeZone(),
      .origin_time = absl::UnixEpoch(),
  };

  // anchor_time = Day 8
  absl::Time anchor_time = absl::UnixEpoch() + absl::Hours(24 * 8);

  // Decode bucket 3, expect Day 9 because 9 mod 6 = 3 and 8 <= 9 < 8 + 6
  absl::Time expected1 = absl::UnixEpoch() + absl::Hours(24 * 9);

  SECAGG_ASSERT_OK_AND_ASSIGN(absl::Time decoded1,
                              DecodeTime(3, info, anchor_time));
  EXPECT_EQ(decoded1, expected1);
  EXPECT_GE(decoded1, anchor_time);
  EXPECT_LT(decoded1, anchor_time + absl::Hours(24 * 6));

  // Decode bucket 1, expect Day 13 because 13 mod 6 = 1 and 8 <= 13 < 8 + 6.
  absl::Time expected2 = absl::UnixEpoch() + absl::Hours(24 * 13);

  SECAGG_ASSERT_OK_AND_ASSIGN(absl::Time decoded2,
                              DecodeTime(1, info, anchor_time));
  EXPECT_EQ(decoded2, expected2);
  EXPECT_GE(decoded2, anchor_time);
  EXPECT_LT(decoded2, anchor_time + absl::Hours(24 * 6));

  // Invalid bucket index raises an error.
  EXPECT_THAT(DecodeTime(6, info, anchor_time),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Bucket index out of range")));
}

}  // namespace
}  // namespace willow
}  // namespace secure_aggregation
