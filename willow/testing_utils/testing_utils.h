// Copyright 2026 Google LLC
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

#ifndef SECURE_AGGREGATION_WILLOW_TESTING_UTILS_TESTING_UTILS_H_
#define SECURE_AGGREGATION_WILLOW_TESTING_UTILS_TESTING_UTILS_H_

#include "willow/input_encoding/codec.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/input_spec.pb.h"

namespace secure_aggregation::willow {

// Returns a test AggregationConfigProto.
AggregationConfigProto CreateTestAggregationConfigProto();

// Returns a test InputSpec proto with one metric and two group-by vectors.
InputSpec CreateTestInputSpecProto();

// Returns a test MetricData with one metric.
MetricData CreateTestMetricData();

// Returns a test GroupData with two group-by vectors.
GroupData CreateTestGroupData();

}  // namespace secure_aggregation::willow

#endif  // SECURE_AGGREGATION_WILLOW_TESTING_UTILS_TESTING_UTILS_H_
