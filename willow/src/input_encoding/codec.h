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

#ifndef SECURE_AGGREGATION_WILLOW_SRC_INPUT_ENCODING_WILLOW_ENCODER_H_
#define SECURE_AGGREGATION_WILLOW_SRC_INPUT_ENCODING_WILLOW_ENCODER_H_

#include <cstdint>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"

namespace secure_aggregation {
namespace willow {

using MetricData = absl::flat_hash_map<std::string, std::vector<int64_t>>;
using GroupData = absl::flat_hash_map<std::string, std::vector<std::string>>;
using EncodedData = absl::flat_hash_map<std::string, std::vector<int64_t>>;

struct DecodedData {
  GroupData group_data;
  MetricData metric_data;
};

class Codec {
 public:
  virtual ~Codec() = default;

  // Encodes the input data into a format suitable for secure aggregation.
  // The structure of the encoded data depends on the specific encoder
  // implementation. The specification used to encode the data is provided at
  // instance creation time, and is used to interpret the input data.
  // metric_data corresponds to vectors to be aggregated across users, and
  // group_by_data corresponds to vectors used to group the resulting
  // aggregations. Therefore, metric_data and group_by_data must contain vectors
  // of the same length, and therefore they represent an input into a
  // distributed group-by operation.
  //
  // Example:
  // metric_data = {"count": {10, 20, 15}}
  // group_by_data = {"country": {"US", "CA", "US"}, "lang": {"en", "fr", "en"}}
  // This represents three records:
  // 1.  country="US", lang="en", count=10
  // 2.  country="CA", lang="fr", count=20
  // 3.  country="US", lang="en", ount=15
  virtual absl::StatusOr<EncodedData> Encode(
      const GroupData& group_by_data, const MetricData& metric_data) const = 0;

  // Decodes the aggregated data back to the original input format.
  // The input `encoded_data` is the result of the secure aggregation.
  virtual absl::StatusOr<DecodedData> Decode(
      const EncodedData& encoded_data) const = 0;
};

}  // namespace willow
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_SRC_INPUT_ENCODING_WILLOW_ENCODER_H_
