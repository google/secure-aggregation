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

#ifndef SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_CODEC_H_
#define SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_CODEC_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "ffi_utils/status_macros.h"
#include "willow/proto/willow/input_spec.pb.h"

namespace secure_aggregation {
namespace willow {

// The maximum number of bins in a flat histogram, which is the maximum size of
// the Cartesian product of domains for string features.
constexpr size_t kMaxFlatHistogramBins = 1000000;

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

  // Validates that the output vectors in the query match the specification
  // used to construct this Codec.
  virtual absl::Status ValidateExampleQuery(
      const absl::flat_hash_map<std::string, std::string>& query_output_specs)
      const = 0;

  // Returns the length of the encoded vector for the given metric.
  // Returns an InvalidArgument error if the metric is not found in the spec.
  virtual absl::StatusOr<size_t> GetEncodedVectorLength(
      absl::string_view metric_name) const = 0;

  // Creates an instance of FlatHistogramCodec.
  static absl::StatusOr<std::unique_ptr<Codec>> CreateFlatHistogramCodec(
      ::secure_aggregation::willow::InputSpec input_spec);

  // Deprecated aliases for backward compatibility
  [[deprecated("Use CreateFlatHistogramCodec instead")]]
  static absl::StatusOr<std::unique_ptr<Codec>> CreateExplicitCodec(
      ::secure_aggregation::willow::InputSpec input_spec) {
    return CreateFlatHistogramCodec(std::move(input_spec));
  }

  [[deprecated(
      "Use CreateFlatHistogramCodec and GetEncodedVectorLength instead")]]
  static absl::Status ValidateExplicitCodecInputSpec(
      const ::secure_aggregation::willow::InputSpec& input_spec,
      size_t max_flattened_domain_size = kMaxFlatHistogramBins) {
    // Creating a codec allocates memory, compared to just validating the input
    // spec, but the memory allocation is just proportional to the
    // size of the input spec.
    SECAGG_ASSIGN_OR_RETURN(std::unique_ptr<Codec> codec,
                            CreateFlatHistogramCodec(input_spec));
    if (!input_spec.metric_vector_specs().empty()) {
      std::string first_metric =
          input_spec.metric_vector_specs(0).vector_name();
      SECAGG_ASSIGN_OR_RETURN(size_t length,
                              codec->GetEncodedVectorLength(first_metric));
      if (length > max_flattened_domain_size) {
        return absl::InvalidArgumentError(
            "Flat histogram bin count exceeds maximum threshold.");
      }
    }
    return absl::OkStatus();
  }
};

}  // namespace willow
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_CODEC_H_
