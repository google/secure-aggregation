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

#include "willow/input_encoding/codec.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "ffi_utils/status_macros.h"
#include "willow/proto/willow/input_spec.pb.h"

namespace secure_aggregation {
namespace willow {

using InputSpec = ::secure_aggregation::willow::InputSpec;
using InputVectorSpec =
    ::secure_aggregation::willow::InputSpec::InputVectorSpec;

// Context storing spec and precomputed indices for a group-by vector.
struct GroupByVectorContext {
  const InputVectorSpec* input_spec;
  absl::flat_hash_map<std::string, int> domain_indices;
};

// FlatHistogramCodecImpl implements a Codec that encodes data into a dense,
// flat 1D histogram representing the Cartesian product of the group-by
// domains.
//
// It must be instantiated through the factory function
// Codec::CreateFlatHistogramCodec.
class FlatHistogramCodecImpl : public Codec {
 public:
  FlatHistogramCodecImpl(const FlatHistogramCodecImpl&) = delete;
  FlatHistogramCodecImpl& operator=(const FlatHistogramCodecImpl&) = delete;
  ~FlatHistogramCodecImpl() override = default;

  absl::StatusOr<EncodedData> Encode(
      const GroupData& group_by_data,
      const MetricData& metric_data) const override;

  absl::StatusOr<DecodedData> Decode(
      const EncodedData& encoded_data) const override;

  absl::Status ValidateExampleQuery(
      const absl::flat_hash_map<std::string, std::string>& query_output_specs)
      const override;

  absl::StatusOr<size_t> GetEncodedVectorLength(
      absl::string_view metric_name) const override;

 private:
  InputSpec input_spec_;
  // Sorted map of group-by vector names to their contexts. Sorted to ensure
  // deterministic encoding into bins regardless of the order of the input spec.
  absl::btree_map<std::string, GroupByVectorContext> group_by_vector_contexts_;
  // Map of metric key names to their specs.
  absl::flat_hash_map<std::string, const InputVectorSpec*> metric_spec_map_;
  // The size of the Cartesian product of all group-by domains.
  std::int64_t flat_histogram_bin_count_;

  absl::Status ValidateData(const GroupData& group_by_data,
                            const MetricData& metric_data) const;

  std::vector<int> GetIndices(int global_index) const;

  size_t GetCombinedIndex(const std::vector<int>& indices) const;

  int EncodeGroupValue(const std::string& group_name,
                       const std::string& value) const;

  absl::StatusOr<std::string> DecodeGroupValue(absl::string_view group_name,
                                               int group_domain_index) const;

  explicit FlatHistogramCodecImpl(
      InputSpec input_spec,
      absl::btree_map<std::string, GroupByVectorContext>
          group_by_vector_contexts,
      absl::flat_hash_map<std::string, const InputVectorSpec*> metric_spec_map,
      size_t flat_histogram_bin_count)
      : input_spec_(std::move(input_spec)),
        group_by_vector_contexts_(std::move(group_by_vector_contexts)),
        metric_spec_map_(std::move(metric_spec_map)),
        flat_histogram_bin_count_(
            static_cast<std::int64_t>(flat_histogram_bin_count)) {}
  friend class Codec;
};

absl::Status FlatHistogramCodecImpl::ValidateData(
    const GroupData& group_by_data, const MetricData& metric_data) const {
  // Check that all vectors in metric_data and group_by_data are present in
  // metric_spec_map and group_by_spec_map_, respectively. This ensures that the
  // spec does not define more vectors than the input data, which is useful to
  // simplify decoding.
  for (const auto& [name, unused] : metric_data) {
    if (!metric_spec_map_.contains(name)) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Key ", name, " found in metric_data but not in input_spec."));
    }
  }
  for (const auto& [name, unused] : group_by_data) {
    if (!group_by_vector_contexts_.contains(name)) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Key ", name, " found in group_by_data but not in input_spec."));
    }
  }

  // Check that:
  // 1. all provided vectors in metric_data, group_by_data, and in
  // input_spec have the same length, and that the length is greater than 0.
  // 2. all metric vector names in metric_data are present in input_spec.
  // 3. all group-by vector names in group_by_data are present in input_spec.
  // 4. metric vectors have the same type as specified in the input_spec.
  // 5. group-by vectors have the same type as specified in the input_spec.
  // 6. all values in group_by_data are in the domain provided in the
  // input_spec.
  if (metric_data.empty()) {
    return absl::InvalidArgumentError("Metric data cannot be empty.");
  }
  int vector_size = 0;
  vector_size = metric_data.begin()->second.size();

  if (vector_size == 0) {
    return absl::InvalidArgumentError(
        "All input vectors must have length > 0.");
  }

  constexpr InputSpec::DataType kDataMetricType = InputSpec::INT64;
  for (const auto& [name, data] : metric_data) {
    if (data.size() != vector_size) {
      return absl::InvalidArgumentError(
          "All metric and group-by vectors must have the same length.");
    }
    auto it = metric_spec_map_.find(name);
    if (it == metric_spec_map_.end()) {
      return absl::InternalError(absl::StrCat(
          "Key ", name, " found in metric_data but not in input_spec."));
    }
    const auto& spec = it->second;
    if (spec->data_type() != kDataMetricType) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Type mismatch for key ", name, ": metric_data type is ",
          InputSpec::DataType_Name(kDataMetricType), " but input_spec type is ",
          InputSpec::DataType_Name(spec->data_type())));
    }
  }

  constexpr InputSpec::DataType kDataGroupByType = InputSpec::STRING;
  for (const auto& [name, data] : group_by_data) {
    if (data.size() != vector_size) {
      return absl::InvalidArgumentError(
          "All metric and group-by vectors must have the same length.");
    }
    auto it = group_by_vector_contexts_.find(name);
    if (it == group_by_vector_contexts_.end()) {
      return absl::InternalError(absl::StrCat(
          "Key ", name, " found in group_by_data but not in input_spec."));
    }
    const auto& context = it->second;
    if (context.input_spec->data_type() != kDataGroupByType) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Type mismatch for key ", name, ": group_by_data type is ",
          InputSpec::DataType_Name(kDataGroupByType),
          " but input_spec type is ",
          InputSpec::DataType_Name(context.input_spec->data_type())));
    }
    // Check that all values in group_by_data are in the domain provided in the
    // input_spec.
    for (const auto& d : data) {
      if (!context.domain_indices.contains(d)) {
        return absl::InvalidArgumentError(
            absl::StrCat("Domain mismatch for key ", name,
                         ": group_by_data value ", d, " not found in domain."));
      }
    }
  }
  return absl::OkStatus();
}

// Returns the indices of elements in individual domains/vectors of size `sizes`
// that correspond to the global index `global_index` of an element of their
// cartesian product.
std::vector<int> FlatHistogramCodecImpl::GetIndices(int global_index) const {
  if (group_by_vector_contexts_.empty()) {
    return {};
  }
  std::vector<int> indices =
      std::vector<int>(group_by_vector_contexts_.size(), -1);
  int64_t current_index = global_index;
  int i = group_by_vector_contexts_.size() - 1;
  for (auto it = group_by_vector_contexts_.rbegin();
       it != group_by_vector_contexts_.rend(); ++it) {
    int domain_size = it->second.domain_indices.size();
    indices[i] = current_index % domain_size;
    current_index /= domain_size;
    i--;
  }
  return indices;
}

// Returns the index of an element in the cartesian product of domains of size
// `sizes`, given the indices of the elements in the individual domains.
// E.g., if sizes = {2, 3} and indices = {1, 0}, this implies we have two
// domains of size 2 and 3 respectively, and we want to find overall index of
// an element that has index 1 in the first domain and index 0 in the second
// domain. The function will return 1 * 3 + 0 = 3.
size_t FlatHistogramCodecImpl::GetCombinedIndex(
    const std::vector<int>& indices) const {
  CHECK_EQ(indices.size(), group_by_vector_contexts_.size());
  int64_t combined_index = 0;
  int i = 0;
  for (const auto& [_, context] : group_by_vector_contexts_) {
    combined_index *= context.domain_indices.size();
    combined_index += indices[i];
    i++;
  }
  return combined_index;
}

// Encodes a single group-by value to its unique group-by domain index within
// its own flattened domain.
int FlatHistogramCodecImpl::EncodeGroupValue(const std::string& group_name,
                                             const std::string& value) const {
  auto context_it = group_by_vector_contexts_.find(group_name);
  CHECK(context_it != group_by_vector_contexts_.end());
  const auto& context = context_it->second;

  auto it = context.domain_indices.find(value);
  CHECK(it != context.domain_indices.end());
  return it->second;
}

// Decodes a group-by domain index to its original value within the group-by
// domain. Must be called on group_names known to be in the input spec.
absl::StatusOr<std::string> FlatHistogramCodecImpl::DecodeGroupValue(
    absl::string_view group_name, int group_domain_index) const {
  auto context_it = group_by_vector_contexts_.find(group_name);
  CHECK(context_it != group_by_vector_contexts_.end());
  const auto& context = context_it->second;

  const auto& domain = context.input_spec->domain_spec().string_values();
  if (group_domain_index < 0 || group_domain_index >= domain.values_size()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Index ", group_domain_index, " for key ", group_name,
                     " is out of bounds [0, ", domain.values_size(), ")."));
  }
  return domain.values(group_domain_index);
}

absl::StatusOr<EncodedData> FlatHistogramCodecImpl::Encode(
    const GroupData& group_by_data, const MetricData& metric_data) const {
  SECAGG_RETURN_IF_ERROR(ValidateData(group_by_data, metric_data));

  absl::flat_hash_map<std::string, std::vector<int64_t>> result;
  if (group_by_vector_contexts_.empty()) {
    // No group-by dimensions, so encoding is just a copy of metric_data.
    for (const auto& [metric_name, values] : metric_data) {
      result[metric_name] = values;
    }
  } else {
    for (const auto& [metric_name, values] : metric_data) {
      result[metric_name] = std::vector<int64_t>(flat_histogram_bin_count_, 0);
      for (int i = 0; i < values.size(); ++i) {
        std::vector<int> indices;
        indices.reserve(group_by_vector_contexts_.size());
        for (const auto& [group_name, _] : group_by_vector_contexts_) {
          auto it_data = group_by_data.find(group_name);
          CHECK(it_data != group_by_data.end());
          CHECK_LT(static_cast<size_t>(i), it_data->second.size());
          const std::string& group_value = it_data->second[i];
          indices.push_back(EncodeGroupValue(group_name, group_value));
        }
        result[metric_name][GetCombinedIndex(indices)] = values[i];
      }
    }
  }
  return result;
}

absl::StatusOr<DecodedData> FlatHistogramCodecImpl::Decode(
    const EncodedData& encoded_data) const {
  DecodedData decoded_data;

  if (group_by_vector_contexts_.empty()) {
    // No group-by, so decoded metrics are just the encoded data.
    decoded_data.metric_data = encoded_data;
    // Check if all encoded vectors have the same size.
    if (encoded_data.empty()) return decoded_data;
    size_t expected_size = encoded_data.begin()->second.size();
    for (const auto& [name, values] : encoded_data) {
      if (values.size() != expected_size) {
        return absl::InvalidArgumentError(
            "Encoded data vectors must have the same size when no group-by "
            "keys are present.");
      }
    }
    return decoded_data;
  }
  for (const auto& [name, values] : encoded_data) {
    if (!metric_spec_map_.contains(name)) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Key ", name, " found in encoded_data but not in input_spec."));
    }
    if (values.size() != flat_histogram_bin_count_) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Encoded data for metric ", name, " has wrong size: expected ",
          flat_histogram_bin_count_, ", got ", values.size()));
    }
  }

  for (int i = 0; i < flat_histogram_bin_count_; ++i) {
    bool has_nonzero_metric = false;
    for (const auto& [metric_name, values] : encoded_data) {
      if (values[i] != 0) {
        has_nonzero_metric = true;
        break;
      }
    }
    if (has_nonzero_metric) {
      std::vector<int> indices = GetIndices(i);
      int j = 0;
      for (const auto& [group_name, _] : group_by_vector_contexts_) {
        SECAGG_ASSIGN_OR_RETURN(std::string decoded_val,
                                DecodeGroupValue(group_name, indices[j]));
        decoded_data.group_data[group_name].push_back(decoded_val);
        j++;
      }
      for (const auto& [metric_name, values] : encoded_data) {
        decoded_data.metric_data[metric_name].push_back(values[i]);
      }
    }
  }
  return decoded_data;
}

absl::Status FlatHistogramCodecImpl::ValidateExampleQuery(
    const absl::flat_hash_map<std::string, std::string>& query_output_specs)
    const {
  for (const auto& [name, type] : query_output_specs) {
    auto group_it = group_by_vector_contexts_.find(name);
    auto metric_it = metric_spec_map_.find(name);

    if (group_it != group_by_vector_contexts_.end()) {
      if (type != "STRING") {
        return absl::InvalidArgumentError(absl::StrCat(
            "Vector ", name, " in query is group-by but type is not STRING."));
      }
    } else if (metric_it != metric_spec_map_.end()) {
      if (type != "INT64") {
        return absl::InvalidArgumentError(absl::StrCat(
            "Vector ", name, " in query is metric but type is not INT64."));
      }
    } else {
      return absl::InvalidArgumentError(
          absl::StrCat("Vector ", name, " in query not found in input spec."));
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<Codec>> Codec::CreateFlatHistogramCodec(
    InputSpec input_spec) {
  // Check that specs include at least one metric vector.
  if (input_spec.metric_vector_specs().empty()) {
    return absl::InvalidArgumentError(
        "input_spec must include at least one metric vector.");
  }
  for (const auto& spec : input_spec.group_by_vector_specs()) {
    if (!spec.domain_spec().has_string_values()) {
      return absl::InvalidArgumentError(
          "Unsupported domain type for group-by vector");
    }
    if (spec.domain_spec().string_values().values_size() == 0) {
      return absl::InvalidArgumentError("String domain cannot be empty.");
    }
  }

  // Construct maps of vector names to specs, and checks for duplicates.
  absl::btree_map<std::string, GroupByVectorContext> group_by_vector_contexts;
  for (const auto& spec : input_spec.group_by_vector_specs()) {
    GroupByVectorContext context;
    context.input_spec = &spec;
    const auto& domain = spec.domain_spec().string_values();
    for (int i = 0; i < domain.values_size(); ++i) {
      context.domain_indices[domain.values(i)] = i;
    }
    if (!group_by_vector_contexts
             .insert({spec.vector_name(), std::move(context)})
             .second) {
      return absl::InvalidArgumentError(
          absl::StrCat("Duplicate vector name: ", spec.vector_name()));
    }
  }
  absl::flat_hash_map<std::string, const InputVectorSpec*> metric_spec_map;
  for (const auto& spec : input_spec.metric_vector_specs()) {
    if (!metric_spec_map.insert({spec.vector_name(), &spec}).second) {
      return absl::InvalidArgumentError(
          absl::StrCat("Duplicate vector name: ", spec.vector_name()));
    }
  }

  // Compute flat histogram bin count.
  int64_t flattened_domain_size = 1;

  for (const auto& [_, context] : group_by_vector_contexts) {
    int domain_size = context.domain_indices.size();
    if (flattened_domain_size >
        std::numeric_limits<int64_t>::max() / domain_size) {
      return absl::InvalidArgumentError("Flat histogram bin count overflow.");
    }
    flattened_domain_size *= domain_size;
  }

  return absl::WrapUnique(new FlatHistogramCodecImpl(
      std::move(input_spec), std::move(group_by_vector_contexts),
      std::move(metric_spec_map), flattened_domain_size));
}

absl::StatusOr<size_t> FlatHistogramCodecImpl::GetEncodedVectorLength(
    absl::string_view metric_name) const {
  if (!metric_spec_map_.contains(metric_name)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Metric ", metric_name, " not found in input spec."));
  }
  return static_cast<size_t>(flat_histogram_bin_count_);
}

}  // namespace willow
}  // namespace secure_aggregation
