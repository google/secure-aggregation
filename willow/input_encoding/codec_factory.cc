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

#include "willow/input_encoding/codec_factory.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "willow/input_encoding/codec.h"
#include "willow/proto/willow/input_spec.pb.h"

namespace secure_aggregation {
namespace willow {

using InputSpec = ::secure_aggregation::willow::InputSpec;
using InputVectorSpec =
    ::secure_aggregation::willow::InputSpec::InputVectorSpec;

// Custom struct for keying group-by domain indices.
struct GroupDomainKey {
  std::string group_name;
  std::string domain_value;

  template <typename H>
  friend H AbslHashValue(H h, const GroupDomainKey& k) {
    return H::combine(std::move(h), k.group_name, k.domain_value);
  }

  bool operator==(const GroupDomainKey& other) const {
    return group_name == other.group_name && domain_value == other.domain_value;
  }
};

// WillowInputExplicitEncoder must be instantiated through the factory class
// CodecFactory.
class ExplicitCodecImpl : public Codec {
 public:
  ExplicitCodecImpl(const ExplicitCodecImpl&) = delete;
  ExplicitCodecImpl& operator=(const ExplicitCodecImpl&) = delete;
  ~ExplicitCodecImpl() override = default;

  absl::StatusOr<EncodedData> Encode(
      const GroupData& group_by_data,
      const MetricData& metric_data) const override;

  absl::StatusOr<DecodedData> Decode(
      const EncodedData& encoded_data) const override;

 private:
  InputSpec input_spec_;
  // Map of group-by key names to their specs.
  absl::flat_hash_map<std::string, const InputVectorSpec*> group_by_spec_map_;
  // Map of metric key names to their specs.
  absl::flat_hash_map<std::string, const InputVectorSpec*> metric_spec_map_;
  std::int64_t flattened_domain_size_;
  // The names of the group-by keys, sorted.
  std::vector<std::string> group_by_keys_;
  // The size of the string domains for each group-by key. The order is the same
  // as in `group_by_keys_`.
  std::vector<int> group_by_domain_sizes_;
  // The indices within their respective domain of each group-by key.
  absl::flat_hash_map<GroupDomainKey, int> group_by_domain_indices_;

  absl::Status ValidateData(const GroupData& group_by_data,
                            const MetricData& metric_data) const;

  std::vector<int> GetIndices(int global_index) const;

  size_t GetCombinedIndex(const std::vector<int>& indices) const;

  explicit ExplicitCodecImpl(
      InputSpec input_spec,
      absl::flat_hash_map<std::string, const InputVectorSpec*>
          group_by_spec_map,
      absl::flat_hash_map<std::string, const InputVectorSpec*> metric_spec_map)
      : input_spec_(std::move(input_spec)),
        group_by_spec_map_(std::move(group_by_spec_map)),
        metric_spec_map_(std::move(metric_spec_map)) {
    group_by_keys_.reserve(group_by_spec_map_.size());
    // Compute sorted group-by keys.
    for (const auto& [key, spec] : group_by_spec_map_) {
      group_by_keys_.push_back(spec->vector_name());
      // Precompute indices into domains to allow efficient lookups.
      const auto& domain = spec->domain_spec().string_values();
      for (int i = 0; i < domain.values_size(); ++i) {
        group_by_domain_indices_[GroupDomainKey{spec->vector_name(),
                                                domain.values(i)}] = i;
      }
    }
    std::sort(group_by_keys_.begin(), group_by_keys_.end());
    // Compute the sizes of the string domains for each group-by key.
    flattened_domain_size_ = 1;
    group_by_domain_sizes_.reserve(group_by_keys_.size());
    for (const auto& key : group_by_keys_) {
      auto spec_it = group_by_spec_map_.find(key);
      CHECK(spec_it !=
            group_by_spec_map_.end());  // We expect the key to be present.
      int domain_size =
          spec_it->second->domain_spec().string_values().values_size();
      group_by_domain_sizes_.push_back(domain_size);
      flattened_domain_size_ *= domain_size;
    }
  }
  friend class CodecFactory;
};

absl::Status ExplicitCodecImpl::ValidateData(
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
    if (!group_by_spec_map_.contains(name)) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Key ", name, " found in group_by_data but not in input_spec."));
    }
  }

  // Check that:
  // 1. all provided vectors in metric_data, group_by_data, and in
  // input_spec have the same length, and that the length is greater than 0.
  // 2. all metric vector names in metric_data are present in input_spec.
  // 3. all group-by vector names in group_by_data are present in input_spec.
  // 4. metric vectors have type INT64.
  // 5. group-by vectors have type STRING.
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
    if (spec->data_type() != InputSpec::INT64) {
      return absl::InvalidArgumentError(
          absl::StrCat("Type mismatch for key ", name,
                       ": metric_data type is int64_t but input_spec type "
                       "is not INT64, it is ",
                       spec->data_type()));
    }
  }

  for (const auto& [name, data] : group_by_data) {
    if (data.size() != vector_size) {
      return absl::InvalidArgumentError(
          "All metric and group-by vectors must have the same length.");
    }
    auto it = group_by_spec_map_.find(name);
    if (it == group_by_spec_map_.end()) {
      return absl::InternalError(absl::StrCat(
          "Key ", name, " found in group_by_data but not in input_spec."));
    }
    const auto& spec = it->second;
    if (spec->data_type() != InputSpec::STRING) {
      return absl::InvalidArgumentError(
          absl::StrCat("Type mismatch for key ", name,
                       ": group_by_data type is string but input_spec type is "
                       "not STRING."));
    }
    // Check that all values in group_by_data are in the domain provided in the
    // input_spec.
    for (const auto& d : data) {
      if (!group_by_domain_indices_.contains(GroupDomainKey{name, d})) {
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
std::vector<int> ExplicitCodecImpl::GetIndices(int global_index) const {
  if (group_by_domain_sizes_.empty()) {
    return {};
  }
  std::vector<int> indices =
      std::vector<int>(group_by_domain_sizes_.size(), -1);
  int64_t current_index = global_index;
  for (int i = group_by_domain_sizes_.size() - 1; i >= 0; --i) {
    indices[i] = current_index % group_by_domain_sizes_[i];
    current_index /= group_by_domain_sizes_[i];
  }
  return indices;
}

// Returns the index of an element in the cartesian product of domains of size
// `sizes`, given the indices of the elements  the individual domains.
// E.g., if sizes = {2, 3} and indices = {1, 0}, this implies we have two
// domains of size 2 and 3 respectively, and we want to find overall index of
// an element that has index 1 in the first domain and index 0 in the second
// domain. The function will return 1 * 3 + 0 = 3.
size_t ExplicitCodecImpl::GetCombinedIndex(
    const std::vector<int>& indices) const {
  int64_t combined_index = 0;
  for (int i = 0; i < indices.size(); ++i) {
    combined_index *= group_by_domain_sizes_[i];
    combined_index += indices[i];
  }
  return combined_index;
}

absl::StatusOr<EncodedData> ExplicitCodecImpl::Encode(
    const GroupData& group_by_data, const MetricData& metric_data) const {
  if (absl::Status status = ValidateData(group_by_data, metric_data);
      !status.ok()) {
    return status;
  }

  absl::flat_hash_map<std::string, std::vector<int64_t>> result;
  if (group_by_keys_.empty()) {
    // No group-by dimensions, so encoding is just a copy of metric_data.
    for (const auto& [metric_name, values] : metric_data) {
      result[metric_name] = values;
    }
  } else {
    for (const auto& [metric_name, values] : metric_data) {
      result[metric_name] = std::vector<int64_t>(flattened_domain_size_, 0);
      for (int i = 0; i < values.size(); ++i) {
        std::vector<int> indices;
        indices.reserve(group_by_keys_.size());
        for (const auto& group_name : group_by_keys_) {
          auto it_data = group_by_data.find(group_name);
          CHECK(it_data != group_by_data.end());
          auto key = it_data->second[i];
          auto it =
              group_by_domain_indices_.find(GroupDomainKey{group_name, key});
          // ValidateData ensures the key exists in the domain.
          indices.push_back(it->second);
        }
        result[metric_name][GetCombinedIndex(indices)] = values[i];
      }
    }
  }
  return result;
}

absl::StatusOr<DecodedData> ExplicitCodecImpl::Decode(
    const EncodedData& encoded_data) const {
  DecodedData decoded_data;

  if (group_by_keys_.empty()) {
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
    if (values.size() != flattened_domain_size_) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Encoded data for metric ", name, " has wrong size: expected ",
          flattened_domain_size_, ", got ", values.size()));
    }
  }

  for (int i = 0; i < flattened_domain_size_; ++i) {
    bool has_nonzero_metric = false;
    for (const auto& [metric_name, values] : encoded_data) {
      if (values[i] != 0) {
        has_nonzero_metric = true;
        break;
      }
    }
    if (has_nonzero_metric) {
      std::vector<int> indices = GetIndices(i);
      for (int j = 0; j < group_by_keys_.size(); ++j) {
        const auto& key_name = group_by_keys_[j];
        auto spec_it = group_by_spec_map_.find(key_name);
        CHECK(spec_it != group_by_spec_map_.end());
        const auto& domain = spec_it->second->domain_spec().string_values();
        // Check that the index is in the domain.
        if (indices[j] >= domain.values_size()) {
          return absl::InvalidArgumentError(absl::StrCat(
              "Index ", indices[j], " for key ", key_name, " is out of bounds ",
              "[0, ", domain.values_size(), ")."));
        }
        decoded_data.group_data[key_name].push_back(domain.values(indices[j]));
      }
      for (const auto& [metric_name, values] : encoded_data) {
        decoded_data.metric_data[metric_name].push_back(values[i]);
      }
    }
  }
  return decoded_data;
}

absl::StatusOr<std::unique_ptr<Codec>> CodecFactory::CreateExplicitCodec(
    InputSpec input_spec, size_t max_flattened_domain_size) {
  // Check that the combined size of the string domains is less than the
  // maximum allowed size.
  size_t flattened_domain_size = 1;
  for (const auto& spec : input_spec.group_by_vector_specs()) {
    flattened_domain_size *= spec.domain_spec().string_values().values_size();
    if (max_flattened_domain_size < flattened_domain_size) {
      return absl::InvalidArgumentError(
          "Global output domain size exceeds maximum threshold.");
    }
  }
  // Check that specs include at least one metric vector.
  if (input_spec.metric_vector_specs().empty()) {
    return absl::InvalidArgumentError(
        "input_spec must include at least one metric vector.");
  }
  // Construct maps of vector names to specs, and checks for duplicates.
  absl::flat_hash_map<std::string, const InputVectorSpec*> group_by_spec_map;
  for (const auto& spec : input_spec.group_by_vector_specs()) {
    if (!group_by_spec_map.insert({spec.vector_name(), &spec}).second) {
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
  return absl::WrapUnique(new ExplicitCodecImpl(std::move(input_spec),
                                                std::move(group_by_spec_map),
                                                std::move(metric_spec_map)));
}

}  // namespace willow
}  // namespace secure_aggregation
