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

#include "willow/src/input_encoding/willow_explicit_encoder.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "willow/proto/willow/input_spec.proto.h"

namespace secure_aggregation {
namespace willow {

using InputVectorSpec = ::third_party_secure_aggregation_willow_proto_willow::
    InputSpec_InputVectorSpec;

struct VectorHasher {
  std::size_t operator()(const std::vector<int>& v) const {
    std::string digest = "";
    for (int i : v) {
      digest += std::to_string(i) + ",";
    }
    return std::hash<std::string>()(digest);
  }
};

// Recursive helper function to generate combinations
void findCombinations(
    const std::vector<int>& sizes, std::vector<std::vector<int>>& result,
    std::vector<int>& currentCombination,
    std::unordered_map<std::vector<int>, int, VectorHasher>& inverse_map,
    int depth) {
  // Base case
  if (depth == sizes.size()) {
    inverse_map[currentCombination] = result.size();
    result.push_back(currentCombination);
    return;
  }

  // Recursive step
  for (int i = 0; i < sizes[depth]; ++i) {
    // Add the current index 'i' to our combination.
    currentCombination.push_back(i);
    // Recurse to handle the next size in the list.
    findCombinations(sizes, result, currentCombination, inverse_map, depth + 1);
    // Backtrack: Remove the element we just added.
    currentCombination.pop_back();
  }
}

std::unordered_map<std::vector<int>, int, VectorHasher> getCombinations(
    const std::vector<int>& sizes) {
  std::vector<std::vector<int>> result;
  std::vector<int> currentCombination;
  std::unordered_map<std::vector<int>, int, VectorHasher> inverse_map;
  findCombinations(sizes, result, currentCombination, inverse_map, 0);
  return inverse_map;
}

absl::StatusOr<std::unordered_map<std::string, std::vector<int64_t>>>
WillowInputExplicitEncoder::Encode() const {
  std::unordered_map<std::string, const InputVectorSpec*> spec_map;
  for (const auto& spec : input_spec_.input_vector_specs()) {
    spec_map[spec.vector_name()] = &spec;
  }

  // Define an ordering of the group-by keys.
  std::vector<std::string> sorted_group_by_keys;
  sorted_group_by_keys.reserve(group_by_data_.size());
  for (const auto& [key, _] : group_by_data_) {
    sorted_group_by_keys.push_back(key);
  }
  std::sort(sorted_group_by_keys.begin(), sorted_group_by_keys.end());

  // Collect the sizes of the string domains for each group-by key.
  std::vector<int> sizes;
  sizes.reserve(sorted_group_by_keys.size());
  for (const auto& key : sorted_group_by_keys) {
    sizes.push_back(
        spec_map.at(key)->domain_spec().string_values().values_size());
  }

  // Generate all combinations of group-by keys. The value of the
  // combination_2_index map is the index of the combination corresponding to
  // the vector of indices.
  std::unordered_map<std::vector<int>, int, VectorHasher> combination_2_index =
      getCombinations(sizes);

  // Compute the total number of elements in the cartesian product of the
  // string domains, which corresponds to the length of the domain once
  // encoded as a vector.
  int64_t encoded_domain_size = 1;
  for (const auto& key : sorted_group_by_keys) {
    encoded_domain_size *=
        spec_map.at(key)->domain_spec().string_values().values_size();
  }
  std::unordered_map<std::string, std::vector<int64_t>> result;
  // iterate over input_data
  for (const auto& [name, data] : input_data_) {
    // initialize the vector for each input_data key
    result[name] = std::vector<int64_t>(encoded_domain_size, 0);
    std::vector<int> indices;
    // iterate over data and copy the corresponding entries to the result
    // vector to their location in the encoded domain
    for (int i = 0; i < data.size(); ++i) {
      indices.clear();
      // iterate over group keys to determine the combination index that
      // correspondss to data[i]
      for (const auto& g_name : sorted_group_by_keys) {
        auto key = group_by_data_.at(g_name)[i];
        // find the index of the key in the string domain. Note that the
        // validation ensures that it is present.
        int index = -1;
        for (int j = 0;
             j <
             spec_map.at(g_name)->domain_spec().string_values().values_size();
             ++j) {
          if (spec_map.at(g_name)->domain_spec().string_values().values(j) ==
              key) {
            index = j;
            break;
          }
        }
        indices.push_back(index);
      }
      result[name][combination_2_index[indices]] = data[i];
    }
  }
  return result;
}

absl::StatusOr<
    std::pair<std::unordered_map<std::string, std::vector<int64_t>>,
              std::unordered_map<std::string, std::vector<std::string>>>>
WillowInputExplicitEncoder::Decode(
    const std::unordered_map<std::string, std::vector<int64_t>>& encoded_data)
    const {
  std::unordered_map<std::string, const InputVectorSpec*> spec_map;
  for (const auto& spec : input_spec_.input_vector_specs()) {
    spec_map[spec.vector_name()] = &spec;
  }

  std::vector<std::string> sorted_group_by_keys;
  sorted_group_by_keys.reserve(group_by_data_.size());
  for (const auto& [key, _] : group_by_data_) {
    sorted_group_by_keys.push_back(key);
  }
  std::sort(sorted_group_by_keys.begin(), sorted_group_by_keys.end());

  std::vector<int> sizes;
  sizes.reserve(sorted_group_by_keys.size());
  for (const auto& key : sorted_group_by_keys) {
    sizes.push_back(
        spec_map.at(key)->domain_spec().string_values().values_size());
  }

  std::vector<std::vector<int>> index_to_combination;
  std::vector<int> currentCombination;
  std::unordered_map<std::vector<int>, int, VectorHasher> combination_to_index;
  findCombinations(sizes, index_to_combination, currentCombination,
                   combination_to_index, 0);

  int64_t encoded_domain_size = 1;
  for (const auto& key : sorted_group_by_keys) {
    encoded_domain_size *=
        spec_map.at(key)->domain_spec().string_values().values_size();
  }

  std::unordered_map<std::string, std::vector<int64_t>> decoded_metrics;
  std::unordered_map<std::string, std::vector<std::string>> decoded_groups;

  for (int i = 0; i < encoded_domain_size; ++i) {
    bool has_nonzero_metric = false;
    for (const auto& [metric_name, data] : encoded_data) {
      if (i >= data.size()) {
        return absl::InvalidArgumentError(
            absl::StrCat("Encoded data for metric ", metric_name,
                         " has wrong size: expected ", encoded_domain_size,
                         ", got ", data.size()));
      }
      if (data.at(i) != 0) {
        has_nonzero_metric = true;
        break;
      }
    }

    if (has_nonzero_metric) {
      const auto& combination = index_to_combination[i];
      for (int j = 0; j < sorted_group_by_keys.size(); ++j) {
        const auto& key_name = sorted_group_by_keys[j];
        int val_idx = combination[j];
        decoded_groups[key_name].push_back(
            spec_map.at(key_name)->domain_spec().string_values().values(
                val_idx));
      }
      for (const auto& [metric_name, data] : encoded_data) {
        decoded_metrics[metric_name].push_back(data.at(i));
      }
    }
  }
  return std::make_pair(decoded_metrics, decoded_groups);
}

}  // namespace willow
}  // namespace secure_aggregation
