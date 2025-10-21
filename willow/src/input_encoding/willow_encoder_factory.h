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

#ifndef SECURE_AGGREGATION_WILLOW_SRC_INPUT_ENCODING_WILLOW_ENCODER_FACTORY_H_
#define SECURE_AGGREGATION_WILLOW_SRC_INPUT_ENCODING_WILLOW_ENCODER_FACTORY_H_
#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "willow/proto/willow/input_spec.proto.h"
#include "willow/src/input_encoding/willow_explicit_encoder.h"

namespace secure_aggregation {
namespace willow {

using ::third_party_secure_aggregation_willow_proto_willow::InputSpec;
using InputVectorSpec = ::third_party_secure_aggregation_willow_proto_willow::
    InputSpec_InputVectorSpec;

// The maximum size of the Cartesian product of domains for string features.
constexpr int64_t kMaxGlobalOutputDomainSize = 1000000;

// Factory class that constructs non-copyable instances of children classes of
// WillowInputEncoder.
class WillowInputEncoderFactory {
 public:
  static absl::Status ValidateInputAndSpec(
      const std::unordered_map<std::string, std::vector<int64_t>>& input_data,
      const std::unordered_map<std::string, std::vector<std::string>>&
          group_by_data,
      const InputSpec input_spec) {
    // Check that input_data is not empty
    if (input_data.empty()) {
      return absl::InvalidArgumentError("input_data must not be empty.");
    }
    // Check that all provided vectors in input_data, group_by_data, and in
    // input_spec have the same length
    int l = input_data.begin()->second.size();
    for (const auto& [name, data] : input_data) {
      if (data.size() != l) {
        return absl::InvalidArgumentError(
            "All input and group_by vectors must have the same length.");
      }
    }
    for (const auto& [name, data] : group_by_data) {
      if (data.size() != l) {
        return absl::InvalidArgumentError(
            "All input and group_b vectors must have the same length.");
      }
    }

    // Check that input_data and group_by_data together have the same keys as
    // input_spec, their data types match, and the type is either int or string.
    if (input_data.size() + group_by_data.size() !=
        input_spec.input_vector_specs_size()) {
      return absl::InvalidArgumentError(
          "input_spec must have the same number of entries as the sum of "
          "entries in input_data and group_by_data.");
    }

    std::unordered_map<std::string, const InputVectorSpec*> spec_map;
    for (const auto& spec : input_spec.input_vector_specs()) {
      spec_map[spec.vector_name()] = &spec;
    }

    for (const auto& [name, data] : input_data) {
      auto it = spec_map.find(name);
      if (it == spec_map.end()) {
        return absl::InvalidArgumentError(absl::StrCat(
            "Key ", name, " found in input_data but not in input_spec."));
      }
      const auto& spec = it->second;
      if (spec->data_type() != InputSpec::INT64) {
        return absl::InvalidArgumentError(
            absl::StrCat("Type mismatch for key ", name,
                         ": input_data type is int64_t but input_spec type "
                         "is not INT64."));
      }
    }

    for (const auto& [name, data] : group_by_data) {
      auto it = spec_map.find(name);
      if (it == spec_map.end()) {
        return absl::InvalidArgumentError(absl::StrCat(
            "Key ", name, " found in group_by_data but not in input_spec."));
      }
      const auto& spec = it->second;
      if (spec->data_type() != InputSpec::STRING) {
        return absl::InvalidArgumentError(absl::StrCat(
            "Type mismatch for key ", name,
            ": group_by_data type is string but input_spec type is "
            "not STRING."));
      }
      for (const auto& d : data) {
        const auto& domain_values =
            spec->domain_spec().string_values().values();
        if (std::find(domain_values.begin(), domain_values.end(), d) ==
            domain_values.end()) {
          return absl::InvalidArgumentError(absl::StrCat(
              "Domain mismatch for key ", name, ": group_by_data value ", d,
              " not found in domain."));
        }
      }
    }

    // Check that the combined size of the string domains is less than the
    // maximum allowed size.
    int64_t encoded_domain_size = 1;
    for (const auto& [name, _] : group_by_data) {
      encoded_domain_size *=
          spec_map.at(name)->domain_spec().string_values().values_size();
      if (kMaxGlobalOutputDomainSize < encoded_domain_size) {
        return absl::InvalidArgumentError(
            "Global output domain size exceeds maximum threshold.");
      }
    }
    return absl::OkStatus();
  }

  // Creates an instance of ExplicitWillowInputEncoder.
  static absl::StatusOr<std::unique_ptr<WillowInputExplicitEncoder>>
  CreateExplicitWillowInputEncoder(
      const std::unordered_map<std::string, std::vector<int64_t>>& input_data,
      const std::unordered_map<std::string, std::vector<std::string>>&
          group_by_data,
      const InputSpec& input_spec) {
    // Check that input_data and input_spec have the same keys, their data
    // types match, and the type is either int or string.
    absl::Status status =
        ValidateInputAndSpec(input_data, group_by_data, input_spec);
    if (!status.ok()) {
      return status;
    }
    return absl::WrapUnique(
        new WillowInputExplicitEncoder(input_data, group_by_data, input_spec));
  }
};

}  // namespace willow
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_SRC_INPUT_ENCODING_WILLOW_ENCODER_FACTORY_H_
