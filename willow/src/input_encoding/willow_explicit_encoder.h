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

#ifndef SECURE_AGGREGATION_WILLOW_SRC_INPUT_ENCODING_WILLOW_EXPLICIT_ENCODER_H_
#define SECURE_AGGREGATION_WILLOW_SRC_INPUT_ENCODING_WILLOW_EXPLICIT_ENCODER_H_

#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "willow/proto/willow/input_spec.proto.h"

namespace secure_aggregation {
namespace willow {

using InputSpec =
    ::third_party_secure_aggregation_willow_proto_willow::InputSpec;

class WillowInputEncoder {
 public:
  virtual ~WillowInputEncoder() = default;

  virtual absl::StatusOr<std::unordered_map<std::string, std::vector<int64_t>>>
  Encode() const = 0;

  virtual absl::StatusOr<
      std::pair<std::unordered_map<std::string, std::vector<int64_t>>,
                std::unordered_map<std::string, std::vector<std::string>>>>
  Decode(const std::unordered_map<std::string, std::vector<int64_t>>&
             encoded_data) const = 0;
};

// WillowInputExplicitEncoder must be instantiated through the factory class
// WillowInputEncoderFactory.
class WillowInputExplicitEncoder : public WillowInputEncoder {
 public:
  WillowInputExplicitEncoder(const WillowInputExplicitEncoder&) = delete;
  WillowInputExplicitEncoder& operator=(const WillowInputExplicitEncoder&) =
      delete;
  ~WillowInputExplicitEncoder() override = default;

  absl::StatusOr<std::unordered_map<std::string, std::vector<int64_t>>> Encode()
      const override;

  absl::StatusOr<
      std::pair<std::unordered_map<std::string, std::vector<int64_t>>,
                std::unordered_map<std::string, std::vector<std::string>>>>
  Decode(const std::unordered_map<std::string, std::vector<int64_t>>&
             encoded_data) const override;

 private:
  const std::unordered_map<std::string, std::vector<int64_t>> input_data_;
  const std::unordered_map<std::string, std::vector<std::string>>
      group_by_data_;
  const InputSpec input_spec_;

  WillowInputExplicitEncoder(
      const std::unordered_map<std::string, std::vector<int64_t>>& input_data,
      const std::unordered_map<std::string, std::vector<std::string>>&
          group_by_data,
      const InputSpec& input_spec)
      : input_data_(input_data),
        group_by_data_(group_by_data),
        input_spec_(input_spec) {}
  friend class WillowInputEncoderFactory;
};

}  // namespace willow
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_SRC_INPUT_ENCODING_WILLOW_EXPLICIT_ENCODER_H_
