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

#ifndef SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_CODEC_FACTORY_H_
#define SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_CODEC_FACTORY_H_
#include <cstddef>
#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "willow/input_encoding/codec.h"
#include "willow/proto/willow/input_spec.pb.h"

namespace secure_aggregation {
namespace willow {

// The maximum size of the Cartesian product of domains for string features.
constexpr size_t kMaxGlobalOutputDomainSize = 1000000;

// Factory class that constructs non-copyable instances of children classes of
// Codec.
class CodecFactory {
 public:
  // Creates an instance of ExplicitCodec.
  static absl::StatusOr<std::unique_ptr<Codec>> CreateExplicitCodec(
      InputSpec input_spec,
      size_t max_flattened_domain_size = kMaxGlobalOutputDomainSize);
};

}  // namespace willow
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_CODEC_FACTORY_H_
