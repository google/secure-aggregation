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

#ifndef SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_CODEC_FACTORY_H_
#define SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_CODEC_FACTORY_H_

#include <cstddef>
#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "willow/input_encoding/codec.h"
#include "willow/proto/willow/input_spec.pb.h"

namespace secure_aggregation {
namespace willow {

class [[deprecated("Use Codec class static methods instead")]] CodecFactory {
 public:
  static absl::StatusOr<std::unique_ptr<Codec>> CreateExplicitCodec(
      InputSpec input_spec) {
    return Codec::CreateFlatHistogramCodec(std::move(input_spec));
  }

  static absl::Status ValidateExplicitCodecInputSpec(
      const InputSpec& input_spec,
      size_t max_flattened_domain_size = kMaxFlatHistogramBins) {
    return Codec::ValidateInputSpec(input_spec, max_flattened_domain_size);
  }
};

}  // namespace willow
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_INPUT_ENCODING_CODEC_FACTORY_H_
