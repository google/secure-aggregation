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

#include "shell_wrapper/single_thread_hkdf.h"

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "ffi_utils/cxx_utils.h"
#include "ffi_utils/status.h"
#include "include/cxx.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_wrapper/shell_types.h"
#include "shell_wrapper/single_thread_hkdf.rs.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"

namespace secure_aggregation {

FfiStatus GenerateSingleThreadHkdfSeed(std::unique_ptr<std::string>& out) {
  auto statusor = rlwe::SingleThreadHkdfPrng::GenerateSeed();
  if (!statusor.ok()) {
    return MakeFfiStatus(std::move(statusor.status()));
  };
  out = std::make_unique<std::string>(*std::move(statusor));
  return MakeFfiStatus();
}
FfiStatus CreateSingleThreadHkdf(rust::Slice<const uint8_t> seed,
                                 SingleThreadHkdfWrapper& out) {
  auto statusor = rlwe::SingleThreadHkdfPrng::Create(ToAbslStringView(seed));
  if (!statusor.ok()) {
    return MakeFfiStatus(std::move(statusor).status());
  }
  out.ptr = *std::move(statusor);
  return MakeFfiStatus();
}

FfiStatus Rand8(SingleThreadHkdfWrapper& prng, uint8_t& out) {
  if (prng.ptr == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }
  auto statusor = prng.ptr->Rand8();
  if (!statusor.ok()) {
    return MakeFfiStatus(std::move(statusor).status());
  }
  out = *statusor;
  return MakeFfiStatus();
}

size_t SingleThreadHkdfSeedLength() {
  return rlwe::SingleThreadHkdfPrng::SeedLength();
}
FfiStatus ComputeHkdfWrapper(rust::Slice<const uint8_t> input,
                             rust::Slice<const uint8_t> salt,
                             rust::Slice<const uint8_t> info, size_t out_len,
                             std::unique_ptr<std::string>& out) {
  auto statusor = crypto::tink::subtle::Hkdf::ComputeHkdf(
      crypto::tink::subtle::SHA256, ToAbslStringView(input),
      ToAbslStringView(salt), ToAbslStringView(info), out_len);
  if (!statusor.ok()) {
    return MakeFfiStatus(std::move(statusor).status());
  }
  out = std::make_unique<std::string>(*std::move(statusor));
  return MakeFfiStatus();
}

}  // namespace secure_aggregation
