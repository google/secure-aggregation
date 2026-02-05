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

#include "ffi_utils/status.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "ffi_utils/cxx_utils.h"
#include "ffi_utils/status.rs.h"
#include "include/cxx.h"

namespace secure_aggregation {

FfiStatus MakeFfiStatus() { return FfiStatus{nullptr}; }

FfiStatus MakeFfiStatus(absl::Status status) {
  if (status.ok()) {
    return MakeFfiStatus();
  }
  return FfiStatus{std::make_unique<absl::Status>(std::move(status))};
}

FfiStatus MakeFfiStatus(int32_t code, rust::Slice<const uint8_t> message) {
  return MakeFfiStatus(absl::Status(static_cast<absl::StatusCode>(code),
                                    ToAbslStringView(message)));
}

FfiStatus CloneFfiStatus(const FfiStatus& status) {
  if (status.ptr == nullptr) {
    return MakeFfiStatus();
  }
  return MakeFfiStatus(*status.ptr);
}

absl::Status UnwrapFfiStatus(FfiStatus status) {
  if (status.ptr == nullptr) {
    return absl::OkStatus();
  }
  absl::Status out = std::move(*status.ptr);
  return out;
}

int32_t FfiStatusCode(const FfiStatus& status) {
  if (status.ptr == nullptr) {
    return 0;
  }
  return static_cast<int32_t>(status.ptr->code());
}

rust::Slice<const uint8_t> FfiStatusMessage(const FfiStatus& status) {
  if (status.ptr == nullptr) {
    return rust::Slice<const uint8_t>();
  }
  return rust::Slice<const uint8_t>(
      reinterpret_cast<const uint8_t*>(status.ptr->message().data()),
      status.ptr->message().size());
}

}  // namespace secure_aggregation
