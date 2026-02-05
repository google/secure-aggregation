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
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "ffi_utils/status.rs.h"
#include "include/cxx.h"

namespace secure_aggregation {

FfiStatus MakeFfiStatus() { return FfiStatus{.code = 0, .message = nullptr}; }
FfiStatus MakeFfiStatus(absl::Status status) {
  return FfiStatus{static_cast<int>(status.code()),
                   std::make_unique<std::string>(status.message())};
}
FfiStatus MakeFfiStatus(int code, std::string message) {
  return FfiStatus{code, std::make_unique<std::string>(std::move(message))};
}

absl::Status UnwrapFfiStatus(FfiStatus status) {
  if (status.code == 0) {
    return absl::OkStatus();
  }
  absl::string_view message = "";
  if (status.message != nullptr) {
    message = *status.message;
  }
  return absl::Status(static_cast<absl::StatusCode>(status.code), message);
}

FfiStatus MakeFfiStatus(int32_t code, rust::Slice<const uint8_t> message) {
  return secure_aggregation::MakeFfiStatus(
      code, std::string(message.begin(), message.end()));
}

}  // namespace secure_aggregation
