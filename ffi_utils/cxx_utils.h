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

#ifndef SECURE_AGGREGATION_FFI_UTILS_CXX_UTILS_H_
#define SECURE_AGGREGATION_FFI_UTILS_CXX_UTILS_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "include/cxx.h"

namespace secure_aggregation {

// Clones a std::string behind a unique_ptr, for compatibility with CXX.
inline std::unique_ptr<std::string> CloneString(const std::string& x) {
  return std::make_unique<std::string>(x);
}

// Returns a reference to an empty std::string.
inline const std::string& EmptyString() {
  static std::string* x = new std::string();
  return *x;
}

// Converts a StringView to an absl::string_view.
inline absl::string_view ToAbslStringView(rust::Slice<const uint8_t> sv) {
  return absl::string_view(reinterpret_cast<const char*>(sv.data()), sv.size());
}

// Converts an absl::string_view to a Rust u8 slice.
inline rust::Slice<const uint8_t> ToRustSlice(absl::string_view sv) {
  return rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(sv.data()),
                                    sv.size());
}

}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_FFI_UTILS_CXX_UTILS_H_
