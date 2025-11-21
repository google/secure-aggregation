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

#include "shell_wrapper/shell_serialization.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "include/cxx.h"
#include "shell_encryption/rns/rns_serialization.pb.h"
#include "shell_wrapper/shell_types.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/status.h"
#include "shell_wrapper/status.rs.h"

using secure_aggregation::MakeFfiStatus;

FfiStatus SerializeRnsPolynomialToBytes(const RnsPolynomialWrapper* poly,
                                        ModuliWrapper moduli,
                                        std::unique_ptr<std::string>& out) {
  if (poly == nullptr || poly->ptr == nullptr || moduli.moduli == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        "All pointer arguments and their wrapped pointers must be non-null."));
  }
  auto serialized = poly->ptr->Serialize({moduli.moduli, moduli.len});
  if (!serialized.ok()) {
    return MakeFfiStatus(serialized.status());
  }
  std::string buffer;
  if (!serialized->SerializeToString(&buffer)) {
    return MakeFfiStatus(
        absl::InternalError("Failed to serialize RNS polynomial to string."));
  }
  out = std::make_unique<std::string>(std::move(buffer));
  return MakeFfiStatus();
}

FfiStatus DeserializeRnsPolynomialFromBytes(
    rust::Slice<const uint8_t> serialized_poly, ModuliWrapper moduli,
    RnsPolynomialWrapper* out) {
  if (out == nullptr || out->ptr == nullptr || moduli.moduli == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        "All pointer arguments and their wrapped pointers must be non-null."));
  }
  rlwe::SerializedRnsPolynomial serialized_poly_proto;
  if (!serialized_poly_proto.ParseFromString(
          ToAbslStringView(serialized_poly))) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        "Failed to parse serialized RNS polynomial"));
  }
  auto poly = secure_aggregation::RnsPolynomial::Deserialize(
      serialized_poly_proto, {moduli.moduli, moduli.len});
  if (!poly.ok()) {
    return MakeFfiStatus(poly.status());
  }
  out->ptr = std::make_unique<secure_aggregation::RnsPolynomial>(
      std::move(poly.value()));
  return MakeFfiStatus();
}
