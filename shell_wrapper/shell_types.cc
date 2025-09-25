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

#include "shell_wrapper/shell_types.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "absl/log/log.h"
#include "absl/numeric/int128.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "shell_encryption/int256.h"
#include "shell_encryption/rns/crt_interpolation.h"
#include "shell_wrapper/shell_aliases.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/status.h"
#include "shell_wrapper/status.rs.h"

namespace secure_aggregation {

RnsContextConfig ParseRnsContextConfig(uint64_t log_n, uint64_t t,
                                       const uint64_t* qs, uint64_t num_qs) {
  RnsContextConfig config = {
      .log_n = static_cast<int>(log_n), .qs = {}, .t = t};
  if (qs == nullptr) {
    return config;
  }
  for (int i = 0; i < num_qs; ++i) {
    config.qs.push_back(qs[i]);
  }
  return config;
}

}  // namespace secure_aggregation

using secure_aggregation::MakeFfiStatus;

FfiStatus WriteSmallRnsPolynomialToBuffer(const RnsPolynomialWrapper* poly,
                                          ModuliWrapper moduli,
                                          uint64_t buffer_len, int64_t* buffer,
                                          uint64_t* n_written) {
  if (poly == nullptr || poly->ptr == nullptr || buffer == nullptr ||
      n_written == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  if (poly->ptr->IsNttForm()) {
    absl::Status status =
        poly->ptr->ConvertToCoeffForm({moduli.moduli, moduli.len});
    if (!status.ok()) {
      return MakeFfiStatus(status);
    }
  }

  for (int i = 0; i < moduli.len; ++i) {
    const auto& coeffs = poly->ptr->Coeffs()[i];
    uint64_t q = moduli.moduli[i]->Modulus();
    uint64_t q_half = q >> 1;

    if (i == 0) {
      // We write to the buffer only for the first modulus.
      *n_written = std::min(static_cast<size_t>(buffer_len), coeffs.size());
    }

    for (int j = 0; j < *n_written; ++j) {
      // For a small integer c, |c| mod q = |c|.
      uint64_t value = coeffs[j].ExportInt(moduli.moduli[i]->ModParams());
      int64_t signed_value;
      if (value < q_half) {
        signed_value = static_cast<int64_t>(value);
      } else {
        // Larger values (but still smaller than q, since ExportInt outputs in
        // the range [0, q]) are represented as negative integers. E.g. q =
        // 1125899906826241, value = 1125899906826240 gives signed_value = -1.
        signed_value = -static_cast<int64_t>(q - value);
      }

      if (i == 0) {
        // Write down to buffer. Technically we only need the first modulus.
        buffer[j] = signed_value;
      } else {
        // But check that the other moduli are consistent with the first one.
        if (signed_value != buffer[j]) {
          return MakeFfiStatus(absl::InvalidArgumentError(
              "Coefficients don't match across moduli, not a small "
              "polynomial."));
        }
      }
    }
  }

  return MakeFfiStatus();
}

FfiStatus ReadSmallRnsPolynomialFromBuffer(const int64_t* buffer,
                                           uint64_t buffer_len,
                                           uint64_t num_coeffs,
                                           ModuliWrapper moduli,
                                           RnsPolynomialWrapper* out) {
  if (buffer == nullptr || out == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  if (buffer_len > num_coeffs) {
    return MakeFfiStatus(
        absl::InvalidArgumentError("Buffer has too many coefficients, it does "
                                   "not fit in one polynomial."));
  }

  int num_moduli = moduli.len;
  std::vector<std::vector<secure_aggregation::ModularInt>> coeffs(num_moduli);
  for (int j = 0; j < num_coeffs; ++j) {
    int64_t value = 0;  // Pad unused coeffs with 0s.
    if (j < buffer_len) {
      value = buffer[j];
    }
    // Convert `value` to balanced representation mod q_i for each q_i.
    for (int i = 0; i < num_moduli; ++i) {
      auto q_i = moduli.moduli[i];
      uint64_t unsigned_value;
      if (value >= 0) {
        unsigned_value = static_cast<uint64_t>(value);
      } else {
        // -q_i < value < 0 for small polynomial, so r.h.s. is positive.
        unsigned_value =
            static_cast<uint64_t>(static_cast<int64_t>(q_i->Modulus()) + value);
      }
      auto value_mod_qi = secure_aggregation::ModularInt::ImportInt(
          unsigned_value, q_i->ModParams());
      if (!value_mod_qi.ok()) {
        return MakeFfiStatus(value_mod_qi.status());
      }
      coeffs[i].push_back(value_mod_qi.value());
    }
  }
  auto poly = secure_aggregation::RnsPolynomial::Create(std::move(coeffs),
                                                        /*is_ntt=*/false);
  if (!poly.ok()) {
    return MakeFfiStatus(poly.status());
  }
  out->ptr = std::make_unique<secure_aggregation::RnsPolynomial>(
      std::move(poly.value()));
  return MakeFfiStatus();
}

FfiStatus AddInPlace(ModuliWrapper moduli, const RnsPolynomialWrapper* in,
                     RnsPolynomialWrapper* out) {
  if (in == nullptr || out == nullptr || in->ptr == nullptr ||
      out->ptr == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }
  if (absl::Status status =
          out->ptr->AddInPlace(*in->ptr, {moduli.moduli, moduli.len});
      !status.ok()) {
    return MakeFfiStatus(std::move(status));
  }
  return MakeFfiStatus();
}

FfiStatus AddInPlaceVec(ModuliWrapper moduli, const RnsPolynomialVecWrapper* in,
                        RnsPolynomialVecWrapper* out) {
  if (in == nullptr || out == nullptr || in->ptr == nullptr ||
      out->ptr == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }
  if (in->ptr->size() != out->ptr->size()) {
    return MakeFfiStatus(
        absl::InvalidArgumentError("`in` and `out` must have the same size."));
  }
  for (int i = 0; i < in->ptr->size(); ++i) {
    absl::Status status =
        out->ptr->at(i).AddInPlace(in->ptr->at(i), {moduli.moduli, moduli.len});
    if (!status.ok()) {
      return MakeFfiStatus(std::move(status));
    }
  }
  return MakeFfiStatus();
}

FfiStatus WriteRnsPolynomialToBuffer128(
    const secure_aggregation::RnsContext* rns_context,
    const RnsPolynomialWrapper* poly, uint64_t buffer_len, uint64_t* buffer) {
  if (buffer == nullptr || poly == nullptr || rns_context == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }
  const uint64_t expected_buffer_len = 2 * poly->ptr->NumCoeffs();
  if (buffer_len != expected_buffer_len) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        absl::StrCat("Expected `buffer_len` == ", expected_buffer_len,
                     " (poly->ptr->NumCoeffs() * 2), but got ", buffer_len)));
  }

  // Convert poly to coefficient form if necessary.
  RnsPolynomialWrapper poly_coefficient_form;
  if (poly->ptr->IsNttForm()) {
    poly_coefficient_form.ptr =
        std::make_unique<secure_aggregation::RnsPolynomial>(*poly->ptr);
    absl::Status status = poly_coefficient_form.ptr->ConvertToCoeffForm(
        rns_context->MainPrimeModuli());
    if (!status.ok()) {
      return MakeFfiStatus(status);
    }
    poly = &poly_coefficient_form;
  }

  // Compute `modulus_hats` and `modulus_hat_invs`.
  auto moduli = rns_context->MainPrimeModuli();
  absl::StatusOr<std::vector<rlwe::uint256>> modulus_hats =
      rlwe::RnsModulusComplements<secure_aggregation::ModularInt,
                                  rlwe::uint256>(moduli);
  if (!modulus_hats.ok()) {
    return MakeFfiStatus(modulus_hats.status());
  }
  absl::StatusOr<std::vector<secure_aggregation::ModularInt>> modulus_hat_invs =
      rns_context->MainPrimeModulusCrtFactors(moduli.size() - 1);
  if (!modulus_hat_invs.ok()) {
    return MakeFfiStatus(modulus_hat_invs.status());
  }

  // Interpolate `poly`.
  absl::StatusOr<std::vector<rlwe::uint256>> interpolated_coeffs =
      rlwe::CrtInterpolation<secure_aggregation::ModularInt, rlwe::uint256>(
          poly->ptr->Coeffs(), moduli, *modulus_hats, *modulus_hat_invs);
  if (!interpolated_coeffs.ok()) {
    return MakeFfiStatus(interpolated_coeffs.status());
  }

  // Safety check that the number of interpolated coefficients doesn't overflow
  // the buffer. Should always pass as long as CrtInterpolation is correct,
  // since `buffer_len` is validated above.
  if (interpolated_coeffs->size() * 2 > buffer_len) {
    return MakeFfiStatus(absl::InternalError(absl::StrCat(
        "2 * interpolated_coeffs->size() (=", interpolated_coeffs->size(),
        ") > buffer_len (=", buffer_len, ")")));
  }
  // Write coefficients to buffer.
  for (int i = 0; i < interpolated_coeffs->size(); ++i) {
    const auto& coeff = (*interpolated_coeffs)[i];
    if (rlwe::Uint256High128(coeff) != 0) {
      return MakeFfiStatus(absl::InvalidArgumentError(
          "Coefficient cannot be larger than 128 bits"));
    }
    absl::uint128 coeff_128 = rlwe::Uint256Low128(coeff);
    buffer[2 * i] = absl::Uint128Low64(coeff_128);
    buffer[2 * i + 1] = absl::Uint128High64(coeff_128);
  }

  return {};
}

RnsPolynomialWrapper CloneRnsPolynomialWrapper(const RnsPolynomialWrapper* in) {
  return RnsPolynomialWrapper{
      .ptr = std::make_unique<secure_aggregation::RnsPolynomial>(
          in->ptr->Clone())};
}

RnsPolynomialVecWrapper CloneRnsPolynomialVecWrapper(
    const RnsPolynomialVecWrapper* in) {
  RnsPolynomialVecWrapper result{
      .len = in->len,
      .ptr = std::make_unique<std::vector<secure_aggregation::RnsPolynomial>>(),
  };
  result.ptr->reserve(in->ptr->size());
  for (const auto& poly : *in->ptr) {
    result.ptr->push_back(poly.Clone());
  }
  return result;
}
