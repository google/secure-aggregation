/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SECURE_AGGREGATION_SHELL_WRAPPER_KAHE_PARAMETERS_H_
#define SECURE_AGGREGATION_SHELL_WRAPPER_KAHE_PARAMETERS_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "include/cxx.h"
#include "shell_wrapper/shell_aliases.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/status.rs.h"

namespace secure_aggregation {

inline const char kNullPointerErrorMessage[] =
    "All pointer arguments and their wrapped pointers must be non-null.";

// Aggregate type that holds the parameters defining a RNS context.
struct RnsContextConfig {
  int log_n;
  std::vector<Integer> qs;  // main prime moduli.
  Integer t;                // plaintext modulus (irrelevant for KAHE).
};

RnsContextConfig ParseRnsContextConfig(uint64_t log_n, uint64_t t,
                                       const uint64_t* qs, uint64_t num_qs);

}  // namespace secure_aggregation

extern "C" {

// Creates an RnsPolynomialWrapper with an empty polynomial.
inline RnsPolynomialWrapper CreateEmptyRnsPolynomialWrapper() {
  auto poly = secure_aggregation::RnsPolynomial::CreateEmpty();
  return RnsPolynomialWrapper{
      .ptr =
          std::make_unique<secure_aggregation::RnsPolynomial>(std::move(poly))};
}

// Clones the RnsPolynomialWrapper. Used to implement Rust's Clone trait, and
// must only be called from there.
RnsPolynomialWrapper CloneRnsPolynomialWrapper(const RnsPolynomialWrapper* in);

// Clones the RnsPolynomialVecWrapper. Used to implement Rust's Clone trait, and
// must only be called from there.
RnsPolynomialVecWrapper CloneRnsPolynomialVecWrapper(
    const RnsPolynomialVecWrapper* in);

// Takes prime moduli {q_i}, and the RNS representation `poly` of a "small"
// polynomial in Z[X] where each coefficient c \in Z verifies |c| < q_i/2 for
// all q_i. Fills in the buffer with the signed integer
// coefficients of `poly`, stopping at `buffer_len` if the polynomial has more
// coefficients.
// Using signed outputs because it is closer to the true distribution (e.g. the
// output will be -1, 0, 1 instead of 0, 1, 1125899906826240). It seems easier
// to take this as input for ZK proofs. And we can decide how to map to uint64_t
// the most efficient way, e.g. add just enough offset and pack many values in
// one uint64_t.
// NOTE: this is not a general purpose serialization function. It is meant
//    to convert KAHE keys into AHE plaintexts on the same machine. It
//    should also be useful to convert the instances/witnesses to a
//    format usable by a ZK proof library.
FfiStatus WriteSmallRnsPolynomialToBuffer(const RnsPolynomialWrapper* poly,
                                          ModuliWrapper moduli,
                                          size_t buffer_len, int64_t* buffer,
                                          uint64_t* n_written);

//  Takes prime moduli {q_i}, and a buffer of `buffer_len` signed integers,
//  representing the coefficients of a "small" polynomial in Z[X] where each
//  coefficient c \in Z verifies |c| < q_i/2 for all q_i. If successful, writes
//  a RnsPolynomialWrapper containing the polynomial in RNS coefficient form to
//  `out`.
FfiStatus ReadSmallRnsPolynomialFromBuffer(const int64_t* buffer,
                                           uint64_t buffer_len,
                                           uint64_t num_coeffs,
                                           ModuliWrapper moduli,
                                           RnsPolynomialWrapper* out);

// Adds the polynomial `in` to `out` in-place, using the RNS `moduli`. Returns
// an absl status. Useful to aggregate public key shares, but also
// ciphertext components A and B.
FfiStatus AddInPlace(ModuliWrapper moduli, const RnsPolynomialWrapper* in,
                     RnsPolynomialWrapper* out);

// Adds the vector of polynomials `in` to `out` in-place element-wise, using the
// RNS `moduli`. Returns an absl status. Does not fail atomically: if the
// returned status is not OK, the value of `out` is undefined.
FfiStatus AddInPlaceVec(ModuliWrapper moduli, const RnsPolynomialVecWrapper* in,
                        RnsPolynomialVecWrapper* out);

// Converts the given RnsPolynomial `poly` to coefficient form, interpolating
// the coefficients to a single modulus using CRT interpolation. Writes the
// resulting coefficient vector to `buffer`, using two consecutive uint64_t
// words for every coefficient, with the lower half being written first.
// Returns an error if any pointer arguments are null, if any coefficient
// exceeds 128 bits, or if `buffer_len` is not equal to
// `2*poly->ptr->NumCoeffs()`.
FfiStatus WriteRnsPolynomialToBuffer128(
    const secure_aggregation::RnsContext* rns_context,
    const RnsPolynomialWrapper* poly, uint64_t buffer_len, uint64_t* buffer);

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

}  // extern "C"

#endif  // SECURE_AGGREGATION_SHELL_WRAPPER_KAHE_PARAMETERS_H_
