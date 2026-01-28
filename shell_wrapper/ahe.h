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

#ifndef SECURE_AGGREGATION_SHELL_WRAPPER_AHE_H_
#define SECURE_AGGREGATION_SHELL_WRAPPER_AHE_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "absl/strings/string_view.h"
#include "ffi_utils/status.h"
#include "include/cxx.h"
#include "shell_encryption/multi_party/public_parameter.h"
#include "shell_encryption/rns/coefficient_encoder.h"
#include "shell_encryption/rns/rns_error_params.h"
#include "shell_encryption/sampler/discrete_gaussian.h"
#include "shell_wrapper/ahe.rs.h"
#include "shell_wrapper/shell_aliases.h"
#include "shell_wrapper/shell_types.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/single_thread_hkdf.h"

namespace secure_aggregation {

// Creates AHE public parameters. `log_n`, `t`, `qs` and `num_qs` are the
// parameters of the RNS context. `error_variance` is the variance of
// the error distribution used to generate the public key and the ciphertext
// components. `s_base_flood` and `s_flood` are used for partial decryption.
// `seed` is the seed used to generate the public parameter (polynomial) u.
// Writes the result to `out` and returns a wrapped absl::Status.
FfiStatus CreateAhePublicParameters(uint64_t log_n, uint64_t t,
                                    const uint64_t* qs, uint64_t num_qs,
                                    uint64_t error_variance,
                                    double s_base_flood, double s_flood,
                                    rust::Slice<const uint8_t> seed,
                                    AhePublicParameters* out);

// Creates a moduli wrapper pointing to the moduli in the public parameters, for
// polynomial operations.
inline ModuliWrapper CreateModuliWrapperFromAheParams(
    const AhePublicParameters& params) {
  auto moduli = params.rlwe_public_parameter->Moduli();
  return ModuliWrapper{.moduli = moduli.data(), .len = moduli.size()};
}

// Returns the plaintext modulus from the public parameters.
inline uint64_t GetPlaintextModulusFromAheParams(
    const AhePublicParameters& params) {
  return params.rns_context->PlaintextModulus();
}

// Creates a `const secure_aggregation::RnsContext*` pointing to the RNS
// context in the public parameters, for polynomial operations.
inline const secure_aggregation::RnsContext* GetRnsContextFromAheParams(
    const AhePublicParameters& params) {
  return params.rns_context.get();
}

// Generates a secret key share.
FfiStatus GenerateSecretKeyShare(const AhePublicParameters& params,
                                 SingleThreadHkdfWrapper* prng,
                                 RnsPolynomialWrapper* out);

// Generates a public key share `public_key_share_b`, and stores the error in
// `public_key_share_error` (for ZK proofs), optionally reports the wraparound
// as well. Returns a wrapped absl::Status. secret_key_share, params and prng
// must all be non-null pointers to valid objects which survive until the
// function returns.
FfiStatus GeneratePublicKeyShareWrapper(
    const RnsPolynomialWrapper& secret_key_share,
    const AhePublicParameters& params, SingleThreadHkdfWrapper* prng,
    RnsPolynomialWrapper* public_key_share_b,
    RnsPolynomialWrapper* public_key_share_error,
    RnsPolynomialWrapper* wraparound);

// Encodes the input values and encrypts them using the public key
// `public_key_b`, which is obtained by summing `public_key_shares_b` from all
// parties. Stores the two components of the
// ciphertext in `ciphertext_component_b` (a.k.a. ct0) and
// `ciphertext_component_a` (a.k.a. ct1). Also stores the secret and error for
// ZK proofs. Returns a wrapped absl::Status.
FfiStatus AheEncrypt(const uint64_t* input_values, uint64_t num_input_values,
                     const RnsPolynomialWrapper& public_key_b,
                     const AhePublicParameters& params,
                     SingleThreadHkdfWrapper* prng,
                     RnsPolynomialWrapper* ciphertext_component_b,
                     RnsPolynomialWrapper* ciphertext_component_a,
                     RnsPolynomialWrapper* ciphertext_secret_r,
                     RnsPolynomialWrapper* ciphertext_error_e,
                     RnsPolynomialWrapper* wraparound);

// Computes the partial decryption of a ciphertext component A. Writes the
// result to `out` and returns a wrapped absl::Status.
FfiStatus PartialDecrypt(const RnsPolynomialWrapper& ciphertext_component_a,
                         const RnsPolynomialWrapper& secret_key_share,
                         const AhePublicParameters& params,
                         SingleThreadHkdfWrapper* prng,
                         RnsPolynomialWrapper* out,
                         RnsPolynomialWrapper* error_flood,
                         RnsPolynomialWrapper* wraparound);

// Recovers messages from a sum of partial decryptions (unlike the public SHELL
// API, which takes a span of partial decryptions). That allows the server to
// accumulate ciphertexts as they come, by calling the usual AddInPlace.
// function, and recover at the end.
FfiStatus RecoverMessages(const RnsPolynomialWrapper& sum_partial_decryptions,
                          const RnsPolynomialWrapper& ciphertext_component_b,
                          const AhePublicParameters& params,
                          uint64_t output_values_length,
                          uint64_t* output_values, uint64_t* n_written);

// Creates a zero polynomial with the same RNS parameters as `params`. Writes
// the result to `out` and returns a wrapped absl::Status.
FfiStatus CreateZeroRnsPolynomialWrapper(const AhePublicParameters& params,
                                         RnsPolynomialWrapper* out);

// Adds `in` to `out` in place.
FfiStatus AddInPlace(const AhePublicParameters& params,
                     const RnsPolynomialWrapper& in, RnsPolynomialWrapper* out);

/// Returns the public key component A from the given parameters.
FfiStatus PublicKeyComponentA(const AhePublicParameters& params,
                              RnsPolynomialWrapper* out);

// Returns the s_flood parameter from the given parameters. Returns
// INVALID_ARGUMENT if `out` is null.
FfiStatus SFlood(const AhePublicParameters& params, double* out);

}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_SHELL_WRAPPER_AHE_H_
