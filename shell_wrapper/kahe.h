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

#ifndef SECURE_AGGREGATION_SHELL_WRAPPER_KAHE_VECTOR_H_
#define SECURE_AGGREGATION_SHELL_WRAPPER_KAHE_VECTOR_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "shell_encryption/rns/coefficient_encoder.h"
#include "shell_encryption/rns/rns_modulus.h"
#include "shell_encryption/sampler/discrete_gaussian.h"
#include "shell_wrapper/shell_aliases.h"
#include "shell_wrapper/shell_types.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/single_thread_hkdf.h"

namespace secure_aggregation {
// Forward-declare types for use by the cxx-generated `kahe.rs.h`.
struct KahePublicParameters;
struct BigIntVector;
}  // namespace secure_aggregation

#include "shell_wrapper/kahe.rs.h"

namespace secure_aggregation {

constexpr double kPrgSecretS = 4.5;
constexpr double kPrgErrorS = 6.36396103067893;  // sqrt(2) * 4.5

// Contains the parameters needed for all the KAHE functions.
// Will be passed around and never changes after initialization. Can
// be created from a compact representation, so we won't have to serialize it
// and it will always live in C++. `public_polynomials` is the public "a"
// parameters generated during Setup.
struct KahePublicParameters {
  std::unique_ptr<const RnsContext> context;
  BigInteger plaintext_modulus;
  RnsInt plaintext_modulus_rns;
  std::vector<const rlwe::PrimeModulus<ModularInt>*> moduli;
  std::vector<BigInteger> modulus_hats;
  std::vector<ModularInt> modulus_hats_invs;
  rlwe::CoefficientEncoder<ModularInt> encoder;
  std::vector<RnsPolynomial> public_polynomials;
  std::unique_ptr<rlwe::DiscreteGaussianSampler<Integer>> error_dg_sampler;
};

// Creates new public parameters.
absl::StatusOr<KahePublicParameters> CreateKahePublicParameters(
    const RnsContextConfig& rns_context_config, int log_kahe_plaintext_modulus,
    int num_public_polynomials, absl::string_view public_seed);

// Generates a KAHE secret key.
absl::StatusOr<RnsPolynomial> GenerateSecretKey(
    const KahePublicParameters& params, Prng* prng);

namespace internal {
// Encrypts a properly encoded polynomial.
// Computes c = e * t + m + a * key (mod Q).
// Almost like
// https://github.com/google/shell-encryption/blob/master/shell_encryption/rns/rns_bgv_public_key.h
// but only with the polynomials needed for symmetric encryption.
//
// This is an internal function, so it takes many simple parameters. The user
// will end up calling a wrapper function to pack and encrypt a vector. That
// function will take a struct of parameters.
absl::StatusOr<RnsPolynomial> EncryptPolynomial(
    const RnsPolynomial& plaintext, const RnsPolynomial& secret_key,
    RnsInt plaintext_modulus_rns, int log_n, const RnsPolynomial& a,
    absl::Span<const rlwe::PrimeModulus<ModularInt>* const> moduli,
    const rlwe::DiscreteGaussianSampler<Integer>* dg_sampler, Prng* prng);

// Decrypts a polynomial.
// Computes p = c - a * k (mod t).
absl::StatusOr<RnsPolynomial> DecryptPolynomial(
    const RnsPolynomial& ciphertext, const RnsPolynomial& secret_key,
    const RnsPolynomial& a,
    absl::Span<const rlwe::PrimeModulus<ModularInt>* const> moduli);

}  // namespace internal

// Encrypts a vector of packed messages, where the packed messages are first
// encoded into plaintext polynomials and then encrypted.
absl::StatusOr<std::vector<RnsPolynomial>> EncodeAndEncryptVector(
    const std::vector<BigInteger>& packed_values,
    const RnsPolynomial& secret_key, const KahePublicParameters& params,
    Prng* prng);

// Decrypts a vector of ciphertexts, and returns the concatenated vector of
// decrypted messages.
absl::StatusOr<std::vector<BigInteger>> DecodeAndDecryptVector(
    absl::Span<const RnsPolynomial> ciphertexts,
    const RnsPolynomial& secret_key, const KahePublicParameters& params);

}  // namespace secure_aggregation

extern "C" {

// Creates public parameters, including RNS context.
// log_t is the log2 of the KAHE plaintext modulus.
FfiStatus CreateKahePublicParametersWrapper(uint64_t log_n, uint64_t log_t,
                                            rust::Slice<const uint64_t> qs,
                                            uint64_t num_public_polynomials,
                                            rust::Slice<const uint8_t> seed,
                                            KahePublicParametersWrapper* out);

// Creates a moduli wrapper pointing to the moduli in the public parameters, for
// polynomial operations.
inline ModuliWrapper CreateModuliWrapperFromKaheParams(
    const KahePublicParametersWrapper& params) {
  return ModuliWrapper{.moduli = params.ptr->moduli.data(),
                       .len = params.ptr->moduli.size()};
}

// Gets an const RnsContext* pointing to the RNS context in the public
// parameters, for polynomial operations.
inline const secure_aggregation::RnsContext* GetRnsContextFromKaheParams(
    const KahePublicParametersWrapper& params) {
  return params.ptr->context.get();
}

// Generates a secret key.
FfiStatus GenerateSecretKeyWrapper(const KahePublicParametersWrapper& params,
                                   SingleThreadHkdfWrapper* prng,
                                   RnsPolynomialWrapper* out);

// Packs `messages` into a vector of BigIntegers using base `packing_base`
// encoding, where the packed values are appended to `packed_values`.
// Expects `packed_values` to be a valid pointer but the underlying vector
// may be unallocated, and expects packing_base > 1, packing_dimension > 0,
// num_coeffs > 0, packing_base^packing_dimension <
// std::numeric_limits<BigInteger>::max().
// Note that `messages` is effectively padded with zeros to the nearest multiple
// of `packing_dimension` before packing.
FfiStatus PackMessagesRaw(rust::Slice<const uint64_t> messages,
                          uint64_t packing_base, uint64_t packing_dimension,
                          uint64_t num_packed_values,
                          BigIntVectorWrapper* packed_values);

// Unpacks messages stored at `packed_values[0..num_packed_values]` and appends
// them to `out`, and removes these packed values from `packed_values`.
// Expects `packed_values.ptr` to be a valid pointer to the vector of packed
// values, and expects packing_base > 1, packing_dimension > 0,
// num_packed_values > 0, packing_base^packing_dimension <
// std::numeric_limits<BigInteger>::max().
FfiStatus UnpackMessagesRaw(uint64_t packing_base, uint64_t packing_dimension,
                            uint64_t num_packed_values,
                            BigIntVectorWrapper& packed_values,
                            rust::Vec<uint64_t>& out);

// Encrypts the messages contained in `packed_values`. If successful, returns OK
// and sets *out to a vector of ciphertext polynomials.
// Expects `out` to be a valid pointer but the underlying vector may be
// unallocated.
FfiStatus Encrypt(const BigIntVectorWrapper& packed_values,
                  const RnsPolynomialWrapper& secret_key,
                  const KahePublicParametersWrapper& params,
                  SingleThreadHkdfWrapper* prng, RnsPolynomialVecWrapper* out);

// Decrypts `ciphertexts` into a vector written to `output_values` buffer, and
// returns a status.
// Expects `output_values` to be a valid pointer but the underlying vector may
// be unallocated.
FfiStatus Decrypt(const RnsPolynomialVecWrapper& ciphertexts,
                  const RnsPolynomialWrapper& secret_key,
                  const KahePublicParametersWrapper& params,
                  BigIntVectorWrapper* output_values);

}  // extern "C"

#endif  // SECURE_AGGREGATION_SHELL_WRAPPER_KAHE_VECTOR_H_
