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

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/numeric/int128.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "include/cxx.h"
#include "shell_encryption/rns/error_distribution.h"
#include "shell_encryption/rns/rns_modulus.h"
#include "shell_encryption/sampler/discrete_gaussian.h"
#include "shell_encryption/testing/testing_prng.h"
#include "shell_wrapper/kahe.h"
#include "shell_wrapper/kahe.rs.h"
#include "shell_wrapper/shell_aliases.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/single_thread_hkdf.h"
#include "shell_wrapper/status.h"
#include "shell_wrapper/status.rs.h"
#include "shell_wrapper/status_matchers.h"

namespace secure_aggregation {
namespace {

using secure_aggregation::secagg_internal::StatusIs;
using ::testing::HasSubstr;

constexpr int kLogN = 12;
constexpr int kNumCoeffs = 1 << kLogN;
constexpr int kLogT = 11;
const BigInteger kT = BigInteger(1) << kLogT;
const std::vector<uint64_t> kQs = {1125899906826241ULL, 1125899906629633ULL};
const RnsContextConfig kRnsContextConfig = {
    .log_n = kLogN,
    .qs = kQs,
    .t = 2,  // Dummy RNS plaintext modulus here
};

rust::Slice<const uint64_t> ToRustSlice(absl::Span<const uint64_t> s) {
  return rust::Slice<const uint64_t>(s.data(), s.size());
}

rust::Slice<const uint8_t> ToRustSlice(absl::string_view s) {
  return rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()),
                                    s.size());
}

TEST(ShellTypesTest, AddErrors) {
  // Test failure cases for AddInPlace and AddInPlaceVec.
  // NOTE: kahe_test.cc and ahe_test.cc also test addition.

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto rns_context,
      RnsContext::Create(kRnsContextConfig.log_n, kRnsContextConfig.qs,
                         /*ps=*/{}, kRnsContextConfig.t));

  std::vector<const rlwe::PrimeModulus<ModularInt>*> moduli_vec =
      rns_context.MainPrimeModuli();
  absl::Span<const rlwe::PrimeModulus<ModularInt>* const> moduli =
      absl::MakeSpan(moduli_vec);

  // Create two polynomials.
  SECAGG_ASSERT_OK_AND_ASSIGN(RnsPolynomial p1,
                              RnsPolynomial::CreateOne(kLogN, moduli));
  SECAGG_ASSERT_OK_AND_ASSIGN(RnsPolynomial p2,
                              RnsPolynomial::CreateZero(kLogN, moduli));
  RnsPolynomialWrapper pw1 = {
      .ptr = std::make_unique<RnsPolynomial>(std::move(p1))};
  RnsPolynomialWrapper pw2 = {
      .ptr = std::make_unique<RnsPolynomial>(std::move(p2))};

  // Invalid wrappers should fail.
  auto empty_moduli_vec = std::vector<const rlwe::PrimeModulus<ModularInt>*>();
  ModuliWrapper empty_moduli_wrapper = {};

  EXPECT_THAT(
      UnwrapFfiStatus(AddInPlace(empty_moduli_wrapper, nullptr, &pw2)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));
  EXPECT_THAT(
      UnwrapFfiStatus(AddInPlace(empty_moduli_wrapper, &pw1, nullptr)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));
  EXPECT_THAT(UnwrapFfiStatus(AddInPlace(empty_moduli_wrapper, &pw1, &pw2)),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Valid moduli wrapper should work.
  auto moduli_wrapper =
      ModuliWrapper{.moduli = moduli.data(), .len = moduli.size()};
  SECAGG_EXPECT_OK(UnwrapFfiStatus(AddInPlace(moduli_wrapper, &pw1, &pw2)));

  // Create vector of polynomials with different lengths.
  SECAGG_ASSERT_OK_AND_ASSIGN(RnsPolynomial a1,
                              RnsPolynomial::CreateOne(kLogN, moduli));
  SECAGG_ASSERT_OK_AND_ASSIGN(RnsPolynomial a2,
                              RnsPolynomial::CreateZero(kLogN, moduli));
  SECAGG_ASSERT_OK_AND_ASSIGN(RnsPolynomial b1,
                              RnsPolynomial::CreateOne(kLogN, moduli));

  RnsPolynomialVecWrapper a = {
      .ptr = std::make_unique<std::vector<RnsPolynomial>>(
          std::vector<RnsPolynomial>{std::move(a1), std::move(a2)})};
  RnsPolynomialVecWrapper b = {
      .ptr = std::make_unique<std::vector<RnsPolynomial>>(
          std::vector<RnsPolynomial>{std::move(b1)})};

  // Invalid wrappers should fail.
  EXPECT_THAT(
      UnwrapFfiStatus(AddInPlaceVec(empty_moduli_wrapper, nullptr, &b)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));
  EXPECT_THAT(
      UnwrapFfiStatus(AddInPlaceVec(empty_moduli_wrapper, &a, nullptr)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));
  EXPECT_THAT(UnwrapFfiStatus(AddInPlaceVec(empty_moduli_wrapper, &a, &b)),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Valid wrapper should still fail because the vectors have different lengths.
  EXPECT_THAT(
      UnwrapFfiStatus(AddInPlaceVec(moduli_wrapper, &a, &b)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("same size")));

  // Same length vectors should work.
  SECAGG_ASSERT_OK_AND_ASSIGN(RnsPolynomial c1,
                              RnsPolynomial::CreateOne(kLogN, moduli));
  SECAGG_ASSERT_OK_AND_ASSIGN(RnsPolynomial c2,
                              RnsPolynomial::CreateZero(kLogN, moduli));

  RnsPolynomialVecWrapper c = {
      .ptr = std::make_unique<std::vector<RnsPolynomial>>(
          std::vector<RnsPolynomial>{std::move(c1), std::move(c2)})};
  SECAGG_EXPECT_OK(UnwrapFfiStatus(AddInPlaceVec(moduli_wrapper, &a, &c)));
}

TEST(ShellTypesTest, WriteSmallRnsPolynomialToBufferKahe) {
  constexpr int num_public_polynomials = 1;
  std::unique_ptr<std::string> public_seed;
  FfiStatus status;
  status = GenerateSingleThreadHkdfSeed(public_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  KahePublicParametersWrapper params_wrapper;
  status = CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params_wrapper);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  ModuliWrapper moduli_wrapper =
      CreateModuliWrapperFromKaheParams(params_wrapper);

  // Create P(X) = 1 in NTT form, which is small.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      RnsPolynomial poly,
      RnsPolynomial::CreateOne(params_wrapper.ptr->context->LogN(),
                               params_wrapper.ptr->moduli));
  RnsPolynomialWrapper poly_wrapper = {
      .ptr = std::make_unique<RnsPolynomial>(std::move(poly))};

  constexpr int buffer_len = 2 * kNumCoeffs;
  int64_t buffer[buffer_len];
  uint64_t n_written;
  FfiStatus res = WriteSmallRnsPolynomialToBuffer(
      &poly_wrapper, moduli_wrapper, buffer_len, buffer, &n_written);
  SECAGG_EXPECT_OK(UnwrapFfiStatus(res));
  EXPECT_EQ(n_written, kNumCoeffs);

  // We get 1 indeed.
  EXPECT_EQ(buffer[0], 1);
  EXPECT_THAT(absl::MakeSpan(buffer).subspan(1, kNumCoeffs - 1),
              ::testing::Each(::testing::Eq(0)));

  // Check that polynomial from the error distribution passes the consistency
  // checks across moduli.
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto prng, Prng::Create(seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto error_dg_sampler,
      rlwe::DiscreteGaussianSampler<Integer>::Create(kPrgErrorS));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      poly, rlwe::SampleDiscreteGaussian<ModularInt>(
                params_wrapper.ptr->context->LogN(), params_wrapper.ptr->moduli,
                error_dg_sampler.get(), prng.get()));

  poly_wrapper = {.ptr = std::make_unique<RnsPolynomial>(std::move(poly))};

  // Write the polynomial to a buffer.
  res = WriteSmallRnsPolynomialToBuffer(&poly_wrapper, moduli_wrapper,
                                        buffer_len, buffer, &n_written);
  SECAGG_EXPECT_OK(UnwrapFfiStatus(res));
  EXPECT_EQ(n_written, kNumCoeffs);
}

TEST(ShellTypesTest, ReadWriteSmallRnsPolynomialToBufferKahe) {
  constexpr int num_public_polynomials = 1;
  std::unique_ptr<std::string> public_seed;
  FfiStatus status;
  status = GenerateSingleThreadHkdfSeed(public_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  KahePublicParametersWrapper params_wrapper;
  status = CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params_wrapper);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  ModuliWrapper moduli_wrapper =
      CreateModuliWrapperFromKaheParams(params_wrapper);

  // Generate a random polynomial with small coefficients.
  constexpr int buffer_len = kNumCoeffs >> 1;
  int64_t buffer[buffer_len];
  absl::BitGen bitgen;
  auto min_q = *absl::c_min_element(kQs);
  int64_t min_q_half = static_cast<int64_t>(min_q >> 1);

  for (int i = 0; i < buffer_len; ++i) {
    buffer[i] = absl::Uniform(bitgen, -min_q_half, min_q_half);
    EXPECT_EQ(buffer[i], static_cast<uint64_t>(buffer[i]));
  }

  RnsPolynomialWrapper poly{nullptr};
  status = ReadSmallRnsPolynomialFromBuffer(buffer, buffer_len, 1 << kLogN,
                                            moduli_wrapper, &poly);
  SECAGG_EXPECT_OK(UnwrapFfiStatus(status));
  EXPECT_NE(poly.ptr, nullptr);

  // The coefficients of the polynomial should match the ones in the
  // buffer.
  const std::vector<std::vector<ModularInt>>& coeff_vectors =
      poly.ptr->Coeffs();
  ASSERT_EQ(coeff_vectors.size(), moduli_wrapper.len);
  for (int i = 0; i < moduli_wrapper.len; ++i) {
    ASSERT_EQ(coeff_vectors[i].size(), kNumCoeffs);
    for (int j = 0; j < kNumCoeffs; ++j) {
      auto coeff =
          coeff_vectors[i][j].ExportInt(moduli_wrapper.moduli[i]->ModParams());
      if (j < buffer_len) {
        int64_t v = buffer[j];
        uint64_t uv;
        if (v >= 0) {
          uv = static_cast<uint64_t>(v);
        } else {
          uv = static_cast<uint64_t>(moduli_wrapper.moduli[i]->Modulus() + v);
        }
        EXPECT_EQ(coeff, uv);
      } else {
        EXPECT_EQ(coeff, 0);
      }
    }
  }

  // Write the polynomial back to another buffer should give the same result.
  int64_t buffer_out[buffer_len];
  uint64_t n_written;
  status = WriteSmallRnsPolynomialToBuffer(&poly, moduli_wrapper, buffer_len,
                                           buffer_out, &n_written);
  SECAGG_EXPECT_OK(UnwrapFfiStatus(status));
  EXPECT_EQ(absl::MakeSpan(buffer_out), absl::MakeSpan(buffer));
}

TEST(ShellTypesTest, ReadWriteErrors) {
  constexpr int num_public_polynomials = 1;
  std::unique_ptr<std::string> public_seed;
  FfiStatus status;
  status = GenerateSingleThreadHkdfSeed(public_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  KahePublicParametersWrapper params_wrapper;
  status = CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params_wrapper);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  ModuliWrapper moduli_wrapper =
      CreateModuliWrapperFromKaheParams(params_wrapper);

  auto prng = rlwe::testing::TestingPrng(0);

  // A uniformly random polynomial with coefficients in Z_Q with Q = q_1 * q_2
  // is not small w.h.p.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      RnsPolynomial poly,
      RnsPolynomial::SampleUniform(params_wrapper.ptr->context->LogN(), &prng,
                                   params_wrapper.ptr->moduli));
  RnsPolynomialWrapper poly_wrapper = {
      .ptr = std::make_unique<RnsPolynomial>(std::move(poly))};

  constexpr int output_buffer_len = 2 * kNumCoeffs;
  int64_t output_buffer[output_buffer_len];
  uint64_t n_written;
  status = WriteSmallRnsPolynomialToBuffer(&poly_wrapper, moduli_wrapper,
                                           output_buffer_len, output_buffer,
                                           &n_written);

  // We should get an error because large coefficients don't have the same value
  // mod q_1 and q_2. Note that the buffer gets filled still.
  EXPECT_THAT(UnwrapFfiStatus(status),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("not a small polynomial")));
  EXPECT_EQ(n_written, kNumCoeffs);

  // Generate a polynomial with too many coefficients.
  constexpr int long_input_buffer_len = kNumCoeffs + 1;
  int64_t long_input_buffer[long_input_buffer_len];
  for (int i = 0; i < long_input_buffer_len; ++i) {
    long_input_buffer[i] = i % 10;
  }

  // Try to read from the buffer.
  status = ReadSmallRnsPolynomialFromBuffer(long_input_buffer,
                                            long_input_buffer_len, 1 << kLogN,
                                            moduli_wrapper, &poly_wrapper);
  // We should get an error.
  EXPECT_THAT(UnwrapFfiStatus(status),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Buffer has too many coefficients")));
}

TEST(AheTest, TestWriteRnsPolynomialToBuffer128) {
  constexpr int num_public_polynomials = 1;
  std::unique_ptr<std::string> public_seed;
  FfiStatus status;
  status = GenerateSingleThreadHkdfSeed(public_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  KahePublicParametersWrapper params_wrapper;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params_wrapper)));
  auto prng = rlwe::testing::TestingPrng(0);

  const secure_aggregation::RnsContext* rns_context =
      GetRnsContextFromKaheParams(params_wrapper);
  ASSERT_EQ(rns_context->MainPrimeModuli(), params_wrapper.ptr->moduli);

  // A uniformly random polynomial with coefficients in Z_Q with Q = q_1 * q_2
  // is not small w.h.p.
  RnsPolynomialWrapper poly = CreateEmptyRnsPolynomialWrapper();
  SECAGG_ASSERT_OK_AND_ASSIGN(
      *(poly.ptr),
      RnsPolynomial::SampleUniform(params_wrapper.ptr->context->LogN(), &prng,
                                   params_wrapper.ptr->moduli));

  // Convert to coefficient vector.
  const int num_coeffs = 1 << kLogN;
  std::vector<uint64_t> buffer(2 * num_coeffs);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(WriteRnsPolynomialToBuffer128(
      rns_context, &poly, buffer.size(), buffer.data())));

  // Recompute A from exported buffer.
  std::vector<std::vector<ModularInt>> coeff_vectors(std::size(kQs));
  for (int i = 0; i < std::size(kQs); ++i) {
    coeff_vectors[i].reserve(num_coeffs);
  }
  for (int i = 0; i < num_coeffs; ++i) {
    absl::uint128 coeff = absl::MakeUint128(buffer[2 * i + 1], buffer[2 * i]);
    for (int j = 0; j < std::size(kQs); ++j) {
      SECAGG_ASSERT_OK_AND_ASSIGN(
          auto modular_int,
          ModularInt::ImportInt(
              static_cast<uint64_t>(coeff % kQs[j]),
              rns_context->MainPrimeModuli()[j]->ModParams()));
      coeff_vectors[j].push_back(std::move(modular_int));
    }
  }
  SECAGG_ASSERT_OK_AND_ASSIGN(
      RnsPolynomial reconstructed_poly,
      RnsPolynomial::Create(std::move(coeff_vectors), false));
  SECAGG_ASSERT_OK(
      reconstructed_poly.ConvertToNttForm(rns_context->MainPrimeModuli()));

  // Check that reconstructed coefficients are the same
  EXPECT_EQ(reconstructed_poly, *(poly.ptr));
}

TEST(AheTest, WriteRnsPolynomialToBuffer128FailsWhenBufferLenIsWrong) {
  constexpr int num_public_polynomials = 1;
  std::unique_ptr<std::string> public_seed;
  FfiStatus status;
  status = GenerateSingleThreadHkdfSeed(public_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  KahePublicParametersWrapper params_wrapper;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params_wrapper)));
  auto prng = rlwe::testing::TestingPrng(0);

  const secure_aggregation::RnsContext* rns_context =
      GetRnsContextFromKaheParams(params_wrapper);

  // A uniformly random polynomial with coefficients in Z_Q with Q = q_1 * q_2
  // is not small w.h.p.
  RnsPolynomialWrapper poly = CreateEmptyRnsPolynomialWrapper();
  SECAGG_ASSERT_OK_AND_ASSIGN(
      *(poly.ptr),
      RnsPolynomial::SampleUniform(params_wrapper.ptr->context->LogN(), &prng,
                                   params_wrapper.ptr->moduli));

  const int num_coeffs = 1 << kLogN;
  std::vector<uint64_t> buffer(2 * num_coeffs);
  EXPECT_THAT(
      UnwrapFfiStatus(WriteRnsPolynomialToBuffer128(
          rns_context, &poly, buffer.size() - 1, buffer.data())),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("buffer_len")));
}

}  // namespace
}  // namespace secure_aggregation
