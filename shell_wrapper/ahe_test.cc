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

#include "shell_wrapper/ahe.h"

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "ffi_utils/status.h"
#include "ffi_utils/status_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "shell_encryption/rns/testing/testing_utils.h"
#include "shell_wrapper/ahe.rs.h"
#include "shell_wrapper/shell_aliases.h"
#include "shell_wrapper/shell_types.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/single_thread_hkdf.h"
#include "shell_wrapper/single_thread_hkdf.rs.h"

namespace secure_aggregation {
namespace {

using ::testing::HasSubstr;

constexpr int kLogN = 11;
constexpr int kT = 10001;
constexpr uint64_t kQs[] = {1073692673, 1073668097};
constexpr uint64_t kQsLarge[] = {1125899906826241, 1125899906629633};
constexpr double kSFlood = 1.0e+10;

constexpr int kNumParties = 3;
constexpr int kPublicKeyVariance = 8;
constexpr uint64_t kMaxValue = 72;
constexpr double kSBase = 12.8;

TEST(AheTest, EncryptDecryptOne) {
  // Create the public parameters.
  std::unique_ptr<std::string> public_seed;
  auto status = GenerateSingleThreadHkdfSeed(public_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  AhePublicParameters public_params;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(CreateAhePublicParameters(
      kLogN, kT, kQs, std::size(kQs), kPublicKeyVariance, kSBase, kSFlood,
      ToRustSlice(*public_seed), &public_params)));

  std::unique_ptr<std::string> private_seed;
  status = GenerateSingleThreadHkdfSeed(private_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  SingleThreadHkdfWrapper prng;
  status = CreateSingleThreadHkdf(ToRustSlice(*private_seed), prng);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));

  RnsPolynomialWrapper sk_share;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(GenerateSecretKeyShare(public_params, &prng, &sk_share)));

  RnsPolynomialWrapper public_key_b = CreateEmptyRnsPolynomialWrapper();
  RnsPolynomialWrapper public_key_share_error =
      CreateEmptyRnsPolynomialWrapper();
  SECAGG_ASSERT_OK(UnwrapFfiStatus(GeneratePublicKeyShareWrapper(
      sk_share, public_params, &prng, &public_key_b, &public_key_share_error,
      nullptr)));

  // Encrypt one vector.
  const int num_messages = 1 << kLogN;
  std::vector<Integer> coeffs0 =
      rlwe::testing::SampleMessages(num_messages, kMaxValue);

  auto ciphertext_b = CreateEmptyRnsPolynomialWrapper();
  auto ciphertext_a = CreateEmptyRnsPolynomialWrapper();
  auto c0_r = CreateEmptyRnsPolynomialWrapper();
  auto c0_e = CreateEmptyRnsPolynomialWrapper();

  SECAGG_ASSERT_OK(UnwrapFfiStatus(AheEncrypt(
      coeffs0.data(), coeffs0.size(), public_key_b, public_params, &prng,
      &ciphertext_b, &ciphertext_a, &c0_r, &c0_e, /*wraparound=*/nullptr)));

  RnsPolynomialWrapper partial_decryption;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      PartialDecrypt(ciphertext_a, sk_share, public_params, &prng,
                     &partial_decryption, /*error_flood=*/nullptr,
                     /*wraparound=*/nullptr)));

  // Recover from partial decryptions and component b
  uint64_t decrypted_buffer[2 * num_messages];
  size_t n_written;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(RecoverMessages(
      partial_decryption, ciphertext_b, public_params,
      std::size(decrypted_buffer), decrypted_buffer, &n_written)));

  for (int i = 0; i < 2; ++i) {
    Integer decrypted_coeff = decrypted_buffer[i];
    Integer expected = coeffs0[i];
    EXPECT_EQ(decrypted_coeff, expected);
  }
}

// Extern C version of
// https://github.com/google/shell-encryption/blob/master/shell_encryption/multi_party/recovery_test.cc
TEST(AheTest, ExternCRecoveryTest) {
  // Create the public parameters.
  std::unique_ptr<std::string> public_seed;
  auto status = GenerateSingleThreadHkdfSeed(public_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  AhePublicParameters public_params;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(CreateAhePublicParameters(
      kLogN, kT, kQs, std::size(kQs), kPublicKeyVariance, kSBase, kSFlood,
      ToRustSlice(*public_seed), &public_params)));

  std::unique_ptr<std::string> private_seed;
  status = GenerateSingleThreadHkdfSeed(private_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  SingleThreadHkdfWrapper prng;
  status = CreateSingleThreadHkdf(ToRustSlice(*private_seed), prng);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));

  std::vector<RnsPolynomialWrapper> secret_key_shares;
  std::vector<RnsPolynomialWrapper> public_key_shares;
  secret_key_shares.reserve(kNumParties);
  public_key_shares.reserve(kNumParties);
  for (int i = 0; i < kNumParties; ++i) {
    RnsPolynomialWrapper sk_share;
    SECAGG_ASSERT_OK(UnwrapFfiStatus(
        GenerateSecretKeyShare(public_params, &prng, &sk_share)));

    RnsPolynomialWrapper public_key_share_b = CreateEmptyRnsPolynomialWrapper();
    RnsPolynomialWrapper public_key_share_error =
        CreateEmptyRnsPolynomialWrapper();
    RnsPolynomialWrapper wraparound = CreateEmptyRnsPolynomialWrapper();
    SECAGG_ASSERT_OK(UnwrapFfiStatus(GeneratePublicKeyShareWrapper(
        sk_share, public_params, &prng, &public_key_share_b,
        &public_key_share_error, &wraparound)));
    secret_key_shares.push_back(std::move(sk_share));
    public_key_shares.push_back(std::move(public_key_share_b));
  }

  // Create public key by aggregating public key shares.
  RnsPolynomialWrapper public_key_b;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      CreateZeroRnsPolynomialWrapper(public_params, &public_key_b)));
  for (const auto& public_key_share : public_key_shares) {
    SECAGG_ASSERT_OK(UnwrapFfiStatus(
        AddInPlace(public_params, public_key_share, &public_key_b)));
  }

  // Encrypt two vectors.
  const int num_messages = 1 << kLogN;
  std::vector<Integer> coeffs0 =
      rlwe::testing::SampleMessages(num_messages, kMaxValue);
  std::vector<Integer> coeffs1 =
      rlwe::testing::SampleMessages(num_messages, kMaxValue);

  auto c0_b = CreateEmptyRnsPolynomialWrapper();
  auto c0_a = CreateEmptyRnsPolynomialWrapper();
  auto c0_r = CreateEmptyRnsPolynomialWrapper();
  auto c0_e = CreateEmptyRnsPolynomialWrapper();
  SECAGG_ASSERT_OK(UnwrapFfiStatus(AheEncrypt(coeffs0.data(), coeffs0.size(),
                                              public_key_b, public_params,
                                              &prng, &c0_b, &c0_a, &c0_r, &c0_e,
                                              /*wraparound=*/nullptr)));

  auto c1_b = CreateEmptyRnsPolynomialWrapper();
  auto c1_a = CreateEmptyRnsPolynomialWrapper();
  auto c1_r = CreateEmptyRnsPolynomialWrapper();
  auto c1_e = CreateEmptyRnsPolynomialWrapper();
  SECAGG_ASSERT_OK(UnwrapFfiStatus(AheEncrypt(coeffs1.data(), coeffs1.size(),
                                              public_key_b, public_params,
                                              &prng, &c1_b, &c1_a, &c1_r, &c1_e,
                                              /*wraparound=*/nullptr)));

  // Accumulate component a
  RnsPolynomialWrapper ciphertext_a;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      CreateZeroRnsPolynomialWrapper(public_params, &ciphertext_a)));
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(AddInPlace(public_params, c0_a, &ciphertext_a)));
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(AddInPlace(public_params, c1_a, &ciphertext_a)));

  // Let all secret key share holders do partial decryption.
  std::vector<RnsPolynomialWrapper> partial_decryptions;
  partial_decryptions.reserve(kNumParties);
  for (int i = 0; i < kNumParties; ++i) {
    RnsPolynomialWrapper partial_decryption;
    SECAGG_ASSERT_OK(UnwrapFfiStatus(
        PartialDecrypt(ciphertext_a, secret_key_shares[i], public_params, &prng,
                       &partial_decryption,
                       /*error_flood=*/nullptr,
                       /*wraparound=*/nullptr)));
    partial_decryptions.push_back(std::move(partial_decryption));
  }

  // Accumulate partial decryptions
  RnsPolynomialWrapper sum_partial_decryptions;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      CreateZeroRnsPolynomialWrapper(public_params, &sum_partial_decryptions)));
  for (const auto& partial_decryption : partial_decryptions) {
    SECAGG_ASSERT_OK(UnwrapFfiStatus(AddInPlace(
        public_params, partial_decryption, &sum_partial_decryptions)));
  }

  // Accumulate component b
  RnsPolynomialWrapper ciphertext_b;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      CreateZeroRnsPolynomialWrapper(public_params, &ciphertext_b)));
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(AddInPlace(public_params, c0_b, &ciphertext_b)));
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(AddInPlace(public_params, c1_b, &ciphertext_b)));

  // Recover from partial decryptions and component b
  uint64_t decrypted_buffer[2 * num_messages];
  size_t n_written;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(RecoverMessages(
      sum_partial_decryptions, ciphertext_b, public_params,
      std::size(decrypted_buffer), decrypted_buffer, &n_written)));
  EXPECT_EQ(n_written, num_messages);

  EXPECT_EQ(public_params.encoder->PlaintextModulus(), kT);

  for (int i = 0; i < num_messages; ++i) {
    Integer decrypted_coeff = decrypted_buffer[i];
    Integer expected = (coeffs0[i] + coeffs1[i]) % kT;
    EXPECT_EQ(decrypted_coeff, expected);
  }
}

}  // namespace
}  // namespace secure_aggregation
