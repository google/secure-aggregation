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

#include "shell_wrapper/kahe.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/types/span.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "include/cxx.h"
#include "shell_encryption/rns/error_distribution.h"
#include "shell_encryption/rns/message_packing.h"
#include "shell_encryption/rns/testing/testing_utils.h"
#include "shell_encryption/sampler/discrete_gaussian.h"
#include "shell_wrapper/kahe.rs.h"
#include "shell_wrapper/shell_aliases.h"
#include "shell_wrapper/shell_types.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/single_thread_hkdf.h"
#include "shell_wrapper/single_thread_hkdf.rs.h"
#include "shell_wrapper/status.h"
#include "shell_wrapper/status.rs.h"
#include "shell_wrapper/status_matchers.h"
#include "shell_wrapper/testing_utils.h"

namespace secure_aggregation {
namespace {

using secure_aggregation::secagg_internal::StatusIs;

constexpr int kLogN = 12;
constexpr int kNumCoeffs = 1 << kLogN;
const std::vector<Integer> kQs = {1125899906826241ULL,
                                  1125899906629633ULL};  // q ~ 2^100

// We need  t * e in [-q/2, q/2).
// We take kLogT < 100 - 1 - log2(kTailBoundMultiplier) - log2(kPrgErrorS)
constexpr int kLogT = 93;
const BigInteger kT = BigInteger(1) << kLogT;

const RnsContextConfig kRnsContextConfig = {
    .log_n = kLogN,
    .qs = kQs,
    .t = 2,  // Dummy RNS plaintext modulus here
};

rust::Slice<const Integer> ToRustSlice(absl::Span<const Integer> s) {
  return rust::Slice<const Integer>(s.data(), s.size());
}

using ::ToRustSlice;  // Import into namespace for correct resolution.

TEST(KaheTest, SamplingSmokeTest) {
  constexpr int num_public_polynomials = 1;
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string public_seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto const params,
      CreateKahePublicParameters(kRnsContextConfig, kLogT,
                                 num_public_polynomials, public_seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto prng, Prng::Create(seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto error_dg_sampler,
      rlwe::DiscreteGaussianSampler<Integer>::Create(kPrgErrorS));

  // Error should not be zero w.h.p.
  SECAGG_ASSERT_OK_AND_ASSIGN(RnsPolynomial c1,
                              rlwe::SampleDiscreteGaussian<ModularInt>(
                                  params.context->LogN(), params.moduli,
                                  error_dg_sampler.get(), prng.get()));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto c2,
      RnsPolynomial::CreateZero(params.context->LogN(), params.moduli));
  EXPECT_NE(c1, c2);

  // Error should be small w.h.p.
  for (int i = 0; i < params.moduli.size(); ++i) {
    // For a small integer c, |c| mod q = |c|, so we check that the RNS
    // representation of |c| is small for each modulus.
    Integer q = params.moduli[i]->Modulus();
    Integer q_half = q >> 1;
    for (auto& coeff : c1.Coeffs()[i]) {
      // Get |c| from the Montgomery representation.
      Integer c = coeff.ExportInt(params.moduli[i]->ModParams());
      Integer abs;
      if (c > q_half) {
        ASSERT_LT(c, q);
        abs = q - c;
      } else {
        abs = c;
      }
      EXPECT_LT(abs,
                rlwe::DiscreteGaussianSampler<Integer>::kTailBoundMultiplier *
                    kPrgErrorS);
    }
  }
}

TEST(KaheTest, KeyGeneration) {
  constexpr int num_public_polynomials = 4;
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string public_seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto const params,
      CreateKahePublicParameters(kRnsContextConfig, kLogT,
                                 num_public_polynomials, public_seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto prng, Prng::Create(seed));

  // Generate two keys and check that they are different.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto key1, GenerateSecretKey(params, prng.get()));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto key2, GenerateSecretKey(params, prng.get()));
  EXPECT_NE(key1, key2);
}

TEST(KaheTest, EncryptDecrypt) {
  constexpr int num_public_polynomials = 2;
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string public_seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto const params,
      CreateKahePublicParameters(kRnsContextConfig, kLogT,
                                 num_public_polynomials, public_seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto prng, Prng::Create(seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto error_dg_sampler,
      rlwe::DiscreteGaussianSampler<Integer>::Create(kPrgErrorS));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto key, GenerateSecretKey(params, prng.get()));

  // Encrypt a random input.
  int num_messages = 10;
  std::vector<BigInteger> messages =
      testing::SampleUint256Messages(num_messages, kT);
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto input0, params.encoder.EncodeBgv<BigInteger>(
                       messages, params.plaintext_modulus, params.moduli));
  auto a0 = params.public_polynomials[0];
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto ciphertext0,
      internal::EncryptPolynomial(input0, key, params.plaintext_modulus_rns,
                                  params.context->LogN(), a0, params.moduli,
                                  error_dg_sampler.get(), prng.get()));

  // Check that decryption works. Decoded input is padded with 0s, so we don't
  // compare with the messages directly.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto decrypted0,
      internal::DecryptPolynomial(ciphertext0, key, a0, params.moduli));
  EXPECT_EQ(params.encoder
                .DecodeBgv<BigInteger>(input0, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value(),
            params.encoder
                .DecodeBgv<BigInteger>(decrypted0, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value());

  // Encrypt another input with a different public polynomial.
  num_messages = 100;
  messages = testing::SampleUint256Messages(num_messages, kT);

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto input1, params.encoder.EncodeBgv<BigInteger>(
                       messages, params.plaintext_modulus, params.moduli));
  EXPECT_NE(params.encoder
                .DecodeBgv<BigInteger>(input1, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value(),
            params.encoder
                .DecodeBgv<BigInteger>(input0, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value());

  auto a1 = params.public_polynomials[0];
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto ciphertext1,
      internal::EncryptPolynomial(input1, key, params.plaintext_modulus_rns,
                                  params.context->LogN(), a1, params.moduli,
                                  error_dg_sampler.get(), prng.get()));
  EXPECT_NE(ciphertext0, ciphertext1);

  // Check that decryption still works.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto decrypted1,
      internal::DecryptPolynomial(ciphertext1, key, a1, params.moduli));
  EXPECT_EQ(params.encoder
                .DecodeBgv<BigInteger>(input1, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value(),
            params.encoder
                .DecodeBgv<BigInteger>(decrypted1, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value());
}

TEST(KaheTest, VectorEncryptDecrypt) {
  constexpr int num_public_polynomials = 10;
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string public_seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto const params,
      CreateKahePublicParameters(kRnsContextConfig, kLogT,
                                 num_public_polynomials, public_seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto prng, Prng::Create(seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto key, GenerateSecretKey(params, prng.get()));

  // Encrypt random input vector that uses all the polynomial coefficients.
  constexpr int num_polynomials = 10;
  std::vector<BigInteger> all_packed_messages;
  all_packed_messages.reserve(kNumCoeffs * num_polynomials);
  for (int i = 0; i < num_polynomials; ++i) {
    auto packed_messages = testing::SampleUint256Messages(kNumCoeffs, kT);
    all_packed_messages.insert(all_packed_messages.end(),
                               packed_messages.begin(), packed_messages.end());
  }

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto ciphertexts,
      EncodeAndEncryptVector(all_packed_messages, key, params, prng.get()));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto decrypted,
                              DecodeAndDecryptVector(ciphertexts, key, params));

  EXPECT_EQ(all_packed_messages, decrypted);
}

TEST(KaheTest, PackMessagesRawAllocatesOutputVectorIfNull) {
  constexpr Integer packing_base = 10;
  constexpr int packing_dimension = 1;
  constexpr int num_packed_values = 10;
  std::vector<Integer> messages =
      rlwe::testing::SampleMessages(num_packed_values, packing_base);
  // Create a wrapper with an unallocated vector.
  BigIntVectorWrapper packed_values{.ptr = nullptr};
  SECAGG_EXPECT_OK(UnwrapFfiStatus(
      PackMessagesRaw(ToRustSlice(messages), packing_base, packing_dimension,
                      num_packed_values, &packed_values)));
  ASSERT_NE(packed_values.ptr, nullptr);
  EXPECT_EQ(packed_values.ptr->size(), num_packed_values);
  EXPECT_EQ(*packed_values.ptr,
            (rlwe::PackMessagesFlat<Integer, BigInteger>(messages, packing_base,
                                                         packing_dimension)));
}

TEST(KaheTest, PackMessagesRawPadsWithZeros) {
  constexpr Integer packing_base = 10;
  constexpr int packing_dimension = 3;
  constexpr int num_messages = 5;
  constexpr int num_packed_values = 10;

  std::vector<Integer> messages =
      rlwe::testing::SampleMessages(num_messages, packing_base);
  BigIntVectorWrapper packed_values{.ptr = nullptr};
  SECAGG_EXPECT_OK(UnwrapFfiStatus(
      PackMessagesRaw(ToRustSlice(messages), packing_base, packing_dimension,
                      num_packed_values, &packed_values)));
  EXPECT_EQ(packed_values.ptr->size(), num_packed_values);

  // Check that the prefix of the packed values match the expected packed
  // values.
  std::vector<BigInteger> expected_packed_values =
      rlwe::PackMessagesFlat<Integer, BigInteger>(messages, packing_base,
                                                  packing_dimension);
  ASSERT_LT(expected_packed_values.size(), packed_values.ptr->size());
  EXPECT_EQ(
      absl::MakeSpan(*packed_values.ptr).first(expected_packed_values.size()),
      expected_packed_values);

  // The suffix should be padded with zeros.
  EXPECT_THAT(
      absl::MakeSpan(*packed_values.ptr).subspan(expected_packed_values.size()),
      ::testing::Each(::testing::Eq(0)));
}

TEST(KaheTest, PackMessagesRawAppendsPackedValues) {
  constexpr Integer packing_base = 10;
  constexpr int packing_dimension = 1;
  constexpr int num_packed_values = 10;
  constexpr BigInteger kT = 65537;

  // Create a wrapper with a vector of already packed values.
  std::vector<BigInteger> already_packed_values =
      testing::SampleUint256Messages(num_packed_values, kT);
  BigIntVectorWrapper packed_values{
      .ptr = std::make_unique<std::vector<BigInteger>>(already_packed_values)};

  // Pack more values and check that they are appended to the existing vector.
  std::vector<Integer> messages =
      rlwe::testing::SampleMessages(num_packed_values, packing_base);
  SECAGG_EXPECT_OK(UnwrapFfiStatus(
      PackMessagesRaw(ToRustSlice(messages), packing_base, packing_dimension,
                      num_packed_values, &packed_values)));
  EXPECT_EQ(packed_values.ptr->size(), num_packed_values * 2);
  EXPECT_EQ(absl::MakeSpan(*packed_values.ptr).first(num_packed_values),
            already_packed_values);
  EXPECT_EQ(absl::MakeSpan(*packed_values.ptr).last(num_packed_values),
            (rlwe::PackMessagesFlat<Integer, BigInteger>(messages, packing_base,
                                                         packing_dimension)));
}

TEST(KaheTest, UnpackMessagesRawRemovesConsumedPackedValues) {
  constexpr Integer packing_base = 10;
  constexpr int packing_dimension = 1;
  constexpr int num_packed_values = 10;
  // Since packing_dimension == 1, `packed` is the same as unpacked messages.
  std::vector<BigInteger> packed =
      testing::SampleUint256Messages(num_packed_values * 2, packing_base);
  BigIntVectorWrapper packed_values{
      .ptr = std::make_unique<std::vector<BigInteger>>(packed)};

  // Unpack `num_packed_values` messages, which should remove the first
  // `num_packed_values` elements from the vector in `packed_values`.
  rust::Vec<Integer> unpacked_messages;
  SECAGG_EXPECT_OK(UnwrapFfiStatus(
      UnpackMessagesRaw(packing_base, packing_dimension, num_packed_values,
                        packed_values, unpacked_messages)));
  EXPECT_EQ(packed_values.ptr->size(), num_packed_values);
  EXPECT_EQ(unpacked_messages.size(), num_packed_values);
  // Unpacked values should match the first half of the original packed values.
  for (int i = 0; i < num_packed_values; ++i) {
    EXPECT_EQ(unpacked_messages[i], static_cast<Integer>(packed[i]));
  }
  // Check that the remaining packed values are unchanged.
  EXPECT_EQ(absl::MakeSpan(*packed_values.ptr).first(num_packed_values),
            absl::MakeSpan(packed).subspan(num_packed_values));
}

TEST(KaheTest, PackAndEncrypt) {
  constexpr int num_packing = 8;
  constexpr int num_public_polynomials = 2;
  constexpr int num_messages = 30;
  constexpr Integer packing_base = 2;

  SECAGG_ASSERT_OK_AND_ASSIGN(std::string public_seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto const params,
      CreateKahePublicParameters(kRnsContextConfig, kLogT,
                                 num_public_polynomials, public_seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto prng, Prng::Create(seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto key, GenerateSecretKey(params, prng.get()));

  std::vector<Integer> input_messages =
      rlwe::testing::SampleMessages(num_messages, packing_base);
  std::vector<BigInteger> packed_messages =
      rlwe::PackMessagesFlat<Integer, BigInteger>(input_messages, packing_base,
                                                  num_packing);
  // packed_messages length should be ceil(num_messages / num_packing).
  int num_packed_messages = (num_messages + num_packing - 1) / num_packing;
  EXPECT_EQ(packed_messages.size(), num_packed_messages);

  // Check that PackMessagesRaw works as expected.
  BigIntVectorWrapper raw_packed_messages_wrapper{
      .ptr = std::make_unique<std::vector<BigInteger>>()};
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      PackMessagesRaw(ToRustSlice(input_messages), packing_base, num_packing,
                      num_packed_messages, &raw_packed_messages_wrapper)));
  EXPECT_EQ(*raw_packed_messages_wrapper.ptr, packed_messages);

  // Encrypt the packed messages.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto ciphertexts,
                              secure_aggregation::EncodeAndEncryptVector(
                                  packed_messages, key, params, prng.get()));
  EXPECT_EQ(ciphertexts.size(), 1);  // Only one ciphertext polynomial needed.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto decrypted,
      secure_aggregation::DecodeAndDecryptVector(ciphertexts, key, params));
  EXPECT_EQ(decrypted.size(), kNumCoeffs);

  // Check that UnpackMessagesRaw works as expected.
  std::vector<Integer> expected_unpacked_messages =
      rlwe::UnpackMessagesFlat<Integer, BigInteger>(decrypted, packing_base,
                                                    num_packing);
  BigIntVectorWrapper decrypted_wrapper{
      .ptr = std::make_unique<std::vector<BigInteger>>(std::move(decrypted))};
  rust::Vec<Integer> unpacked_messages;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      UnpackMessagesRaw(packing_base, num_packing, packed_messages.size(),
                        decrypted_wrapper, unpacked_messages)));
  EXPECT_EQ(absl::MakeSpan(unpacked_messages.data(), num_messages),
            absl::MakeSpan(expected_unpacked_messages.data(), num_messages));
  // Check against the original input messages.
  EXPECT_EQ(absl::MakeSpan(unpacked_messages.data(), num_messages),
            absl::MakeSpan(input_messages).subspan(0, num_messages));
  // Check unpacked messages are padded with zeros.
  ASSERT_GE(expected_unpacked_messages.size(), num_messages);
  EXPECT_THAT(
      absl::MakeSpan(unpacked_messages.data(), unpacked_messages.size())
          .subspan(num_messages, unpacked_messages.size() - num_messages),
      ::testing::Each(::testing::Eq(0)));
}

TEST(KaheTest, RawVectorEncryptOnePolynomial) {
  constexpr int num_packing = 2;
  constexpr int num_public_polynomials = 2;
  constexpr int num_messages = 10;
  constexpr Integer packing_base = 10;

  std::unique_ptr<std::string> public_seed;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(GenerateSingleThreadHkdfSeed(public_seed)));
  KahePublicParametersWrapper params;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params)));
  std::unique_ptr<std::string> private_seed;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(GenerateSingleThreadHkdfSeed(private_seed)));
  SingleThreadHkdfWrapper prng;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      CreateSingleThreadHkdf(ToRustSlice(*private_seed), prng)));
  RnsPolynomialWrapper key;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(params, &prng, &key)));

  // Generate random messages that fit on one polynomial.
  std::vector<Integer> input_messages =
      rlwe::testing::SampleMessages(num_messages, packing_base);

  BigIntVectorWrapper packed_messages_wrapper{
      .ptr = std::make_unique<std::vector<BigInteger>>()};
  int num_packed_messages = (num_messages + num_packing - 1) / num_packing;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      PackMessagesRaw(ToRustSlice(input_messages), packing_base, num_packing,
                      num_packed_messages, &packed_messages_wrapper)));
  // packed_messages length should be ceil(num_messages / num_packing).
  EXPECT_EQ(packed_messages_wrapper.ptr->size(), num_packed_messages);

  RnsPolynomialVecWrapper ciphertexts;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      Encrypt(packed_messages_wrapper, key, params, &prng, &ciphertexts)));

  // Check that decryption works when we decrypt only what we need.
  BigIntVectorWrapper decrypted_wrapper{
      .ptr = std::make_unique<std::vector<BigInteger>>()};
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(Decrypt(ciphertexts, key, params, &decrypted_wrapper)));

  rust::Vec<Integer> unpacked_decrypted_messages;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(UnpackMessagesRaw(
      packing_base, num_packing, decrypted_wrapper.ptr->size(),
      decrypted_wrapper, unpacked_decrypted_messages)));

  // Filled the whole buffer with right messages.
  EXPECT_EQ(absl::MakeSpan(unpacked_decrypted_messages.data(), num_messages),
            absl::MakeSpan(input_messages));

  // Check that decryption still work when we receive some padding.
  constexpr int buffer_length =
      2 * kNumCoeffs * num_packing;  // Room for 2 plaintext polynomials.
  constexpr int padded_length =
      kNumCoeffs * num_packing;  // What the padded input really needs.
  BigIntVectorWrapper decrypted_long_messages_wrapper{
      .ptr = std::make_unique<std::vector<BigInteger>>()};
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      Decrypt(ciphertexts, key, params, &decrypted_long_messages_wrapper)));

  rust::Vec<Integer> unpacked_decrypted_long_messages;
  unpacked_decrypted_long_messages.reserve(buffer_length);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(UnpackMessagesRaw(
      packing_base, num_packing, decrypted_long_messages_wrapper.ptr->size(),
      decrypted_long_messages_wrapper, unpacked_decrypted_long_messages)));

  // The non-zero messages are identical.
  EXPECT_EQ(
      absl::MakeSpan(unpacked_decrypted_long_messages.data(), num_messages),
      absl::MakeSpan(input_messages));

  // Decrypted messages are padded to zero up to the end of the polynomial.
  EXPECT_THAT(absl::MakeSpan(unpacked_decrypted_long_messages.data(),
                             unpacked_decrypted_long_messages.size())
                  .subspan(num_messages, padded_length - num_messages),
              ::testing::Each(::testing::Eq(0)));
}

TEST(KaheTest, RawVectorEncryptTwoPolynomials) {
  constexpr int num_packing = 8;
  constexpr int num_public_polynomials = 2;

  std::unique_ptr<std::string> public_seed;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(GenerateSingleThreadHkdfSeed(public_seed)));
  KahePublicParametersWrapper params;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params)));
  std::unique_ptr<std::string> private_seed;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(GenerateSingleThreadHkdfSeed(private_seed)));
  SingleThreadHkdfWrapper prng;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      CreateSingleThreadHkdf(ToRustSlice(*private_seed), prng)));
  RnsPolynomialWrapper key;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(params, &prng, &key)));

  // Generate random messages that need two polynomials.
  constexpr int num_messages = kNumCoeffs * num_packing + 10;
  constexpr int num_packed_messages =
      (num_messages + num_packing - 1) / num_packing;
  constexpr Integer packing_base = 2;
  std::vector<Integer> input_messages =
      rlwe::testing::SampleMessages(num_messages, packing_base);

  BigIntVectorWrapper packed_messages_wrapper{
      .ptr = std::make_unique<std::vector<BigInteger>>()};
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      PackMessagesRaw(ToRustSlice(input_messages), packing_base, num_packing,
                      num_packed_messages, &packed_messages_wrapper)));
  RnsPolynomialVecWrapper ciphertexts;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      Encrypt(packed_messages_wrapper, key, params, &prng, &ciphertexts)));

  // Check that decryption works when we decrypt only what we need.
  BigIntVectorWrapper decrypted_wrapper{
      .ptr = std::make_unique<std::vector<BigInteger>>()};
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(Decrypt(ciphertexts, key, params, &decrypted_wrapper)));
  rust::Vec<Integer> unpacked_decrypted_messages;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(UnpackMessagesRaw(
      packing_base, num_packing, decrypted_wrapper.ptr->size(),
      decrypted_wrapper, unpacked_decrypted_messages)));

  EXPECT_GE(unpacked_decrypted_messages.size(), num_messages);
  EXPECT_EQ(absl::MakeSpan(input_messages),
            absl::MakeSpan(unpacked_decrypted_messages.data(), num_messages));
}

TEST(KaheTest, Failures) {
  constexpr int num_packing = 8;
  constexpr int num_public_polynomials = 2;

  std::unique_ptr<std::string> public_seed;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(GenerateSingleThreadHkdfSeed(public_seed)));
  KahePublicParametersWrapper params;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params)));
  std::unique_ptr<std::string> private_seed;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(GenerateSingleThreadHkdfSeed(private_seed)));
  SingleThreadHkdfWrapper prng;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      CreateSingleThreadHkdf(ToRustSlice(*private_seed), prng)));
  RnsPolynomialWrapper key;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(params, &prng, &key)));

  // Generate random messages that need 3 polynomials.
  constexpr int num_messages = kNumCoeffs * num_packing * 3;
  constexpr int num_packed_messages =
      (num_messages + num_packing - 1) / num_packing;
  constexpr Integer packing_base = 2;
  std::vector<Integer> input_messages =
      rlwe::testing::SampleMessages(num_messages, packing_base);

  // Check that encryption fails if we don't have enough public polynomials.
  BigIntVectorWrapper packed_messages_wrapper{
      .ptr = std::make_unique<std::vector<BigInteger>>()};
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      PackMessagesRaw(ToRustSlice(input_messages), packing_base, num_packing,
                      num_packed_messages, &packed_messages_wrapper)));
  RnsPolynomialVecWrapper ciphertexts;
  EXPECT_THAT(UnwrapFfiStatus(Encrypt(packed_messages_wrapper, key, params,
                                      &prng, &ciphertexts)),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Check failures on invalid pointers or wrappers
  KahePublicParametersWrapper bad_params = {.ptr = nullptr};
  EXPECT_THAT(UnwrapFfiStatus(Encrypt(packed_messages_wrapper, key, bad_params,
                                      &prng, &ciphertexts)),
              StatusIs(absl::StatusCode::kInvalidArgument));

  RnsPolynomialVecWrapper bad_ciphertexts{.len = 1, .ptr = nullptr};
  BigIntVectorWrapper decrypted_wrapper;
  EXPECT_THAT(UnwrapFfiStatus(
                  Decrypt(bad_ciphertexts, key, params, &decrypted_wrapper)),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Also check keygen and parameters.
  RnsPolynomialWrapper key_out;
  EXPECT_THAT(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(bad_params, &prng, &key_out)),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(UnwrapFfiStatus(CreateKahePublicParametersWrapper(
                  kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
                  ToRustSlice(*public_seed), /*out=*/nullptr)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KaheTest, PackMessagesRawFailsIfNullOutputWrapper) {
  constexpr Integer packing_base = 10;
  constexpr int packing_dimension = 1;
  constexpr int num_messages = 10;
  std::vector<Integer> input_messages =
      rlwe::testing::SampleMessages(num_messages, packing_base);
  EXPECT_THAT(UnwrapFfiStatus(PackMessagesRaw(
                  ToRustSlice(input_messages), packing_base, packing_dimension,
                  num_messages, /*packed_values=*/nullptr)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KaheTest, PackMessagesRawFailsIfInputTooLong) {
  constexpr Integer packing_base = 10;
  constexpr int packing_dimension = 1;
  constexpr int num_packed_messages = 10;
  constexpr int bad_num_messages = num_packed_messages * packing_dimension + 1;
  std::vector<Integer> bad_input_messages =
      rlwe::testing::SampleMessages(bad_num_messages, packing_base);
  BigIntVectorWrapper packed_messages_wrapper{
      .ptr = std::make_unique<std::vector<BigInteger>>()};
  EXPECT_THAT(
      UnwrapFfiStatus(PackMessagesRaw(
          ToRustSlice(bad_input_messages), packing_base, packing_dimension,
          num_packed_messages, &packed_messages_wrapper)),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KaheTest, UnpackMessagesRawFailsIfUnallocatedPackedValues) {
  constexpr Integer packing_base = 10;
  constexpr int packing_dimension = 1;
  constexpr int num_packed_messages = 10;
  BigIntVectorWrapper bad_packed_values{.ptr = nullptr};
  rust::Vec<Integer> unpacked_messages;
  EXPECT_THAT(UnwrapFfiStatus(UnpackMessagesRaw(
                  packing_base, packing_dimension, num_packed_messages,
                  bad_packed_values, unpacked_messages)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KaheTest, UnpackMessagesRawFailsIfPackedValuesTooShort) {
  constexpr Integer packing_base = 10;
  constexpr int packing_dimension = 1;
  constexpr int num_packed_messages = 10;
  // A wrapper with a packed message vector that is shorter than expected.
  BigIntVectorWrapper bad_packed_values{
      .ptr = std::make_unique<std::vector<BigInteger>>(num_packed_messages - 1,
                                                       0)};
  rust::Vec<Integer> unpacked_messages;
  EXPECT_THAT(UnwrapFfiStatus(UnpackMessagesRaw(
                  packing_base, packing_dimension, num_packed_messages,
                  bad_packed_values, unpacked_messages)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KaheTest, AddInPlacePolynomial) {
  constexpr int num_public_polynomials = 1;

  std::unique_ptr<std::string> public_seed;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(GenerateSingleThreadHkdfSeed(public_seed)));
  KahePublicParametersWrapper params;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params)));
  auto moduli = CreateModuliWrapperFromKaheParams(params);

  std::unique_ptr<std::string> private_seed;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(GenerateSingleThreadHkdfSeed(private_seed)));
  SingleThreadHkdfWrapper prng;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      CreateSingleThreadHkdf(ToRustSlice(*private_seed), prng)));

  // Generate two keys.
  RnsPolynomialWrapper key1;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(params, &prng, &key1)));
  RnsPolynomialWrapper key2;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(params, &prng, &key2)));

  // Sample two messages and encrypt them.
  constexpr int num_messages = 10;
  constexpr Integer packing_base = 10;
  constexpr Integer input_domain =
      packing_base / 2;  // 2 inputs should fit in the base.
  constexpr int num_packing = 3;
  constexpr int num_packed_messages =
      (num_messages + num_packing - 1) / num_packing;
  std::vector<Integer> input_values1 =
      rlwe::testing::SampleMessages(num_messages, input_domain);
  BigIntVectorWrapper packed_messages_wrapper1{
      .ptr = std::make_unique<std::vector<BigInteger>>()};
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      PackMessagesRaw(ToRustSlice(input_values1), packing_base, num_packing,
                      num_packed_messages, &packed_messages_wrapper1)));
  RnsPolynomialVecWrapper ciphertexts1;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      Encrypt(packed_messages_wrapper1, key1, params, &prng, &ciphertexts1)));
  std::vector<Integer> input_values2 =
      rlwe::testing::SampleMessages(num_messages, input_domain);
  BigIntVectorWrapper packed_messages_wrapper2{
      .ptr = std::make_unique<std::vector<BigInteger>>()};
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      PackMessagesRaw(ToRustSlice(input_values2), packing_base, num_packing,
                      num_packed_messages, &packed_messages_wrapper2)));
  RnsPolynomialVecWrapper ciphertexts2;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      Encrypt(packed_messages_wrapper2, key2, params, &prng, &ciphertexts2)));

  // Check that we can add keys (single polynomials) correctly.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto manual_sum_copy,
                              key1.ptr->Add(*key2.ptr, params.ptr->moduli));
  SECAGG_ASSERT_OK(UnwrapFfiStatus(AddInPlace(moduli, &key1, &key2)));
  ASSERT_EQ(manual_sum_copy, *key2.ptr);

  // Check that we can add vectors of polynomials.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      manual_sum_copy,
      ciphertexts1.ptr->at(0).Add(ciphertexts2.ptr->at(0), params.ptr->moduli));
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(AddInPlaceVec(moduli, &ciphertexts1, &ciphertexts2)));
  ASSERT_EQ(manual_sum_copy, ciphertexts2.ptr->at(0));

  // Check homomorphism.
  BigIntVectorWrapper decrypted_wrapper{
      .ptr = std::make_unique<std::vector<BigInteger>>()};
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(Decrypt(ciphertexts2, key2, params, &decrypted_wrapper)));
  rust::Vec<Integer> unpacked_decrypted_messages;
  unpacked_decrypted_messages.reserve(num_messages);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(UnpackMessagesRaw(
      packing_base, num_packing, decrypted_wrapper.ptr->size(),
      decrypted_wrapper, unpacked_decrypted_messages)));
  for (int i = 0; i < num_messages; ++i) {
    EXPECT_EQ(input_values1[i] + input_values2[i],
              unpacked_decrypted_messages[i]);
  }
}

}  // namespace
}  // namespace secure_aggregation
