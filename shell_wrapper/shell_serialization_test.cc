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
#include <vector>

#include "absl/status/status.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "include/cxx.h"
#include "shell_encryption/rns/rns_serialization.pb.h"
#include "shell_encryption/testing/testing_prng.h"
#include "shell_wrapper/shell_aliases.h"
#include "shell_wrapper/shell_types.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/status.h"
#include "shell_wrapper/status_matchers.h"

namespace secure_aggregation {
namespace {

using secure_aggregation::secagg_internal::StatusIs;
using ::testing::HasSubstr;

constexpr int kLogN = 12;
const std::vector<Integer> kQs = {1125899906826241ULL, 1125899906629633ULL};

TEST(ShellSerializationTest, SerializeRnsPolynomialToBytesFailsOnNullptr) {
  constexpr int kT = 2;  // Dummy plaintext modulus.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto rns_context,
                              RnsContext::Create(kLogN, kQs,
                                                 /*ps=*/{}, kT));
  auto moduli = rns_context.MainPrimeModuli();
  auto moduli_wrapper =
      ModuliWrapper{.moduli = moduli.data(), .len = moduli.size()};

  auto serialized_bytes = std::make_unique<std::string>();
  EXPECT_THAT(
      UnwrapFfiStatus(SerializeRnsPolynomialToBytes(
          /*poly=*/nullptr, moduli_wrapper, serialized_bytes)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));

  RnsPolynomialWrapper null_poly_wrapper = {.ptr = nullptr};
  EXPECT_THAT(
      UnwrapFfiStatus(SerializeRnsPolynomialToBytes(
          &null_poly_wrapper, moduli_wrapper, serialized_bytes)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto poly,
                              RnsPolynomial::CreateZero(kLogN, moduli));
  RnsPolynomialWrapper poly_wrapper = {
      .ptr = std::make_unique<RnsPolynomial>(std::move(poly))};
  EXPECT_THAT(
      UnwrapFfiStatus(SerializeRnsPolynomialToBytes(
          &poly_wrapper, ModuliWrapper{.moduli = nullptr, .len = 0},
          serialized_bytes)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));
}

TEST(ShellSerializationTest, DeserializeRnsPolynomialFromBytesFailsOnNullptr) {
  constexpr int kT = 2;  // Dummy plaintext modulus.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto rns_context,
                              RnsContext::Create(kLogN, kQs,
                                                 /*ps=*/{}, kT));
  auto moduli = rns_context.MainPrimeModuli();
  auto moduli_wrapper =
      ModuliWrapper{.moduli = moduli.data(), .len = moduli.size()};
  std::string empty_serialized_bytes;
  rust::Slice<const uint8_t> empty_serialized =
      ToRustSlice(empty_serialized_bytes);
  EXPECT_THAT(
      UnwrapFfiStatus(DeserializeRnsPolynomialFromBytes(
          empty_serialized, moduli_wrapper, /*out=*/nullptr)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));

  RnsPolynomialWrapper null_poly_wrapper = {.ptr = nullptr};
  EXPECT_THAT(
      UnwrapFfiStatus(DeserializeRnsPolynomialFromBytes(
          empty_serialized, moduli_wrapper, &null_poly_wrapper)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto poly,
                              RnsPolynomial::CreateZero(kLogN, moduli));
  RnsPolynomialWrapper poly_wrapper = {
      .ptr = std::make_unique<RnsPolynomial>(std::move(poly))};
  EXPECT_THAT(
      UnwrapFfiStatus(DeserializeRnsPolynomialFromBytes(
          empty_serialized, ModuliWrapper{.moduli = nullptr, .len = 0},
          /*out=*/nullptr)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));
}

// Tests that the output of SerializeRnsPolynomialToBytes can be deserialized
// to the same RnsPolynomial.
TEST(ShellSerializationTest, SerializeRnsPolynomialToBytes) {
  constexpr int kT = 2;  // Dummy plaintext modulus.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto rns_context,
                              RnsContext::Create(kLogN, kQs,
                                                 /*ps=*/{}, kT));
  auto moduli = rns_context.MainPrimeModuli();
  auto moduli_wrapper =
      ModuliWrapper{.moduli = moduli.data(), .len = moduli.size()};
  auto prng = rlwe::testing::TestingPrng(0);
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto poly, RnsPolynomial::SampleUniform(kLogN, &prng, moduli));
  RnsPolynomialWrapper poly_wrapper = {
      .ptr = std::make_unique<RnsPolynomial>(std::move(poly))};
  auto serialized_bytes = std::make_unique<std::string>();
  SECAGG_EXPECT_OK(UnwrapFfiStatus(SerializeRnsPolynomialToBytes(
      &poly_wrapper, moduli_wrapper, serialized_bytes)));

  // Create a proto from the serialized bytes and then deserialize it.
  rlwe::SerializedRnsPolynomial serialized_poly_proto;
  ASSERT_TRUE(serialized_poly_proto.ParseFromString(*serialized_bytes));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto deserialized_poly,
      RnsPolynomial::Deserialize(serialized_poly_proto, moduli));
  EXPECT_EQ(deserialized_poly, *(poly_wrapper.ptr));
}

TEST(ShellSerializationTest, DeserializeRnsPolynomialFromBytes) {
  constexpr int kT = 2;  // Dummy plaintext modulus.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto rns_context,
                              RnsContext::Create(kLogN, kQs,
                                                 /*ps=*/{}, kT));
  auto moduli = rns_context.MainPrimeModuli();
  auto moduli_wrapper =
      ModuliWrapper{.moduli = moduli.data(), .len = moduli.size()};
  auto prng = rlwe::testing::TestingPrng(0);
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto poly, RnsPolynomial::SampleUniform(kLogN, &prng, moduli));

  // Serialize the RnsPolynomial to bytes.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_proto, poly.Serialize(moduli));
  std::string serialized_bytes;
  serialized_proto.SerializeToString(&serialized_bytes);
  rust::Slice<const uint8_t> serialized_poly = ToRustSlice(serialized_bytes);

  // Deserialize the bytes to an RnsPolynomial.
  RnsPolynomialWrapper poly_wrapper = CreateEmptyRnsPolynomialWrapper();
  SECAGG_EXPECT_OK(UnwrapFfiStatus(DeserializeRnsPolynomialFromBytes(
      serialized_poly, moduli_wrapper, &poly_wrapper)));
  EXPECT_EQ(poly, *(poly_wrapper.ptr));
}

}  // namespace
}  // namespace secure_aggregation
