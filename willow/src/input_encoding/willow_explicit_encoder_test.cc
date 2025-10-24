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

#include "willow/src/input_encoding/willow_explicit_encoder.h"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "absl/status/status.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "willow/proto/willow/input_spec.proto.h"
#include "willow/src/input_encoding/willow_encoder_factory.h"

namespace secure_aggregation {
namespace willow {
namespace {

using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;
using ::testing::status::IsOkAndHolds;
using ::testing::status::StatusIs;

TEST(WillowInputEncoderFactoryTest, ValidateInputAndSpecLengthMismatch) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {1, 2, 3};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  group_by_data["feature1"] = {"a", "b", "a"};
  InputSpec input_spec;
  InputSpec::InputVectorSpec* spec1 = input_spec.add_input_vector_specs();
  spec1->set_vector_name("metric1");
  spec1->set_data_type(InputSpec::INT64);
  // Missing spec for "feature1"

  EXPECT_THAT(
      WillowInputEncoderFactory::ValidateInputAndSpec(input_data, group_by_data,
                                                      input_spec),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "input_spec must have the same number of entries as the sum of "
              "entries in input_data and group_by_data.")));
}

TEST(WillowInputEncoderFactoryTest, ValidateInputAndSpecTypeMismatch) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {1, 2, 3};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  InputSpec input_spec;
  InputSpec::InputVectorSpec* spec1 = input_spec.add_input_vector_specs();
  spec1->set_vector_name("metric1");
  spec1->set_data_type(InputSpec::STRING);

  EXPECT_THAT(WillowInputEncoderFactory::ValidateInputAndSpec(
                  input_data, group_by_data, input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Type mismatch for key metric1")));
}

TEST(WillowInputEncoderFactoryTest, ValidateInputAndSpecEmptyInputData) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  group_by_data["feature1"] = {"a", "b", "a"};
  InputSpec input_spec;
  InputSpec::InputVectorSpec* spec1 = input_spec.add_input_vector_specs();
  spec1->set_vector_name("feature1");
  spec1->set_data_type(InputSpec::STRING);

  EXPECT_THAT(WillowInputEncoderFactory::ValidateInputAndSpec(
                  input_data, group_by_data, input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("input_data must not be empty")));
}

TEST(WillowInputEncoderFactoryTest, ValidateInputAndSpecDomainValueNotFound) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {1};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  group_by_data["feature1"] = {"c"};
  InputSpec input_spec;
  InputSpec::InputVectorSpec* spec1 = input_spec.add_input_vector_specs();
  spec1->set_vector_name("metric1");
  spec1->set_data_type(InputSpec::INT64);
  InputSpec::InputVectorSpec* spec2 = input_spec.add_input_vector_specs();
  spec2->set_vector_name("feature1");
  spec2->set_data_type(InputSpec::STRING);
  spec2->mutable_domain_spec()->mutable_string_values()->add_values("a");
  spec2->mutable_domain_spec()->mutable_string_values()->add_values("b");

  EXPECT_THAT(WillowInputEncoderFactory::ValidateInputAndSpec(
                  input_data, group_by_data, input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Domain mismatch for key feature1")));
}

TEST(WillowInputEncoderFactoryTest,
     ValidateInputAndSpecInputDataVectorLengthMismatch) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {1, 2, 3};
  input_data["metric2"] = {1, 2};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  InputSpec input_spec;
  InputSpec::InputVectorSpec* spec1 = input_spec.add_input_vector_specs();
  spec1->set_vector_name("metric1");
  spec1->set_data_type(InputSpec::INT64);
  InputSpec::InputVectorSpec* spec2 = input_spec.add_input_vector_specs();
  spec2->set_vector_name("metric2");
  spec2->set_data_type(InputSpec::INT64);

  EXPECT_THAT(WillowInputEncoderFactory::ValidateInputAndSpec(
                  input_data, group_by_data, input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("must have the same length")));
}

TEST(WillowInputEncoderFactoryTest,
     ValidateInputAndSpecGroupByDataVectorLengthMismatch) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {1, 2, 3};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  group_by_data["feature1"] = {"a", "b"};
  InputSpec input_spec;
  InputSpec::InputVectorSpec* spec1 = input_spec.add_input_vector_specs();
  spec1->set_vector_name("metric1");
  spec1->set_data_type(InputSpec::INT64);
  InputSpec::InputVectorSpec* spec2 = input_spec.add_input_vector_specs();
  spec2->set_vector_name("feature1");
  spec2->set_data_type(InputSpec::STRING);
  spec2->mutable_domain_spec()->mutable_string_values()->add_values("a");
  spec2->mutable_domain_spec()->mutable_string_values()->add_values("b");

  EXPECT_THAT(WillowInputEncoderFactory::ValidateInputAndSpec(
                  input_data, group_by_data, input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("must have the same length")));
}

TEST(WillowInputEncoderFactoryTest,
     ValidateInputAndSpecDomainSizeVectorLengthMismatch) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {1, 2, 3};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  group_by_data["feature1"] = {"a", "b", "c"};
  InputSpec input_spec;
  InputSpec::InputVectorSpec* spec1 = input_spec.add_input_vector_specs();
  spec1->set_vector_name("metric1");
  spec1->set_data_type(InputSpec::INT64);
  spec1->mutable_domain_spec()->mutable_string_values()->add_values("x");
  InputSpec::InputVectorSpec* spec2 = input_spec.add_input_vector_specs();
  spec2->set_vector_name("feature1");
  spec2->set_data_type(InputSpec::STRING);
  spec2->mutable_domain_spec()->mutable_string_values()->add_values("a");
  spec2->mutable_domain_spec()->mutable_string_values()->add_values("b");

  EXPECT_THAT(WillowInputEncoderFactory::ValidateInputAndSpec(
                  input_data, group_by_data, input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Domain mismatch for key feature1: "
                                 "group_by_data value c not found in domain")));
}

TEST(WillowInputEncoderFactoryTest, ValidateInputAndSpecInputKeyNotInSpec) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {1};
  input_data["metric2"] = {2};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  InputSpec input_spec;
  InputSpec::InputVectorSpec* spec1 = input_spec.add_input_vector_specs();
  spec1->set_vector_name("metric1");
  spec1->set_data_type(InputSpec::INT64);
  spec1->mutable_domain_spec()->mutable_string_values()->add_values("x");

  EXPECT_THAT(
      WillowInputEncoderFactory::ValidateInputAndSpec(input_data, group_by_data,
                                                      input_spec),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "input_spec must have the same number of entries as the sum of "
              "entries in input_data and group_by_data.")));
}

TEST(WillowInputEncoderFactoryTest, ValidateInputAndSpecGroupByKeyNotInSpec) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {1};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  group_by_data["feature1"] = {"a"};
  InputSpec input_spec;
  InputSpec::InputVectorSpec* spec1 = input_spec.add_input_vector_specs();
  spec1->set_vector_name("metric1");
  spec1->set_data_type(InputSpec::INT64);
  spec1->mutable_domain_spec()->mutable_string_values()->add_values("x");

  EXPECT_THAT(
      WillowInputEncoderFactory::ValidateInputAndSpec(input_data, group_by_data,
                                                      input_spec),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "input_spec must have the same number of entries as the sum of "
              "entries in input_data and group_by_data.")));
}

TEST(WillowInputEncoderFactoryTest, ValidateInputAndSpecGroupByTypeMismatch) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {1};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  group_by_data["feature1"] = {"a"};
  InputSpec input_spec;
  InputSpec::InputVectorSpec* spec1 = input_spec.add_input_vector_specs();
  spec1->set_vector_name("metric1");
  spec1->set_data_type(InputSpec::INT64);
  spec1->mutable_domain_spec()->mutable_string_values()->add_values("x");
  InputSpec::InputVectorSpec* spec2 = input_spec.add_input_vector_specs();
  spec2->set_vector_name("feature1");
  spec2->set_data_type(InputSpec::INT64);
  spec2->mutable_domain_spec()->mutable_string_values()->add_values("y");

  EXPECT_THAT(WillowInputEncoderFactory::ValidateInputAndSpec(
                  input_data, group_by_data, input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Type mismatch for key feature1")));
}

TEST(WillowInputEncoderFactoryTest,
     ValidateInputAndSpecGlobalDomainSizeExceeded) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {1};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  group_by_data["feature1"] = {"a"};
  InputSpec input_spec;
  InputSpec::InputVectorSpec* spec1 = input_spec.add_input_vector_specs();
  spec1->set_vector_name("metric1");
  spec1->set_data_type(InputSpec::INT64);
  spec1->mutable_domain_spec()->mutable_string_values()->add_values("1, 2, 3");
  InputSpec::InputVectorSpec* spec2 = input_spec.add_input_vector_specs();
  spec2->set_vector_name("feature1");
  spec2->set_data_type(InputSpec::STRING);
  spec2->mutable_domain_spec()->mutable_string_values()->add_values("a");
  for (int i = 0; i < 1000000; ++i) {
    spec2->mutable_domain_spec()->mutable_string_values()->add_values(
        std::to_string(i));
  }

  EXPECT_THAT(WillowInputEncoderFactory::ValidateInputAndSpec(
                  input_data, group_by_data, input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Global output domain size exceeds")));
}

InputSpec::InputVectorSpec CreateStringSpec(
    const std::string& name, const std::vector<std::string>& domain) {
  InputSpec::InputVectorSpec spec;
  spec.set_vector_name(name);
  spec.set_data_type(InputSpec::STRING);
  for (const auto& val : domain) {
    spec.mutable_domain_spec()->mutable_string_values()->add_values(val);
  }
  return spec;
}

InputSpec::InputVectorSpec CreateIntSpec(const std::string& name) {
  InputSpec::InputVectorSpec spec;
  spec.set_vector_name(name);
  spec.set_data_type(InputSpec::INT64);
  return spec;
}

TEST(WillowInputEncoderFactoryTest, EncodeSimpleGroupBy) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {10, 20, 5};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  group_by_data["country"] = {"US", "CA", "US"};
  group_by_data["lang"] = {"en", "es", "es"};
  InputSpec input_spec;
  *input_spec.add_input_vector_specs() = CreateIntSpec("metric1");
  *input_spec.add_input_vector_specs() = CreateStringSpec(
      "country", {"CA", "GB", "MX", "US"});  // CA=0, GB=1, MX=2, US=3
  *input_spec.add_input_vector_specs() =
      CreateStringSpec("lang", {"en", "es"});  // en=0, es=1

  // group_by keys are sorted: "country", "lang"
  // value_to_index_maps["country"]: {"CA":0, "GB":1, "MX":2, "US":3}
  // value_to_index_maps["lang"]: {"en":0, "es":1}

  // Row 0: country=US(3), lang=en(0). metric1=10.
  // combo_index = 3*2 + 0 = 6
  // Row 1: country=CA(0), lang=es(1). metric1=20.
  // combo_index = 0*2 + 1 = 1
  // Row 2: country=US(3), lang=es(1). metric1=5.
  // combo_index = 3*2 + 1 = 7

  // Expected histogram for metric1:
  // Index 0 (CA, en): 0
  // Index 1 (CA, es): 20
  // Index 2 (GB, en): 0
  // Index 3 (GB, es): 0
  // Index 4 (MX, en): 0
  // Index 5 (MX, es): 0
  // Index 6 (US, en): 10
  // Index 7 (US, es): 5
  // Result: [0, 20, 0, 0, 0, 0, 10, 5]

  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<WillowInputExplicitEncoder> encoder,
      WillowInputEncoderFactory::CreateExplicitWillowInputEncoder(
          input_data, group_by_data, input_spec));

  EXPECT_THAT(encoder->Encode(),
              IsOkAndHolds(UnorderedElementsAre(
                  Pair("metric1", ElementsAre(0, 20, 0, 0, 0, 0, 10, 5)))));
}

TEST(WillowInputEncoderFactoryTest, EncodeTwoMetricsOneGroupBy) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {10, 20};
  input_data["metric2"] = {100, 200};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  group_by_data["country"] = {"US", "CA"};
  InputSpec input_spec;
  *input_spec.add_input_vector_specs() = CreateIntSpec("metric1");
  *input_spec.add_input_vector_specs() = CreateIntSpec("metric2");
  *input_spec.add_input_vector_specs() =
      CreateStringSpec("country", {"CA", "US"});  // CA=0, US=1

  // group_by keys are sorted: "country"
  // value_to_index_maps["country"]: {"CA":0, "US":1}
  // combinations: {0}->0, {1}->1

  // Row 0: country=US(1), metric1=10, metric2=100.
  // combo_index for {1} is 1.
  // result["metric1"][1]=10, result["metric2"][1]=100
  // Row 1: country=CA(0), metric1=20, metric2=200.
  // combo_index for {0} is 0.
  // result["metric1"][0]=20, result["metric2"][0]=200

  // Expected:
  // metric1: [20, 10]
  // metric2: [200, 100]

  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<WillowInputExplicitEncoder> encoder,
      WillowInputEncoderFactory::CreateExplicitWillowInputEncoder(
          input_data, group_by_data, input_spec));

  EXPECT_THAT(encoder->Encode(), IsOkAndHolds(UnorderedElementsAre(
                                     Pair("metric1", ElementsAre(20, 10)),
                                     Pair("metric2", ElementsAre(200, 100)))));
}

TEST(WillowInputEncoderFactoryTest, EncodeThenDecode) {
  std::unordered_map<std::string, std::vector<int64_t>> input_data;
  input_data["metric1"] = {10, 20, 5};
  std::unordered_map<std::string, std::vector<std::string>> group_by_data;
  group_by_data["country"] = {"US", "CA", "US"};
  group_by_data["lang"] = {"en", "es", "es"};
  InputSpec input_spec;
  *input_spec.add_input_vector_specs() = CreateIntSpec("metric1");
  *input_spec.add_input_vector_specs() =
      CreateStringSpec("country", {"CA", "GB", "MX", "US"});
  *input_spec.add_input_vector_specs() = CreateStringSpec("lang", {"en", "es"});

  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<WillowInputExplicitEncoder> encoder,
      WillowInputEncoderFactory::CreateExplicitWillowInputEncoder(
          input_data, group_by_data, input_spec));

  ASSERT_OK_AND_ASSIGN(auto encoded_data, encoder->Encode());
  ASSERT_OK_AND_ASSIGN(auto decoded_pair, encoder->Decode(encoded_data));

  const auto& decoded_metrics = decoded_pair.first;
  const auto& decoded_groups = decoded_pair.second;

  // The decoded output is sparse and only contains rows with non-zero metrics.
  // The order depends on iteration over dense vector.
  // metric1 values for combo indices 1,6,7 are 20,10,5.
  // The decoded result should contain 3 rows in order of combination index.
  // combo 1: CA, es, metric1=20
  // combo 6: US, en, metric1=10
  // combo 7: US, es, metric1=5
  EXPECT_THAT(decoded_metrics.at("metric1"), ElementsAre(20, 10, 5));
  EXPECT_THAT(decoded_groups.at("country"), ElementsAre("CA", "US", "US"));
  EXPECT_THAT(decoded_groups.at("lang"), ElementsAre("es", "en", "es"));
}

}  // namespace
}  // namespace willow
}  // namespace secure_aggregation
