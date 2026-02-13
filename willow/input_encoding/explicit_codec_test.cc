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

#include <memory>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "ffi_utils/status_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "willow/input_encoding/codec.h"
#include "willow/input_encoding/codec_factory.h"
#include "willow/proto/willow/input_spec.pb.h"
#include "willow/testing_utils/testing_utils.h"

namespace secure_aggregation {
namespace willow {
namespace {

using ::secure_aggregation::secagg_internal::IsOkAndHolds;
using ::secure_aggregation::secagg_internal::StatusIs;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

TEST(CodecFactoryTest, ValidateInputAndSpecLengthMismatch) {
  MetricData metric_data;
  metric_data["metric1"] = {1, 2, 3};
  GroupData group_by_data;
  group_by_data["feature1"] = {"a", "b", "a"};
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  // Missing group_by_vector_specs for "feature1"

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key feature1 found in group_by_data but not "
                                 "in input_spec.")));
}

TEST(CodecFactoryTest, ValidateInputAndSpecTypeMismatch) {
  MetricData metric_data;
  metric_data["metric1"] = {1, 2, 3};
  GroupData group_by_data;
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::STRING);

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Type mismatch for key metric1")));
}

TEST(CodecFactoryTest, ValidateInputAndSpecEmptyInputData) {
  MetricData metric_data;
  GroupData group_by_data;
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("feature1");
  group_by_spec->set_data_type(InputSpec::STRING);

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Metric data cannot be empty.")));
}

TEST(CodecFactoryTest, ValidateInputAndSpecDomainValueNotFound) {
  MetricData metric_data;
  metric_data["metric1"] = {1};
  GroupData group_by_data;
  group_by_data["feature1"] = {"c"};
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("feature1");
  group_by_spec->set_data_type(InputSpec::STRING);
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "a");
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "b");

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Domain mismatch for key feature1")));
}

TEST(CodecFactoryTest, ValidateInputAndSpecInputDataVectorLengthMismatch) {
  MetricData metric_data;
  metric_data["metric1"] = {1, 2, 3};
  metric_data["metric2"] = {1, 2};
  GroupData group_by_data;
  InputSpec input_spec;
  auto* metric_spec1 = input_spec.add_metric_vector_specs();
  metric_spec1->set_vector_name("metric1");
  metric_spec1->set_data_type(InputSpec::INT64);
  auto* metric_spec2 = input_spec.add_metric_vector_specs();
  metric_spec2->set_vector_name("metric2");
  metric_spec2->set_data_type(InputSpec::INT64);

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("must have the same length")));
}

TEST(CodecFactoryTest, ValidateInputAndSpecGroupByDataVectorLengthMismatch) {
  MetricData metric_data;
  metric_data["metric1"] = {1, 2, 3};
  GroupData group_by_data;
  group_by_data["feature1"] = {"a", "b"};
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("feature1");
  group_by_spec->set_data_type(InputSpec::STRING);
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "a");
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "b");

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("must have the same length")));
}

TEST(CodecFactoryTest, ValidateInputAndSpecDomainSizeVectorLengthMismatch) {
  MetricData metric_data;
  metric_data["metric1"] = {1, 2, 3};
  GroupData group_by_data;
  group_by_data["feature1"] = {"a", "b", "c"};
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  metric_spec->mutable_domain_spec()->mutable_string_values()->add_values("x");
  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("feature1");
  group_by_spec->set_data_type(InputSpec::STRING);
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "a");
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "b");

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Domain mismatch for key feature1: "
                                 "group_by_data value c not found in domain")));
}

TEST(CodecFactoryTest, ValidateInputAndSpecInputKeyNotInSpec) {
  MetricData metric_data;
  metric_data["metric1"] = {1};
  metric_data["metric2"] = {2};
  GroupData group_by_data;
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  metric_spec->mutable_domain_spec()->mutable_string_values()->add_values("x");
  // Missing metric_vector_specs for "metric2"

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key metric2 found in metric_data but not in "
                                 "input_spec.")));
}

TEST(CodecFactoryTest, ValidateInputAndSpecGroupByKeyNotInSpec) {
  MetricData metric_data;
  metric_data["metric1"] = {1};
  GroupData group_by_data;
  group_by_data["feature1"] = {"a"};
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  metric_spec->mutable_domain_spec()->mutable_string_values()->add_values("x");
  // Missing group_by_vector_specs for "feature1"

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key feature1 found in group_by_data but not "
                                 "in input_spec.")));
}

TEST(CodecFactoryTest, ValidateInputAndSpecGroupByTypeMismatch) {
  MetricData metric_data;
  metric_data["metric1"] = {1};
  GroupData group_by_data;
  group_by_data["feature1"] = {"a"};
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  metric_spec->mutable_domain_spec()->mutable_string_values()->add_values("x");
  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("feature1");
  group_by_spec->set_data_type(InputSpec::INT64);
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "y");

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Type mismatch for key feature1")));
}

TEST(CodecFactoryTest, ValidateInputAndSpecGlobalDomainSizeExceeded) {
  MetricData metric_data;
  metric_data["metric1"] = {1};
  GroupData group_by_data;
  group_by_data["feature1"] = {"a"};
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  metric_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "1, 2, 3");
  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("feature1");
  group_by_spec->set_data_type(InputSpec::STRING);
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "a");
  for (int i = 0; i < 1000000; ++i) {
    input_spec.mutable_group_by_vector_specs(0)
        ->mutable_domain_spec()
        ->mutable_string_values()
        ->add_values(std::to_string(i));
  }

  EXPECT_THAT(CodecFactory::CreateExplicitCodec(input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Global output domain size exceeds")));
}

TEST(CodecFactoryTest, ValidateInputAndSpecCustomGlobalDomainSize) {
  MetricData metric_data;
  metric_data["metric1"] = {1};
  GroupData group_by_data;
  group_by_data["feature1"] = {"a"};
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("feature1");
  group_by_spec->set_data_type(InputSpec::STRING);
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "a");
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "b");
  // Domain size is 2.
  EXPECT_THAT(CodecFactory::CreateExplicitCodec(input_spec, 1),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Global output domain size exceeds")));
  SECAGG_EXPECT_OK(CodecFactory::CreateExplicitCodec(input_spec, 2));
}

TEST(CodecFactoryTest, EncodeSimpleGroupBy) {
  InputSpec input_spec = CreateTestInputSpecProto();
  MetricData metric_data = CreateTestMetricData();
  GroupData group_by_data = CreateTestGroupData();

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

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));

  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              IsOkAndHolds(UnorderedElementsAre(
                  Pair("metric1", ElementsAre(0, 20, 0, 0, 0, 0, 10, 5)))));
}

TEST(CodecFactoryTest, EncodeTwoMetricsOneGroupBy) {
  MetricData metric_data;
  metric_data["metric1"] = {10, 20};
  metric_data["metric2"] = {100, 200};
  GroupData group_by_data;
  group_by_data["country"] = {"US", "CA"};
  InputSpec input_spec;
  auto* metric_spec1 = input_spec.add_metric_vector_specs();
  metric_spec1->set_vector_name("metric1");
  metric_spec1->set_data_type(InputSpec::INT64);
  auto* metric_spec2 = input_spec.add_metric_vector_specs();
  metric_spec2->set_vector_name("metric2");
  metric_spec2->set_data_type(InputSpec::INT64);
  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("country");
  group_by_spec->set_data_type(InputSpec::STRING);
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "CA");
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "US");

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

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));

  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              IsOkAndHolds(UnorderedElementsAre(
                  Pair("metric1", ElementsAre(20, 10)),
                  Pair("metric2", ElementsAre(200, 100)))));
}

TEST(CodecFactoryTest, EncodeThenDecode) {
  InputSpec input_spec = CreateTestInputSpecProto();
  MetricData metric_data = CreateTestMetricData();
  GroupData group_by_data = CreateTestGroupData();

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));

  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded_data,
                              encoder->Encode(group_by_data, metric_data));
  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_data,
                              encoder->Decode(encoded_data));

  const GroupData& decoded_groups = decoded_data.group_data;
  const MetricData& decoded_metrics = decoded_data.metric_data;

  // The decoded output is sparse and only contains rows with non-zero metrics.
  // The order depends on iteration over dense vector.
  // metric1 values for combo indices 1,6,7 are 20,10,5.
  // The decoded result should contain 3 rows in order of combination index.
  // combo 1: CA, es, metric1=20
  // combo 6: US, en, metric1=10
  // combo 7: US, es, metric1=5
  EXPECT_THAT(decoded_metrics,
              UnorderedElementsAre(Pair("metric1", ElementsAre(20, 10, 5))));
  EXPECT_THAT(
      decoded_groups,
      UnorderedElementsAre(Pair("country", ElementsAre("CA", "US", "US")),
                           Pair("lang", ElementsAre("es", "en", "es"))));
}

TEST(CodecFactoryTest, EncodeThenDecodeDataOrderDoesNotMatter) {
  InputSpec input_spec = CreateTestInputSpecProto();
  MetricData metric_data1 = CreateTestMetricData();
  GroupData group_by_data1 = CreateTestGroupData();

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder1,
                              CodecFactory::CreateExplicitCodec(input_spec));

  // Note that the order of metric_data2 and group_by_data2 is different from
  // metric_data1 and group_by_data1. The decoded result should be the same.
  MetricData metric_data2;
  metric_data2["metric1"] = {20, 10, 5};
  GroupData group_by_data2;
  group_by_data2["lang"] = {"es", "en", "es"};
  group_by_data2["country"] = {"CA", "US", "US"};

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder2,
                              CodecFactory::CreateExplicitCodec(input_spec));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto encoded_data,
                              encoder1->Encode(group_by_data1, metric_data1));
  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_data,
                              encoder2->Decode(encoded_data));

  const auto& decoded_groups = decoded_data.group_data;
  const auto& decoded_metrics = decoded_data.metric_data;

  EXPECT_THAT(decoded_metrics,
              UnorderedElementsAre(Pair("metric1", ElementsAre(20, 10, 5))));
  EXPECT_THAT(
      decoded_groups,
      UnorderedElementsAre(Pair("country", ElementsAre("CA", "US", "US")),
                           Pair("lang", ElementsAre("es", "en", "es"))));
}

TEST(CodecFactoryTest, EncodeThenDecodeNoGroupBy) {
  MetricData metric_data;
  metric_data["metric1"] = {10, 20, 5};
  MetricData expected_metric_data = metric_data;
  GroupData group_by_data;
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));

  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded_data,
                              encoder->Encode(group_by_data, metric_data));
  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_data,
                              encoder->Decode(encoded_data));

  const GroupData& decoded_groups = decoded_data.group_data;
  const MetricData& decoded_metrics = decoded_data.metric_data;

  EXPECT_EQ(decoded_groups.size(), 0);
  EXPECT_THAT(decoded_metrics,
              UnorderedElementsAre(Pair("metric1", ElementsAre(10, 20, 5))));
}

TEST(CodecFactoryTest, EncodeWithDomainValueNotFound) {
  MetricData metric_data;
  metric_data["metric1"] = {10};
  GroupData group_by_data;
  group_by_data["country"] = {"US"};
  group_by_data["lang"] = {"en"};
  group_by_data["feature1"] = {"c"};  // 'c' is not in the domain

  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  auto* group_by_spec1 = input_spec.add_group_by_vector_specs();
  group_by_spec1->set_vector_name("country");
  group_by_spec1->set_data_type(InputSpec::STRING);
  group_by_spec1->mutable_domain_spec()->mutable_string_values()->add_values(
      "US");
  group_by_spec1->mutable_domain_spec()->mutable_string_values()->add_values(
      "CA");
  auto* group_by_spec2 = input_spec.add_group_by_vector_specs();
  group_by_spec2->set_vector_name("lang");
  group_by_spec2->set_data_type(InputSpec::STRING);
  group_by_spec2->mutable_domain_spec()->mutable_string_values()->add_values(
      "en");
  group_by_spec2->mutable_domain_spec()->mutable_string_values()->add_values(
      "fr");
  auto* group_by_spec3 = input_spec.add_group_by_vector_specs();
  group_by_spec3->set_vector_name("feature1");
  group_by_spec3->set_data_type(InputSpec::STRING);
  group_by_spec3->mutable_domain_spec()->mutable_string_values()->add_values(
      "a");
  group_by_spec3->mutable_domain_spec()->mutable_string_values()->add_values(
      "b");

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));

  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Domain mismatch for key feature1: "
                                 "group_by_data value c not found in domain")));
}

}  // namespace
}  // namespace willow
}  // namespace secure_aggregation
