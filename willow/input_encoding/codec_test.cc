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

#include "willow/input_encoding/codec.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/time/time.h"
#include "ffi_utils/status_matchers.h"
#include "gmock/gmock.h"
#include "google/protobuf/duration.pb.h"
#include "gtest/gtest.h"
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

TEST(CodecTest, ValidateInputAndSpecLengthMismatch) {
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
                              Codec::CreateFlatHistogramCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key feature1 found in group_by_data but not "
                                 "in input_spec.")));
}

TEST(CodecTest, ValidateInputAndSpecTypeMismatch) {
  MetricData metric_data;
  metric_data["metric1"] = {1, 2, 3};
  GroupData group_by_data;
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::STRING);

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              Codec::CreateFlatHistogramCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Type mismatch for key metric1")));
}

TEST(CodecTest, ValidateInputAndSpecEmptyInputData) {
  MetricData metric_data;
  GroupData group_by_data;
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("feature1");
  group_by_spec->set_data_type(InputSpec::STRING);
  group_by_spec->mutable_domain_spec()->mutable_string_values()->add_values(
      "a");

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              Codec::CreateFlatHistogramCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Metric data cannot be empty.")));
}

TEST(CodecTest, ValidateInputAndSpecDomainValueNotFound) {
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
                              Codec::CreateFlatHistogramCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Domain mismatch for key feature1")));
}

TEST(CodecTest, ValidateInputAndSpecInputDataVectorLengthMismatch) {
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
                              Codec::CreateFlatHistogramCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("must have the same length")));
}

TEST(CodecTest, ValidateInputAndSpecGroupByDataVectorLengthMismatch) {
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
                              Codec::CreateFlatHistogramCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("must have the same length")));
}

TEST(CodecTest, ValidateInputAndSpecDomainSizeVectorLengthMismatch) {
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
                              Codec::CreateFlatHistogramCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Domain mismatch for key feature1: "
                                 "group_by_data value c not found in domain")));
}

TEST(CodecTest, ValidateInputAndSpecInputKeyNotInSpec) {
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
                              Codec::CreateFlatHistogramCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key metric2 found in metric_data but not in "
                                 "input_spec.")));
}

TEST(CodecTest, ValidateInputAndSpecGroupByKeyNotInSpec) {
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
                              Codec::CreateFlatHistogramCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key feature1 found in group_by_data but not "
                                 "in input_spec.")));
}

TEST(CodecTest, ValidateInputAndSpecGroupByTypeMismatch) {
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
                              Codec::CreateFlatHistogramCodec(input_spec));
  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Type mismatch for key feature1")));
}

TEST(CodecTest, ValidateInputAndSpecMaxFlatHistogramBinsExceeded) {
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

  EXPECT_THAT(Codec::ValidateExplicitCodecInputSpec(input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Flat histogram bin count exceeds")));
}

TEST(CodecTest, ValidateInputAndSpecCustomMaxFlatHistogramBins) {
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
  EXPECT_THAT(Codec::ValidateExplicitCodecInputSpec(input_spec, 1),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Flat histogram bin count exceeds")));
  SECAGG_EXPECT_OK(Codec::ValidateExplicitCodecInputSpec(input_spec, 2));
}

TEST(CodecTest, ValidateInputSpecFlattenedDomainSize) {
  InputSpec input_spec;

  // Metric 1
  auto* metric_spec1 = input_spec.add_metric_vector_specs();
  metric_spec1->set_vector_name("metric1");
  metric_spec1->set_data_type(InputSpec::INT64);

  // Metric 2
  auto* metric_spec2 = input_spec.add_metric_vector_specs();
  metric_spec2->set_vector_name("metric2");
  metric_spec2->set_data_type(InputSpec::INT64);

  // Group-by 1: Time Domain (size = 5 + 1 = 6)
  auto* group_by_spec1 = input_spec.add_group_by_vector_specs();
  group_by_spec1->set_vector_name("time");
  group_by_spec1->set_data_type(InputSpec::STRING);
  auto* time_domain = group_by_spec1->mutable_domain_spec()->mutable_time();
  time_domain->mutable_period_duration()->set_seconds(86400);  // 1 day
  time_domain->set_num_periods(5);                             // 5 days
  time_domain->set_timezone("UTC");
  time_domain->set_format(absl::RFC3339_full);

  // Group-by 2: String values domain (size = 3)
  auto* group_by_spec2 = input_spec.add_group_by_vector_specs();
  group_by_spec2->set_vector_name("country");
  group_by_spec2->set_data_type(InputSpec::STRING);
  auto* string_values =
      group_by_spec2->mutable_domain_spec()->mutable_string_values();
  string_values->add_values("US");
  string_values->add_values("CA");
  string_values->add_values("MX");

  // Total flattened domain size is (num_periods + 1) * string_values_size = 6 *
  // 3 = 18. Passing a smaller limit should fail.
  EXPECT_THAT(Codec::ValidateExplicitCodecInputSpec(input_spec, 17),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Flat histogram bin count exceeds")));
  SECAGG_EXPECT_OK(Codec::ValidateExplicitCodecInputSpec(input_spec, 18));
}

TEST(CodecTest, EncodeSimpleGroupBy) {
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
                              Codec::CreateFlatHistogramCodec(input_spec));

  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              IsOkAndHolds(UnorderedElementsAre(
                  Pair("metric1", ElementsAre(0, 20, 0, 0, 0, 0, 10, 5)))));
}

TEST(CodecTest, EncodeTwoMetricsOneGroupBy) {
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
                              Codec::CreateFlatHistogramCodec(input_spec));

  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              IsOkAndHolds(UnorderedElementsAre(
                  Pair("metric1", ElementsAre(20, 10)),
                  Pair("metric2", ElementsAre(200, 100)))));
}

TEST(CodecTest, EncodeThenDecode) {
  InputSpec input_spec = CreateTestInputSpecProto();
  MetricData metric_data = CreateTestMetricData();
  GroupData group_by_data = CreateTestGroupData();

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              Codec::CreateFlatHistogramCodec(input_spec));

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

TEST(CodecTest, EncodeThenDecodeDataOrderDoesNotMatter) {
  InputSpec input_spec = CreateTestInputSpecProto();
  MetricData metric_data1 = CreateTestMetricData();
  GroupData group_by_data1 = CreateTestGroupData();

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder1,
                              Codec::CreateFlatHistogramCodec(input_spec));

  // Note that the order of metric_data2 and group_by_data2 is different from
  // metric_data1 and group_by_data1. The decoded result should be the same.
  MetricData metric_data2;
  metric_data2["metric1"] = {20, 10, 5};
  GroupData group_by_data2;
  group_by_data2["lang"] = {"es", "en", "es"};
  group_by_data2["country"] = {"CA", "US", "US"};

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder2,
                              Codec::CreateFlatHistogramCodec(input_spec));

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

TEST(CodecTest, EncodeThenDecodeNoGroupBy) {
  MetricData metric_data;
  metric_data["metric1"] = {10, 20, 5};
  MetricData expected_metric_data = metric_data;
  GroupData group_by_data;
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);

  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              Codec::CreateFlatHistogramCodec(input_spec));

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

TEST(CodecTest, EncodeWithDomainValueNotFound) {
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
                              Codec::CreateFlatHistogramCodec(input_spec));

  EXPECT_THAT(encoder->Encode(group_by_data, metric_data),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Domain mismatch for key feature1: "
                                 "group_by_data value c not found in domain")));
}

TEST(CodecTest, CreateCodecUnsupportedDomain) {
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);

  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("group1");
  group_by_spec->set_data_type(InputSpec::STRING);

  // Set unsupported interval domain on a group-by vector
  group_by_spec->mutable_domain_spec()->mutable_interval()->set_min(0);
  group_by_spec->mutable_domain_spec()->mutable_interval()->set_max(10);

  EXPECT_THAT(Codec::CreateFlatHistogramCodec(input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported domain type")));
}

TEST(CodecTest, GetEncodedVectorLengthSuccess) {
  InputSpec input_spec = CreateTestInputSpecProto();
  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> codec,
                              Codec::CreateFlatHistogramCodec(input_spec));
  EXPECT_THAT(codec->GetEncodedVectorLength("metric1"), IsOkAndHolds(8));
  EXPECT_THAT(codec->GetEncodedVectorLength("unknown_metric"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("not found in input spec")));
}

TEST(CodecTest, CreateCodecOverflow) {
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);

  // Add 8 domains of size 2^10. (2^10)^8 = 2^80 > 2^64, which overflows
  // int64_t.
  for (int j = 0; j < 8; ++j) {
    auto* spec = input_spec.add_group_by_vector_specs();
    spec->set_vector_name("group" + std::to_string(j));
    spec->set_data_type(InputSpec::STRING);
    for (int i = 0; i < 1024; ++i) {
      spec->mutable_domain_spec()->mutable_string_values()->add_values(
          std::to_string(i));
    }
  }

  EXPECT_THAT(
      Codec::CreateFlatHistogramCodec(input_spec),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("overflow")));
}

TEST(CodecTest, ValidateInputSpecWithTimeDomain) {
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);

  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("time");
  group_by_spec->set_data_type(InputSpec::STRING);

  auto* time_domain = group_by_spec->mutable_domain_spec()->mutable_time();
  time_domain->mutable_period_duration()->set_seconds(86400);  // 1 day
  time_domain->set_num_periods(6);                             // 6 days
  time_domain->set_timezone("UTC");

  // Valid spec
  SECAGG_EXPECT_OK(Codec::ValidateExplicitCodecInputSpec(input_spec));

  // Valid spec with lookback_window
  time_domain->mutable_lookback_window()->set_seconds(86400 * 2);  // 2 days
  SECAGG_EXPECT_OK(Codec::ValidateExplicitCodecInputSpec(input_spec));

  // Invalid lookback_window <= 0
  time_domain->mutable_lookback_window()->set_seconds(0);
  EXPECT_THAT(Codec::ValidateExplicitCodecInputSpec(input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("lookback_window must be > 0")));
  time_domain->clear_lookback_window();

  // Invalid period_duration <= 0
  time_domain->mutable_period_duration()->set_seconds(0);
  EXPECT_THAT(Codec::ValidateExplicitCodecInputSpec(input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("period_duration must be > 0")));
  time_domain->mutable_period_duration()->set_seconds(86400);

  // Invalid num_periods <= 0
  time_domain->set_num_periods(0);
  EXPECT_THAT(Codec::ValidateExplicitCodecInputSpec(input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("num_periods must be > 0")));
  time_domain->set_num_periods(6);

  // Invalid timezone
  time_domain->set_timezone("Invalid/Timezone");
  EXPECT_THAT(Codec::ValidateExplicitCodecInputSpec(input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid timezone")));
  time_domain->set_timezone("UTC");

  // Invalid data type (must be STRING)
  group_by_spec->set_data_type(InputSpec::INT64);
  EXPECT_THAT(Codec::ValidateExplicitCodecInputSpec(input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Time domain can only be used with STRING")));
}

TEST(CodecTest, CreateFlatHistogramCodecWithoutReferenceTimeFails) {
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);

  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("time");
  group_by_spec->set_data_type(InputSpec::STRING);

  auto* time_domain = group_by_spec->mutable_domain_spec()->mutable_time();
  time_domain->mutable_period_duration()->set_seconds(86400);  // 1 day
  time_domain->set_num_periods(6);                             // 6 days
  time_domain->set_timezone("UTC");

  // Creation without reference_time should fail
  EXPECT_THAT(Codec::CreateFlatHistogramCodec(input_spec),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("reference_time is required")));
}

TEST(CodecTest, EncodeTimeDomain) {
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);

  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("time");
  group_by_spec->set_data_type(InputSpec::STRING);

  auto* time_domain = group_by_spec->mutable_domain_spec()->mutable_time();
  time_domain->mutable_period_duration()->set_seconds(86400);  // 1 day
  time_domain->set_num_periods(6);                             // 6 days
  time_domain->set_timezone("UTC");
  time_domain->set_format(absl::RFC3339_full);
  time_domain->mutable_lookback_window()->set_seconds(86400 * 2);  // 2 days

  // Encoding time = Day 8 start
  absl::Time encoding_time;
  std::string err;
  ASSERT_TRUE(absl::ParseTime(absl::RFC3339_full, "1970-01-09T00:00:00Z",
                              &encoding_time, &err))
      << err;

  // Event times
  std::string t1_str =
      "1970-01-08T12:00:00Z";  // Valid (Day 7, 12h ago relative to Day 8 start)
  std::string t2_str = "1970-01-06T12:00:00Z";  // Stale (Day 5, 2.5d ago)
  std::string t3_str = "1970-01-10T12:00:00Z";  // Future (Day 9, 1.5d future)

  MetricData metric_data;
  metric_data["metric1"] = {10, 20, 30};
  GroupData group_by_data;
  group_by_data["time"] = {t1_str, t2_str, t3_str};

  SECAGG_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Codec> encoder,
      Codec::CreateFlatHistogramCodec(input_spec, encoding_time));

  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded_data,
                              encoder->Encode(group_by_data, metric_data));

  EXPECT_THAT(encoded_data.at("metric1"), ElementsAre(0, 10, 0, 0, 0, 0, 30));
}

TEST(CodecTest, DecodeTimeDomain) {
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);

  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("time");
  group_by_spec->set_data_type(InputSpec::STRING);

  auto* time_domain = group_by_spec->mutable_domain_spec()->mutable_time();
  time_domain->mutable_period_duration()->set_seconds(86400);  // 1 day
  time_domain->set_num_periods(6);                             // 6 days
  time_domain->set_timezone("UTC");
  time_domain->set_format("%Y-%m-%d");

  // decoding_anchor_time = 1970-01-09 00:00:00 UTC (Day 8 start)
  absl::Time decoding_anchor_time;
  std::string err;
  ASSERT_TRUE(absl::ParseTime(absl::RFC3339_full, "1970-01-09T00:00:00Z",
                              &decoding_anchor_time, &err))
      << err;

  SECAGG_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Codec> decoder,
      Codec::CreateFlatHistogramCodec(input_spec, decoding_anchor_time));

  // Create a histogram with 7 buckets (num_periods + 1).
  EncodedData encoded_data;
  encoded_data["metric1"] = std::vector<int64_t>(7, 0);
  encoded_data["metric1"][2] = 100;
  encoded_data["metric1"][6] = 200;

  // Decode and check the timestamps.
  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_data,
                              decoder->Decode(encoded_data));
  EXPECT_THAT(decoded_data.metric_data.at("metric1"), ElementsAre(100, 200));

  // Bucket 2 maps to Day 8 since since 8 % 6 = 2 and 8 <= 8 < 8 + 6.
  std::string expected_time_2 = "1970-01-09";
  // Bucket 6 is an invalid timestamp, so it maps back to the default.
  std::string expected_time_6 = "1970-01-01";
  EXPECT_THAT(decoded_data.group_data.at("time"),
              ElementsAre(expected_time_2, expected_time_6));
}

TEST(CodecTest, EncodeThenDecodeLocalTime) {
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);

  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("time");
  group_by_spec->set_data_type(InputSpec::STRING);

  auto* time_domain = group_by_spec->mutable_domain_spec()->mutable_time();
  time_domain->mutable_period_duration()->set_seconds(86400);  // 1 day
  time_domain->set_num_periods(6);                             // 6 days
  // Unset timezone defaults to UTC.
  time_domain->set_format("%Y-%m-%d");  // No timezone in output, just civil day
  time_domain->mutable_lookback_window()->set_seconds(86400 * 2);  // 2 days

  // Scenario: Two local events occurring in different physical timezones, but
  // representing the exact same civil day on their respective devices.

  // --- Client 1 (New York, EDT/UTC-4) ---
  absl::TimeZone ny_tz;
  ASSERT_TRUE(absl::LoadTimeZone("America/New_York", &ny_tz));
  // Device encodes at local 17:34:56.
  absl::Time encoding_time1;
  ASSERT_TRUE(absl::ParseTime(absl::RFC3339_full, "2026-05-12T17:34:56-04:00",
                              &encoding_time1, nullptr));

  // Event occurred 15 minutes prior to encoding.
  absl::Time event_time_ny = encoding_time1 - absl::Minutes(15);
  // Format using local format "%Y-%m-%d" -> "2026-05-12".
  std::string t1_str = absl::FormatTime("%Y-%m-%d", event_time_ny, ny_tz);
  MetricData md1;
  md1["metric1"] = {10};
  GroupData gd1;
  gd1["time"] = {t1_str};

  SECAGG_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Codec> encoder1,
      Codec::CreateFlatHistogramCodec(input_spec, encoding_time1));
  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData ed1, encoder1->Encode(gd1, md1));

  // --- Client 2 (Los Angeles, PDT/UTC-7) ---
  absl::TimeZone la_tz;
  ASSERT_TRUE(absl::LoadTimeZone("America/Los_Angeles", &la_tz));
  // Device encodes at local 17:39:12.
  absl::Time encoding_time2;
  ASSERT_TRUE(absl::ParseTime(absl::RFC3339_full, "2026-05-12T17:39:12-07:00",
                              &encoding_time2, nullptr));

  // Event occurred 3 hours and 12 minutes prior to encoding
  absl::Time event_time_la =
      encoding_time2 - absl::Hours(3) - absl::Minutes(12);
  // Format using local format "%Y-%m-%d" -> "2026-05-12".
  std::string t2_str = absl::FormatTime("%Y-%m-%d", event_time_la, la_tz);
  MetricData md2;
  md2["metric1"] = {20};
  GroupData gd2;
  gd2["time"] = {t2_str};

  SECAGG_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Codec> encoder2,
      Codec::CreateFlatHistogramCodec(input_spec, encoding_time2));
  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData ed2, encoder2->Encode(gd2, md2));

  // Decode using decoding_anchor_time = 2026-05-12T00:00:00Z UTC.
  absl::Time decoding_anchor_time;
  ASSERT_TRUE(absl::ParseTime(absl::RFC3339_full, "2026-05-12T00:00:00Z",
                              &decoding_anchor_time, nullptr));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Codec> decoder,
      Codec::CreateFlatHistogramCodec(input_spec, decoding_anchor_time));

  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_data_1, decoder->Decode(ed1));
  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_data_2, decoder->Decode(ed2));

  // The bucket maps back to 2026-05-12.
  std::string expected_decoded_time = "2026-05-12";

  EXPECT_THAT(decoded_data_1.metric_data.at("metric1"), ElementsAre(10));
  EXPECT_THAT(decoded_data_1.group_data.at("time"),
              ElementsAre(expected_decoded_time));

  EXPECT_THAT(decoded_data_2.metric_data.at("metric1"), ElementsAre(20));
  EXPECT_THAT(decoded_data_2.group_data.at("time"),
              ElementsAre(expected_decoded_time));
}

TEST(CodecTest, EncodeThenDecodeAbsoluteTime) {
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);

  auto* group_by_spec = input_spec.add_group_by_vector_specs();
  group_by_spec->set_vector_name("time");
  group_by_spec->set_data_type(InputSpec::STRING);

  auto* time_domain = group_by_spec->mutable_domain_spec()->mutable_time();
  time_domain->mutable_period_duration()->set_seconds(86400);  // 1 day
  time_domain->set_num_periods(6);                             // 6 days
  time_domain->set_timezone("America/Los_Angeles");  // Output TimeZone
  time_domain->set_format(absl::RFC3339_full);
  time_domain->mutable_lookback_window()->set_seconds(86400 * 2);  // 2 days

  // Scenario: Two local events occurring in different civil days but at the
  // same absolute time. Both devices also encode at the exact same absolute
  // physical time. Just past midnight ET on May 12, but still May 11 in LA.
  absl::Time encoding_time;
  ASSERT_TRUE(absl::ParseTime(absl::RFC3339_full, "2026-05-12T00:34:56-04:00",
                              &encoding_time, nullptr));

  // Event occurred 3 minutes prior to encoding.
  absl::Time event_time = encoding_time - absl::Minutes(3);

  // --- Client 1 (New York, EDT/UTC-4) ---
  absl::TimeZone ny_tz;
  ASSERT_TRUE(absl::LoadTimeZone("America/New_York", &ny_tz));
  std::string t1_str = absl::FormatTime(absl::RFC3339_full, event_time, ny_tz);
  MetricData md1;
  md1["metric1"] = {10};
  GroupData gd1;
  gd1["time"] = {t1_str};

  SECAGG_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Codec> encoder1,
      Codec::CreateFlatHistogramCodec(input_spec, encoding_time));
  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData ed1, encoder1->Encode(gd1, md1));

  // --- Client 2 (Los Angeles, PDT/UTC-7) ---
  absl::TimeZone la_tz;
  ASSERT_TRUE(absl::LoadTimeZone("America/Los_Angeles", &la_tz));
  std::string t2_str = absl::FormatTime(absl::RFC3339_full, event_time, la_tz);
  MetricData md2;
  md2["metric1"] = {20};
  GroupData gd2;
  gd2["time"] = {t2_str};

  SECAGG_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Codec> encoder2,
      Codec::CreateFlatHistogramCodec(input_spec, encoding_time));
  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData ed2, encoder2->Encode(gd2, md2));

  // Decode using anchor time before the events.
  absl::Time decoding_anchor_time;
  ASSERT_TRUE(absl::ParseTime(absl::RFC3339_full, "2026-05-10T00:00:00Z",
                              &decoding_anchor_time, nullptr));

  SECAGG_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Codec> decoder,
      Codec::CreateFlatHistogramCodec(input_spec, decoding_anchor_time));

  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_data_1, decoder->Decode(ed1));
  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_data_2, decoder->Decode(ed2));

  // Reconstructed absolute time is 2026-05-12T00:00:00Z UTC. It's the start of
  // the day in UTC because the default origin time is in UTC, and the period is
  // 1 day. Formatted back using the spec's configured timezone
  // (America/Los_Angeles, PDT UTC-7) and full RFC3339 format:
  // 2026-05-12T00:00:00Z UTC -> "2026-05-11T17:00:00-07:00".
  std::string expected_decoded_time = "2026-05-11T17:00:00-07:00";

  EXPECT_THAT(decoded_data_1.metric_data.at("metric1"), ElementsAre(10));
  EXPECT_THAT(decoded_data_1.group_data.at("time"),
              ElementsAre(expected_decoded_time));

  EXPECT_THAT(decoded_data_2.metric_data.at("metric1"), ElementsAre(20));
  EXPECT_THAT(decoded_data_2.group_data.at("time"),
              ElementsAre(expected_decoded_time));
}

}  // namespace
}  // namespace willow
}  // namespace secure_aggregation
