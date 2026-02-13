// Copyright 2026 Google LLC
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

#include "willow/testing_utils/testing_utils.h"

#include "willow/input_encoding/codec.h"

namespace secure_aggregation::willow {

AggregationConfigProto CreateTestAggregationConfigProto() {
  AggregationConfigProto config;
  VectorConfig vector_config;
  vector_config.set_length(8);  // 4 countries x 2 languages
  vector_config.set_bound(100);
  (*config.mutable_vector_configs())["metric1"] = vector_config;
  config.set_max_number_of_decryptors(1);
  config.set_max_number_of_clients(10);
  config.set_key_id("test");
  return config;
}

InputSpec CreateTestInputSpecProto() {
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
  metric_spec->mutable_domain_spec()->mutable_interval()->set_min(0);
  metric_spec->mutable_domain_spec()->mutable_interval()->set_max(100);
  auto* group_by_spec1 = input_spec.add_group_by_vector_specs();
  group_by_spec1->set_vector_name("country");
  group_by_spec1->set_data_type(InputSpec::STRING);
  group_by_spec1->mutable_domain_spec()->mutable_string_values()->add_values(
      "CA");
  group_by_spec1->mutable_domain_spec()->mutable_string_values()->add_values(
      "GB");
  group_by_spec1->mutable_domain_spec()->mutable_string_values()->add_values(
      "MX");
  group_by_spec1->mutable_domain_spec()->mutable_string_values()->add_values(
      "US");
  auto* group_by_spec2 = input_spec.add_group_by_vector_specs();
  group_by_spec2->set_vector_name("lang");
  group_by_spec2->set_data_type(InputSpec::STRING);
  group_by_spec2->mutable_domain_spec()->mutable_string_values()->add_values(
      "en");
  group_by_spec2->mutable_domain_spec()->mutable_string_values()->add_values(
      "es");
  return input_spec;
}

MetricData CreateTestMetricData() {
  MetricData metric_data;
  metric_data["metric1"] = {10, 20, 5};
  return metric_data;
}

GroupData CreateTestGroupData() {
  GroupData group_by_data;
  group_by_data["country"] = {"US", "CA", "US"};
  group_by_data["lang"] = {"en", "es", "es"};
  return group_by_data;
}

}  // namespace secure_aggregation::willow
