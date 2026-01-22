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

#include "willow/src/api/client.h"

#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "shell_wrapper/status_matchers.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/input_spec.pb.h"
#include "willow/src/input_encoding/codec.h"
#include "willow/src/input_encoding/codec_factory.h"
#include "willow/src/testing_utils/shell_testing_decryptor.h"

namespace secure_aggregation {
namespace willow {
namespace {

using secure_aggregation::secagg_internal::StatusIs;
using secure_aggregation::testing::ShellTestingDecryptor;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

AggregationConfigProto CreateTestConfig() {
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

TEST(WillowShellClientTest, InitializeAndGenerateContribution) {
  AggregationConfigProto config = CreateTestConfig();

  // Create and encode input.
  MetricData metric_data;
  metric_data["metric1"] = {10, 20, 5};
  GroupData group_by_data;
  group_by_data["country"] = {"US", "CA", "US"};
  group_by_data["lang"] = {"en", "es", "es"};
  InputSpec input_spec;
  auto* metric_spec = input_spec.add_metric_vector_specs();
  metric_spec->set_vector_name("metric1");
  metric_spec->set_data_type(InputSpec::INT64);
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
  SECAGG_ASSERT_OK_AND_ASSIGN(std::unique_ptr<Codec> encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));
  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded_data,
                              encoder->Encode(group_by_data, metric_data));

  // Initialize decryptor and generate public key.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto decryptor,
                              ShellTestingDecryptor::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto public_key, decryptor->GeneratePublicKey());

  // Generate client contribution, encrypted towards public key with
  // server-provided nonce.
  std::string nonce = "nonce";
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message,
      GenerateClientContribution(config, encoded_data, public_key, nonce));

  // Decrypt and build C++ copy of the data.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto decrypted_encoded_data,
                              decryptor->Decrypt(client_message));

  // Check that encoded data matches.
  EXPECT_EQ(decrypted_encoded_data.size(), encoded_data.size());
  for (const auto& [name, values] : encoded_data) {
    EXPECT_TRUE(decrypted_encoded_data.contains(name));
    const auto& decrypted_values = decrypted_encoded_data[name];
    EXPECT_THAT(decrypted_values, ElementsAreArray(values));
  }

  // Decode decrypted data.
  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_data,
                              encoder->Decode(decrypted_encoded_data));

  // Verify the decoded data matches the original input.
  const GroupData& decoded_groups = decoded_data.group_data;
  const MetricData& decoded_metrics = decoded_data.metric_data;
  EXPECT_THAT(decoded_metrics,
              UnorderedElementsAre(Pair("metric1", ElementsAre(20, 10, 5))));
  EXPECT_THAT(
      decoded_groups,
      UnorderedElementsAre(Pair("country", ElementsAre("CA", "US", "US")),
                           Pair("lang", ElementsAre("es", "en", "es"))));
}

TEST(WillowShellClientTest, EmptyEncodedData) {
  AggregationConfigProto config = CreateTestConfig();

  // Create empty encoded data.
  EncodedData encoded_data;
  EXPECT_EQ(encoded_data.size(), 0);

  // Initialize decryptor and generate public key.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto decryptor,
                              ShellTestingDecryptor::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto public_key, decryptor->GeneratePublicKey());

  // Generate client contribution.
  std::string nonce = "nonce";
  auto client_message =
      GenerateClientContribution(config, encoded_data, public_key, nonce);

  // Encoded data is empty but aggregation config has a metric.
  EXPECT_THAT(client_message, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(WillowShellClientTest, InvalidAggregationConfig) {
  // Originally valid config.
  AggregationConfigProto config = CreateTestConfig();

  // Create encoded data directly.
  EncodedData encoded_data = {{"metric1", {0, 20, 0, 0, 0, 0, 10, 5}}};

  // Initialize decryptor and generate public key.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto decryptor,
                              ShellTestingDecryptor::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto public_key, decryptor->GeneratePublicKey());

  // Encryption should work with valid config.
  std::string nonce = "nonce";
  SECAGG_EXPECT_OK(
      GenerateClientContribution(config, encoded_data, public_key, nonce));

  // Make aggregation config invalid by removing metrics.
  config.clear_vector_configs();

  // Initialization fails because aggregation config is invalid.
  EXPECT_THAT(
      GenerateClientContribution(config, encoded_data, public_key, nonce),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace willow
}  // namespace secure_aggregation
