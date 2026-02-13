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

#include "willow/api/client.h"

#include <memory>
#include <string>

#include "absl/status/status.h"
#include "ffi_utils/status_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "willow/input_encoding/codec.h"
#include "willow/input_encoding/codec_factory.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/input_spec.pb.h"
#include "willow/testing_utils/shell_testing_decryptor.h"
#include "willow/testing_utils/testing_utils.h"

namespace secure_aggregation {
namespace willow {
namespace {

using secure_aggregation::secagg_internal::StatusIs;
using secure_aggregation::testing::ShellTestingDecryptor;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

TEST(WillowShellClientTest, InitializeAndGenerateContribution) {
  AggregationConfigProto config = CreateTestAggregationConfigProto();

  // Create and encode input.
  MetricData metric_data = CreateTestMetricData();
  GroupData group_by_data = CreateTestGroupData();
  InputSpec input_spec = CreateTestInputSpecProto();
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
  AggregationConfigProto config = CreateTestAggregationConfigProto();

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
  AggregationConfigProto config = CreateTestAggregationConfigProto();

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
