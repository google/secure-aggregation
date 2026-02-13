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

#include "willow/testing_utils/shell_testing_decryptor.h"

#include "absl/status/status.h"
#include "ffi_utils/status_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "willow/proto/willow/aggregation_config.pb.h"

namespace secure_aggregation {
namespace {

using secure_aggregation::secagg_internal::StatusIs;
using ::testing::NotNull;

TEST(ShellTestingDecryptorTest, CreateAndGenerateKey) {
  willow::AggregationConfigProto config;
  config.set_max_number_of_decryptors(1);
  config.set_max_number_of_clients(1);
  config.set_max_decryptor_dropouts(0);
  config.set_key_id("test_key");
  auto& vector_config = (*config.mutable_vector_configs())["test_vec"];
  vector_config.set_length(10);
  vector_config.set_bound(100);

  SECAGG_ASSERT_OK_AND_ASSIGN(auto decryptor,
                              testing::ShellTestingDecryptor::Create(config));
  ASSERT_THAT(decryptor, NotNull());

  SECAGG_ASSERT_OK_AND_ASSIGN(const auto& pk, decryptor->GeneratePublicKey());
  EXPECT_TRUE(pk.has_poly());
}

TEST(ShellTestingDecryptorTest, InvalidAggregationConfig) {
  // Aggregation config with no metrics.
  willow::AggregationConfigProto config_proto;
  config_proto.set_max_number_of_decryptors(1);
  config_proto.set_max_decryptor_dropouts(0);
  config_proto.set_max_number_of_clients(2);
  config_proto.set_key_id("test");

  // Initialization fails because aggregation config is invalid.
  EXPECT_THAT(testing::ShellTestingDecryptor::Create(config_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace secure_aggregation
