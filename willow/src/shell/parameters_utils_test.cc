/*
 * Copyright 2026 Google LLC
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

#include "willow/src/shell/parameters_utils.h"

#include "absl/status/status.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "willow/proto/willow/aggregation_config.pb.h"

namespace secure_aggregation {
namespace willow {
namespace {

TEST(ParameterUtilsTest, CreateHumanReadableShellConfigTest) {
  AggregationConfigProto config;
  VectorConfig vector_config;
  vector_config.set_length(10);
  vector_config.set_bound(100);
  (*config.mutable_vector_configs())["test_vector"] = vector_config;
  config.set_max_number_of_decryptors(1);
  config.set_max_number_of_clients(10);
  config.set_session_id("test_session");

  auto result = CreateHumanReadableShellConfig(config);

  ASSERT_TRUE(result.ok());
  EXPECT_THAT(*result, ::testing::HasSubstr("ShellKaheConfig"));
  EXPECT_THAT(*result, ::testing::HasSubstr("ShellAheConfig"));
}

TEST(ParameterUtilsTest, CreateHumanReadableShellConfigInvalidConfigTest) {
  AggregationConfigProto config;
  config.set_max_number_of_decryptors(1);
  config.set_max_number_of_clients(10);
  config.set_session_id("test_session");

  auto result = CreateHumanReadableShellConfig(config);

  EXPECT_EQ(result.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(
      result.status().message(),
      ::testing::HasSubstr("empty vector configs in aggregation config"));
}

}  // namespace
}  // namespace willow
}  // namespace secure_aggregation
