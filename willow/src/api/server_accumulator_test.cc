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

#include "willow/src/api/server_accumulator.h"

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "gtest/gtest.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/server_accumulator.pb.h"

namespace secure_aggregation {
namespace {

using ::secure_aggregation::willow::AggregationConfigProto;
using ::secure_aggregation::willow::ClientMessageList;
using ::secure_aggregation::willow::ServerAccumulatorState;
using ::secure_aggregation::willow::VectorConfig;

AggregationConfigProto CreateValidConfig() {
  AggregationConfigProto config;
  VectorConfig vector_config;
  vector_config.set_length(10);
  vector_config.set_bound(100);
  (*config.mutable_vector_configs())["test_vector"] = vector_config;
  config.set_max_number_of_decryptors(1);
  config.set_max_number_of_clients(10);
  config.set_session_id("test_session");
  return config;
}

TEST(WillowShellServerAccumulatorTest, CreateSucceedsWithValidConfig) {
  AggregationConfigProto config = CreateValidConfig();
  auto accumulator_or = WillowShellServerAccumulator::Create(config);
  ASSERT_TRUE(accumulator_or.ok()) << accumulator_or.status();
  EXPECT_NE(*accumulator_or, nullptr);
}

TEST(WillowShellServerAccumulatorTest, ToSerializedStateHasCorrectConfig) {
  AggregationConfigProto config = CreateValidConfig();
  auto accumulator = *WillowShellServerAccumulator::Create(config);
  auto serialized_state_or = accumulator->ToSerializedState();
  ASSERT_TRUE(serialized_state_or.ok()) << serialized_state_or.status();

  ServerAccumulatorState state;
  ASSERT_TRUE(state.ParseFromString(*serialized_state_or));
  // Check if the config matches. We serialize and deserialize to compare protos
  // easily or check fields.
  EXPECT_EQ(state.aggregation_config().session_id(), config.session_id());
  EXPECT_EQ(state.aggregation_config().max_number_of_clients(),
            config.max_number_of_clients());
}

TEST(WillowShellServerAccumulatorTest, CreateFromSerializedStateRoundTrip) {
  AggregationConfigProto config = CreateValidConfig();
  auto accumulator = *WillowShellServerAccumulator::Create(config);
  auto serialized_state_or = accumulator->ToSerializedState();
  ASSERT_TRUE(serialized_state_or.ok()) << serialized_state_or.status();

  auto accumulator2_or =
      WillowShellServerAccumulator::CreateFromSerializedState(
          *serialized_state_or);
  ASSERT_TRUE(accumulator2_or.ok()) << accumulator2_or.status();
  EXPECT_NE(*accumulator2_or, nullptr);

  auto serialized_state2_or = (*accumulator2_or)->ToSerializedState();
  ASSERT_TRUE(serialized_state2_or.ok()) << serialized_state2_or.status();
  EXPECT_EQ(*serialized_state_or, *serialized_state2_or);
}

TEST(WillowShellServerAccumulatorTest, MergeSucceedsWithEmptyAccumulators) {
  AggregationConfigProto config = CreateValidConfig();
  auto accumulator1 = *WillowShellServerAccumulator::Create(config);
  auto accumulator2 = *WillowShellServerAccumulator::Create(config);

  EXPECT_TRUE(accumulator1->Merge(std::move(accumulator2)).ok());
}

TEST(WillowShellServerAccumulatorTest, ProcessClientMessagesWithEmptyList) {
  AggregationConfigProto config = CreateValidConfig();
  auto accumulator = *WillowShellServerAccumulator::Create(config);
  ClientMessageList empty_list;
  EXPECT_TRUE(accumulator->ProcessClientMessages(empty_list).ok());
}

}  // namespace
}  // namespace secure_aggregation
