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
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "ffi_utils/status_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/messages.pb.h"
#include "willow/proto/willow/server_accumulator.pb.h"
#include "willow/src/api/client.h"
#include "willow/src/input_encoding/codec.h"
#include "willow/src/testing_utils/shell_testing_decryptor.h"

namespace secure_aggregation {
namespace willow {
namespace {

using ::secure_aggregation::secagg_internal::StatusIs;
using ::testing::HasSubstr;

AggregationConfigProto CreateValidConfig() {
  AggregationConfigProto config;
  VectorConfig vector_config;
  vector_config.set_length(10);
  vector_config.set_bound(100);
  (*config.mutable_vector_configs())["test_vector"] = vector_config;
  config.set_max_number_of_decryptors(1);
  config.set_max_number_of_clients(10);
  config.set_key_id("test_key");
  return config;
}

TEST(BasicServerAccumulatorTest, CreateSucceedsWithValidConfig) {
  AggregationConfigProto config = CreateValidConfig();
  auto accumulator_or = ServerAccumulator::Create(config);
  ASSERT_TRUE(accumulator_or.ok()) << accumulator_or.status();
  EXPECT_NE(*accumulator_or, nullptr);
}

TEST(BasicServerAccumulatorTest, ToSerializedStateHasCorrectConfig) {
  AggregationConfigProto config = CreateValidConfig();
  SECAGG_ASSERT_OK_AND_ASSIGN(auto accumulator,
                              ServerAccumulator::Create(config));
  auto serialized_state_or = accumulator->ToSerializedState();
  ASSERT_TRUE(serialized_state_or.ok()) << serialized_state_or.status();

  ServerAccumulatorState state;
  ASSERT_TRUE(state.ParseFromString(*serialized_state_or));
  // Check if the config matches. We serialize and deserialize to compare protos
  // easily or check fields.
  EXPECT_EQ(state.aggregation_config().key_id(), config.key_id());
  EXPECT_EQ(state.aggregation_config().max_number_of_clients(),
            config.max_number_of_clients());
}

TEST(BasicServerAccumulatorTest, CreateFromSerializedStateRoundTrip) {
  AggregationConfigProto config = CreateValidConfig();
  SECAGG_ASSERT_OK_AND_ASSIGN(auto accumulator,
                              ServerAccumulator::Create(config));
  auto serialized_state_or = accumulator->ToSerializedState();
  ASSERT_TRUE(serialized_state_or.ok()) << serialized_state_or.status();

  auto accumulator2_or =
      ServerAccumulator::CreateFromSerializedState(*serialized_state_or);
  ASSERT_TRUE(accumulator2_or.ok()) << accumulator2_or.status();
  EXPECT_NE(*accumulator2_or, nullptr);

  auto serialized_state2_or = (*accumulator2_or)->ToSerializedState();
  ASSERT_TRUE(serialized_state2_or.ok()) << serialized_state2_or.status();
  EXPECT_EQ(*serialized_state_or, *serialized_state2_or);
}

TEST(BasicServerAccumulatorTest, MergeSucceedsWithEmptyAccumulators) {
  AggregationConfigProto config = CreateValidConfig();
  SECAGG_ASSERT_OK_AND_ASSIGN(auto accumulator1,
                              ServerAccumulator::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto accumulator2,
                              ServerAccumulator::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_1,
                              accumulator1->ToSerializedState());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_2,
                              accumulator2->ToSerializedState());

  EXPECT_TRUE(accumulator1->Merge(std::move(accumulator2)).ok());
}

TEST(BasicServerAccumulatorTest, ProcessClientMessagesWithEmptyList) {
  AggregationConfigProto config = CreateValidConfig();
  auto accumulator = *ServerAccumulator::Create(config);
  ClientMessageRange empty_list;
  EXPECT_TRUE(accumulator->ProcessClientMessages(empty_list).ok());
}

class ServerAccumulatorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    config_ = CreateValidConfig();
    SECAGG_ASSERT_OK_AND_ASSIGN(accumulator_,
                                ServerAccumulator::Create(config_));
    SECAGG_ASSERT_OK_AND_ASSIGN(
        decryptor_, testing::ShellTestingDecryptor::Create(config_));
    SECAGG_ASSERT_OK_AND_ASSIGN(public_key_, decryptor_->GeneratePublicKey());
  }

  AggregationConfigProto config_;
  std::unique_ptr<ServerAccumulator> accumulator_;
  std::unique_ptr<testing::ShellTestingDecryptor> decryptor_;
  willow::ShellAhePublicKey public_key_;
};

TEST_F(ServerAccumulatorTest, ProcessSingleMessageSucceeds) {
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};
  std::string nonce = "nonce1";
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message,
      GenerateClientContribution(config_, encoded_data, public_key_, nonce));
  ClientMessageRange messages;
  *messages.add_client_messages() = client_message;
  messages.mutable_nonce_range()->set_start("nonce1");
  messages.mutable_nonce_range()->set_end("nonce2");

  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages).ok());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_state,
                              accumulator_->ToSerializedState());
  ServerAccumulatorState state;
  ASSERT_TRUE(state.ParseFromString(serialized_state));
  ASSERT_EQ(state.processed_nonce_ranges_size(), 1);
  EXPECT_EQ(state.processed_nonce_ranges_size(), state.verifier_states_size());
  EXPECT_EQ(state.processed_nonce_ranges(0).start(), "nonce1");
  EXPECT_EQ(state.processed_nonce_ranges(0).end(), "nonce2");
}

TEST_F(ServerAccumulatorTest, ProcessMessageOutOfRangeFails) {
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};
  std::string nonce = "nonce1";
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message,
      GenerateClientContribution(config_, encoded_data, public_key_, nonce));
  ClientMessageRange messages;
  *messages.add_client_messages() = client_message;
  messages.mutable_nonce_range()->set_start("nonce2");
  messages.mutable_nonce_range()->set_end("nonce3");

  EXPECT_THAT(accumulator_->ProcessClientMessages(messages),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("outside of range")));
}

TEST_F(ServerAccumulatorTest, ProcessRangeTwiceFails) {
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};
  std::string nonce = "nonce1";
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message,
      GenerateClientContribution(config_, encoded_data, public_key_, nonce));
  ClientMessageRange messages;
  *messages.add_client_messages() = client_message;
  messages.mutable_nonce_range()->set_start("nonce1");
  messages.mutable_nonce_range()->set_end("nonce2");

  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages).ok());
  EXPECT_THAT(accumulator_->ProcessClientMessages(messages),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("already processed")));
}

TEST_F(ServerAccumulatorTest, ProcessMultipleMessagesSucceeds) {
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message1,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce1"));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message2,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce2"));

  ClientMessageRange messages;
  *messages.add_client_messages() = client_message1;
  *messages.add_client_messages() = client_message2;
  messages.mutable_nonce_range()->set_start("nonce1");
  messages.mutable_nonce_range()->set_end("nonce3");

  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages).ok());

  SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_state,
                              accumulator_->ToSerializedState());
  ServerAccumulatorState state;
  ASSERT_TRUE(state.ParseFromString(serialized_state));
  ASSERT_EQ(state.processed_nonce_ranges_size(), 1);
  EXPECT_EQ(state.processed_nonce_ranges_size(), state.verifier_states_size());
  EXPECT_EQ(state.processed_nonce_ranges(0).start(), "nonce1");
  EXPECT_EQ(state.processed_nonce_ranges(0).end(), "nonce3");
}

TEST_F(ServerAccumulatorTest, ProcessClientMessagesIgnoresInvalidMessage) {
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message1,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce1"));

  // Use a valid message for nonce1, but change nonce to nonce2.
  // This invalidates the proof which is bound to the nonce.
  auto client_message2 = client_message1;
  client_message2.set_nonce("nonce2");

  ClientMessageRange messages;
  *messages.add_client_messages() = client_message1;
  *messages.add_client_messages() = client_message2;
  messages.mutable_nonce_range()->set_start("nonce1");
  messages.mutable_nonce_range()->set_end("nonce3");

  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages).ok());

  // We expect the range to be processed despite the invalid message.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_state,
                              accumulator_->ToSerializedState());
  ServerAccumulatorState state;
  ASSERT_TRUE(state.ParseFromString(serialized_state));
  ASSERT_EQ(state.processed_nonce_ranges_size(), 1);
  EXPECT_EQ(state.processed_nonce_ranges_size(), state.verifier_states_size());
  EXPECT_EQ(state.processed_nonce_ranges(0).start(), "nonce1");
  EXPECT_EQ(state.processed_nonce_ranges(0).end(), "nonce3");
}

TEST_F(ServerAccumulatorTest, ProcessClientMessagesMergesAdjacentRanges) {
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message1,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce1"));
  ClientMessageRange messages1;
  *messages1.add_client_messages() = client_message1;
  messages1.mutable_nonce_range()->set_start("nonce1");
  messages1.mutable_nonce_range()->set_end("nonce2");
  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages1).ok());

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message2,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce2"));
  ClientMessageRange messages2;
  *messages2.add_client_messages() = client_message2;
  messages2.mutable_nonce_range()->set_start("nonce2");
  messages2.mutable_nonce_range()->set_end("nonce3");
  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages2).ok());

  SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_state,
                              accumulator_->ToSerializedState());
  ServerAccumulatorState state;
  ASSERT_TRUE(state.ParseFromString(serialized_state));
  ASSERT_EQ(state.processed_nonce_ranges_size(), 1);
  EXPECT_EQ(state.processed_nonce_ranges_size(), state.verifier_states_size());
  EXPECT_EQ(state.processed_nonce_ranges(0).start(), "nonce1");
  EXPECT_EQ(state.processed_nonce_ranges(0).end(), "nonce3");
}

TEST_F(ServerAccumulatorTest, MergeSucceedsWithNonEmptyAccumulators) {
  SECAGG_ASSERT_OK_AND_ASSIGN(auto accumulator2,
                              ServerAccumulator::Create(config_));
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message1,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce1"));
  ClientMessageRange messages1;
  *messages1.add_client_messages() = client_message1;
  messages1.mutable_nonce_range()->set_start("nonce1");
  messages1.mutable_nonce_range()->set_end("nonce2");
  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages1).ok());

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message2,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce3"));
  ClientMessageRange messages2;
  *messages2.add_client_messages() = client_message2;
  messages2.mutable_nonce_range()->set_start("nonce3");
  messages2.mutable_nonce_range()->set_end("nonce4");
  EXPECT_TRUE(accumulator2->ProcessClientMessages(messages2).ok());

  EXPECT_TRUE(accumulator_->Merge(std::move(accumulator2)).ok());

  SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_state,
                              accumulator_->ToSerializedState());
  ServerAccumulatorState state;
  ASSERT_TRUE(state.ParseFromString(serialized_state));
  ASSERT_EQ(state.processed_nonce_ranges_size(), 2);
  EXPECT_EQ(state.processed_nonce_ranges_size(), state.verifier_states_size());
  // Ranges should be sorted.
  EXPECT_EQ(state.processed_nonce_ranges(0).start(), "nonce1");
  EXPECT_EQ(state.processed_nonce_ranges(0).end(), "nonce2");
  EXPECT_EQ(state.processed_nonce_ranges(1).start(), "nonce3");
  EXPECT_EQ(state.processed_nonce_ranges(1).end(), "nonce4");
}

TEST_F(ServerAccumulatorTest, MergeSucceedsAndMergesAdjacentRanges) {
  SECAGG_ASSERT_OK_AND_ASSIGN(auto accumulator2,
                              ServerAccumulator::Create(config_));
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message1,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce1"));
  ClientMessageRange messages1;
  *messages1.add_client_messages() = client_message1;
  messages1.mutable_nonce_range()->set_start("nonce1");
  messages1.mutable_nonce_range()->set_end("nonce2");
  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages1).ok());

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message2,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce2"));
  ClientMessageRange messages2;
  *messages2.add_client_messages() = client_message2;
  messages2.mutable_nonce_range()->set_start("nonce2");
  messages2.mutable_nonce_range()->set_end("nonce3");
  EXPECT_TRUE(accumulator2->ProcessClientMessages(messages2).ok());

  EXPECT_TRUE(accumulator_->Merge(std::move(accumulator2)).ok());

  SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_state,
                              accumulator_->ToSerializedState());
  ServerAccumulatorState state;
  ASSERT_TRUE(state.ParseFromString(serialized_state));
  ASSERT_EQ(state.processed_nonce_ranges_size(), 1);
  EXPECT_EQ(state.processed_nonce_ranges_size(), state.verifier_states_size());
  EXPECT_EQ(state.processed_nonce_ranges(0).start(), "nonce1");
  EXPECT_EQ(state.processed_nonce_ranges(0).end(), "nonce3");
}

TEST_F(ServerAccumulatorTest, MergeFailsWithOverlappingRanges) {
  SECAGG_ASSERT_OK_AND_ASSIGN(auto accumulator2,
                              ServerAccumulator::Create(config_));
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message1,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce1"));
  ClientMessageRange messages1;
  *messages1.add_client_messages() = client_message1;
  messages1.mutable_nonce_range()->set_start("nonce1");
  messages1.mutable_nonce_range()->set_end("nonce3");
  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages1).ok());

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message2,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce2"));
  ClientMessageRange messages2;
  *messages2.add_client_messages() = client_message2;
  messages2.mutable_nonce_range()->set_start("nonce2");
  messages2.mutable_nonce_range()->set_end("nonce4");
  EXPECT_TRUE(accumulator2->ProcessClientMessages(messages2).ok());

  EXPECT_THAT(
      accumulator_->Merge(std::move(accumulator2)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("overlaps")));
}

TEST_F(ServerAccumulatorTest, MergeFailsWithConfigMismatch) {
  AggregationConfigProto config2 = config_;
  config2.set_key_id("other_key");
  SECAGG_ASSERT_OK_AND_ASSIGN(auto accumulator2,
                              ServerAccumulator::Create(config2));

  EXPECT_THAT(accumulator_->Merge(std::move(accumulator2)),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("config mismatch")));
}

TEST_F(ServerAccumulatorTest, ProcessClientMessagesMergesThreeRanges) {
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};

  // Create messages for 3 ranges.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message1,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce1"));
  ClientMessageRange messages1;
  *messages1.add_client_messages() = client_message1;
  messages1.mutable_nonce_range()->set_start("nonce1");
  messages1.mutable_nonce_range()->set_end("nonce2");

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message2,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce2"));
  ClientMessageRange messages2;
  *messages2.add_client_messages() = client_message2;
  messages2.mutable_nonce_range()->set_start("nonce2");
  messages2.mutable_nonce_range()->set_end("nonce3");

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message3,
      GenerateClientContribution(config_, encoded_data, public_key_, "nonce3"));
  ClientMessageRange messages3;
  *messages3.add_client_messages() = client_message3;
  messages3.mutable_nonce_range()->set_start("nonce3");
  messages3.mutable_nonce_range()->set_end("nonce4");

  // Process range 1 and 3.
  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages1).ok());
  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages3).ok());

  // Check state: should have 2 ranges.
  {
    SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_state,
                                accumulator_->ToSerializedState());
    ServerAccumulatorState state;
    ASSERT_TRUE(state.ParseFromString(serialized_state));
    ASSERT_EQ(state.processed_nonce_ranges_size(), 2);
    EXPECT_EQ(state.processed_nonce_ranges_size(),
              state.verifier_states_size());
    EXPECT_EQ(state.processed_nonce_ranges(0).start(), "nonce1");
    EXPECT_EQ(state.processed_nonce_ranges(0).end(), "nonce2");
    EXPECT_EQ(state.processed_nonce_ranges(1).start(), "nonce3");
    EXPECT_EQ(state.processed_nonce_ranges(1).end(), "nonce4");
  }

  // Process range 2 (filling the gap).
  EXPECT_TRUE(accumulator_->ProcessClientMessages(messages2).ok());

  // Check state: should have 1 range [nonce1, nonce4).
  {
    SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_state,
                                accumulator_->ToSerializedState());
    ServerAccumulatorState state;
    ASSERT_TRUE(state.ParseFromString(serialized_state));
    ASSERT_EQ(state.processed_nonce_ranges_size(), 1);
    EXPECT_EQ(state.processed_nonce_ranges_size(),
              state.verifier_states_size());
    EXPECT_EQ(state.processed_nonce_ranges(0).start(), "nonce1");
    EXPECT_EQ(state.processed_nonce_ranges(0).end(), "nonce4");
  }
}

TEST_F(ServerAccumulatorTest, VerifiesCorrectly) {
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};
  std::string nonce = "nonce1";
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message,
      GenerateClientContribution(config_, encoded_data, public_key_, nonce));
  ClientMessageRange messages;
  *messages.add_client_messages() = client_message;
  messages.mutable_nonce_range()->set_start("nonce1");
  messages.mutable_nonce_range()->set_end("nonce2");

  SECAGG_ASSERT_OK(accumulator_->ProcessClientMessages(messages));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto serialized_state,
                              accumulator_->ToSerializedState());
  ServerAccumulatorState state;
  ASSERT_TRUE(state.ParseFromString(serialized_state));

  ASSERT_EQ(state.verifier_states_size(), 1);
  willow::VerifierStateProto verifier_state = state.verifier_states(0);

  // Proto should be non-empty, i.e. the underlying Rust Option should be Some.
  ASSERT_GE(verifier_state.ByteSizeLong(), 1);
}

TEST_F(ServerAccumulatorTest, FinalizeSucceeds) {
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};
  std::string nonce = "nonce1";
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message,
      GenerateClientContribution(config_, encoded_data, public_key_, nonce));
  ClientMessageRange messages;
  *messages.add_client_messages() = client_message;
  messages.mutable_nonce_range()->set_start("nonce1");
  messages.mutable_nonce_range()->set_end("nonce2");

  SECAGG_ASSERT_OK(accumulator_->ProcessClientMessages(messages));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto finalized_accumulator_result,
                              std::move(*accumulator_).Finalize());
}

TEST_F(ServerAccumulatorTest, FinalizeFailsWithEmptyAccumulator) {
  EXPECT_THAT(std::move(*accumulator_).Finalize(),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("Must handle at least one client message")));
}

TEST_F(ServerAccumulatorTest, FinalizesAndDecryptsCorrectly) {
  willow::EncodedData encoded_data = {
      {"test_vector", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}};
  std::string nonce = "nonce1";
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto client_message,
      GenerateClientContribution(config_, encoded_data, public_key_, nonce));
  ClientMessageRange messages;
  *messages.add_client_messages() = client_message;
  messages.mutable_nonce_range()->set_start("nonce1");
  messages.mutable_nonce_range()->set_end("nonce2");

  SECAGG_ASSERT_OK(accumulator_->ProcessClientMessages(messages));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto finalized_result,
                              std::move(*accumulator_).Finalize());

  std::string partial_decryption_request =
      finalized_result.decryption_request();

  SECAGG_ASSERT_OK_AND_ASSIGN(
      std::string partial_decryption_response,
      decryptor_->GenerateSerializedPartialDecryptionResponse(
          partial_decryption_request));

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto final_result_decryptor,
      FinalResultDecryptor::CreateFromSerialized(
          finalized_result.final_result_decryptor_state()));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto result, final_result_decryptor->Decrypt(
                                               partial_decryption_response));

  EXPECT_EQ(result, encoded_data);
}

}  // namespace
}  // namespace willow
}  // namespace secure_aggregation
