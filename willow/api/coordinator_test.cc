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

#include "willow/api/coordinator.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "ffi_utils/status_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "willow/proto/shell/ciphertexts.pb.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/messages.pb.h"
#include "willow/testing_utils/shell_testing_decryptor.h"

namespace secure_aggregation {
namespace willow {
namespace {

using ::secure_aggregation::secagg_internal::StatusIs;
using ::secure_aggregation::testing::ShellTestingDecryptor;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::SizeIs;

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

TEST(CoordinatorTest, CreateSucceedsWithValidConfig) {
  AggregationConfigProto config = CreateValidConfig();
  auto coordinator_or = Coordinator::Create(config);
  ASSERT_TRUE(coordinator_or.ok()) << coordinator_or.status();
  EXPECT_NE(*coordinator_or, nullptr);
}

TEST(CoordinatorTest, HandleSetupSubmissionsSucceedsAndTransitionsState) {
  AggregationConfigProto config = CreateValidConfig();
  SECAGG_ASSERT_OK_AND_ASSIGN(auto coordinator, Coordinator::Create(config));

  // Handle setup submissions with empty contributions for state testing.
  std::vector<SetupContribution> non_reputable;
  std::vector<SetupContribution> reputable;
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto verify_request,
      coordinator->HandleSetupSubmissions(non_reputable, reputable));
  EXPECT_THAT(verify_request.key_contributions(), IsEmpty());

  // Calling HandleSetupSubmissions a second time should fail because the
  // coordinator is no longer in PreSetup status.
  EXPECT_THAT(
      coordinator->HandleSetupSubmissions(non_reputable, reputable),
      StatusIs(absl::StatusCode::kFailedPrecondition, HasSubstr("PreSetup")));
}

TEST(CoordinatorTest, SerializeAndReinstantiatePreservesState) {
  AggregationConfigProto config = CreateValidConfig();
  SECAGG_ASSERT_OK_AND_ASSIGN(auto coordinator, Coordinator::Create(config));

  // Serialize and reinstantiate in PreSetup state.
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string pre_setup_state,
                              coordinator->ToSerializedState());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      coordinator, Coordinator::CreateFromSerializedState(pre_setup_state));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto decryptor,
                              ShellTestingDecryptor::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(SetupContribution contrib,
                              decryptor->CreateSetupContribution());
  contrib.add_encrypted_randomness_shares()->set_encrypted_share("test_share");

  std::vector<SetupContribution> non_reputable = {std::move(contrib)};
  std::vector<SetupContribution> reputable;
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto verify_request,
      coordinator->HandleSetupSubmissions(non_reputable, reputable));
  EXPECT_THAT(verify_request.key_contributions(), SizeIs(1));

  // Serialize and reinstantiate in KeySharesReceived state with populated
  // encrypted_randomness_shares.
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string post_setup_state,
                              coordinator->ToSerializedState());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      coordinator, Coordinator::CreateFromSerializedState(post_setup_state));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string roundtrip_post_setup_state,
                              coordinator->ToSerializedState());
  EXPECT_EQ(roundtrip_post_setup_state, post_setup_state);

  CoordinatorState parsed_state;
  ASSERT_TRUE(parsed_state.ParseFromString(roundtrip_post_setup_state));
  EXPECT_EQ(parsed_state.status(), COORDINATOR_STATUS_KEY_SHARES_RECEIVED);
  ASSERT_THAT(parsed_state.encrypted_randomness_shares(), SizeIs(1));
  ASSERT_THAT(parsed_state.encrypted_randomness_shares(0).shares(), SizeIs(1));
  EXPECT_EQ(
      parsed_state.encrypted_randomness_shares(0).shares(0).encrypted_share(),
      "test_share");

  // Reinstantiated coordinator must preserve KeySharesReceived status and
  // reject a duplicate HandleSetupSubmissions call.
  EXPECT_THAT(
      coordinator->HandleSetupSubmissions(non_reputable, reputable),
      StatusIs(absl::StatusCode::kFailedPrecondition, HasSubstr("PreSetup")));
}

TEST(CoordinatorTest, CreateFromSerializedStateFailsWithInvalidBytes) {
  EXPECT_THAT(Coordinator::CreateFromSerializedState("not_a_valid_proto"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse CoordinatorState")));
}

TEST(CoordinatorTest, CreateFromSerializedStateFailsWithoutAggregationConfig) {
  CoordinatorState state_without_config;
  state_without_config.set_status(COORDINATOR_STATUS_PRE_SETUP);
  EXPECT_THAT(Coordinator::CreateFromSerializedState(
                  state_without_config.SerializeAsString()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("missing aggregation_config")));
}

TEST(CoordinatorTest, CreateFromSerializedStateFailsWithUnspecifiedStatus) {
  CoordinatorState state_with_unspecified_status;
  *state_with_unspecified_status.mutable_aggregation_config() =
      CreateValidConfig();
  EXPECT_THAT(Coordinator::CreateFromSerializedState(
                  state_with_unspecified_status.SerializeAsString()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("CoordinatorStatus")));
}

TEST(CoordinatorTest, PrepareDecryptionRequestFailsWhenNotInCorrectState) {
  AggregationConfigProto config = CreateValidConfig();
  SECAGG_ASSERT_OK_AND_ASSIGN(auto coordinator, Coordinator::Create(config));

  // PrepareDecryptionRequest without calling HandleSetupSubmissions first
  // should fail.
  ShellAhePartialDecCiphertext dummy_ct;
  auto request_or = coordinator->PrepareDecryptionRequest(dummy_ct);
  EXPECT_FALSE(request_or.ok());
}

TEST(CoordinatorTest, AggregateAndFinalizeFailsWhenNotInCorrectState) {
  AggregationConfigProto config = CreateValidConfig();
  SECAGG_ASSERT_OK_AND_ASSIGN(auto coordinator, Coordinator::Create(config));

  std::vector<PartialDecryptionResponse> responses;
  auto finalize_or =
      coordinator->AggregateAndFinalizePartialDecryptions(responses);
  EXPECT_FALSE(finalize_or.ok());
}

}  // namespace
}  // namespace willow
}  // namespace secure_aggregation
