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
#include <vector>

#include "absl/status/statusor.h"
#include "ffi_utils/status_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "willow/proto/shell/ciphertexts.pb.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/messages.pb.h"

namespace secure_aggregation {
namespace willow {
namespace {

using ::testing::IsEmpty;

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
  auto second_attempt =
      coordinator->HandleSetupSubmissions(non_reputable, reputable);
  EXPECT_FALSE(second_attempt.ok());
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
