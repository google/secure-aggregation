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

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "ffi_utils/status_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "willow/api/client.h"
#include "willow/api/coordinator.h"
#include "willow/api/server_accumulator.h"
#include "willow/input_encoding/codec.h"
#include "willow/input_encoding/codec_factory.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/input_spec.pb.h"
#include "willow/proto/willow/messages.pb.h"
#include "willow/testing_utils/shell_testing_decryptor.h"
#include "willow/testing_utils/testing_utils.h"

namespace secure_aggregation {
namespace willow {
namespace {

using ::secure_aggregation::testing::ShellTestingDecryptor;
using ::testing::ElementsAre;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

constexpr char kTimestampPrefix[] = "\x00\x00\x00\x01";
constexpr int kTimestampPrefixSize = 4;

// Creates a nonce with the 4-byte timestamp prefix followed by the suffix,
// for time-based partitioning in the pipeline. Meanwhile, ServerAccumulator
// compares against the nonce suffix without the 4-byte timestamp prefix.
std::string PrefixedNonce(const std::string& suffix) {
  return std::string(kTimestampPrefix, kTimestampPrefixSize) + suffix;
}

TEST(WillowV1ApiE2ETest, MultiDecryptorCoordinatorFullPipelineWithCodec) {
  // Define schema, encoder, and aggregation configuration.
  InputSpec input_spec = CreateTestInputSpecProto();
  SECAGG_ASSERT_OK_AND_ASSIGN(auto encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));

  constexpr int64_t kMaxClients = 10;
  // The parameters used by `CreateAggregationConfig` below are secure for only
  // a single decryptor when assuming all clients are corrupted. As we are
  // testing functionality here anyway, we set `max_number_of_decryptors` to 1
  // just to obtain the AHE parameters.
  constexpr int64_t kMaxDecryptors = 1;
  constexpr int64_t kMaxDecryptorDropouts = 0;
  constexpr int64_t kDefaultMaxMetricValue = 100;

  SECAGG_ASSERT_OK_AND_ASSIGN(
      AggregationConfigProto config,
      CreateAggregationConfig(input_spec, "test_key", kMaxClients,
                              kMaxDecryptors, kMaxDecryptorDropouts,
                              kDefaultMaxMetricValue));

  // Instantiate Coordinator and multi-decryptors (1 reputable, 2
  // non-reputable).
  SECAGG_ASSERT_OK_AND_ASSIGN(auto coordinator, Coordinator::Create(config));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto reputable_decryptor,
                              ShellTestingDecryptor::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto non_reputable_decryptor1,
                              ShellTestingDecryptor::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto non_reputable_decryptor2,
                              ShellTestingDecryptor::Create(config));

  // Each decryptor generates a setup contribution.
  SECAGG_ASSERT_OK_AND_ASSIGN(SetupContribution reputable_contrib,
                              reputable_decryptor->CreateSetupContribution());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      SetupContribution non_reputable_contrib1,
      non_reputable_decryptor1->CreateSetupContribution());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      SetupContribution non_reputable_contrib2,
      non_reputable_decryptor2->CreateSetupContribution());

  std::vector<SetupContribution> reputable_contribs = {
      std::move(reputable_contrib)};
  std::vector<SetupContribution> non_reputable_contribs = {
      std::move(non_reputable_contrib1), std::move(non_reputable_contrib2)};

  // Coordinator handles setup submissions and produces verification request.
  SECAGG_ASSERT_OK_AND_ASSIGN(VerifyKeyContributionsRequest verify_request,
                              coordinator->HandleSetupSubmissions(
                                  non_reputable_contribs, reputable_contribs));

  // Serialize and reinstantiate Coordinator after setup round.
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string serialized_coord_state,
                              coordinator->ToSerializedState());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      coordinator,
      Coordinator::CreateFromSerializedState(serialized_coord_state));

  // Reputable decryptor verifies contributions and aggregates global public
  // key.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      ShellAhePublicKey public_key,
      reputable_decryptor->VerifyAndAggregateKeyContributions(verify_request));

  // Define inputs for 3 clients with multi-group overlap and encode them
  // using Codec.
  GroupData group_by_data0 = {{"country", {"US", "CA", "MX"}},
                              {"lang", {"en", "es", "en"}}};
  MetricData metric_data0 = {{"metric1", {17, 42, 10}}};

  GroupData group_by_data1 = {{"country", {"US", "US", "MX"}},
                              {"lang", {"en", "es", "en"}}};
  MetricData metric_data1 = {{"metric1", {23, 83, 29}}};

  GroupData group_by_data2 = {{"country", {"CA", "GB", "US"}},
                              {"lang", {"es", "en", "es"}}};
  MetricData metric_data2 = {{"metric1", {54, 61, 15}}};

  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded0,
                              encoder->Encode(group_by_data0, metric_data0));
  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded1,
                              encoder->Encode(group_by_data1, metric_data1));
  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded2,
                              encoder->Encode(group_by_data2, metric_data2));

  // Generate client messages encrypted towards aggregate public key.
  std::string nonce0 = PrefixedNonce("nonce0");
  std::string nonce1 = PrefixedNonce("nonce1");
  std::string nonce2 = PrefixedNonce("nonce2");

  SECAGG_ASSERT_OK_AND_ASSIGN(
      ClientMessage msg0,
      GenerateClientContribution(config, encoded0, public_key, nonce0));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      ClientMessage msg1,
      GenerateClientContribution(config, encoded1, public_key, nonce1));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      ClientMessage msg2,
      GenerateClientContribution(config, encoded2, public_key, nonce2));

  // Process client messages across 2 server accumulators and merge them.
  // In production, these accumulators could be running in parallel shards
  // within a pipeline.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto acc1, ServerAccumulator::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto acc2, ServerAccumulator::Create(config));

  ClientMessageRange range1;
  *range1.add_client_messages() = std::move(msg0);
  *range1.add_client_messages() = std::move(msg1);
  range1.mutable_nonce_range()->set_start("nonce0");
  range1.mutable_nonce_range()->set_end("nonce2");

  ClientMessageRange range2;
  *range2.add_client_messages() = std::move(msg2);
  range2.mutable_nonce_range()->set_start("nonce2");
  range2.mutable_nonce_range()->set_end("nonce3");

  SECAGG_ASSERT_OK(acc1->ProcessClientMessages(range1));
  SECAGG_ASSERT_OK(acc2->ProcessClientMessages(range2));

  SECAGG_ASSERT_OK(acc1->Merge(std::move(acc2)));

  // Finalize accumulation.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      FinalizedAccumulatorResult finalized_accumulator_result,
      std::move(*acc1).Finalize());

  // Extract verifier ciphertext and prepare decryption request via
  // Coordinator.
  // In a multi-decryptor pipeline, we parse the verifier ciphertext from the
  // finalized accumulator's decryption request and pass it to the Coordinator
  // to prepare the multi-decryptor PartialDecryptionRequest.
  PartialDecryptionRequest acc_dec_req;
  ASSERT_TRUE(acc_dec_req.ParseFromString(
      finalized_accumulator_result.decryption_request()));

  SECAGG_ASSERT_OK_AND_ASSIGN(PartialDecryptionRequest dec_request,
                              coordinator->PrepareDecryptionRequest(
                                  acc_dec_req.partial_dec_ciphertext()));

  // Serialize and reinstantiate Coordinator while awaiting partial decryptions.
  SECAGG_ASSERT_OK_AND_ASSIGN(serialized_coord_state,
                              coordinator->ToSerializedState());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      coordinator,
      Coordinator::CreateFromSerializedState(serialized_coord_state));

  // Multi-decryptors each produce a partial decryption response.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      PartialDecryptionResponse response_reputable,
      reputable_decryptor->HandlePartialDecryptionRequest(dec_request));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      PartialDecryptionResponse response_non_reputable1,
      non_reputable_decryptor1->HandlePartialDecryptionRequest(dec_request));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      PartialDecryptionResponse response_non_reputable2,
      non_reputable_decryptor2->HandlePartialDecryptionRequest(dec_request));

  std::vector<PartialDecryptionResponse> partial_responses = {
      std::move(response_reputable), std::move(response_non_reputable1),
      std::move(response_non_reputable2)};

  // Coordinator aggregates partial decryptions and finalizes partial
  // decryption sum.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      FinalizedPartialDecryption finalized_pd,
      coordinator->AggregateAndFinalizePartialDecryptions(partial_responses));

  // Serialize and reinstantiate Coordinator in OutputReady state.
  SECAGG_ASSERT_OK_AND_ASSIGN(serialized_coord_state,
                              coordinator->ToSerializedState());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      coordinator,
      Coordinator::CreateFromSerializedState(serialized_coord_state));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string roundtrip_output_ready_state,
                              coordinator->ToSerializedState());
  EXPECT_EQ(roundtrip_output_ready_state, serialized_coord_state);

  // Recover final result using FinalResultDecryptor.
  // In production, this code runs within the pipeline, using the serialized
  // final_result_decryptor_state produced during Finalize() to decrypt the
  // aggregated response from the decryptor service.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto final_result_decryptor,
      FinalResultDecryptor::CreateFromSerialized(
          finalized_accumulator_result.final_result_decryptor_state()));

  PartialDecryptionResponse full_pd_response;
  *full_pd_response.mutable_partial_decryption() =
      finalized_pd.partial_decryption_sum();

  SECAGG_ASSERT_OK_AND_ASSIGN(
      EncodedData recovered_data,
      final_result_decryptor->Decrypt(full_pd_response.SerializeAsString()));

  // Decode recovered data using Codec and verify per-group metric sums.
  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_results,
                              encoder->Decode(recovered_data));

  // The decoded result contains 5 non-zero group combinations ordered by
  // Cartesian index:
  // - ("CA", "es"): 42 (client 0) + 54 (client 2) = 96
  // - ("GB", "en"): 61 (client 2) = 61
  // - ("MX", "en"): 10 (client 0) + 29 (client 1) = 39
  // - ("US", "en"): 17 (client 0) + 23 (client 1) = 40
  // - ("US", "es"): 83 (client 1) + 15 (client 2) = 98
  EXPECT_THAT(
      decoded_results.metric_data,
      UnorderedElementsAre(Pair("metric1", ElementsAre(96, 61, 39, 40, 98))));
  EXPECT_THAT(decoded_results.group_data,
              UnorderedElementsAre(
                  Pair("country", ElementsAre("CA", "GB", "MX", "US", "US")),
                  Pair("lang", ElementsAre("es", "en", "en", "en", "es"))));
}

TEST(WillowV1ApiE2ETest,
     RecoverableMultiDecryptorCoordinatorFullPipelineWithDropoutRecovery) {
  InputSpec input_spec = CreateTestInputSpecProto();
  SECAGG_ASSERT_OK_AND_ASSIGN(auto encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));

  constexpr int64_t kMaxClients = 10;
  constexpr int64_t kMaxDecryptors = 1;
  constexpr int64_t kMaxDecryptorDropouts = 0;
  constexpr int64_t kDefaultMaxMetricValue = 100;

  SECAGG_ASSERT_OK_AND_ASSIGN(
      AggregationConfigProto config,
      CreateAggregationConfig(input_spec, "test_key_recoverable", kMaxClients,
                              kMaxDecryptors, kMaxDecryptorDropouts,
                              kDefaultMaxMetricValue));

  // Configure a 3-of-5 recoverable committee (tolerating up to d = 5 - 3 = 2
  // dropped non-reputable decryptors) plus 1 reputable decryptor.
  constexpr uint32_t kNumCommitteeDecryptors = 5;
  constexpr uint32_t kThreshold = 3;
  constexpr absl::string_view kSessionContext =
      "api_e2e_recoverable_3_of_5_session";

  SECAGG_ASSERT_OK_AND_ASSIGN(auto coordinator, Coordinator::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto reputable_decryptor,
                              ShellTestingDecryptor::Create(config));

  std::vector<std::unique_ptr<ShellTestingDecryptor>> committee_decryptors;
  std::vector<std::string> roster_pks;
  for (uint32_t i = 1; i <= kNumCommitteeDecryptors; ++i) {
    SECAGG_ASSERT_OK_AND_ASSIGN(auto dec,
                                ShellTestingDecryptor::Create(config));
    SECAGG_ASSERT_OK_AND_ASSIGN(std::string pk, dec->GenerateHpkePublicKey());
    roster_pks.push_back(std::move(pk));
    committee_decryptors.push_back(std::move(dec));
  }

  SECAGG_ASSERT_OK_AND_ASSIGN(CommitteeConfigProto coord_committee_cfg,
                              ShellTestingDecryptor::BuildCommitteeConfig(
                                  /*my_index=*/1, kNumCommitteeDecryptors,
                                  kThreshold, kSessionContext, roster_pks));
  SECAGG_ASSERT_OK(coordinator->ConfigureCommittee(coord_committee_cfg));

  // Generate setup contributions (1 reputable + 5 recoverable committee).
  SECAGG_ASSERT_OK_AND_ASSIGN(SetupContribution reputable_contrib,
                              reputable_decryptor->CreateSetupContribution());
  std::vector<SetupContribution> reputable_contribs = {
      std::move(reputable_contrib)};

  std::vector<SetupContribution> non_reputable_contribs;
  for (uint32_t i = 1; i <= kNumCommitteeDecryptors; ++i) {
    SECAGG_ASSERT_OK_AND_ASSIGN(CommitteeConfigProto dec_cfg,
                                ShellTestingDecryptor::BuildCommitteeConfig(
                                    i, kNumCommitteeDecryptors, kThreshold,
                                    kSessionContext, roster_pks));
    SECAGG_ASSERT_OK_AND_ASSIGN(
        SetupContribution contrib,
        committee_decryptors[i - 1]->CreateRecoverableSetupContribution(
            dec_cfg, roster_pks));
    non_reputable_contribs.push_back(std::move(contrib));
  }

  SECAGG_ASSERT_OK_AND_ASSIGN(VerifyKeyContributionsRequest verify_request,
                              coordinator->HandleSetupSubmissions(
                                  non_reputable_contribs, reputable_contribs));

  // Serialize and reinstantiate Coordinator after setup round.
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string serialized_coord_state,
                              coordinator->ToSerializedState());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      coordinator,
      Coordinator::CreateFromSerializedState(serialized_coord_state));

  // Reputable decryptor verifies all 6 ZK proofs and aggregates global PK.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      ShellAhePublicKey public_key,
      reputable_decryptor->VerifyAndAggregateKeyContributions(verify_request));

  // Encode inputs for 3 clients and accumulate across 2 ServerAccumulators.
  GroupData group_by_data0 = {{"country", {"US", "CA", "MX"}},
                              {"lang", {"en", "es", "en"}}};
  MetricData metric_data0 = {{"metric1", {17, 42, 10}}};

  GroupData group_by_data1 = {{"country", {"US", "US", "MX"}},
                              {"lang", {"en", "es", "en"}}};
  MetricData metric_data1 = {{"metric1", {23, 83, 29}}};

  GroupData group_by_data2 = {{"country", {"CA", "GB", "US"}},
                              {"lang", {"es", "en", "es"}}};
  MetricData metric_data2 = {{"metric1", {54, 61, 15}}};

  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded0,
                              encoder->Encode(group_by_data0, metric_data0));
  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded1,
                              encoder->Encode(group_by_data1, metric_data1));
  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded2,
                              encoder->Encode(group_by_data2, metric_data2));

  SECAGG_ASSERT_OK_AND_ASSIGN(
      ClientMessage msg0,
      GenerateClientContribution(config, encoded0, public_key,
                                 PrefixedNonce("nonce0")));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      ClientMessage msg1,
      GenerateClientContribution(config, encoded1, public_key,
                                 PrefixedNonce("nonce1")));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      ClientMessage msg2,
      GenerateClientContribution(config, encoded2, public_key,
                                 PrefixedNonce("nonce2")));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto acc1, ServerAccumulator::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto acc2, ServerAccumulator::Create(config));

  ClientMessageRange range1;
  *range1.add_client_messages() = std::move(msg0);
  *range1.add_client_messages() = std::move(msg1);
  range1.mutable_nonce_range()->set_start("nonce0");
  range1.mutable_nonce_range()->set_end("nonce2");

  ClientMessageRange range2;
  *range2.add_client_messages() = std::move(msg2);
  range2.mutable_nonce_range()->set_start("nonce2");
  range2.mutable_nonce_range()->set_end("nonce3");

  SECAGG_ASSERT_OK(acc1->ProcessClientMessages(range1));
  SECAGG_ASSERT_OK(acc2->ProcessClientMessages(range2));
  SECAGG_ASSERT_OK(acc1->Merge(std::move(acc2)));

  SECAGG_ASSERT_OK_AND_ASSIGN(
      FinalizedAccumulatorResult finalized_accumulator_result,
      std::move(*acc1).Finalize());

  PartialDecryptionRequest acc_dec_req;
  ASSERT_TRUE(acc_dec_req.ParseFromString(
      finalized_accumulator_result.decryption_request()));

  SECAGG_ASSERT_OK_AND_ASSIGN(PartialDecryptionRequest dec_request,
                              coordinator->PrepareDecryptionRequest(
                                  acc_dec_req.partial_dec_ciphertext()));

  // Serialize and reinstantiate Coordinator while awaiting partial decryptions.
  SECAGG_ASSERT_OK_AND_ASSIGN(serialized_coord_state,
                              coordinator->ToSerializedState());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      coordinator,
      Coordinator::CreateFromSerializedState(serialized_coord_state));

  // Committee decryptors {2, 5} DROP OUT! Only survivors {1, 3, 4} (t = 3)
  // and the reputable decryptor respond to the partial decryption request.
  std::vector<PartialDecryptionResponse> partial_responses;
  SECAGG_ASSERT_OK_AND_ASSIGN(
      PartialDecryptionResponse response_reputable,
      reputable_decryptor->HandlePartialDecryptionRequest(dec_request));
  partial_responses.push_back(std::move(response_reputable));

  for (uint32_t survivor_idx : {1u, 3u, 4u}) {
    SECAGG_ASSERT_OK_AND_ASSIGN(
        PartialDecryptionResponse resp,
        committee_decryptors[survivor_idx - 1]->HandlePartialDecryptionRequest(
            dec_request));
    EXPECT_EQ(resp.decryptor_index(), survivor_idx);
    partial_responses.push_back(std::move(resp));
  }

  SECAGG_ASSERT_OK(coordinator->AggregatePartialDecryptions(partial_responses));

  // Serialize and reinstantiate Coordinator in AwaitingRecovery state!
  SECAGG_ASSERT_OK_AND_ASSIGN(serialized_coord_state,
                              coordinator->ToSerializedState());
  CoordinatorState parsed_awaiting_recovery;
  ASSERT_TRUE(parsed_awaiting_recovery.ParseFromString(serialized_coord_state));
  EXPECT_EQ(parsed_awaiting_recovery.status(),
            COORDINATOR_STATUS_AWAITING_RECOVERY);
  EXPECT_THAT(parsed_awaiting_recovery.responded_decryptor_indices(),
              ElementsAre(1, 3, 4));

  SECAGG_ASSERT_OK_AND_ASSIGN(
      coordinator,
      Coordinator::CreateFromSerializedState(serialized_coord_state));

  // Create indexed recovery requests for survivors {1, 3, 4} to recover dropped
  // committee decryptors {2, 5}.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto indexed_recovery_requests,
                              coordinator->CreateIndexedRecoveryRequests());
  ASSERT_EQ(indexed_recovery_requests.size(), 3u);

  std::vector<RecoveryResponse> recovery_responses;
  for (const auto& [survivor_idx, rec_req] : indexed_recovery_requests) {
    EXPECT_EQ(rec_req.indexed_encrypted_shares().size(), 2u);
    EXPECT_TRUE(rec_req.indexed_encrypted_shares().contains(2));
    EXPECT_TRUE(rec_req.indexed_encrypted_shares().contains(5));

    SECAGG_ASSERT_OK_AND_ASSIGN(
        RecoveryResponse rec_resp,
        committee_decryptors[survivor_idx - 1]->HandleRecoveryRequest(rec_req));
    // One-shot enforcement: a second recovery request on the same survivor must
    // fail because its state is now burned to Finished.
    EXPECT_FALSE(committee_decryptors[survivor_idx - 1]
                     ->HandleRecoveryRequest(rec_req)
                     .ok());
    recovery_responses.push_back(std::move(rec_resp));
  }

  // Coordinator reconstructs dropped decryptors {2, 5}, verifies Step 14 PK
  // binding, and accumulates their simulated partial decryptions.
  SECAGG_ASSERT_OK(coordinator->RecoverDroppedDecryptors(recovery_responses));

  // Serialize and reinstantiate Coordinator in OutputReady state.
  SECAGG_ASSERT_OK_AND_ASSIGN(serialized_coord_state,
                              coordinator->ToSerializedState());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      coordinator,
      Coordinator::CreateFromSerializedState(serialized_coord_state));

  SECAGG_ASSERT_OK_AND_ASSIGN(FinalizedPartialDecryption finalized_pd,
                              coordinator->FinalizePartialDecryption());

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto final_result_decryptor,
      FinalResultDecryptor::CreateFromSerialized(
          finalized_accumulator_result.final_result_decryptor_state()));

  PartialDecryptionResponse full_pd_response;
  *full_pd_response.mutable_partial_decryption() =
      finalized_pd.partial_decryption_sum();

  SECAGG_ASSERT_OK_AND_ASSIGN(
      EncodedData recovered_data,
      final_result_decryptor->Decrypt(full_pd_response.SerializeAsString()));

  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_results,
                              encoder->Decode(recovered_data));

  EXPECT_THAT(
      decoded_results.metric_data,
      UnorderedElementsAre(Pair("metric1", ElementsAre(96, 61, 39, 40, 98))));
  EXPECT_THAT(decoded_results.group_data,
              UnorderedElementsAre(
                  Pair("country", ElementsAre("CA", "GB", "MX", "US", "US")),
                  Pair("lang", ElementsAre("es", "en", "en", "en", "es"))));
}

}  // namespace
}  // namespace willow
}  // namespace secure_aggregation
