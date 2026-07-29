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

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "ffi_utils/status_macros.h"
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
using ::testing::ElementsAreArray;

constexpr char kTimestampPrefix[] = "\x00\x00\x00\x01";
constexpr int kTimestampPrefixSize = 4;

std::string PrefixedNonce(const std::string& suffix) {
  return std::string(kTimestampPrefix, kTimestampPrefixSize) + suffix;
}

TEST(WillowV1ApiE2ETest, MultiDecryptorCoordinatorFullPipelineWithCodec) {
  // 1. Define schema, encoder, and aggregation configuration.
  InputSpec input_spec = CreateTestInputSpecProto();
  SECAGG_ASSERT_OK_AND_ASSIGN(auto encoder,
                              CodecFactory::CreateExplicitCodec(input_spec));

  constexpr int64_t kMaxClients = 10;
  constexpr int64_t kMaxDecryptors =
      1;  // Cryptosystem params currently set for 1.
  constexpr int64_t kMaxDecryptorDropouts = 0;
  constexpr int64_t kDefaultMaxMetricValue = 100;

  SECAGG_ASSERT_OK_AND_ASSIGN(
      AggregationConfigProto config,
      CreateAggregationConfig(input_spec, "multi_decryptor_e2e_key",
                              kMaxClients, kMaxDecryptors,
                              kMaxDecryptorDropouts, kDefaultMaxMetricValue));

  // 2. Instantiate Coordinator and multi-decryptors (1 reputable, 2
  // non-reputable).
  SECAGG_ASSERT_OK_AND_ASSIGN(auto coordinator, Coordinator::Create(config));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto reputable_decryptor,
                              ShellTestingDecryptor::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto non_reputable_decryptor1,
                              ShellTestingDecryptor::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto non_reputable_decryptor2,
                              ShellTestingDecryptor::Create(config));

  // 3. Each decryptor generates a setup contribution.
  SECAGG_ASSERT_OK_AND_ASSIGN(SetupContribution reputable_contrib,
                              reputable_decryptor->CreateSetupContribution());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      SetupContribution non_reputable_contrib1,
      non_reputable_decryptor1->CreateSetupContribution());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      SetupContribution non_reputable_contrib2,
      non_reputable_decryptor2->CreateSetupContribution());

  std::vector<SetupContribution> reputable_contribs = {reputable_contrib};
  std::vector<SetupContribution> non_reputable_contribs = {
      non_reputable_contrib1, non_reputable_contrib2};

  // 4. Coordinator handles setup submissions and produces verification request.
  SECAGG_ASSERT_OK_AND_ASSIGN(VerifyKeyContributionsRequest verify_request,
                              coordinator->HandleSetupSubmissions(
                                  non_reputable_contribs, reputable_contribs));

  // 5. Reputable decryptor verifies contributions and aggregates global public
  // key.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      ShellAhePublicKey public_key,
      reputable_decryptor->VerifyAndAggregateKeyContributions(verify_request));

  // 6. Define inputs for 3 clients and encode them using Codec.
  GroupData group_by_data0 = {{"country", {"US", "CA"}},
                              {"lang", {"en", "es"}}};
  MetricData metric_data0 = {{"metric1", {17, 42}}};

  GroupData group_by_data1 = {{"country", {"US", "MX"}},
                              {"lang", {"es", "en"}}};
  MetricData metric_data1 = {{"metric1", {83, 29}}};

  GroupData group_by_data2 = {{"country", {"CA", "GB"}},
                              {"lang", {"es", "en"}}};
  MetricData metric_data2 = {{"metric1", {54, 61}}};

  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded0,
                              encoder->Encode(group_by_data0, metric_data0));
  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded1,
                              encoder->Encode(group_by_data1, metric_data1));
  SECAGG_ASSERT_OK_AND_ASSIGN(EncodedData encoded2,
                              encoder->Encode(group_by_data2, metric_data2));

  // 7. Generate client messages encrypted towards aggregate public key.
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

  // 8. Process client messages across 2 server accumulators and merge them.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto acc1, ServerAccumulator::Create(config));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto acc2, ServerAccumulator::Create(config));

  ClientMessageRange range1;
  *range1.add_client_messages() = msg0;
  *range1.add_client_messages() = msg1;
  range1.mutable_nonce_range()->set_start("nonce0");
  range1.mutable_nonce_range()->set_end("nonce2");

  ClientMessageRange range2;
  *range2.add_client_messages() = msg2;
  range2.mutable_nonce_range()->set_start("nonce2");
  range2.mutable_nonce_range()->set_end("nonce3");

  SECAGG_ASSERT_OK(acc1->ProcessClientMessages(range1));
  SECAGG_ASSERT_OK(acc2->ProcessClientMessages(range2));

  SECAGG_ASSERT_OK(acc1->Merge(std::move(acc2)));

  // 9. Finalize accumulation.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      FinalizedAccumulatorResult finalized_accumulator_result,
      std::move(*acc1).Finalize());

  // 10. Extract verifier ciphertext and prepare decryption request via
  // Coordinator.
  PartialDecryptionRequest acc_dec_req;
  ASSERT_TRUE(acc_dec_req.ParseFromString(
      finalized_accumulator_result.decryption_request()));

  SECAGG_ASSERT_OK_AND_ASSIGN(PartialDecryptionRequest dec_request,
                              coordinator->PrepareDecryptionRequest(
                                  acc_dec_req.partial_dec_ciphertext()));

  // 11. Multi-decryptors each produce a partial decryption response.
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
      response_reputable, response_non_reputable1, response_non_reputable2};

  // 12. Coordinator aggregates partial decryptions and finalizes partial
  // decryption sum.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      FinalizedPartialDecryption finalized_pd,
      coordinator->AggregateAndFinalizePartialDecryptions(partial_responses));

  // 13. Recover final result using FinalResultDecryptor.
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

  // 14. Decode recovered data using Codec and verify metric sums.
  SECAGG_ASSERT_OK_AND_ASSIGN(DecodedData decoded_results,
                              encoder->Decode(recovered_data));

  // Expected sum across all 3 client contributions for metric1: 17 + 42 + 83 +
  // 29 + 54 + 61 = 286.
  int64_t total_metric1_sum = 0;
  for (const auto& [metric_name, values] : decoded_results.metric_data) {
    if (metric_name == "metric1") {
      for (int64_t val : values) {
        total_metric1_sum += val;
      }
    }
  }
  EXPECT_EQ(total_metric1_sum, 286);
}

}  // namespace
}  // namespace willow
}  // namespace secure_aggregation
