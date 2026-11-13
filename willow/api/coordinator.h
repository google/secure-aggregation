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

#ifndef SECURE_AGGREGATION_WILLOW_API_COORDINATOR_H_
#define SECURE_AGGREGATION_WILLOW_API_COORDINATOR_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "include/cxx.h"
#include "willow/api/coordinator.rs.h"
#include "willow/proto/shell/ciphertexts.pb.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/messages.pb.h"

namespace secure_aggregation {
namespace willow {

// Implements a C++ wrapper around the untrusted multi-decryptor Coordinator.
// Manages protocol flow and aggregates messages from all decryptors.
class Coordinator {
 public:
  // Creates a new coordinator with the given aggregation_config.
  static absl::StatusOr<std::unique_ptr<Coordinator>> Create(
      const AggregationConfigProto& aggregation_config);

  // Creates a new coordinator from the given serialized state, which must
  // correspond to a serialized CoordinatorState proto produced by
  // ToSerializedState() (including its embedded AggregationConfig).
  static absl::StatusOr<std::unique_ptr<Coordinator>> CreateFromSerializedState(
      absl::string_view serialized_state);

  // Converts the current state of the coordinator to a serialized
  // CoordinatorState proto.
  absl::StatusOr<std::string> ToSerializedState() const;

  // Configures the coordinator for a recoverable multi-decryptor committee
  // session. Must be called in PreSetup status before HandleSetupSubmissions.
  absl::Status ConfigureCommittee(const CommitteeConfigProto& committee_config);

  // Stores setup contributions from all decryptors during key generation and
  // creates a request for reputable decryptors to verify and aggregate key
  // contributions into a public key.
  absl::StatusOr<VerifyKeyContributionsRequest> HandleSetupSubmissions(
      absl::Span<const SetupContribution> non_reputable_contributions,
      absl::Span<const SetupContribution> reputable_contributions);

  // Combines the verifier ciphertext half (obtained from the accumulation
  // pipeline) with the AHE DP noise component sum received at setup, to prepare
  // a decryption request for decryptors.
  absl::StatusOr<PartialDecryptionRequest> PrepareDecryptionRequest(
      const ShellAhePartialDecCiphertext& verifier_ciphertext);

  // Accumulates partial decryptions from responding decryptors.
  // In recoverable committee mode, transitions the coordinator to OutputReady
  // when all committee decryptors respond, or to AwaitingRecovery when at least
  // `threshold` (but fewer than `num_decryptors`) respond.
  absl::Status AggregatePartialDecryptions(
      absl::Span<const PartialDecryptionResponse> partial_responses);

  // Creates recovery requests keyed by 1-based surviving `decryptor_index`
  // (ordered by ascending `responded_decryptor_indices`) to decrypt shares of
  // dropped decryptors. Returns an empty vector if the coordinator is already
  // in OutputReady status (zero dropouts).
  absl::StatusOr<std::vector<std::pair<uint32_t, RecoveryRequest>>>
  CreateIndexedRecoveryRequests() const;

  // Creates recovery requests ordered by ascending surviving `decryptor_index`.
  // Returns an empty vector if the coordinator is already in OutputReady status
  // (zero dropouts).
  absl::StatusOr<std::vector<RecoveryRequest>> CreateRecoveryRequests();

  // Recovers secret key shares of dropped decryptors from survivor
  // RecoveryResponses, verifies regenerated public key shares against setup
  // (Willow Paper Fig. 10 Step 14), accumulates their simulated partial
  // decryptions, and transitions the coordinator to OutputReady.
  absl::Status RecoverDroppedDecryptors(
      absl::Span<const RecoveryResponse> recovery_responses);

  // Finalizes and returns the accumulated partial decryption sum when the
  // coordinator is in OutputReady status, transitioning to Finished.
  absl::StatusOr<FinalizedPartialDecryption> FinalizePartialDecryption();

  // Accumulates partial decryptions and finalizes the partial decryption sum
  // in a single step (for the zero-dropout fast path).
  absl::StatusOr<FinalizedPartialDecryption>
  AggregateAndFinalizePartialDecryptions(
      absl::Span<const PartialDecryptionResponse> partial_responses);

 private:
  explicit Coordinator(
      rust::Box<secure_aggregation::WillowShellCoordinator> coordinator)
      : coordinator_(std::move(coordinator)) {}

  rust::Box<secure_aggregation::WillowShellCoordinator> coordinator_;
};

}  // namespace willow
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_API_COORDINATOR_H_
