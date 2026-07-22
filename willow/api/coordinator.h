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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
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
  // Creates a new coordinator with the given aggregation_config and empty
  // state.
  static absl::StatusOr<std::unique_ptr<Coordinator>> Create(
      const AggregationConfigProto& aggregation_config);

  // Stores setup contributions from all decryptors during key generation and
  // creates a request for reputable decryptors to verify key contributions.
  absl::StatusOr<VerifyKeyContributionsRequest> HandleSetupSubmissions(
      const std::vector<SetupContribution>& non_reputable_contributions,
      const std::vector<SetupContribution>& reputable_contributions);

  // Combines the verifier's ciphertext half with the accumulated AHE components
  // to prepare a decryption request for decryptors.
  absl::StatusOr<PartialDecryptionRequest> PrepareDecryptionRequest(
      const ShellAhePartialDecCiphertext& verifier_ciphertext);

  // Accumulates partial decryptions from responding decryptors, executes
  // dropout recovery if necessary (currently returns error if dropouts exist
  // pending secret sharing review), and finalizes the partial decryption sum.
  absl::StatusOr<FinalizedPartialDecryption>
  AggregateAndFinalizePartialDecryptions(
      const std::vector<PartialDecryptionResponse>& partial_responses);

 private:
  explicit Coordinator(
      rust::Box<secure_aggregation::WillowShellCoordinator> coordinator)
      : coordinator_(std::move(coordinator)) {}

  rust::Box<secure_aggregation::WillowShellCoordinator> coordinator_;
};

}  // namespace willow
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_API_COORDINATOR_H_
