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

#ifndef SECURE_AGGREGATION_WILLOW_TESTING_UTILS_SHELL_TESTING_DECRYPTOR_H_
#define SECURE_AGGREGATION_WILLOW_TESTING_UTILS_SHELL_TESTING_DECRYPTOR_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "willow/input_encoding/codec.h"
#include "willow/proto/shell/ciphertexts.pb.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/messages.pb.h"
#include "willow/testing_utils/shell_testing_decryptor.rs.h"

namespace secure_aggregation {
namespace testing {

// Basic implementation of a single decryptor that uses Shell operations
// directly. Useful for testing Shell clients or servers, by checking that
// encrypted messages can be decrypted properly.
class ShellTestingDecryptor {
 public:
  // Creates a new ShellTestingDecryptor from the given config. The key_id from
  // the config is used to seed KAHE and AHE public parameters.
  static absl::StatusOr<std::unique_ptr<ShellTestingDecryptor>> Create(
      const willow::AggregationConfigProto& aggregation_config);

  // Generates a new AHE public key, and stores the corresponding secret key.
  absl::StatusOr<willow::ShellAhePublicKey> GeneratePublicKey();

  // Generates a setup contribution containing key share and key gen proof.
  absl::StatusOr<willow::SetupContribution> CreateSetupContribution();

  // Generates a 32-byte raw X25519 HPKE public key for recoverable committee
  // secret sharing and stores the corresponding HPKE keypair in this decryptor.
  absl::StatusOr<std::string> GenerateHpkePublicKey();

  // Builds a validated CommitteeConfigProto for `my_index` (1-based in
  // `1..=num_decryptors`) given the ordered 1..=num_decryptors roster of raw
  // 32-byte HPKE public keys (`roster_hpke_public_keys[i - 1]` for index `i`),
  // computing the canonical SHA-256 `roster_hash`.
  static absl::StatusOr<willow::CommitteeConfigProto> BuildCommitteeConfig(
      uint32_t my_index, uint32_t num_decryptors, uint32_t threshold,
      absl::string_view session_context,
      absl::Span<const std::string> roster_hpke_public_keys);

  // Generates a recoverable committee setup contribution containing the
  // 1-based `decryptor_index`, `FeldmanCommitment`, `KeyContribution` (derived
  // deterministically from the Feldman VSS secret), and HPKE-encrypted shares
  // for all peer committee members (`{1..=num_decryptors} \ {my_index}`).
  // Requires `GenerateHpkePublicKey()` to have been called first on this
  // decryptor.
  absl::StatusOr<willow::SetupContribution> CreateRecoverableSetupContribution(
      const willow::CommitteeConfigProto& committee_config,
      absl::Span<const std::string> roster_hpke_public_keys);

  // Handles a one-shot RecoveryRequest from the Coordinator to decrypt Feldman
  // VSS shares of dropped committee members.
  absl::StatusOr<willow::RecoveryResponse> HandleRecoveryRequest(
      const willow::RecoveryRequest& request);

  // Verifies key generation proofs and aggregates key contributions into public
  // key.
  absl::StatusOr<willow::ShellAhePublicKey> VerifyAndAggregateKeyContributions(
      const willow::VerifyKeyContributionsRequest& request);

  // Handles a partial decryption request (e.g. from Coordinator).
  absl::StatusOr<willow::PartialDecryptionResponse>
  HandlePartialDecryptionRequest(
      const willow::PartialDecryptionRequest& request);

  // Convenience testing helper: decrypts a raw ClientMessage end-to-end by
  // combining Decryptor partial decryption with Accumulator KAHE key recovery
  // and payload decryption. Does not verify the client proof in the message.
  absl::StatusOr<willow::EncodedData> Decrypt(
      const willow::ClientMessage& message);

  // Computes partial decryption for a request containing an AHE partial
  // decryption ciphertext.
  absl::StatusOr<std::string> GenerateSerializedPartialDecryptionResponse(
      std::string serialized_partial_decryption_request);

 private:
  explicit ShellTestingDecryptor(
      rust::Box<ShellTestingDecryptorRust> decryptor);

  rust::Box<ShellTestingDecryptorRust> decryptor_;
};

}  // namespace testing
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_WILLOW_TESTING_UTILS_SHELL_TESTING_DECRYPTOR_H_
