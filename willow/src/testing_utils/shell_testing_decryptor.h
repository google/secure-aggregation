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

#ifndef SECURE_AGGREGATION_WILLOW_SRC_TESTING_UTILS_SHELL_TESTING_DECRYPTOR_H_
#define SECURE_AGGREGATION_WILLOW_SRC_TESTING_UTILS_SHELL_TESTING_DECRYPTOR_H_

#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "willow/proto/shell/ciphertexts.pb.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/messages.pb.h"
#include "willow/src/input_encoding/codec.h"
#include "willow/src/testing_utils/shell_testing_decryptor.rs.h"

namespace secure_aggregation {
namespace testing {

// Basic implementation of a single decryptor that uses Shell operations
// directly. Useful for testing Shell clients or servers, by checking that
// encrypted messages can be decrypted properly.
class ShellTestingDecryptor {
 public:
  // Creates a new ShellTestingDecryptor from the given config, hashing the
  // session ID from the config to seed KAHE and AHE public parameters.
  static absl::StatusOr<std::unique_ptr<ShellTestingDecryptor>> Create(
      const willow::AggregationConfigProto& aggregation_config);

  // Generates a new AHE public key, and stores the corresponding secret key.
  absl::StatusOr<willow::ShellAhePublicKey> GeneratePublicKey();

  // Decrypts a client message using the stored AHE secret key, by recovering
  // the KAHE key from the AHE ciphertext and then decrypting the KAHE
  // ciphertext. Does not verify the client proof contained in the message.
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

#endif  // SECURE_AGGREGATION_WILLOW_SRC_TESTING_UTILS_SHELL_TESTING_DECRYPTOR_H_
