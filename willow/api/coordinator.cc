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

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/span.h"
#include "ffi_utils/cxx_utils.h"
#include "ffi_utils/status_macros.h"
#include "include/cxx.h"
#include "willow/api/coordinator.rs.h"
#include "willow/proto/shell/ciphertexts.pb.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/messages.pb.h"

namespace secure_aggregation {
namespace willow {
namespace {

// Helper to serialize an array of C++ protobufs and pass them
// across the FFI boundary as a slice of byte views.
template <typename T>
struct SerializedProtoSpan {
  std::vector<std::string> strs;
  std::vector<SerializedProtoView> views;
  rust::Slice<const SerializedProtoView> slice;

  explicit SerializedProtoSpan(absl::Span<const T> protos) {
    strs.reserve(protos.size());
    views.reserve(protos.size());
    for (const auto& proto : protos) {
      strs.push_back(proto.SerializeAsString());
      views.push_back(SerializedProtoView{ToRustSlice(strs.back())});
    }
    slice = rust::Slice<const SerializedProtoView>(views.data(), views.size());
  }
};

}  // namespace

absl::StatusOr<std::unique_ptr<Coordinator>> Coordinator::Create(
    const AggregationConfigProto& aggregation_config) {
  std::string config_str = aggregation_config.SerializeAsString();
  secure_aggregation::WillowShellCoordinator* coord_ptr = nullptr;
  SECAGG_RETURN_IF_FFI_ERROR(NewWillowShellCoordinatorFromSerializedConfig(
      ToRustSlice(config_str), &coord_ptr));
  auto coord_box = WillowShellCoordinatorIntoBox(coord_ptr);
  return std::unique_ptr<Coordinator>(new Coordinator(std::move(coord_box)));
}

absl::StatusOr<VerifyKeyContributionsRequest>
Coordinator::HandleSetupSubmissions(
    absl::Span<const SetupContribution> non_reputable_contributions,
    absl::Span<const SetupContribution> reputable_contributions) {
  SerializedProtoSpan<SetupContribution> non_reputable_helper(
      non_reputable_contributions);
  SerializedProtoSpan<SetupContribution> reputable_helper(
      reputable_contributions);

  rust::Vec<uint8_t> result_bytes;
  // We only pass slices to Rust, which point to views of strings owned by
  // SerializedProtoSpan
  SECAGG_RETURN_IF_FFI_ERROR(coordinator_->HandleSetupSubmissions(
      non_reputable_helper.slice, reputable_helper.slice, result_bytes));

  VerifyKeyContributionsRequest verify_request;
  if (!verify_request.ParseFromArray(result_bytes.data(),
                                     result_bytes.size())) {
    return absl::InternalError(
        "Failed to parse VerifyKeyContributionsRequest from serialized FFI "
        "bytes.");
  }
  return verify_request;
}

absl::StatusOr<PartialDecryptionRequest> Coordinator::PrepareDecryptionRequest(
    const ShellAhePartialDecCiphertext& verifier_ciphertext) {
  std::string ct_str = verifier_ciphertext.SerializeAsString();
  rust::Vec<uint8_t> result_bytes;
  SECAGG_RETURN_IF_FFI_ERROR(coordinator_->PrepareDecryptionRequest(
      ToRustSlice(ct_str), result_bytes));

  PartialDecryptionRequest dec_request;
  if (!dec_request.ParseFromArray(result_bytes.data(), result_bytes.size())) {
    return absl::InternalError(
        "Failed to parse PartialDecryptionRequest from serialized FFI bytes.");
  }
  return dec_request;
}

absl::StatusOr<FinalizedPartialDecryption>
Coordinator::AggregateAndFinalizePartialDecryptions(
    absl::Span<const PartialDecryptionResponse> partial_responses) {
  SerializedProtoSpan<PartialDecryptionResponse> responses_helper(
      partial_responses);

  rust::Vec<uint8_t> result_bytes;
  SECAGG_RETURN_IF_FFI_ERROR(
      coordinator_->AggregateAndFinalizePartialDecryptions(
          responses_helper.slice, result_bytes));

  FinalizedPartialDecryption finalized_pd;
  if (!finalized_pd.ParseFromArray(result_bytes.data(), result_bytes.size())) {
    return absl::InternalError(
        "Failed to parse FinalizedPartialDecryption from serialized FFI "
        "bytes.");
  }
  return finalized_pd;
}

}  // namespace willow
}  // namespace secure_aggregation
