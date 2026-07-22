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
#include "ffi_utils/cxx_utils.h"
#include "ffi_utils/status_macros.h"
#include "include/cxx.h"
#include "willow/api/coordinator.rs.h"
#include "willow/proto/shell/ciphertexts.pb.h"
#include "willow/proto/willow/aggregation_config.pb.h"
#include "willow/proto/willow/messages.pb.h"

namespace secure_aggregation {
namespace willow {

absl::StatusOr<std::unique_ptr<Coordinator>> Coordinator::Create(
    const AggregationConfigProto& aggregation_config) {
  std::string config_str = aggregation_config.SerializeAsString();
  auto config_ptr = std::make_unique<std::string>(std::move(config_str));
  secure_aggregation::WillowShellCoordinator* coord_ptr = nullptr;
  SECAGG_RETURN_IF_FFI_ERROR(NewWillowShellCoordinatorFromSerializedConfig(
      std::move(config_ptr), &coord_ptr));
  auto coord_box = WillowShellCoordinatorIntoBox(coord_ptr);
  return std::unique_ptr<Coordinator>(new Coordinator(std::move(coord_box)));
}

absl::StatusOr<VerifyKeyContributionsRequest>
Coordinator::HandleSetupSubmissions(
    const std::vector<SetupContribution>& non_reputable_contributions,
    const std::vector<SetupContribution>& reputable_contributions) {
  std::vector<std::string> non_reputable_strs;
  non_reputable_strs.reserve(non_reputable_contributions.size());
  for (const auto& contrib : non_reputable_contributions) {
    non_reputable_strs.push_back(contrib.SerializeAsString());
  }
  std::vector<SerializedProtoView> non_reputable_views;
  non_reputable_views.reserve(non_reputable_strs.size());
  for (const auto& str : non_reputable_strs) {
    non_reputable_views.push_back(SerializedProtoView{ToRustSlice(str)});
  }
  rust::Slice<const SerializedProtoView> non_reputable_slice(
      non_reputable_views.data(), non_reputable_views.size());

  std::vector<std::string> reputable_strs;
  reputable_strs.reserve(reputable_contributions.size());
  for (const auto& contrib : reputable_contributions) {
    reputable_strs.push_back(contrib.SerializeAsString());
  }
  std::vector<SerializedProtoView> reputable_views;
  reputable_views.reserve(reputable_strs.size());
  for (const auto& str : reputable_strs) {
    reputable_views.push_back(SerializedProtoView{ToRustSlice(str)});
  }
  rust::Slice<const SerializedProtoView> reputable_slice(
      reputable_views.data(), reputable_views.size());

  rust::Vec<uint8_t> result_bytes;
  SECAGG_RETURN_IF_FFI_ERROR(coordinator_->HandleSetupSubmissions(
      non_reputable_slice, reputable_slice, &result_bytes));

  VerifyKeyContributionsRequest verify_request;
  std::string result_str(reinterpret_cast<const char*>(result_bytes.data()),
                         result_bytes.size());
  if (!verify_request.ParseFromString(result_str)) {
    return absl::InternalError(
        "Failed to parse VerifyKeyContributionsRequest from serialized FFI "
        "bytes.");
  }
  return verify_request;
}

absl::StatusOr<PartialDecryptionRequest> Coordinator::PrepareDecryptionRequest(
    const ShellAhePartialDecCiphertext& verifier_ciphertext) {
  std::string ct_str = verifier_ciphertext.SerializeAsString();
  auto ct_ptr = std::make_unique<std::string>(std::move(ct_str));
  rust::Vec<uint8_t> result_bytes;
  SECAGG_RETURN_IF_FFI_ERROR(
      coordinator_->PrepareDecryptionRequest(std::move(ct_ptr), &result_bytes));

  PartialDecryptionRequest dec_request;
  std::string result_str(reinterpret_cast<const char*>(result_bytes.data()),
                         result_bytes.size());
  if (!dec_request.ParseFromString(result_str)) {
    return absl::InternalError(
        "Failed to parse PartialDecryptionRequest from serialized FFI bytes.");
  }
  return dec_request;
}

absl::StatusOr<FinalizedPartialDecryption>
Coordinator::AggregateAndFinalizePartialDecryptions(
    const std::vector<PartialDecryptionResponse>& partial_responses) {
  std::vector<std::string> response_strs;
  response_strs.reserve(partial_responses.size());
  for (const auto& resp : partial_responses) {
    response_strs.push_back(resp.SerializeAsString());
  }
  std::vector<SerializedProtoView> response_views;
  response_views.reserve(response_strs.size());
  for (const auto& str : response_strs) {
    response_views.push_back(SerializedProtoView{ToRustSlice(str)});
  }
  rust::Slice<const SerializedProtoView> responses_slice(response_views.data(),
                                                         response_views.size());

  rust::Vec<uint8_t> result_bytes;
  SECAGG_RETURN_IF_FFI_ERROR(
      coordinator_->AggregateAndFinalizePartialDecryptions(responses_slice,
                                                           &result_bytes));

  FinalizedPartialDecryption finalized_pd;
  std::string result_str(reinterpret_cast<const char*>(result_bytes.data()),
                         result_bytes.size());
  if (!finalized_pd.ParseFromString(result_str)) {
    return absl::InternalError(
        "Failed to parse FinalizedPartialDecryption from serialized FFI "
        "bytes.");
  }
  return finalized_pd;
}

}  // namespace willow
}  // namespace secure_aggregation
