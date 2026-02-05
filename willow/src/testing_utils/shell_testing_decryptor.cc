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

#include "willow/src/testing_utils/shell_testing_decryptor.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "ffi_utils/cxx_utils.h"
#include "ffi_utils/status_macros.h"
#include "willow/src/input_encoding/codec.h"
#include "willow/src/testing_utils/shell_testing_decryptor.rs.h"

namespace secure_aggregation {
namespace testing {

ShellTestingDecryptor::ShellTestingDecryptor(
    rust::Box<ShellTestingDecryptorRust> decryptor)
    : decryptor_(std::move(decryptor)) {}

absl::StatusOr<std::unique_ptr<ShellTestingDecryptor>>
ShellTestingDecryptor::Create(
    const willow::AggregationConfigProto& aggregation_config) {
  std::string aggregation_config_proto = aggregation_config.SerializeAsString();
  rust::Slice<const uint8_t> slice = ToRustSlice(aggregation_config_proto);

  ShellTestingDecryptorRust* out;
  SECAGG_RETURN_IF_FFI_ERROR(create_shell_testing_decryptor(slice, &out));

  // Use `into_box` to avoid linker issues arising from rust::Box::from_raw.
  return absl::WrapUnique(new ShellTestingDecryptor(decryptor_into_box(out)));
}

absl::StatusOr<willow::ShellAhePublicKey>
ShellTestingDecryptor::GeneratePublicKey() {
  rust::Vec<uint8_t> out;
  SECAGG_RETURN_IF_FFI_ERROR(decryptor_->generate_public_key(&out));

  willow::ShellAhePublicKey public_key;
  if (!public_key.ParseFromArray(out.data(), out.size())) {
    return absl::InternalError("Failed to parse ShellAhePublicKey");
  }
  return public_key;
}

absl::StatusOr<willow::EncodedData> ShellTestingDecryptor::Decrypt(
    const willow::ClientMessage& message) {
  std::string contribution_proto = message.SerializeAsString();
  rust::Slice<const uint8_t> slice(
      reinterpret_cast<const uint8_t*>(contribution_proto.data()),
      contribution_proto.size());

  rust::Vec<EncodedDataEntry> rust_flat_data;
  SECAGG_RETURN_IF_FFI_ERROR(decryptor_->decrypt(slice, &rust_flat_data));

  willow::EncodedData encoded_data;
  for (const auto& rust_entry : rust_flat_data) {
    std::string key(rust_entry.key);
    std::vector<int64_t> val;
    val.reserve(rust_entry.values.size());
    for (auto v : rust_entry.values) {
      val.push_back(static_cast<int64_t>(v));
    }
    encoded_data[std::move(key)] = std::move(val);
  }

  return encoded_data;
}

absl::StatusOr<std::string>
ShellTestingDecryptor::GenerateSerializedPartialDecryptionResponse(
    std::string serialized_partial_decryption_request) {
  rust::Vec<uint8_t> out;
  SECAGG_RETURN_IF_FFI_ERROR(decryptor_->generate_partial_decryption_response(
      ToRustSlice(serialized_partial_decryption_request), &out));
  return std::string(reinterpret_cast<const char*>(out.data()), out.size());
}

}  // namespace testing
}  // namespace secure_aggregation
