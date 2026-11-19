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

#include "shell_wrapper/hpke.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/base/call_once.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "ffi_utils/cxx_utils.h"
#include "ffi_utils/status.h"
#include "include/cxx.h"
#include "shell_wrapper/hpke.rs.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/config/global_registry.h"
#include "tink/hybrid/hpke_config.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/keyset_handle.h"
#include "tink/proto_keyset_format.h"

namespace secure_aggregation {
namespace {

absl::Status EnsureTinkHpkeRegistered() {
  static absl::once_flag register_once;
  static absl::Status* register_status = nullptr;
  absl::call_once(register_once, []() {
    absl::Status status = crypto::tink::RegisterHpke();
    if (status.ok()) {
      status = crypto::tink::AeadConfig::Register();
    }
    register_status = new absl::Status(std::move(status));
  });
  return *register_status;
}

// Enforces that an HPKE or AEAD keyset handle has been validated by Tink and
// contains exactly one enabled primary key. Combined with
// `EnsureTinkHpkeRegistered()` (which registers only `RegisterHpke()` for
// `HybridEncrypt`/`HybridDecrypt`, never ECIES `HybridConfig::Register()`),
// `GetPrimitive<HybridEncrypt>` / `GetPrimitive<HybridDecrypt>` accepts
// exclusively single-key HPKE keysets.
absl::Status ValidateSingleKeyKeyset(
    const crypto::tink::KeysetHandle& keyset_handle) {
  absl::Status validate_status = keyset_handle.Validate();
  if (!validate_status.ok()) {
    return validate_status;
  }
  if (keyset_handle.size() != 1) {
    return absl::InvalidArgumentError(
        "Keyset must contain exactly one enabled primary key");
  }
  return absl::OkStatus();
}

}  // namespace

FfiStatus GenerateHpkeKeyset(
    bool raw_output_prefix, HpkeKeysetWrapper& private_keyset_out,
    std::unique_ptr<std::string>& serialized_public_keyset_out) {
  absl::Status reg_status = EnsureTinkHpkeRegistered();
  if (!reg_status.ok()) {
    return MakeFfiStatus(std::move(reg_status));
  }

  const auto& key_template =
      raw_output_prefix
          ? crypto::tink::HybridKeyTemplates::HpkeX25519HkdfSha256Aes128GcmRaw()
          : crypto::tink::HybridKeyTemplates::HpkeX25519HkdfSha256Aes128Gcm();

  absl::StatusOr<std::unique_ptr<crypto::tink::KeysetHandle>> private_handle =
      crypto::tink::KeysetHandle::GenerateNew(
          key_template, crypto::tink::KeyGenConfigGlobalRegistry());
  if (!private_handle.ok()) {
    return MakeFfiStatus(std::move(private_handle).status());
  }

  absl::StatusOr<std::unique_ptr<crypto::tink::KeysetHandle>> public_handle =
      (*private_handle)
          ->GetPublicKeysetHandle(crypto::tink::KeyGenConfigGlobalRegistry());
  if (!public_handle.ok()) {
    return MakeFfiStatus(std::move(public_handle).status());
  }

  absl::StatusOr<std::string> serialized_public =
      crypto::tink::SerializeKeysetWithoutSecretToProtoKeysetFormat(
          **public_handle);
  if (!serialized_public.ok()) {
    return MakeFfiStatus(std::move(serialized_public).status());
  }

  private_keyset_out.ptr = *std::move(private_handle);
  serialized_public_keyset_out =
      std::make_unique<std::string>(*std::move(serialized_public));
  return MakeFfiStatus();
}

FfiStatus GetPublicKeysetFromPrivate(
    const HpkeKeysetWrapper& private_keyset,
    std::unique_ptr<std::string>& serialized_public_keyset_out) {
  absl::Status reg_status = EnsureTinkHpkeRegistered();
  if (!reg_status.ok()) {
    return MakeFfiStatus(std::move(reg_status));
  }
  if (private_keyset.ptr == nullptr) {
    return MakeFfiStatus(
        absl::InvalidArgumentError("HPKE private keyset handle is null"));
  }

  absl::StatusOr<std::unique_ptr<crypto::tink::KeysetHandle>> public_handle =
      private_keyset.ptr->GetPublicKeysetHandle(
          crypto::tink::KeyGenConfigGlobalRegistry());
  if (!public_handle.ok()) {
    return MakeFfiStatus(std::move(public_handle).status());
  }

  absl::StatusOr<std::string> serialized_public =
      crypto::tink::SerializeKeysetWithoutSecretToProtoKeysetFormat(
          **public_handle);
  if (!serialized_public.ok()) {
    return MakeFfiStatus(std::move(serialized_public).status());
  }

  serialized_public_keyset_out =
      std::make_unique<std::string>(*std::move(serialized_public));
  return MakeFfiStatus();
}

void CloneHpkeKeyset(const HpkeKeysetWrapper& src, HpkeKeysetWrapper& dst) {
  if (src.ptr == nullptr) {
    dst.ptr = nullptr;
  } else {
    dst.ptr = std::make_unique<crypto::tink::KeysetHandle>(*src.ptr);
  }
}

FfiStatus ValidateHpkePublicKeyset(
    rust::Slice<const uint8_t> serialized_public_keyset) {
  absl::Status reg_status = EnsureTinkHpkeRegistered();
  if (!reg_status.ok()) {
    return MakeFfiStatus(std::move(reg_status));
  }
  if (serialized_public_keyset.empty()) {
    return MakeFfiStatus(
        absl::InvalidArgumentError("Serialized HPKE public keyset is empty"));
  }

  absl::StatusOr<crypto::tink::KeysetHandle> public_handle =
      crypto::tink::ParseKeysetWithoutSecretFromProtoKeysetFormat(
          ToAbslStringView(serialized_public_keyset));
  if (!public_handle.ok()) {
    return MakeFfiStatus(std::move(public_handle).status());
  }
  absl::Status single_key_status = ValidateSingleKeyKeyset(*public_handle);
  if (!single_key_status.ok()) {
    return MakeFfiStatus(std::move(single_key_status));
  }

  absl::StatusOr<std::unique_ptr<crypto::tink::HybridEncrypt>> hybrid_encrypt =
      public_handle->GetPrimitive<crypto::tink::HybridEncrypt>(
          crypto::tink::ConfigGlobalRegistry());
  if (!hybrid_encrypt.ok()) {
    return MakeFfiStatus(std::move(hybrid_encrypt).status());
  }
  return MakeFfiStatus();
}

FfiStatus HpkeEncrypt(rust::Slice<const uint8_t> serialized_public_keyset,
                      rust::Slice<const uint8_t> plaintext,
                      rust::Slice<const uint8_t> context_info,
                      std::unique_ptr<std::string>& ciphertext_out) {
  absl::Status reg_status = EnsureTinkHpkeRegistered();
  if (!reg_status.ok()) {
    return MakeFfiStatus(std::move(reg_status));
  }
  if (serialized_public_keyset.empty()) {
    return MakeFfiStatus(
        absl::InvalidArgumentError("Serialized HPKE public keyset is empty"));
  }

  absl::StatusOr<crypto::tink::KeysetHandle> public_handle =
      crypto::tink::ParseKeysetWithoutSecretFromProtoKeysetFormat(
          ToAbslStringView(serialized_public_keyset));
  if (!public_handle.ok()) {
    return MakeFfiStatus(std::move(public_handle).status());
  }
  absl::Status single_key_status = ValidateSingleKeyKeyset(*public_handle);
  if (!single_key_status.ok()) {
    return MakeFfiStatus(std::move(single_key_status));
  }

  absl::StatusOr<std::unique_ptr<crypto::tink::HybridEncrypt>> hybrid_encrypt =
      public_handle->GetPrimitive<crypto::tink::HybridEncrypt>(
          crypto::tink::ConfigGlobalRegistry());
  if (!hybrid_encrypt.ok()) {
    return MakeFfiStatus(std::move(hybrid_encrypt).status());
  }

  absl::StatusOr<std::string> ciphertext =
      (*hybrid_encrypt)
          ->Encrypt(ToAbslStringView(plaintext),
                    ToAbslStringView(context_info));
  if (!ciphertext.ok()) {
    return MakeFfiStatus(std::move(ciphertext).status());
  }

  ciphertext_out = std::make_unique<std::string>(*std::move(ciphertext));
  return MakeFfiStatus();
}

FfiStatus HpkeDecrypt(const HpkeKeysetWrapper& private_keyset,
                      rust::Slice<const uint8_t> ciphertext,
                      rust::Slice<const uint8_t> context_info,
                      std::unique_ptr<std::string>& plaintext_out) {
  absl::Status reg_status = EnsureTinkHpkeRegistered();
  if (!reg_status.ok()) {
    return MakeFfiStatus(std::move(reg_status));
  }
  if (private_keyset.ptr == nullptr) {
    return MakeFfiStatus(
        absl::InvalidArgumentError("HPKE private keyset handle is null"));
  }
  absl::Status single_key_status = ValidateSingleKeyKeyset(*private_keyset.ptr);
  if (!single_key_status.ok()) {
    return MakeFfiStatus(std::move(single_key_status));
  }

  absl::StatusOr<std::unique_ptr<crypto::tink::HybridDecrypt>> hybrid_decrypt =
      private_keyset.ptr->GetPrimitive<crypto::tink::HybridDecrypt>(
          crypto::tink::ConfigGlobalRegistry());
  if (!hybrid_decrypt.ok()) {
    return MakeFfiStatus(std::move(hybrid_decrypt).status());
  }

  absl::StatusOr<std::string> plaintext =
      (*hybrid_decrypt)
          ->Decrypt(ToAbslStringView(ciphertext),
                    ToAbslStringView(context_info));
  if (!plaintext.ok()) {
    return MakeFfiStatus(std::move(plaintext).status());
  }

  plaintext_out = std::make_unique<std::string>(*std::move(plaintext));
  return MakeFfiStatus();
}

FfiStatus GenerateHpkeKeysetWrappingAead(HpkeKeysetWrapper& aead_keyset_out) {
  absl::Status reg_status = EnsureTinkHpkeRegistered();
  if (!reg_status.ok()) {
    return MakeFfiStatus(std::move(reg_status));
  }

  absl::StatusOr<std::unique_ptr<crypto::tink::KeysetHandle>> aead_handle =
      crypto::tink::KeysetHandle::GenerateNew(
          crypto::tink::AeadKeyTemplates::Aes256Gcm(),
          crypto::tink::KeyGenConfigGlobalRegistry());
  if (!aead_handle.ok()) {
    return MakeFfiStatus(std::move(aead_handle).status());
  }

  aead_keyset_out.ptr = *std::move(aead_handle);
  return MakeFfiStatus();
}

FfiStatus SerializeHpkePrivateKeysetEncrypted(
    const HpkeKeysetWrapper& private_keyset,
    const HpkeKeysetWrapper& aead_keyset,
    rust::Slice<const uint8_t> associated_data,
    std::unique_ptr<std::string>& encrypted_keyset_out) {
  absl::Status reg_status = EnsureTinkHpkeRegistered();
  if (!reg_status.ok()) {
    return MakeFfiStatus(std::move(reg_status));
  }
  if (private_keyset.ptr == nullptr || aead_keyset.ptr == nullptr) {
    return MakeFfiStatus(
        absl::InvalidArgumentError("HPKE or AEAD keyset handle is null"));
  }

  absl::StatusOr<std::unique_ptr<crypto::tink::Aead>> aead =
      aead_keyset.ptr->GetPrimitive<crypto::tink::Aead>(
          crypto::tink::ConfigGlobalRegistry());
  if (!aead.ok()) {
    return MakeFfiStatus(std::move(aead).status());
  }

  absl::StatusOr<std::string> encrypted =
      crypto::tink::SerializeKeysetToEncryptedKeysetFormat(
          *private_keyset.ptr, **aead, ToAbslStringView(associated_data));
  if (!encrypted.ok()) {
    return MakeFfiStatus(std::move(encrypted).status());
  }

  encrypted_keyset_out = std::make_unique<std::string>(*std::move(encrypted));
  return MakeFfiStatus();
}

FfiStatus ParseHpkePrivateKeysetEncrypted(
    rust::Slice<const uint8_t> encrypted_keyset,
    const HpkeKeysetWrapper& aead_keyset,
    rust::Slice<const uint8_t> associated_data,
    HpkeKeysetWrapper& private_keyset_out) {
  absl::Status reg_status = EnsureTinkHpkeRegistered();
  if (!reg_status.ok()) {
    return MakeFfiStatus(std::move(reg_status));
  }
  if (aead_keyset.ptr == nullptr) {
    return MakeFfiStatus(
        absl::InvalidArgumentError("AEAD keyset handle is null"));
  }

  absl::StatusOr<std::unique_ptr<crypto::tink::Aead>> aead =
      aead_keyset.ptr->GetPrimitive<crypto::tink::Aead>(
          crypto::tink::ConfigGlobalRegistry());
  if (!aead.ok()) {
    return MakeFfiStatus(std::move(aead).status());
  }

  absl::StatusOr<crypto::tink::KeysetHandle> parsed =
      crypto::tink::ParseKeysetFromEncryptedKeysetFormat(
          ToAbslStringView(encrypted_keyset), **aead,
          ToAbslStringView(associated_data));
  if (!parsed.ok()) {
    return MakeFfiStatus(std::move(parsed).status());
  }
  absl::Status single_key_status = ValidateSingleKeyKeyset(*parsed);
  if (!single_key_status.ok()) {
    return MakeFfiStatus(std::move(single_key_status));
  }

  absl::StatusOr<std::unique_ptr<crypto::tink::HybridDecrypt>> check_decrypt =
      parsed->GetPrimitive<crypto::tink::HybridDecrypt>(
          crypto::tink::ConfigGlobalRegistry());
  if (!check_decrypt.ok()) {
    return MakeFfiStatus(std::move(check_decrypt).status());
  }

  private_keyset_out.ptr =
      std::make_unique<crypto::tink::KeysetHandle>(*std::move(parsed));
  return MakeFfiStatus();
}

}  // namespace secure_aggregation
