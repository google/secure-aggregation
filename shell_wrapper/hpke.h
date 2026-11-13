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

#ifndef SECURE_AGGREGATION_SHELL_WRAPPER_HPKE_H_
#define SECURE_AGGREGATION_SHELL_WRAPPER_HPKE_H_

#include <cstdint>
#include <memory>
#include <string>

#include "ffi_utils/status.h"
#include "ffi_utils/status.rs.h"
#include "include/cxx.h"
#include "shell_wrapper/hpke.rs.h"
#include "tink/keyset_handle.h"

namespace secure_aggregation {

// Generates a new Tink HPKE (DHKEM_X25519_HKDF_SHA256 / HKDF_SHA256 /
// AES_128_GCM) private keyset handle and its serialized public keyset in
// Tink ProtoKeysetFormat (`SerializeKeysetWithoutSecretToProtoKeysetFormat`).
// If `raw_output_prefix` is true, uses `HpkeX25519HkdfSha256Aes128GcmRaw()`;
// otherwise uses `HpkeX25519HkdfSha256Aes128Gcm()` (`TINK` 5-byte prefix).
FfiStatus GenerateHpkeKeyset(
    bool raw_output_prefix, HpkeKeysetWrapper& private_keyset_out,
    std::unique_ptr<std::string>& serialized_public_keyset_out);

// Extracts and serializes the public keyset from an existing HPKE private
// keyset handle using `SerializeKeysetWithoutSecretToProtoKeysetFormat`.
FfiStatus GetPublicKeysetFromPrivate(
    const HpkeKeysetWrapper& private_keyset,
    std::unique_ptr<std::string>& serialized_public_keyset_out);

// Deep-copies an `HpkeKeysetWrapper`.
void CloneHpkeKeyset(const HpkeKeysetWrapper& src, HpkeKeysetWrapper& dst);

// Validates that `serialized_public_keyset` parses via
// `ParseKeysetWithoutSecretFromProtoKeysetFormat` and produces a valid
// `crypto::tink::HybridEncrypt` primitive.
FfiStatus ValidateHpkePublicKeyset(
    rust::Slice<const uint8_t> serialized_public_keyset);

// Encrypts `plaintext` with `context_info` under `serialized_public_keyset`
// using Tink's `HybridEncrypt`.
FfiStatus HpkeEncrypt(rust::Slice<const uint8_t> serialized_public_keyset,
                      rust::Slice<const uint8_t> plaintext,
                      rust::Slice<const uint8_t> context_info,
                      std::unique_ptr<std::string>& ciphertext_out);

// Decrypts `ciphertext` with `context_info` using `private_keyset`'s
// `HybridDecrypt` primitive.
FfiStatus HpkeDecrypt(const HpkeKeysetWrapper& private_keyset,
                      rust::Slice<const uint8_t> ciphertext,
                      rust::Slice<const uint8_t> context_info,
                      std::unique_ptr<std::string>& plaintext_out);

// Generates an AES-256-GCM Tink AEAD keyset handle for encrypting HPKE
// private keysets via `SerializeKeysetToEncryptedKeysetFormat`.
FfiStatus GenerateHpkeKeysetWrappingAead(HpkeKeysetWrapper& aead_keyset_out);

// Serializes `private_keyset` to Tink EncryptedKeysetFormat under
// `aead_keyset` and `associated_data`
// (`SerializeKeysetToEncryptedKeysetFormat`).
FfiStatus SerializeHpkePrivateKeysetEncrypted(
    const HpkeKeysetWrapper& private_keyset,
    const HpkeKeysetWrapper& aead_keyset,
    rust::Slice<const uint8_t> associated_data,
    std::unique_ptr<std::string>& encrypted_keyset_out);

// Parses an encrypted HPKE private keyset using
// `ParseKeysetFromEncryptedKeysetFormat` and verifies it supports
// `HybridDecrypt`.
FfiStatus ParseHpkePrivateKeysetEncrypted(
    rust::Slice<const uint8_t> encrypted_keyset,
    const HpkeKeysetWrapper& aead_keyset,
    rust::Slice<const uint8_t> associated_data,
    HpkeKeysetWrapper& private_keyset_out);

}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_SHELL_WRAPPER_HPKE_H_
