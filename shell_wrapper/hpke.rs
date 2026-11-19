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

//! Rust FFI wrapper around Tink C++ HPKE (`DHKEM_X25519_HKDF_SHA256`,
//! `HKDF_SHA256`, `AES_128_GCM`) using only `//visibility:public` Tink targets.

use status::{rust_status_from_cpp, StatusError};

#[cxx::bridge(namespace = "secure_aggregation")]
mod ffi {
    struct HpkeKeysetWrapper {
        ptr: UniquePtr<KeysetHandle>,
    }

    unsafe extern "C++" {
        type FfiStatus = status::ffi::FfiStatus;

        include!("shell_wrapper/hpke.h");

        #[namespace = "crypto::tink"]
        type KeysetHandle;

        pub fn GenerateHpkeKeyset(
            raw_output_prefix: bool,
            private_keyset_out: &mut HpkeKeysetWrapper,
            serialized_public_keyset_out: &mut UniquePtr<CxxString>,
        ) -> FfiStatus;

        pub fn GetPublicKeysetFromPrivate(
            private_keyset: &HpkeKeysetWrapper,
            serialized_public_keyset_out: &mut UniquePtr<CxxString>,
        ) -> FfiStatus;

        pub fn CloneHpkeKeyset(src: &HpkeKeysetWrapper, dst: &mut HpkeKeysetWrapper);

        pub fn ValidateHpkePublicKeyset(serialized_public_keyset: &[u8]) -> FfiStatus;

        pub fn HpkeEncrypt(
            serialized_public_keyset: &[u8],
            plaintext: &[u8],
            context_info: &[u8],
            ciphertext_out: &mut UniquePtr<CxxString>,
        ) -> FfiStatus;

        pub fn HpkeDecrypt(
            private_keyset: &HpkeKeysetWrapper,
            ciphertext: &[u8],
            context_info: &[u8],
            plaintext_out: &mut UniquePtr<CxxString>,
        ) -> FfiStatus;

        pub fn GenerateHpkeKeysetWrappingAead(aead_keyset_out: &mut HpkeKeysetWrapper)
            -> FfiStatus;

        pub fn SerializeHpkePrivateKeysetEncrypted(
            private_keyset: &HpkeKeysetWrapper,
            aead_keyset: &HpkeKeysetWrapper,
            associated_data: &[u8],
            encrypted_keyset_out: &mut UniquePtr<CxxString>,
        ) -> FfiStatus;

        pub fn ParseHpkePrivateKeysetEncrypted(
            encrypted_keyset: &[u8],
            aead_keyset: &HpkeKeysetWrapper,
            associated_data: &[u8],
            private_keyset_out: &mut HpkeKeysetWrapper,
        ) -> FfiStatus;
    }
}

/// Opaque handle to a Tink HPKE private `KeysetHandle` (or wrapping AEAD `KeysetHandle`).
pub struct HpkeKeyset(ffi::HpkeKeysetWrapper);

impl Clone for HpkeKeyset {
    fn clone(&self) -> Self {
        let mut dst = ffi::HpkeKeysetWrapper { ptr: cxx::UniquePtr::null() };
        ffi::CloneHpkeKeyset(&self.0, &mut dst);
        Self(dst)
    }
}

impl std::fmt::Debug for HpkeKeyset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HpkeKeyset([REDACTED])")
    }
}

/// Generates a new HPKE keypair (`HpkeX25519HkdfSha256Aes128Gcm` or `Raw`) and returns the
/// private `HpkeKeyset` handle along with the serialized public keyset in Tink ProtoKeysetFormat.
pub fn generate_hpke_keyset(raw_output_prefix: bool) -> Result<(HpkeKeyset, Vec<u8>), StatusError> {
    let mut private_keyset = ffi::HpkeKeysetWrapper { ptr: cxx::UniquePtr::null() };
    let mut public_bytes = cxx::UniquePtr::null();
    rust_status_from_cpp(ffi::GenerateHpkeKeyset(
        raw_output_prefix,
        &mut private_keyset,
        &mut public_bytes,
    ))?;
    let pub_vec = public_bytes.as_ref().map(|s| s.as_bytes().to_vec()).unwrap_or_default();
    Ok((HpkeKeyset(private_keyset), pub_vec))
}

/// Extracts and serializes the public keyset from an existing `HpkeKeyset`.
pub fn get_public_keyset_from_private(private_keyset: &HpkeKeyset) -> Result<Vec<u8>, StatusError> {
    let mut public_bytes = cxx::UniquePtr::null();
    rust_status_from_cpp(ffi::GetPublicKeysetFromPrivate(&private_keyset.0, &mut public_bytes))?;
    Ok(public_bytes.as_ref().map(|s| s.as_bytes().to_vec()).unwrap_or_default())
}

/// Validates that `serialized_public_keyset` is a valid Tink `HybridEncrypt` public keyset.
pub fn validate_hpke_public_keyset(serialized_public_keyset: &[u8]) -> status::Status {
    rust_status_from_cpp(ffi::ValidateHpkePublicKeyset(serialized_public_keyset))
}

/// Encrypts `plaintext` with `context_info` under `serialized_public_keyset`.
pub fn hpke_encrypt(
    serialized_public_keyset: &[u8],
    plaintext: &[u8],
    context_info: &[u8],
) -> Result<Vec<u8>, StatusError> {
    let mut ciphertext = cxx::UniquePtr::null();
    rust_status_from_cpp(ffi::HpkeEncrypt(
        serialized_public_keyset,
        plaintext,
        context_info,
        &mut ciphertext,
    ))?;
    Ok(ciphertext.as_ref().map(|s| s.as_bytes().to_vec()).unwrap_or_default())
}

/// Decrypts `ciphertext` with `context_info` using `private_keyset`.
pub fn hpke_decrypt(
    private_keyset: &HpkeKeyset,
    ciphertext: &[u8],
    context_info: &[u8],
) -> Result<Vec<u8>, StatusError> {
    let mut plaintext = cxx::UniquePtr::null();
    rust_status_from_cpp(ffi::HpkeDecrypt(
        &private_keyset.0,
        ciphertext,
        context_info,
        &mut plaintext,
    ))?;
    Ok(plaintext.as_ref().map(|s| s.as_bytes().to_vec()).unwrap_or_default())
}

/// Generates a fresh AES-256-GCM AEAD keyset handle for wrapping HPKE private keysets.
pub fn generate_wrapping_aead() -> Result<HpkeKeyset, StatusError> {
    let mut aead_keyset = ffi::HpkeKeysetWrapper { ptr: cxx::UniquePtr::null() };
    rust_status_from_cpp(ffi::GenerateHpkeKeysetWrappingAead(&mut aead_keyset))?;
    Ok(HpkeKeyset(aead_keyset))
}

/// Serializes `private_keyset` to Tink EncryptedKeysetFormat under `aead_keyset` and
/// `associated_data` (`SerializeKeysetToEncryptedKeysetFormat`).
pub fn serialize_hpke_private_keyset_encrypted(
    private_keyset: &HpkeKeyset,
    aead_keyset: &HpkeKeyset,
    associated_data: &[u8],
) -> Result<Vec<u8>, StatusError> {
    let mut encrypted = cxx::UniquePtr::null();
    rust_status_from_cpp(ffi::SerializeHpkePrivateKeysetEncrypted(
        &private_keyset.0,
        &aead_keyset.0,
        associated_data,
        &mut encrypted,
    ))?;
    Ok(encrypted.as_ref().map(|s| s.as_bytes().to_vec()).unwrap_or_default())
}

/// Parses an encrypted HPKE private keyset using `ParseKeysetFromEncryptedKeysetFormat`.
pub fn parse_hpke_private_keyset_encrypted(
    encrypted_keyset: &[u8],
    aead_keyset: &HpkeKeyset,
    associated_data: &[u8],
) -> Result<HpkeKeyset, StatusError> {
    let mut private_keyset = ffi::HpkeKeysetWrapper { ptr: cxx::UniquePtr::null() };
    rust_status_from_cpp(ffi::ParseHpkePrivateKeysetEncrypted(
        encrypted_keyset,
        &aead_keyset.0,
        associated_data,
        &mut private_keyset,
    ))?;
    Ok(HpkeKeyset(private_keyset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::{gtest, verify_eq, verify_that, Result as GTestResult};
    use status::StatusErrorCode;
    use status_matchers_rs::status_is;

    #[gtest]
    fn test_hpke_roundtrip_tink_and_raw_templates() -> GTestResult<()> {
        for raw_prefix in [false, true] {
            let (sk, pk) = generate_hpke_keyset(raw_prefix)?;
            validate_hpke_public_keyset(&pk)?;
            let derived_pk = get_public_keyset_from_private(&sk)?;
            verify_eq!(derived_pk, pk)?;

            let msg = b"32-byte-secret-scalar-share-test";
            let info = b"willow_share_hpke_v1_ctx";
            let ct = hpke_encrypt(&pk, msg, info)?;
            let pt = hpke_decrypt(&sk, &ct, info)?;
            verify_eq!(pt, msg)?;

            // Cloned private keyset also decrypts.
            let sk_clone = sk.clone();
            let pt_clone = hpke_decrypt(&sk_clone, &ct, info)?;
            verify_eq!(pt_clone, msg)?;

            // Wrong context_info fails closed.
            verify_that!(
                hpke_decrypt(&sk, &ct, b"wrong_ctx"),
                status_is(StatusErrorCode::INVALID_ARGUMENT)
            )?;
        }
        Ok(())
    }

    #[gtest]
    fn test_encrypted_keyset_serialization_roundtrip() -> GTestResult<()> {
        let (sk, pk) = generate_hpke_keyset(false)?;
        let aead = generate_wrapping_aead()?;
        let ad = b"decryptor-state-ad";

        let encrypted = serialize_hpke_private_keyset_encrypted(&sk, &aead, ad)?;
        let restored_sk = parse_hpke_private_keyset_encrypted(&encrypted, &aead, ad)?;

        let ct = hpke_encrypt(&pk, b"hello-hpke", b"ctx")?;
        let pt = hpke_decrypt(&restored_sk, &ct, b"ctx")?;
        verify_eq!(pt, b"hello-hpke")?;

        // Wrong associated data or wrong AEAD key fails closed.
        verify_that!(
            parse_hpke_private_keyset_encrypted(&encrypted, &aead, b"wrong-ad"),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        let other_aead = generate_wrapping_aead()?;
        verify_that!(
            parse_hpke_private_keyset_encrypted(&encrypted, &other_aead, ad),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        Ok(())
    }
}
