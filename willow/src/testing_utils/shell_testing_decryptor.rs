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

use aggregation_config::AggregationConfig;
use aggregation_config_rust_proto::AggregationConfigProto;
use ahe_shell::Ciphertext as VaheCiphertext;
use ahe_traits::{AheBase, AheKeygen, PartialDec};
use kahe_shell::Ciphertext as KaheCiphertext;
use kahe_shell::ShellKahe;
use kahe_traits::{KaheBase, KaheDecrypt, TrySecretKeyFrom};
use messages::{ClientMessage, PartialDecryptionRequest, PartialDecryptionResponse};
use messages_rust_proto::ClientMessage as ClientMessageProto;
use messages_rust_proto::PartialDecryptionRequest as PartialDecryptionRequestProto;
use parameters_shell::create_shell_configs;
use prng_traits::SecurePrng;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use single_thread_hkdf::SingleThreadHkdfPrng;
use status::ffi::FfiStatus;
use status::{StatusError, StatusErrorCode};
use vahe_shell::ShellVahe;
use vahe_traits::Recover;
use vahe_traits::{HasVahe, VaheBase};

/// Basic implementation of a single decryptor that uses Shell operations directly. Useful for
/// testing Shell clients, by checking that encrypted messages can be decrypted properly. Comes with
/// a C++ interface.
pub struct ShellTestingDecryptor {
    kahe: ShellKahe,
    vahe: ShellVahe,
    prng: SingleThreadHkdfPrng,
    secret_key: Option<<ShellVahe as AheBase>::SecretKeyShare>,
}

impl HasVahe for ShellTestingDecryptor {
    type Vahe = ShellVahe;
    fn vahe(&self) -> &Self::Vahe {
        &self.vahe
    }
}

impl ShellTestingDecryptor {
    /// Creates a new ShellTestingDecryptor, using the given context string to seed KAHE and AHE
    /// public parameters.
    pub fn new(
        aggregation_config: &AggregationConfig,
        context_string: &[u8],
    ) -> Result<ShellTestingDecryptor, StatusError> {
        let (kahe_config, ahe_config) = create_shell_configs(aggregation_config)?;
        let kahe = ShellKahe::new(kahe_config, context_string)?;
        let vahe = ShellVahe::new(ahe_config, context_string)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let prng = SingleThreadHkdfPrng::create(&seed)?;
        Ok(ShellTestingDecryptor { kahe, vahe, prng, secret_key: None })
    }

    /// Generates a new AHE public key, and stores the corresponding secret key.
    pub fn generate_public_key(
        &mut self,
    ) -> Result<<ShellVahe as AheBase>::PublicKey, StatusError> {
        let (sk_share, pk_share, _) = self.vahe.key_gen(&mut self.prng)?;
        self.secret_key = Some(sk_share);
        let public_key = self.vahe.aggregate_public_key_shares(&[pk_share])?;
        Ok(public_key)
    }

    /// Decrypts a client message using the stored AHE secret key, by recovering the KAHE key from
    /// the AHE ciphertext and then decrypting the KAHE ciphertext. Does not verify the client proof
    /// contained in the message.
    pub fn decrypt(
        &mut self,
        client_message: &ClientMessage<ShellKahe, ShellVahe>,
    ) -> Result<<ShellKahe as KaheBase>::Plaintext, StatusError> {
        let partial_dec_ciphertext =
            self.vahe.get_partial_dec_ciphertext(&client_message.ahe_ciphertext)?;
        let rest_of_ciphertext =
            self.vahe.get_recover_ciphertext(&client_message.ahe_ciphertext)?;
        match &self.secret_key {
            None => Err(StatusError::new_with_current_location(
                StatusErrorCode::InvalidArgument,
                "No secret key available",
            )),
            Some(sk_share) => {
                let partial_decryption =
                    self.vahe.partial_decrypt(&partial_dec_ciphertext, sk_share, &mut self.prng)?;
                let decrypted_kahe_key =
                    self.vahe.recover(&partial_decryption, &rest_of_ciphertext, None)?;
                let decrypted_kahe_key = self.kahe.try_secret_key_from(decrypted_kahe_key)?;
                let decrypted_plaintext =
                    self.kahe.decrypt(&client_message.kahe_ciphertext, &decrypted_kahe_key)?;
                Ok(decrypted_plaintext)
            }
        }
    }

    fn generate_public_key_serialized(&mut self) -> Result<Vec<u8>, StatusError> {
        let pk = self.generate_public_key()?;
        pk.to_proto(&self.vahe)
            .map_err(|e| status::internal(format!("ToProto error: {}", e)))?
            .serialize()
            .map_err(|e| status::internal(format!("Serialize error: {}", e)))
    }

    /// SAFETY: `out` and `out_status_message` must not be null.
    unsafe fn generate_public_key_ffi(
        &mut self,
        out: *mut Vec<u8>,
        out_status_message: *mut cxx::UniquePtr<cxx::CxxString>,
    ) -> i32 {
        match self.generate_public_key_serialized() {
            Ok(pk) => {
                *out = pk;
                0
            }
            Err(status_error) => {
                let ffi_status: FfiStatus = status_error.into();
                *out_status_message = ffi_status.message;
                ffi_status.code
            }
        }
    }

    fn decrypt_serialized(
        &mut self,
        contribution: &[u8],
    ) -> Result<Vec<ffi::EncodedDataEntry>, StatusError> {
        let client_message_proto = ClientMessageProto::parse(contribution)
            .map_err(|e| status::internal(format!("Failed to parse ClientMessageProto: {}", e)))?;

        let kahe_ciphertext =
            KaheCiphertext::from_proto(client_message_proto.kahe_ciphertext(), &self.kahe)?;
        let ahe_ciphertext =
            VaheCiphertext::from_proto(client_message_proto.ahe_ciphertext(), &self.vahe)?;

        let proof =
            <ShellVahe as VaheBase>::EncryptionProof::from_proto(client_message_proto.proof(), ())?;
        let nonce = client_message_proto.nonce().to_vec();

        let client_message = ClientMessage { kahe_ciphertext, ahe_ciphertext, proof, nonce };

        let plaintext = self.decrypt(&client_message)?;
        let entries = plaintext
            .into_iter()
            .map(|(key, values)| ffi::EncodedDataEntry { key, values })
            .collect();
        Ok(entries)
    }

    /// SAFETY: all pointer arguments (`out`, `out_status_message`) must be valid for writes.
    unsafe fn decrypt_ffi(
        &mut self,
        contribution: &[u8],
        out: *mut Vec<ffi::EncodedDataEntry>,
        out_status_message: *mut cxx::UniquePtr<cxx::CxxString>,
    ) -> i32 {
        match self.decrypt_serialized(contribution) {
            Ok(result) => {
                *out = result;
                0
            }
            Err(status_error) => {
                let ffi_status: FfiStatus = status_error.into();
                *out_status_message = ffi_status.message;
                ffi_status.code
            }
        }
    }

    fn generate_partial_decryption_response(
        &mut self,
        request: &PartialDecryptionRequest<ShellVahe>,
    ) -> Result<PartialDecryptionResponse<ShellVahe>, StatusError> {
        match &self.secret_key {
            None => Err(StatusError::new_with_current_location(
                StatusErrorCode::InvalidArgument,
                "No secret key available",
            )),
            Some(sk_share) => {
                let partial_decryption = self.vahe.partial_decrypt(
                    &request.partial_dec_ciphertext,
                    sk_share,
                    &mut self.prng,
                )?;
                Ok(PartialDecryptionResponse { partial_decryption })
            }
        }
    }

    fn generate_partial_decryption_response_serialized(
        &mut self,
        request: &[u8],
    ) -> Result<Vec<u8>, StatusError> {
        let request_proto = PartialDecryptionRequestProto::parse(request).map_err(|e| {
            status::internal(format!("Failed to parse PartialDecryptionRequestProto: {}", e))
        })?;
        let request = PartialDecryptionRequest::from_proto(request_proto, self)?;
        let response = self.generate_partial_decryption_response(&request)?;
        response
            .to_proto(self)
            .map_err(|e| status::internal(format!("ToProto error: {}", e)))?
            .serialize()
            .map_err(|e| status::internal(format!("Serialize error: {}", e)))
    }

    /// SAFETY: all pointer arguments (`out`, `out_status_message`) must be valid for writes.
    unsafe fn generate_partial_decryption_response_ffi(
        &mut self,
        request: &[u8],
        out: *mut Vec<u8>,
        out_status_message: *mut cxx::UniquePtr<cxx::CxxString>,
    ) -> i32 {
        match self.generate_partial_decryption_response_serialized(request) {
            Ok(response) => {
                *out = response;
                0
            }
            Err(status_error) => {
                let ffi_status: FfiStatus = status_error.into();
                *out_status_message = ffi_status.message;
                ffi_status.code
            }
        }
    }
}

/// CXX bridge to call ShellTestingDecryptor from C++, using serialized protos as input and output.
///
/// SAFETY: all functions in this module are only called from the wrapping C++ library,
///   ensuring that output pointers are correctly wrapped by a rust::Box, and that pointer
///   arguments are not null.
#[cxx::bridge(namespace = "secure_aggregation::testing")]
pub mod ffi {
    struct EncodedDataEntry {
        key: String,
        values: Vec<u64>,
    }

    extern "Rust" {
        #[cxx_name = "ShellTestingDecryptorRust"]
        type ShellTestingDecryptor;

        unsafe fn create_shell_testing_decryptor(
            config: &[u8],
            out: *mut *mut ShellTestingDecryptor,
            out_status_message: *mut UniquePtr<CxxString>,
        ) -> i32;

        #[rust_name = "generate_public_key_ffi"]
        unsafe fn generate_public_key(
            self: &mut ShellTestingDecryptor,
            out: *mut Vec<u8>,
            out_status_message: *mut UniquePtr<CxxString>,
        ) -> i32;

        #[rust_name = "decrypt_ffi"]
        unsafe fn decrypt(
            self: &mut ShellTestingDecryptor,
            contribution: &[u8],
            out: *mut Vec<EncodedDataEntry>,
            out_status_message: *mut UniquePtr<CxxString>,
        ) -> i32;

        #[rust_name = "generate_partial_decryption_response_ffi"]
        unsafe fn generate_partial_decryption_response(
            self: &mut ShellTestingDecryptor,
            request: &[u8],
            out: *mut Vec<u8>,
            out_status_message: *mut UniquePtr<CxxString>,
        ) -> i32;

        unsafe fn decryptor_into_box(ptr: *mut ShellTestingDecryptor)
            -> Box<ShellTestingDecryptor>;
    }
}

fn create_shell_testing_decryptor_impl(
    config: &[u8],
) -> Result<Box<ShellTestingDecryptor>, StatusError> {
    let aggregation_config_proto = AggregationConfigProto::parse(config)
        .map_err(|e| status::internal(format!("Failed to parse AggregationConfigProto: {}", e)))?;
    let aggregation_config = AggregationConfig::from_proto(aggregation_config_proto, ())?;
    let context_bytes = aggregation_config.compute_context_bytes()?;
    let decryptor = ShellTestingDecryptor::new(&aggregation_config, &context_bytes)?;
    Ok(Box::new(decryptor))
}

/// SAFETY: `out` and `out_status_message` must not be null.
unsafe fn create_shell_testing_decryptor(
    config: &[u8],
    out: *mut *mut ShellTestingDecryptor,
    out_status_message: *mut cxx::UniquePtr<cxx::CxxString>,
) -> i32 {
    match create_shell_testing_decryptor_impl(config) {
        Ok(decryptor) => {
            *out = Box::into_raw(decryptor);
            0
        }
        Err(status_error) => {
            let ffi_status: FfiStatus = status_error.into();
            *out_status_message = ffi_status.message;
            ffi_status.code
        }
    }
}

/// Converts a raw pointer to a Box. Ideally we would use `rust::Box::from_raw`
/// (https://cxx.rs/binding/box.html) directly from C++, but that causes linker errors.
///
/// SAFETY: `ptr` must have been created by `Box::into_raw`, as in `create_shell_testing_decryptor`.
unsafe fn decryptor_into_box(ptr: *mut ShellTestingDecryptor) -> Box<ShellTestingDecryptor> {
    Box::from_raw(ptr)
}
