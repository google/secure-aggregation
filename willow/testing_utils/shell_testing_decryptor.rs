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
use ahe_traits::AheBase;
use decryptor::{Decryptor, DecryptorState};
use kahe_traits::{KaheBase, KaheDecrypt, TrySecretKeyFrom};
use messages::{
    ClientMessage, PartialDecryptionRequest, PartialDecryptionResponse,
    VerifyKeyContributionsRequest,
};
use messages_rust_proto::ClientMessage as ClientMessageProto;
use messages_rust_proto::PartialDecryptionRequest as PartialDecryptionRequestProto;
use messages_rust_proto::VerifyKeyContributionsRequest as VerifyKeyContributionsRequestProto;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use shell_ahe::Ciphertext as VaheCiphertext;
use shell_kahe::Ciphertext as KaheCiphertext;
use shell_kahe::ShellKahe;
use shell_parameters::create_shell_configs;
use shell_vahe::ShellVahe;
use status::StatusError;
use std::rc::Rc;
use vahe_traits::{HasVahe, Recover, VaheBase};

/// Basic implementation of a decryptor that uses Shell operations directly. Useful for
/// testing Shell clients and accumulators, by checking that encrypted messages can be decrypted properly.
///
/// Each function is implemented in 3 layers:
///  - Layer 1: Strongly-typed public Rust API (`pub fn`) operating on native protocol objects.
///  - Layer 2: Safe serialization helpers (`fn *_serialized`) handling Protobuf bytes.
///  - Layer 3: Unsafe CXX FFI bridge (`unsafe fn *_ffi`) interfacing with C++.
pub struct ShellTestingDecryptor {
    kahe: Rc<ShellKahe>,
    decryptor: Decryptor<ShellVahe>,
    state: DecryptorState<ShellVahe>,
}

impl HasVahe for ShellTestingDecryptor {
    type Vahe = ShellVahe;
    fn vahe(&self) -> &Self::Vahe {
        self.decryptor.vahe()
    }
}

impl kahe_traits::HasKahe for ShellTestingDecryptor {
    type Kahe = ShellKahe;
    fn kahe(&self) -> &Self::Kahe {
        &self.kahe
    }
}

impl ShellTestingDecryptor {
    /// Creates a new `ShellTestingDecryptor`, using the given context string to seed KAHE and AHE
    /// public parameters and initializing the underlying `Decryptor` and `DecryptorState`.
    pub fn new(
        aggregation_config: &AggregationConfig,
        context_bytes: &[u8],
    ) -> Result<ShellTestingDecryptor, StatusError> {
        let (kahe_config, ahe_config) = create_shell_configs(aggregation_config)?;
        let kahe = Rc::new(ShellKahe::new(kahe_config, context_bytes)?);
        let vahe = Rc::new(ShellVahe::new(ahe_config, context_bytes)?);
        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe)?;
        let state = DecryptorState {
            sk_share: None,
            kahe: None,
            aggregation_config: Some(aggregation_config.clone()),
        };
        Ok(ShellTestingDecryptor { kahe, decryptor, state })
    }

    /// Generates a new AHE public key, and stores the corresponding secret key share in `DecryptorState`.
    pub fn generate_public_key(
        &mut self,
    ) -> Result<<ShellVahe as AheBase>::PublicKey, StatusError> {
        let setup = self.decryptor.create_setup_contribution(&mut self.state)?;
        let pk_share = setup.key_contribution.public_key_share;
        self.vahe().aggregate_public_key_shares(std::iter::once(&pk_share))
    }

    /// Convenience testing helper: decrypts a raw `ClientMessage` end-to-end by combining
    /// `Decryptor` partial decryption with Accumulator KAHE key recovery and payload decryption.
    /// Does not verify ZK client proof contained in the message.
    pub fn decrypt(
        &mut self,
        client_message: &ClientMessage<ShellKahe, ShellVahe>,
    ) -> Result<<ShellKahe as KaheBase>::Plaintext, StatusError> {
        // Operations directly on the underlying KAHE and AHE primitives to avoid the overhead of
        // instantiating a full accumulator.
        let partial_dec_ciphertext =
            self.vahe().get_partial_dec_ciphertext(&client_message.ahe_ciphertext)?;
        let rest_of_ciphertext =
            self.vahe().get_recover_ciphertext(&client_message.ahe_ciphertext)?;
        let request = PartialDecryptionRequest { partial_dec_ciphertext, aggregation_config: None };
        let response = self.decryptor.handle_partial_decryption_request::<ShellKahe>(
            request,
            None,
            &mut self.state,
        )?;
        let decrypted_kahe_key =
            self.vahe().recover(&response.partial_decryption, &rest_of_ciphertext, None)?;
        let decrypted_kahe_key = self.kahe.try_secret_key_from(decrypted_kahe_key)?;
        let decrypted_plaintext =
            self.kahe.decrypt(&client_message.kahe_ciphertext, &decrypted_kahe_key)?;
        Ok(decrypted_plaintext)
    }

    fn generate_public_key_serialized(&mut self) -> Result<Vec<u8>, StatusError> {
        let pk = self.generate_public_key()?;
        pk.to_proto(self.vahe())
            .map_err(|e| status::internal(&format!("ToProto error: {}", e)))?
            .serialize()
            .map_err(|e| status::internal(&format!("Serialize error: {}", e)))
    }

    /// SAFETY: `out` must be valid for writes.
    unsafe fn generate_public_key_ffi(&mut self, out: *mut Vec<u8>) -> ffi::FfiStatus {
        self.generate_public_key_serialized().map(|pk| unsafe { *out = pk }).into()
    }

    fn decrypt_serialized(
        &mut self,
        contribution: &[u8],
    ) -> Result<Vec<ffi::EncodedDataEntry>, StatusError> {
        let client_message_proto = ClientMessageProto::parse(contribution)
            .map_err(|e| status::internal(&format!("Failed to parse ClientMessageProto: {}", e)))?;

        let kahe_ciphertext =
            KaheCiphertext::from_proto(client_message_proto.kahe_ciphertext(), self.kahe.as_ref())?;
        let ahe_ciphertext =
            VaheCiphertext::from_proto(client_message_proto.ahe_ciphertext(), self.vahe())?;

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

    /// SAFETY: `out` must be valid for writes.
    unsafe fn decrypt_ffi(
        &mut self,
        contribution: &[u8],
        out: *mut Vec<ffi::EncodedDataEntry>,
    ) -> ffi::FfiStatus {
        self.decrypt_serialized(contribution).map(|result| unsafe { *out = result }).into()
    }

    /// Creates a committee setup contribution containing a key share and key gen proof.
    pub fn create_setup_contribution(
        &mut self,
    ) -> Result<messages::SetupContribution<ShellVahe>, StatusError> {
        self.decryptor.create_setup_contribution(&mut self.state)
    }

    fn create_setup_contribution_serialized(&mut self) -> Result<Vec<u8>, StatusError> {
        let setup_contribution = self.create_setup_contribution()?;
        let proto = setup_contribution.to_proto(self)?;
        proto.serialize().map_err(|e| status::internal(&format!("Serialize error: {}", e)))
    }

    /// SAFETY: `out` must be valid for writes.
    unsafe fn create_setup_contribution_ffi(&mut self, out: *mut Vec<u8>) -> ffi::FfiStatus {
        self.create_setup_contribution_serialized().map(|res| unsafe { *out = res }).into()
    }

    /// Verifies key generation proofs and aggregates key contributions into a public key.
    pub fn verify_and_aggregate_key_contributions(
        &mut self,
        request: VerifyKeyContributionsRequest<ShellVahe>,
    ) -> Result<<ShellVahe as AheBase>::PublicKey, StatusError> {
        self.decryptor.verify_and_aggregate_key_contributions(request)
    }

    fn verify_and_aggregate_key_contributions_serialized(
        &mut self,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, StatusError> {
        let request_proto =
            VerifyKeyContributionsRequestProto::parse(request_bytes).map_err(|e| {
                status::internal(&format!("Failed to parse VerifyKeyContributionsRequest: {}", e))
            })?;
        let request = VerifyKeyContributionsRequest::from_proto(request_proto, self)?;
        let public_key = self.verify_and_aggregate_key_contributions(request)?;
        let proto = public_key.to_proto(self.vahe())?;
        proto.serialize().map_err(|e| status::internal(&format!("Serialize error: {}", e)))
    }

    /// SAFETY: `out` must be valid for writes.
    unsafe fn verify_and_aggregate_key_contributions_ffi(
        &mut self,
        request_bytes: &[u8],
        out: *mut Vec<u8>,
    ) -> ffi::FfiStatus {
        self.verify_and_aggregate_key_contributions_serialized(request_bytes)
            .map(|res| unsafe { *out = res })
            .into()
    }

    /// Handles a partial decryption request from a Coordinator, returning a partial decryption response.
    pub fn handle_partial_decryption_request(
        &mut self,
        request: PartialDecryptionRequest<ShellVahe>,
    ) -> Result<PartialDecryptionResponse<ShellKahe, ShellVahe>, StatusError> {
        self.decryptor.handle_partial_decryption_request::<ShellKahe>(
            request,
            None,
            &mut self.state,
        )
    }

    fn handle_partial_decryption_request_serialized(
        &mut self,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, StatusError> {
        let request_proto = PartialDecryptionRequestProto::parse(request_bytes).map_err(|e| {
            status::internal(&format!("Failed to parse PartialDecryptionRequestProto: {}", e))
        })?;
        let request = PartialDecryptionRequest::from_proto(request_proto, self)?;
        let response = self.handle_partial_decryption_request(request)?;
        response
            .to_proto((self, Some(self.kahe.as_ref())))
            .map_err(|e| status::internal(&format!("ToProto error: {}", e)))?
            .serialize()
            .map_err(|e| status::internal(&format!("Serialize error: {}", e)))
    }

    /// SAFETY: `out` must be valid for writes.
    unsafe fn handle_partial_decryption_request_ffi(
        &mut self,
        request_bytes: &[u8],
        out: *mut Vec<u8>,
    ) -> ffi::FfiStatus {
        self.handle_partial_decryption_request_serialized(request_bytes)
            .map(|response| unsafe { *out = response })
            .into()
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

    unsafe extern "C++" {
        include!("ffi_utils/status.rs.h");
        #[namespace = "secure_aggregation"]
        type FfiStatus = status::ffi::FfiStatus;
    }

    extern "Rust" {
        #[cxx_name = "ShellTestingDecryptorRust"]
        type ShellTestingDecryptor;

        unsafe fn create_shell_testing_decryptor(
            config: &[u8],
            out: *mut *mut ShellTestingDecryptor,
        ) -> FfiStatus;

        #[rust_name = "generate_public_key_ffi"]
        unsafe fn generate_public_key(
            self: &mut ShellTestingDecryptor,
            out: *mut Vec<u8>,
        ) -> FfiStatus;

        #[rust_name = "create_setup_contribution_ffi"]
        unsafe fn create_setup_contribution(
            self: &mut ShellTestingDecryptor,
            out: *mut Vec<u8>,
        ) -> FfiStatus;

        #[rust_name = "verify_and_aggregate_key_contributions_ffi"]
        unsafe fn verify_and_aggregate_key_contributions(
            self: &mut ShellTestingDecryptor,
            request: &[u8],
            out: *mut Vec<u8>,
        ) -> FfiStatus;

        #[rust_name = "decrypt_ffi"]
        unsafe fn decrypt(
            self: &mut ShellTestingDecryptor,
            contribution: &[u8],
            out: *mut Vec<EncodedDataEntry>,
        ) -> FfiStatus;

        #[rust_name = "handle_partial_decryption_request_ffi"]
        unsafe fn generate_partial_decryption_response(
            self: &mut ShellTestingDecryptor,
            request: &[u8],
            out: *mut Vec<u8>,
        ) -> FfiStatus;

        unsafe fn decryptor_into_box(ptr: *mut ShellTestingDecryptor)
            -> Box<ShellTestingDecryptor>;
    }
}

fn create_shell_testing_decryptor_impl(
    config: &[u8],
) -> Result<Box<ShellTestingDecryptor>, StatusError> {
    let aggregation_config_proto = AggregationConfigProto::parse(config)
        .map_err(|e| status::internal(&format!("Failed to parse AggregationConfigProto: {}", e)))?;
    let aggregation_config = AggregationConfig::from_proto(aggregation_config_proto, ())?;
    let context_bytes = &aggregation_config.key_id;
    let decryptor = ShellTestingDecryptor::new(&aggregation_config, context_bytes)?;
    Ok(Box::new(decryptor))
}

/// SAFETY: `out` must be valid for writes.
unsafe fn create_shell_testing_decryptor(
    config: &[u8],
    out: *mut *mut ShellTestingDecryptor,
) -> ffi::FfiStatus {
    create_shell_testing_decryptor_impl(config)
        .map(|decryptor| unsafe { *out = Box::into_raw(decryptor) })
        .into()
}

/// Converts a raw pointer to a Box. Ideally we would use `rust::Box::from_raw`
/// (https://cxx.rs/binding/box.html) directly from C++, but that causes linker errors.
///
/// SAFETY: `ptr` must have been created by `Box::into_raw`, as in `create_shell_testing_decryptor`.
unsafe fn decryptor_into_box(ptr: *mut ShellTestingDecryptor) -> Box<ShellTestingDecryptor> {
    unsafe { Box::from_raw(ptr) }
}
