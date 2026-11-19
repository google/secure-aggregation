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
    compute_roster_hash, ClientMessage, CommitteeConfig, PartialDecryptionRequest,
    PartialDecryptionResponse, RecoveryRequest, RecoveryResponse, VerifyKeyContributionsRequest,
};
use messages_rust_proto::ClientMessage as ClientMessageProto;
use messages_rust_proto::CommitteeConfigProto;
use messages_rust_proto::PartialDecryptionRequest as PartialDecryptionRequestProto;
use messages_rust_proto::RecoveryRequest as RecoveryRequestProto;
use messages_rust_proto::VerifyKeyContributionsRequest as VerifyKeyContributionsRequestProto;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use share_cipher::{ShareCipher, TinkHpkePrivateKey, TinkHpkePublicKey, TinkHpkeShareCipher};
use shell_ahe::Ciphertext as VaheCiphertext;
use shell_kahe::Ciphertext as KaheCiphertext;
use shell_kahe::ShellKahe;
use shell_parameters::create_shell_configs;
use shell_vahe::ShellVahe;
use status::StatusError;
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::rc::Rc;
use vahe_traits::{HasVahe, Recover, VaheBase};

/// Basic implementation of a decryptor that uses Shell operations directly. Useful for
/// testing Shell clients and accumulators, by checking that encrypted messages can be decrypted
/// properly.
///
/// Each function is implemented in 3 layers:
///  - Layer 1: Strongly-typed public Rust API (`pub fn`) operating on native protocol objects.
///  - Layer 2: Safe serialization helpers (`fn *_serialized`) handling Protobuf bytes.
///  - Layer 3: Unsafe CXX FFI bridge (`unsafe fn *_ffi`) interfacing with C++.
pub struct ShellTestingDecryptor {
    kahe: Rc<ShellKahe>,
    decryptor: Decryptor<ShellVahe>,
    state: DecryptorState<ShellVahe>,
    hpke_keypair: Option<(TinkHpkePrivateKey, TinkHpkePublicKey)>,
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
        let mut state = DecryptorState::default();
        state.aggregation_config = Some(aggregation_config.clone());
        Ok(ShellTestingDecryptor { kahe, decryptor, state, hpke_keypair: None })
    }

    /// Generates a new AHE public key, and stores the corresponding secret key share in
    /// `DecryptorState`.
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

    /// Generates an HPKE keypair for recoverable committee secret sharing, stores it in
    /// `self.hpke_keypair`, and returns the 32-byte raw X25519 public key.
    pub fn generate_hpke_public_key(&mut self) -> Result<Vec<u8>, StatusError> {
        let (sk, pk) = TinkHpkeShareCipher::generate_keypair()?;
        let pk_bytes = pk.as_bytes().to_vec();
        self.hpke_keypair = Some((sk, pk));
        Ok(pk_bytes)
    }

    /// SAFETY: `out` must be valid for writes.
    unsafe fn generate_hpke_public_key_ffi(&mut self, out: *mut Vec<u8>) -> ffi::FfiStatus {
        self.generate_hpke_public_key().map(|res| unsafe { *out = res }).into()
    }

    /// Creates a recoverable committee setup contribution.
    pub fn create_recoverable_setup_contribution(
        &mut self,
        committee_config: CommitteeConfig,
        roster_pks: &BTreeMap<NonZeroU32, TinkHpkePublicKey>,
    ) -> Result<messages::SetupContribution<ShellVahe>, StatusError> {
        let (hpke_sk, _) = self.hpke_keypair.as_ref().ok_or_else(|| {
            status::failed_precondition(
                "ShellTestingDecryptor has no HPKE keypair (call GenerateHpkePublicKey first)",
            )
        })?;
        self.decryptor.create_recoverable_setup_contribution(
            committee_config,
            roster_pks,
            hpke_sk,
            &mut self.state,
        )
    }

    fn create_recoverable_setup_contribution_serialized(
        &mut self,
        committee_config_bytes: &[u8],
        roster_views: &[ffi::ByteSliceView],
    ) -> Result<Vec<u8>, StatusError> {
        let cfg_proto = CommitteeConfigProto::parse(committee_config_bytes).map_err(|e| {
            status::invalid_argument(&format!("Failed to parse CommitteeConfigProto: {}", e))
        })?;
        let cfg = CommitteeConfig::from_proto(cfg_proto, ())?;
        if roster_views.len() != cfg.num_decryptors as usize {
            return Err(status::invalid_argument(
                "roster_hpke_public_keys count must equal committee_config.num_decryptors",
            ));
        }
        let mut roster_pks = BTreeMap::new();
        for (i, view) in roster_views.iter().enumerate() {
            let idx = NonZeroU32::new((i + 1) as u32)
                .ok_or_else(|| status::internal("1-based roster index must be non-zero"))?;
            let pk = TinkHpkePublicKey::from_bytes(view.data.to_vec())?;
            roster_pks.insert(idx, pk);
        }
        let contrib = self.create_recoverable_setup_contribution(cfg, &roster_pks)?;
        let proto = contrib.to_proto(self)?;
        proto.serialize().map_err(|e| status::internal(&format!("Serialize error: {}", e)))
    }

    /// SAFETY: `out` must be valid for writes.
    unsafe fn create_recoverable_setup_contribution_ffi(
        &mut self,
        committee_config_bytes: &[u8],
        roster_views: &[ffi::ByteSliceView],
        out: *mut Vec<u8>,
    ) -> ffi::FfiStatus {
        self.create_recoverable_setup_contribution_serialized(committee_config_bytes, roster_views)
            .map(|res| unsafe { *out = res })
            .into()
    }

    /// Handles a one-shot recovery request from the Coordinator.
    pub fn handle_recovery_request(
        &mut self,
        request: RecoveryRequest,
    ) -> Result<RecoveryResponse, StatusError> {
        self.decryptor.handle_recovery_request(request, &mut self.state)
    }

    fn handle_recovery_request_serialized(
        &mut self,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, StatusError> {
        let req_proto = RecoveryRequestProto::parse(request_bytes).map_err(|e| {
            status::invalid_argument(&format!("Failed to parse RecoveryRequestProto: {}", e))
        })?;
        let req = RecoveryRequest::from_proto(req_proto, ())?;
        let resp = self.handle_recovery_request(req)?;
        let proto = resp.to_proto(())?;
        proto.serialize().map_err(|e| status::internal(&format!("Serialize error: {}", e)))
    }

    /// SAFETY: `out` must be valid for writes.
    unsafe fn handle_recovery_request_ffi(
        &mut self,
        request_bytes: &[u8],
        out: *mut Vec<u8>,
    ) -> ffi::FfiStatus {
        self.handle_recovery_request_serialized(request_bytes)
            .map(|res| unsafe { *out = res })
            .into()
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

    /// Handles a partial decryption request from a Coordinator, returning a partial decryption
    /// response.
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

    struct ByteSliceView<'a> {
        data: &'a [u8],
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

        unsafe fn build_committee_config(
            my_index: u32,
            num_decryptors: u32,
            threshold: u32,
            session_context: &[u8],
            roster_views: &[ByteSliceView],
            out: *mut Vec<u8>,
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

        #[rust_name = "generate_hpke_public_key_ffi"]
        unsafe fn generate_hpke_public_key(
            self: &mut ShellTestingDecryptor,
            out: *mut Vec<u8>,
        ) -> FfiStatus;

        #[rust_name = "create_recoverable_setup_contribution_ffi"]
        unsafe fn create_recoverable_setup_contribution(
            self: &mut ShellTestingDecryptor,
            committee_config_bytes: &[u8],
            roster_views: &[ByteSliceView],
            out: *mut Vec<u8>,
        ) -> FfiStatus;

        #[rust_name = "handle_recovery_request_ffi"]
        unsafe fn handle_recovery_request(
            self: &mut ShellTestingDecryptor,
            request: &[u8],
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

fn build_committee_config_impl(
    my_index: u32,
    num_decryptors: u32,
    threshold: u32,
    session_context: &[u8],
    roster_views: &[ffi::ByteSliceView],
) -> Result<Vec<u8>, StatusError> {
    let my_idx = NonZeroU32::new(my_index).ok_or_else(|| {
        status::invalid_argument("build_committee_config: my_index must be non-zero")
    })?;
    if roster_views.len() != num_decryptors as usize {
        return Err(status::invalid_argument(
            "build_committee_config: roster_hpke_public_keys count must equal num_decryptors",
        ));
    }
    let mut raw_roster = BTreeMap::new();
    for (i, view) in roster_views.iter().enumerate() {
        let idx = NonZeroU32::new((i + 1) as u32)
            .ok_or_else(|| status::internal("1-based roster index must be non-zero"))?;
        raw_roster.insert(idx, view.data.to_vec());
    }
    let roster_hash = compute_roster_hash(num_decryptors, threshold, &raw_roster)?;
    let cfg = CommitteeConfig::new(
        my_idx,
        num_decryptors,
        threshold,
        roster_hash,
        session_context.to_vec(),
    )?;
    let proto = cfg.to_proto(())?;
    proto.serialize().map_err(|e| status::internal(&format!("Serialize error: {}", e)))
}

/// SAFETY: `out` must be valid for writes.
unsafe fn build_committee_config(
    my_index: u32,
    num_decryptors: u32,
    threshold: u32,
    session_context: &[u8],
    roster_views: &[ffi::ByteSliceView],
    out: *mut Vec<u8>,
) -> ffi::FfiStatus {
    build_committee_config_impl(my_index, num_decryptors, threshold, session_context, roster_views)
        .map(|bytes| unsafe { *out = bytes })
        .into()
}

/// Converts a raw pointer to a Box. Ideally we would use `rust::Box::from_raw`
/// (https://cxx.rs/binding/box.html) directly from C++, but that causes linker errors.
///
/// SAFETY: `ptr` must have been created by `Box::into_raw`, as in `create_shell_testing_decryptor`.
unsafe fn decryptor_into_box(ptr: *mut ShellTestingDecryptor) -> Box<ShellTestingDecryptor> {
    unsafe { Box::from_raw(ptr) }
}
