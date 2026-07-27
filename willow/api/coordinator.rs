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

use aggregation_config::AggregationConfig;
use aggregation_config_rust_proto::AggregationConfigProto;
use ahe_traits::AheBase;
use decryptor_traits::SecureAggregationCoordinator;
use kahe_traits::{HasKahe, KaheBase};
use messages::CoordinatorState;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use shell_ciphertexts_rust_proto::ShellAhePartialDecCiphertext as ShellAhePartialDecCiphertextProto;
use shell_kahe::ShellKahe;
use shell_parameters::create_shell_configs;
use shell_vahe::ShellVahe;
use status::StatusError;
use std::rc::Rc;
use vahe_traits::HasVahe;
use willow_v1_coordinator::WillowV1Coordinator;

#[cxx::bridge(namespace = "secure_aggregation")]
pub mod ffi {
    // CXX doesn't support nested types, so we define a struct here so that functions can take
    // an array of protobuf views. The slice is over values owned by the C++
    // SerializedProtoSpan object.
    struct SerializedProtoView<'a> {
        data: &'a [u8],
    }

    unsafe extern "C++" {
        include!("ffi_utils/status.rs.h");
        type FfiStatus = status::ffi::FfiStatus;
    }

    extern "Rust" {
        type WillowShellCoordinator;

        #[cxx_name = "NewWillowShellCoordinatorFromSerializedConfig"]
        unsafe fn new_willow_shell_coordinator_from_serialized_config(
            serialized_aggregation_config: &[u8],
            out: *mut *mut WillowShellCoordinator,
        ) -> FfiStatus;

        #[cxx_name = "WillowShellCoordinatorIntoBox"]
        unsafe fn willow_shell_coordinator_into_box(
            ptr: *mut WillowShellCoordinator,
        ) -> Box<WillowShellCoordinator>;

        #[cxx_name = "HandleSetupSubmissions"]
        fn handle_setup_submissions_ffi(
            self: &mut WillowShellCoordinator,
            non_reputable_contributions: &[SerializedProtoView],
            reputable_contributions: &[SerializedProtoView],
            out_verify_request: &mut Vec<u8>,
        ) -> FfiStatus;

        #[cxx_name = "PrepareDecryptionRequest"]
        fn prepare_decryption_request_ffi(
            self: &mut WillowShellCoordinator,
            verifier_ciphertext: &[u8],
            out_decryption_request: &mut Vec<u8>,
        ) -> FfiStatus;

        #[cxx_name = "AggregateAndFinalizePartialDecryptions"]
        fn aggregate_and_finalize_partial_decryptions_ffi(
            self: &mut WillowShellCoordinator,
            partial_responses: &[SerializedProtoView],
            out_finalized_pd: &mut Vec<u8>,
        ) -> FfiStatus;
    }
}

pub struct WillowShellCoordinator {
    kahe: Rc<ShellKahe>,
    coord: WillowV1Coordinator<ShellVahe>,
    coord_state: CoordinatorState<ShellVahe>,
}

impl HasKahe for WillowShellCoordinator {
    type Kahe = ShellKahe;
    fn kahe(&self) -> &Self::Kahe {
        &self.kahe
    }
}

impl HasVahe for WillowShellCoordinator {
    type Vahe = ShellVahe;
    fn vahe(&self) -> &Self::Vahe {
        self.coord.vahe()
    }
}

/// Converts a raw pointer to a Box. Ideally we would use `rust::Box::from_raw`
/// (https://cxx.rs/binding/box.html) directly from C++, but that causes linker errors.
///
/// SAFETY: `ptr` must have been created by Box::into_raw or one of the functions in this module.
unsafe fn willow_shell_coordinator_into_box(
    ptr: *mut WillowShellCoordinator,
) -> Box<WillowShellCoordinator> {
    unsafe { Box::from_raw(ptr) }
}

/// SAFETY: `out` must be a valid pointer for writes.
unsafe fn new_willow_shell_coordinator_from_serialized_config(
    serialized_aggregation_config: &[u8],
    out: *mut *mut WillowShellCoordinator,
) -> ffi::FfiStatus {
    WillowShellCoordinator::new_from_serialized_config(serialized_aggregation_config)
        .map(|coord| unsafe { *out = Box::into_raw(Box::new(coord)) })
        .into()
}

impl WillowShellCoordinator {
    fn new_from_serialized_config(config: &[u8]) -> Result<Self, StatusError> {
        let aggregation_config_proto = AggregationConfigProto::parse(config).map_err(|e| {
            status::internal(&format!("Failed to parse AggregationConfigProto: {}", e))
        })?;
        let aggregation_config = AggregationConfig::from_proto(aggregation_config_proto, ())?;
        let (kahe_config, ahe_config) = create_shell_configs(&aggregation_config)?;
        let context_bytes = &aggregation_config.key_id;
        let kahe = Rc::new(ShellKahe::new(kahe_config, context_bytes)?);
        let vahe = Rc::new(ShellVahe::new(ahe_config, context_bytes)?);
        let coord = WillowV1Coordinator { vahe };
        let coord_state = CoordinatorState::default();
        Ok(WillowShellCoordinator { kahe, coord, coord_state })
    }

    /// Helper function to parse protobuf views using the coordinator's context.
    fn parse_views<'a, T>(
        &'a self,
        views: &[ffi::SerializedProtoView],
    ) -> Result<Vec<T>, StatusError>
    where
        T: FromProto<&'a WillowShellCoordinator>,
        T::Proto: protobuf::Message,
    {
        let mut result = Vec::with_capacity(views.len());
        for view in views {
            let proto = <T::Proto>::parse(view.data)
                .map_err(|e| status::internal(&format!("Failed to parse proto view: {}", e)))?;
            result.push(T::from_proto(proto, self)?);
        }
        Ok(result)
    }

    fn handle_setup_submissions(
        &mut self,
        non_reputable_views: &[ffi::SerializedProtoView],
        reputable_views: &[ffi::SerializedProtoView],
    ) -> Result<Vec<u8>, StatusError> {
        let non_reputable = self.parse_views(non_reputable_views)?;
        let reputable = self.parse_views(reputable_views)?;

        let verify_request =
            self.coord.handle_setup_submissions(non_reputable, reputable, &mut self.coord_state)?;
        let proto = verify_request.to_proto(&*self)?;
        proto.serialize().map_err(|e| {
            status::internal(&format!("Failed to serialize VerifyKeyContributionsRequest: {}", e))
        })
    }

    fn handle_setup_submissions_ffi(
        &mut self,
        non_reputable_contributions: &[ffi::SerializedProtoView],
        reputable_contributions: &[ffi::SerializedProtoView],
        out_verify_request: &mut Vec<u8>,
    ) -> ffi::FfiStatus {
        self.handle_setup_submissions(non_reputable_contributions, reputable_contributions)
            .map(|serialized| {
                *out_verify_request = serialized;
            })
            .into()
    }

    fn prepare_decryption_request(
        &mut self,
        verifier_ciphertext: &[u8],
    ) -> Result<Vec<u8>, StatusError> {
        let ct_proto =
            ShellAhePartialDecCiphertextProto::parse(verifier_ciphertext).map_err(|e| {
                status::internal(&format!("Failed to parse ShellAhePartialDecCiphertext: {}", e))
            })?;
        let ct =
            <ShellVahe as AheBase>::PartialDecCiphertext::from_proto(ct_proto, self.coord.vahe())?;

        let request = self.coord.prepare_decryption_request(&ct, &mut self.coord_state)?;
        let proto = request.to_proto(&*self)?;
        proto.serialize().map_err(|e| {
            status::internal(&format!("Failed to serialize PartialDecryptionRequest: {}", e))
        })
    }

    fn prepare_decryption_request_ffi(
        &mut self,
        verifier_ciphertext: &[u8],
        out_decryption_request: &mut Vec<u8>,
    ) -> ffi::FfiStatus {
        self.prepare_decryption_request(verifier_ciphertext)
            .map(|serialized| {
                *out_decryption_request = serialized;
            })
            .into()
    }

    fn aggregate_and_finalize_partial_decryptions(
        &mut self,
        partial_response_views: &[ffi::SerializedProtoView],
    ) -> Result<Vec<u8>, StatusError> {
        let responses = self.parse_views(partial_response_views)?;

        self.coord.aggregate_partial_decryptions(
            responses,
            Some(self.kahe.as_ref()),
            &mut self.coord_state,
        )?;

        let finalized_pd = self.coord.finalize_partial_decryption(&mut self.coord_state)?;
        let proto = finalized_pd.to_proto(&*self)?;
        proto.serialize().map_err(|e| {
            status::internal(&format!("Failed to serialize FinalizedPartialDecryption: {}", e))
        })
    }

    fn aggregate_and_finalize_partial_decryptions_ffi(
        &mut self,
        partial_responses: &[ffi::SerializedProtoView],
        out_finalized_pd: &mut Vec<u8>,
    ) -> ffi::FfiStatus {
        self.aggregate_and_finalize_partial_decryptions(partial_responses)
            .map(|serialized| {
                *out_finalized_pd = serialized;
            })
            .into()
    }
}
