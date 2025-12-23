// Copyright 2025 Google LLC
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
use kahe_shell::ShellKahe;
use kahe_traits::KaheBase;
use messages::ClientMessage;
use parameters_shell::{create_shell_ahe_config, create_shell_kahe_config};
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use protobuf::AsView;
use server_accumulator_rust_proto::{ClientMessageList, ServerAccumulatorState};
use server_traits::SecureAggregationServer;
use status::StatusError;
use vahe_shell::ShellVahe;
use verifier_traits::SecureAggregationVerifier;
use willow_v1_server::{ServerState, WillowV1Server};
use willow_v1_verifier::{VerifierState, WillowV1Verifier};

#[cxx::bridge]
pub mod ffi {
    extern "Rust" {
        #[namespace = "secure_aggregation"]
        type ServerAccumulator;

        // We cannot use status::FfiStatus because CXX requires shared structs to be defined in the
        // same module. So using separate message and pointer as a workaround.
        // SAFETY: All functions in this module are only called from the wrapping C++ library,
        //   ensuring that output pointers are correctly wrapped by a rust::Box, and that pointer
        //   arguments are not null.

        #[namespace = "secure_aggregation"]
        #[cxx_name = "NewServerAccumulatorFromSerializedConfig"]
        unsafe fn new_server_accumulator_from_serialized_config(
            serialized_aggregation_config: UniquePtr<CxxString>,
            out: *mut *mut ServerAccumulator,
            out_status_message: *mut UniquePtr<CxxString>,
        ) -> i32;

        #[namespace = "secure_aggregation"]
        #[cxx_name = "NewServerAccumulatorFromSerializedState"]
        unsafe fn new_server_accumulator_from_serialized_state(
            serialized_server_accumulator: UniquePtr<CxxString>,
            out: *mut *mut ServerAccumulator,
            out_status_message: *mut UniquePtr<CxxString>,
        ) -> i32;

        #[namespace = "secure_aggregation"]
        #[cxx_name = "ProcessClientMessages"]
        unsafe fn process_client_messages_ffi(
            self: &mut ServerAccumulator,
            client_messages: UniquePtr<CxxString>,
            out_status_message: *mut UniquePtr<CxxString>,
        ) -> i32;

        #[namespace = "secure_aggregation"]
        #[cxx_name = "ToSerializedState"]
        unsafe fn to_serialized_state_ffi(
            self: &ServerAccumulator,
            out: *mut Vec<u8>,
            out_status_message: *mut UniquePtr<CxxString>,
        ) -> i32;

        #[namespace = "secure_aggregation"]
        #[cxx_name = "Merge"]
        unsafe fn merge_ffi(
            self: &mut ServerAccumulator,
            other: Box<ServerAccumulator>,
            out_status_message: *mut UniquePtr<CxxString>,
        ) -> i32;

        #[namespace = "secure_aggregation"]
        #[cxx_name = "IntoBox"]
        unsafe fn into_box(ptr: *mut ServerAccumulator) -> Box<ServerAccumulator>;
    }
}

use status::ffi::FfiStatus;

pub struct ServerAccumulator {
    server: WillowV1Server<ShellKahe, ShellVahe>,
    server_state: ServerState<ShellKahe, ShellVahe>,
    verifier: WillowV1Verifier<ShellVahe>,
    verifier_state: VerifierState<ShellVahe>,
    aggregation_config: AggregationConfig,
}

impl ServerAccumulator {
    fn new(aggregation_config: AggregationConfig) -> Result<Self, StatusError> {
        let context_string = aggregation_config.session_id.as_bytes();
        let vahe_config = create_shell_ahe_config(aggregation_config.max_number_of_decryptors)?;
        let kahe_config = create_shell_kahe_config(&aggregation_config)?;
        let server_kahe = ShellKahe::new(kahe_config, context_string)?;
        let server_vahe = ShellVahe::new(vahe_config.clone(), context_string)?;
        let verifier_vahe = ShellVahe::new(vahe_config, context_string)?;
        let server = WillowV1Server { kahe: server_kahe, vahe: server_vahe };
        let verifier = WillowV1Verifier { vahe: verifier_vahe };
        Ok(Self {
            server: server,
            server_state: Default::default(),
            verifier: verifier,
            verifier_state: Default::default(),
            aggregation_config: aggregation_config,
        })
    }

    fn new_from_serialized_config(
        serialized_aggregation_config: cxx::UniquePtr<cxx::CxxString>,
    ) -> Result<Self, StatusError> {
        let serialized_aggregation_config_proto = AggregationConfigProto::parse(
            serialized_aggregation_config.as_bytes(),
        )
        .map_err(|e| status::internal(format!("Failed to parse AggregationConfigProto: {}", e)))?;
        let aggregation_config =
            AggregationConfig::from_proto(serialized_aggregation_config_proto, ())?;
        Self::new(aggregation_config)
    }

    fn new_from_serialized_state(
        serialized_server_accumulator: cxx::UniquePtr<cxx::CxxString>,
    ) -> Result<Self, StatusError> {
        let serialized_server_accumulator_proto = ServerAccumulatorState::parse(
            serialized_server_accumulator.as_bytes(),
        )
        .map_err(|e| status::internal(format!("Failed to parse ServerAccumulatorState: {}", e)))?;
        Self::from_proto(serialized_server_accumulator_proto, ())
    }

    fn process_client_message(
        &mut self,
        client_message: ClientMessage<ShellKahe, ShellVahe>,
    ) -> Result<(), StatusError> {
        let (ciphertext_contribution, decryption_request_contribution) =
            self.server.split_client_message(client_message)?;
        // Create a copy of the server and verifier state. Only update the accumulator state if
        // processing succeededs all the way.
        let mut server_state = self.server_state.clone();
        let mut verifier_state = self.verifier_state.clone();
        self.verifier.verify_and_include(decryption_request_contribution, &mut verifier_state)?;
        self.server.handle_ciphertext_contribution(ciphertext_contribution, &mut server_state)?;
        self.server_state = server_state;
        self.verifier_state = verifier_state;
        Ok(())
    }

    // Processes a list of client messages. If an invalid message is encountered, an error is logged
    // and processing continues.
    pub fn process_client_messages(
        &mut self,
        mut client_messages: Vec<ClientMessage<ShellKahe, ShellVahe>>,
    ) -> () {
        client_messages.sort_by(|a, b| a.nonce.cmp(&b.nonce));
        for message in client_messages {
            if let Err(status) = self.process_client_message(message) {
                eprintln!("Failed to process client message: {}", status);
            }
        }
    }

    fn process_client_messages_serialized(
        &mut self,
        client_messages: cxx::UniquePtr<cxx::CxxString>,
    ) -> Result<(), StatusError> {
        let client_messages_proto = ClientMessageList::parse(client_messages.as_bytes())
            .map_err(|e| status::internal(format!("Failed to parse ClientMessageList: {}", e)))?;
        std::mem::drop(client_messages); // Release memory early. `client_messages` can be huge.
        let client_messages: Result<Vec<_>, _> = client_messages_proto
            .client_messages()
            .iter()
            .map(|m| ClientMessage::from_proto(m, &self.server))
            .collect();
        std::mem::drop(client_messages_proto);
        self.process_client_messages(client_messages?);
        Ok(())
    }

    // SAFETY:
    //   - `out_status_message` must not be null.
    pub unsafe fn process_client_messages_ffi(
        &mut self,
        client_messages: cxx::UniquePtr<cxx::CxxString>,
        out_status_message: *mut cxx::UniquePtr<cxx::CxxString>,
    ) -> i32 {
        match self.process_client_messages_serialized(client_messages) {
            Ok(()) => 0,
            Err(status_error) => {
                let ffi_status: FfiStatus = status_error.into();
                *out_status_message = ffi_status.message;
                ffi_status.code
            }
        }
    }

    pub fn merge(&mut self, other: Box<Self>) -> Result<(), StatusError> {
        if self.aggregation_config != other.aggregation_config {
            return Err(status::invalid_argument("Aggregation config mismatch"));
        }
        let server_state = std::mem::take(&mut self.server_state);
        let verifier_state = std::mem::take(&mut self.verifier_state);
        self.server_state = self.server.merge_states(server_state, other.server_state)?;
        self.verifier_state = self.verifier.merge_states(verifier_state, other.verifier_state)?;
        Ok(())
    }

    fn to_serialized_state(&self) -> Result<Vec<u8>, StatusError> {
        self.to_proto(())?.serialize().map_err(|e| {
            status::internal(format!("Failed to serialize ServerAccumulatorState: {}", e))
        })
    }

    // SAFETY:
    //   - `out_status_message` must not be null.
    pub unsafe fn merge_ffi(
        self: &mut ServerAccumulator,
        other: Box<ServerAccumulator>,
        out_status_message: *mut cxx::UniquePtr<cxx::CxxString>,
    ) -> i32 {
        match self.merge(other) {
            Ok(()) => 0,
            Err(status_error) => {
                let ffi_status: FfiStatus = status_error.into();
                *out_status_message = ffi_status.message;
                ffi_status.code
            }
        }
    }

    pub unsafe fn to_serialized_state_ffi(
        &self,
        out: *mut Vec<u8>,
        out_status_message: *mut cxx::UniquePtr<cxx::CxxString>,
    ) -> i32 {
        match self.to_serialized_state() {
            Ok(serialized_state) => {
                *out = serialized_state;
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

impl ToProto for ServerAccumulator {
    type Proto = ServerAccumulatorState;

    fn to_proto(&self, _context: ()) -> Result<Self::Proto, StatusError> {
        Ok(proto!(ServerAccumulatorState {
            server_state: self.server_state.to_proto(&self.server)?,
            verifier_state: self.verifier_state.to_proto(&self.verifier)?,
            aggregation_config: self.aggregation_config.to_proto(())?,
        }))
    }
}

impl FromProto for ServerAccumulator {
    type Proto = ServerAccumulatorState;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        _context: (),
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let aggregation_config = AggregationConfig::from_proto(proto.aggregation_config(), ())?;
        let mut result = Self::new(aggregation_config)?;
        result.server_state = ServerState::from_proto(proto.server_state(), &result.server)?;
        result.verifier_state =
            VerifierState::from_proto(proto.verifier_state(), &result.verifier)?;
        Ok(result)
    }
}

// SAFETY:
//   - `out` must not be null. It must be turned into a rust::Box on the C++ side.
//   - `out_status_message` must not be null.
unsafe fn new_server_accumulator_from_serialized_config(
    serialized_aggregation_config: cxx::UniquePtr<cxx::CxxString>,
    out: *mut *mut ServerAccumulator,
    out_status_message: *mut cxx::UniquePtr<cxx::CxxString>,
) -> i32 {
    match ServerAccumulator::new_from_serialized_config(serialized_aggregation_config) {
        Ok(server_accumulator) => {
            *out = Box::into_raw(Box::new(server_accumulator));
            0
        }
        Err(status_error) => {
            let ffi_status: FfiStatus = status_error.into();
            *out_status_message = ffi_status.message;
            ffi_status.code
        }
    }
}

// SAFETY:
//   - `out` must not be null. It must be turned into a rust::Box on the C++ side.
//   - `out_status_message` must not be null.
unsafe fn new_server_accumulator_from_serialized_state(
    serialized_server_accumulator: cxx::UniquePtr<cxx::CxxString>,
    out: *mut *mut ServerAccumulator,
    out_status_message: *mut cxx::UniquePtr<cxx::CxxString>,
) -> i32 {
    match ServerAccumulator::new_from_serialized_state(serialized_server_accumulator) {
        Ok(server_accumulator) => {
            *out = Box::into_raw(Box::new(server_accumulator));
            0
        }
        Err(status_error) => {
            let ffi_status: FfiStatus = status_error.into();
            *out_status_message = ffi_status.message;
            ffi_status.code
        }
    }
}

// SAFETY:
//   - `ptr` must have been created by Box::into_raw or one of the functions in this module.
unsafe fn into_box(ptr: *mut ServerAccumulator) -> Box<ServerAccumulator> {
    Box::from_raw(ptr)
}
