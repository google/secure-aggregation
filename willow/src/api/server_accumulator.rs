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
use rangemap::RangeSet;
use server_accumulator_rust_proto::{ClientMessageRange, NonceRange, ServerAccumulatorState};
use server_traits::SecureAggregationServer;
use status::StatusError;
use std::collections::BTreeMap;
use std::ops::Range;
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
    // Server struct used to perform aggregation of client contributions.
    server: WillowV1Server<ShellKahe, ShellVahe>,
    // Server state containing the accumulated ciphertexts.
    server_state: ServerState<ShellKahe, ShellVahe>,
    // Verifier struct used to verify client contributions.
    verifier: WillowV1Verifier<ShellVahe>,
    // Verifier states, one for each range of nonces processed. The map is keyed by the start of the
    // range.
    verifier_states: BTreeMap<Vec<u8>, VerifierState<ShellVahe>>,
    // The set of ranges processed. Used to determine when verifier states of adjacent ranges can
    // be merged.
    ranges_processed: RangeSet<Vec<u8>>,
    // The aggregation config used to create this accumulator.
    aggregation_config: AggregationConfig,
}

impl ServerAccumulator {
    fn new(aggregation_config: AggregationConfig) -> Result<Self, StatusError> {
        let context_string = aggregation_config.compute_context_bytes()?;
        let vahe_config = create_shell_ahe_config(aggregation_config.max_number_of_decryptors)?;
        let kahe_config = create_shell_kahe_config(&aggregation_config)?;
        let server_kahe = ShellKahe::new(kahe_config, &context_string)?;
        let server_vahe = ShellVahe::new(vahe_config.clone(), &context_string)?;
        let verifier_vahe = ShellVahe::new(vahe_config, &context_string)?;
        let server = WillowV1Server { kahe: server_kahe, vahe: server_vahe };
        let verifier = WillowV1Verifier { vahe: verifier_vahe };
        Ok(Self {
            server: server,
            server_state: Default::default(),
            verifier: verifier,
            verifier_states: Default::default(),
            ranges_processed: Default::default(),
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

    // Updates the server and verifier states with the given client message. In case of error,
    // the states are UNDEFINED, and callers should not assume that they are in any particular state.
    fn process_client_message(
        &self,
        server_state: &mut ServerState<ShellKahe, ShellVahe>,
        verifier_state: &mut VerifierState<ShellVahe>,
        client_message: ClientMessage<ShellKahe, ShellVahe>,
    ) -> Result<(), StatusError> {
        let (ciphertext_contribution, decryption_request_contribution) =
            self.server.split_client_message(client_message)?;
        self.verifier.verify_and_include(decryption_request_contribution, verifier_state)?;
        self.server.handle_ciphertext_contribution(ciphertext_contribution, server_state)?;
        Ok(())
    }

    // Updates the given verifier states and ranges processed with the new verifier state and nonce
    // range. Merges verifier states if the nonce range is adjacent to a range already processed.
    // In case of error, `verifier_states` is unchanged, but `ranges_processed` may be in an
    // UNDEFINED state.
    fn merge_verifier_states(
        &self,
        verifier_states: &mut BTreeMap<Vec<u8>, VerifierState<ShellVahe>>,
        ranges_processed: &mut RangeSet<Vec<u8>>,
        mut new_verifier_state: VerifierState<ShellVahe>,
        nonce_range: Range<Vec<u8>>,
    ) -> Result<(), StatusError> {
        // Check if we can merge verifier ranges. To do that, we insert `nonce_range` into
        // `self.ranges_processed`. If the insertion increases the number of ranges, it means the
        // range is not adjacent to any range already processed, and we just insert
        // `new_verifier_state` into `self.verifier_states`. Otherwise, we need to merge with
        // existing verifier states.
        let num_ranges_before = ranges_processed.len();
        ranges_processed.insert(nonce_range.clone());
        if ranges_processed.len() > num_ranges_before {
            verifier_states.insert(nonce_range.start, new_verifier_state);
        } else {
            // Three possible cases: We merged with a range to the left, a range to the right, or
            // both.
            let merged_range = ranges_processed
                .get(&nonce_range.start)
                .ok_or(status::internal("Failed to retrieve range we just inserted"))?;
            let state_retrieval_error =
                status::internal("Failed to retrieve verifier state for merged range");
            if merged_range.start < nonce_range.start {
                // We merged with a range to the left. Get the existing verifier state and merge it
                // into `new_verifier_state`. The start of the existing range is equal to the start
                // of the merged range.
                let old_verifier_state = verifier_states
                    .get(&merged_range.start)
                    .ok_or(state_retrieval_error.clone())?;
                new_verifier_state =
                    self.verifier.merge_states(new_verifier_state, old_verifier_state.clone())?;
            }
            if merged_range.end > nonce_range.end {
                // We merged with a range to the right. Get the existing verifier state and merge it
                // into `new_verifier_state`. The start of the existing range is equal to the end of
                // `nonce_range`.
                let old_verifier_state =
                    verifier_states.get(&nonce_range.end).ok_or(state_retrieval_error)?;
                new_verifier_state =
                    self.verifier.merge_states(new_verifier_state, old_verifier_state.clone())?;
                // Remove the old range, since after this there are no more errors possible.
                verifier_states.remove(&nonce_range.end);
            }
            verifier_states.insert(merged_range.start.clone(), new_verifier_state);
        }
        Ok(())
    }

    // Processes a list of client messages. If an invalid message is encountered, an error is logged
    // and processing continues. However, if a message is out of range, processing stops and an
    // error is returned immediately.
    pub fn process_client_messages(
        &mut self,
        mut client_messages: Vec<ClientMessage<ShellKahe, ShellVahe>>,
        nonce_range: Range<Vec<u8>>,
    ) -> Result<(), StatusError> {
        client_messages.sort_by(|a, b| a.nonce.cmp(&b.nonce));
        // Check that `nonce_range` does not overlap with any range already processed.
        if self.ranges_processed.overlaps(&nonce_range) {
            return Err(status::invalid_argument(format!(
                "Invalid nonce range: [{:?}, {:?}) overlaps with already processed range",
                nonce_range.start, nonce_range.end,
            )));
        }

        // Insert client messages into a new server and verifier state.
        let mut new_verifier_state = VerifierState::default();
        let mut new_server_state = ServerState::default();
        for message in client_messages {
            if message.nonce < nonce_range.start || message.nonce >= nonce_range.end {
                // Return immediately in case a message is out of range.
                return Err(status::invalid_argument(format!(
                    "Invalid nonce: {:?} outside of range [{:?}, {:?})",
                    message.nonce, nonce_range.start, nonce_range.end,
                )));
            }
            let old_server_state = new_server_state.clone();
            let old_verifier_state = new_verifier_state.clone();
            if let Err(status) =
                self.process_client_message(&mut new_server_state, &mut new_verifier_state, message)
            {
                // Restore previous states on error, so we can continue processing messages.
                new_server_state = old_server_state;
                new_verifier_state = old_verifier_state;
                eprintln!("Failed to process client message: {}", status);
            }
        }

        // Merge new states into `self`.
        let new_server_state =
            self.server.merge_states(self.server_state.clone(), new_server_state)?;
        let mut new_ranges_processed = self.ranges_processed.clone();
        let mut verifier_states = std::mem::take(&mut self.verifier_states);
        if let Err(status) = self.merge_verifier_states(
            &mut verifier_states,      // Unchanged in case of error.
            &mut new_ranges_processed, // Undefined in case of error.
            new_verifier_state,
            nonce_range,
        ) {
            // Restore (unchanged) verifier states.
            self.verifier_states = verifier_states;
            return Err(status);
        }
        self.ranges_processed = new_ranges_processed;
        self.server_state = new_server_state;
        self.verifier_states = verifier_states;
        Ok(())
    }

    fn process_client_messages_serialized(
        &mut self,
        client_messages: cxx::UniquePtr<cxx::CxxString>,
    ) -> Result<(), StatusError> {
        let client_range_proto = ClientMessageRange::parse(client_messages.as_bytes())
            .map_err(|e| status::internal(format!("Failed to parse ClientMessageRange: {}", e)))?;
        std::mem::drop(client_messages); // Release memory early. `client_messages` can be huge.
        if !client_range_proto.client_messages().is_empty() {
            let client_messages: Result<Vec<_>, _> = client_range_proto
                .client_messages()
                .iter()
                .map(|m| ClientMessage::from_proto(m, &self.server))
                .collect();
            let nonce_range = nonce_range_from_proto(client_range_proto.nonce_range())?;
            std::mem::drop(client_range_proto);
            self.process_client_messages(client_messages?, nonce_range)?;
        }
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

    // Atomically merges the other accumulator into `self`.
    // On error, `self` is left unchanged.
    pub fn merge(&mut self, other: Box<Self>) -> Result<(), StatusError> {
        if self.aggregation_config != other.aggregation_config {
            return Err(status::invalid_argument("Aggregation config mismatch"));
        }
        let num_states = other.verifier_states.len();
        if other.ranges_processed.len() != num_states {
            return Err(status::internal(
                "The number of verifier states must match the number of processed nonce ranges",
            ));
        }
        let mut nonce_ranges = vec![];
        nonce_ranges.reserve(num_states);
        let mut verifier_states = vec![];
        verifier_states.reserve(num_states);
        for (nonce_range, (nonce_range_start, verifier_state)) in
            std::iter::zip(other.ranges_processed, other.verifier_states)
        {
            if nonce_range.start != nonce_range_start {
                // This should not happen on properly constructed accumulators, since the order of
                // iteration over BTreeMap is by ascending key, same as RangeSet.
                return Err(status::internal(format!(
                    "Nonce range mismatch: range starts at {:?}, but verifier state indexed by {:?}",
                    nonce_range.start, nonce_range_start,
                )));
            }
            if self.ranges_processed.overlaps(&nonce_range) {
                return Err(status::invalid_argument(format!(
                    "Invalid nonce range: [{:?}, {:?}) overlaps with already processed range",
                    nonce_range.start, nonce_range.end,
                )));
            }
            nonce_ranges.push(nonce_range);
            verifier_states.push(verifier_state);
        }

        let new_server_state =
            self.server.merge_states(self.server_state.clone(), other.server_state)?;
        // Back up states of `self`, to restore on error.
        let mut new_verifier_states = self.verifier_states.clone();
        let mut new_ranges_processed = self.ranges_processed.clone();
        for (nonce_range, verifier_state) in std::iter::zip(nonce_ranges, verifier_states) {
            self.merge_verifier_states(
                &mut new_verifier_states,
                &mut new_ranges_processed,
                verifier_state,
                nonce_range,
            )?;
        }
        self.server_state = new_server_state;
        self.ranges_processed = new_ranges_processed;
        self.verifier_states = new_verifier_states;

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

fn nonce_range_from_proto(
    proto: impl AsView<Proxied = NonceRange>,
) -> Result<Range<Vec<u8>>, StatusError> {
    let proto = proto.as_view();
    if proto.start() >= proto.end() {
        return Err(status::invalid_argument(format!(
            "Invalid nonce range: {:?} >= {:?}",
            proto.start(),
            proto.end(),
        )));
    }
    Ok(proto.start().to_vec()..proto.end().to_vec())
}

impl ToProto for ServerAccumulator {
    type Proto = ServerAccumulatorState;

    fn to_proto(&self, _context: ()) -> Result<Self::Proto, StatusError> {
        let mut out = proto!(ServerAccumulatorState {
            server_state: self.server_state.to_proto(&self.server)?,
            aggregation_config: self.aggregation_config.to_proto(())?,
        });
        for verifier_state in self.verifier_states.values() {
            out.verifier_states_mut().push(verifier_state.to_proto(&self.verifier)?);
        }
        for range in self.ranges_processed.iter() {
            out.processed_nonce_ranges_mut()
                .push(proto!(NonceRange { start: range.start.clone(), end: range.end.clone() }));
        }
        Ok(out)
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
        if proto.processed_nonce_ranges().len() != proto.verifier_states().len() {
            return Err(status::invalid_argument(
                "The number of verifier states must match the number of processed nonce ranges",
            ));
        }
        result.verifier_states = BTreeMap::new();
        result.ranges_processed = RangeSet::new();
        for (verifier_state_proto, nonce_range_proto) in
            std::iter::zip(proto.verifier_states().iter(), proto.processed_nonce_ranges().iter())
        {
            let range = nonce_range_from_proto(nonce_range_proto)?;
            result.ranges_processed.insert(range);
            let verifier_state = VerifierState::from_proto(verifier_state_proto, &result.verifier)?;
            result.verifier_states.insert(nonce_range_proto.start().to_vec(), verifier_state);
            // Check that range insertion indeed added another range that didn't overlap.
            if result.ranges_processed.len() != result.verifier_states.len() {
                return Err(status::invalid_argument(format!(
                    "Invalid range: [{:?}, {:?}) either overlaps or is adjacent to another range",
                    nonce_range_proto.start(),
                    nonce_range_proto.end()
                )));
            }
        }
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
