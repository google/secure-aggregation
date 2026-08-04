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

use accumulator_traits::CiphertextAccumulator;
use aggregation_config::AggregationConfig;
use aggregation_config_rust_proto::AggregationConfigProto;
use ahe_traits::AheBase;
use default_accumulator::{CiphertextAccumulatorState, DefaultCiphertextAccumulator};
use default_verifier::{DefaultVerifier, VerifierState};
use kahe_traits::KaheBase;
use messages::{ClientMessage, FinalizedPartialDecryption, PartialDecryptionResponse};
use messages_rust_proto::PartialDecryptionResponse as PartialDecryptionResponseProto;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use protobuf::AsView;
use rangemap::RangeSet;
use server_accumulator_rust_proto::{
    ClientMessageRange, FinalResultDecryptorState, NonceRange, ServerAccumulatorState,
};
use shell_kahe::ShellKahe;
use shell_parameters::create_shell_configs;
use shell_vahe::ShellVahe;
use status::StatusError;
use std::collections::BTreeMap;
use std::ops::Range;
use std::rc::Rc;
use verifier_traits::Verifier;

#[cxx::bridge(namespace = "secure_aggregation")]
pub mod ffi {

    // CXX requires shared structs to be defined in the same module.
    struct EncodedDataEntry {
        key: String,
        values: Vec<u64>,
    }

    // Re-define FfiStatus since CXX requires shared structs to be defined in the same module
    // (https://github.com/dtolnay/cxx/issues/297#issuecomment-727042059)
    unsafe extern "C++" {
        include!("ffi_utils/status.rs.h");
        type FfiStatus = status::ffi::FfiStatus;
    }

    extern "Rust" {
        type ServerAccumulator;

        // SAFETY: All functions in this module are only called from the wrapping C++ library,
        //   ensuring that output pointers are correctly wrapped by a rust::Box, and that pointer
        //   arguments are not null.

        #[cxx_name = "NewServerAccumulatorFromSerializedConfig"]
        unsafe fn new_server_accumulator_from_serialized_config(
            serialized_aggregation_config: UniquePtr<CxxString>,
            out: *mut *mut ServerAccumulator,
        ) -> FfiStatus;

        #[cxx_name = "NewServerAccumulatorFromSerializedState"]
        unsafe fn new_server_accumulator_from_serialized_state(
            serialized_server_accumulator: UniquePtr<CxxString>,
            out: *mut *mut ServerAccumulator,
        ) -> FfiStatus;

        #[cxx_name = "ProcessClientMessages"]
        fn process_client_messages_ffi(
            self: &mut ServerAccumulator,
            client_messages: UniquePtr<CxxString>,
        ) -> FfiStatus;

        #[cxx_name = "ToSerializedState"]
        unsafe fn to_serialized_state_ffi(self: &ServerAccumulator, out: *mut Vec<u8>)
            -> FfiStatus;

        #[cxx_name = "Merge"]
        fn merge_ffi(self: &mut ServerAccumulator, other: Box<ServerAccumulator>) -> FfiStatus;

        #[cxx_name = "IntoBox"]
        unsafe fn into_box(ptr: *mut ServerAccumulator) -> Box<ServerAccumulator>;

        type FinalResultDecryptor;

        #[cxx_name = "FinalizeServerAccumulator"]
        unsafe fn finalize_accumulator_ffi(
            accumulator: Box<ServerAccumulator>,
            out_decryption_request: *mut Vec<u8>,
            out_final_result_decryptor_state: *mut Vec<u8>,
        ) -> FfiStatus;

        #[cxx_name = "Decrypt"]
        unsafe fn decrypt_ffi(
            self: &mut FinalResultDecryptor,
            serialized_partial_decryption_response: UniquePtr<CxxString>,
            out: *mut Vec<EncodedDataEntry>,
        ) -> FfiStatus;

        #[cxx_name = "CreateFinalResultDecryptorFromSerialized"]
        unsafe fn create_final_result_decryptor_from_serialized(
            serialized_final_result_decryptor_state: UniquePtr<CxxString>,
            out: *mut *mut FinalResultDecryptor,
        ) -> FfiStatus;

        #[cxx_name = "FinalResultDecryptorIntoBox"]
        unsafe fn final_result_decryptor_into_box(
            ptr: *mut FinalResultDecryptor,
        ) -> Box<FinalResultDecryptor>;
    }
}

pub struct ServerAccumulator {
    // Accumulator struct used to perform aggregation of client contributions.
    accumulator: DefaultCiphertextAccumulator<ShellKahe, ShellVahe>,
    // Accumulator state containing the accumulated ciphertexts.
    accumulator_state: CiphertextAccumulatorState<ShellKahe, ShellVahe>,
    // Verifier struct used to verify client contributions.
    verifier: DefaultVerifier<ShellVahe>,
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
        let (kahe_config, vahe_config) = create_shell_configs(&aggregation_config)?;
        let context_bytes = &aggregation_config.key_id;
        let kahe = Rc::new(ShellKahe::new(kahe_config, &context_bytes)?);
        let vahe = Rc::new(ShellVahe::new(vahe_config, &context_bytes)?);
        let accumulator =
            DefaultCiphertextAccumulator { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
        let verifier = DefaultVerifier { vahe };
        Ok(Self {
            accumulator,
            accumulator_state: Default::default(),
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
        .map_err(|e| status::internal(&format!("Failed to parse AggregationConfigProto: {}", e)))?;
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
        .map_err(|e| status::internal(&format!("Failed to parse ServerAccumulatorState: {}", e)))?;
        Self::from_proto(serialized_server_accumulator_proto, ())
    }

    // Updates the accumulator and verifier states with the given client message. In case of error,
    // the states are UNDEFINED, and callers should not assume that they are in any particular state.
    fn process_client_message(
        &self,
        accumulator_state: &mut CiphertextAccumulatorState<ShellKahe, ShellVahe>,
        verifier_state: &mut VerifierState<ShellVahe>,
        client_message: ClientMessage<ShellKahe, ShellVahe>,
    ) -> Result<(), StatusError> {
        let (ciphertext_contribution, decryption_request_contribution) =
            self.accumulator.split_client_message(client_message)?;
        self.verifier.verify_and_include(decryption_request_contribution, verifier_state)?;
        self.accumulator
            .accumulate_ciphertext_contribution(ciphertext_contribution, accumulator_state)?;
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
            return Err(status::invalid_argument(&format!(
                "Invalid nonce range: [{:?}, {:?}) overlaps with already processed range",
                nonce_range.start, nonce_range.end,
            )));
        }

        // Insert client messages into a new accumulator and verifier state.
        let mut new_verifier_state = VerifierState::default();
        let mut new_accumulator_state = CiphertextAccumulatorState::default();
        // The nonce range boundaries are derived from the random suffix of the
        // nonce (i.e., without the 4-byte timestamp prefix). To compare message
        // nonces against these boundaries, we strip the same prefix.
        const TIMESTAMP_PREFIX_SIZE: usize = 4;
        for message in client_messages {
            let nonce_suffix = if message.nonce.len() > TIMESTAMP_PREFIX_SIZE {
                &message.nonce[TIMESTAMP_PREFIX_SIZE..]
            } else {
                &message.nonce[..]
            };
            if nonce_suffix < nonce_range.start.as_slice()
                || nonce_suffix >= nonce_range.end.as_slice()
            {
                // Return immediately in case a message is out of range.
                return Err(status::invalid_argument(&format!(
                    "Invalid nonce: {:?} outside of range [{:?}, {:?})",
                    message.nonce, nonce_range.start, nonce_range.end,
                )));
            }
            let old_accumulator_state = new_accumulator_state.clone();
            let old_verifier_state = new_verifier_state.clone();
            if let Err(status) = self.process_client_message(
                &mut new_accumulator_state,
                &mut new_verifier_state,
                message,
            ) {
                // Restore previous states on error, so we can continue processing messages.
                new_accumulator_state = old_accumulator_state;
                new_verifier_state = old_verifier_state;
                eprintln!("Failed to process client message: {}", status);
            }
        }

        // Merge new states into `self`.
        let new_accumulator_state =
            self.accumulator.merge_states(self.accumulator_state.clone(), new_accumulator_state)?;
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
        self.accumulator_state = new_accumulator_state;
        self.verifier_states = verifier_states;
        Ok(())
    }

    fn process_client_messages_serialized(
        &mut self,
        client_messages: cxx::UniquePtr<cxx::CxxString>,
    ) -> Result<(), StatusError> {
        let client_range_proto = ClientMessageRange::parse(client_messages.as_bytes())
            .map_err(|e| status::internal(&format!("Failed to parse ClientMessageRange: {}", e)))?;
        std::mem::drop(client_messages); // Release memory early. `client_messages` can be huge.
        if !client_range_proto.client_messages().is_empty() {
            let client_messages: Result<Vec<_>, _> = client_range_proto
                .client_messages()
                .iter()
                .map(|m| ClientMessage::from_proto(m, &self.accumulator))
                .collect();
            let nonce_range = nonce_range_from_proto(client_range_proto.nonce_range())?;
            std::mem::drop(client_range_proto);
            self.process_client_messages(client_messages?, nonce_range)?;
        }
        Ok(())
    }

    pub fn process_client_messages_ffi(
        &mut self,
        client_messages: cxx::UniquePtr<cxx::CxxString>,
    ) -> ffi::FfiStatus {
        self.process_client_messages_serialized(client_messages).into()
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
                return Err(status::internal(&format!(
                    "Nonce range mismatch: range starts at {:?}, but verifier state indexed by {:?}",
                    nonce_range.start, nonce_range_start,
                )));
            }
            if self.ranges_processed.overlaps(&nonce_range) {
                return Err(status::invalid_argument(&format!(
                    "Invalid nonce range: [{:?}, {:?}) overlaps with already processed range",
                    nonce_range.start, nonce_range.end,
                )));
            }
            nonce_ranges.push(nonce_range);
            verifier_states.push(verifier_state);
        }

        let new_accumulator_state = self
            .accumulator
            .merge_states(self.accumulator_state.clone(), other.accumulator_state)?;
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
        self.accumulator_state = new_accumulator_state;
        self.ranges_processed = new_ranges_processed;
        self.verifier_states = new_verifier_states;

        Ok(())
    }

    fn to_serialized_state(&self) -> Result<Vec<u8>, StatusError> {
        self.to_proto(())?.serialize().map_err(|e| {
            status::internal(&format!("Failed to serialize ServerAccumulatorState: {}", e))
        })
    }

    pub fn merge_ffi(
        self: &mut ServerAccumulator,
        other: Box<ServerAccumulator>,
    ) -> ffi::FfiStatus {
        self.merge(other).into()
    }

    /// SAFETY: `out` must be valid for writes.
    pub unsafe fn to_serialized_state_ffi(&self, out: *mut Vec<u8>) -> ffi::FfiStatus {
        self.to_serialized_state().map(|result| unsafe { *out = result }).into()
    }
}

fn nonce_range_from_proto(
    proto: impl AsView<Proxied = NonceRange>,
) -> Result<Range<Vec<u8>>, StatusError> {
    let proto = proto.as_view();
    if proto.start() >= proto.end() {
        return Err(status::invalid_argument(&format!(
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
            server_state: self.accumulator_state.to_proto(&self.accumulator)?,
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
        result.accumulator_state =
            CiphertextAccumulatorState::from_proto(proto.server_state(), &result.accumulator)?;
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
                return Err(status::invalid_argument(&format!(
                    "Invalid range: [{:?}, {:?}) either overlaps or is adjacent to another range",
                    nonce_range_proto.start(),
                    nonce_range_proto.end()
                )));
            }
        }
        Ok(result)
    }
}

/// SAFETY: `out` must be valid for writes. It must be turned into a rust::Box on the C++ side.
unsafe fn new_server_accumulator_from_serialized_config(
    serialized_aggregation_config: cxx::UniquePtr<cxx::CxxString>,
    out: *mut *mut ServerAccumulator,
) -> ffi::FfiStatus {
    ServerAccumulator::new_from_serialized_config(serialized_aggregation_config)
        .map(|result| unsafe { *out = Box::into_raw(Box::new(result)) })
        .into()
}

/// SAFETY: `out` must be valid for writes. It must be turned into a rust::Box on the C++ side.
unsafe fn new_server_accumulator_from_serialized_state(
    serialized_server_accumulator: cxx::UniquePtr<cxx::CxxString>,
    out: *mut *mut ServerAccumulator,
) -> ffi::FfiStatus {
    ServerAccumulator::new_from_serialized_state(serialized_server_accumulator)
        .map(|result| unsafe { *out = Box::into_raw(Box::new(result)) })
        .into()
}

// SAFETY:
//   - `ptr` must have been created by Box::into_raw or one of the functions in this module.
unsafe fn into_box(ptr: *mut ServerAccumulator) -> Box<ServerAccumulator> {
    unsafe { Box::from_raw(ptr) }
}

/// SAFETY:
///   - `ptr` must have been created by Box::into_raw or one of the functions in this module.
unsafe fn final_result_decryptor_into_box(
    ptr: *mut FinalResultDecryptor,
) -> Box<FinalResultDecryptor> {
    unsafe { Box::from_raw(ptr) }
}

/// Final result decryptor.
pub struct FinalResultDecryptor {
    /// Contains aggregated KAHE ciphertexts and aggregated AHE recover ciphertexts (ct_0)
    ///
    /// NOTE: We technically only need client_sum, not decryptor_public_key_shares or
    /// partial_decryption_sum, but because of the monolithic SecureAggregationServer trait
    /// (b/476137863) we need a complete CiphertextAccumulatorState to call the decryption functions.
    accumulator_state: CiphertextAccumulatorState<ShellKahe, ShellVahe>,

    /// Accumulator used to hold the necessary KAHE and AHE contexts.
    accumulator: DefaultCiphertextAccumulator<ShellKahe, ShellVahe>,
}

fn finalize_accumulator(accumulator: ServerAccumulator) -> Result<(Vec<u8>, Vec<u8>), StatusError> {
    // Consume and merge all verifier states into one.
    let mut final_verifier_state = VerifierState::default();
    let verifier_states = accumulator.verifier_states;
    for (_, verifier_state) in verifier_states.into_iter() {
        final_verifier_state =
            accumulator.verifier.merge_states(verifier_state, final_verifier_state)?;
    }

    // Use merged verifier to prepare partial decryption request (i.e. sum of AHE ct_1 ciphertexts)
    // The decryption service expects a serialized PartialDecryptionRequestProto
    // (https://github.com/google-parfait/trusted-computations-platform/blob/60804e2364ad789cf0682d19d5957dba5d076553/apps/willow/decryptor/actor/src/actor.rs#L290)
    let partial_decryption_request =
        accumulator.verifier.create_partial_decryption_request(final_verifier_state)?;
    let serialized_decryption_request = partial_decryption_request
        .to_proto(&accumulator.accumulator)?
        .serialize()
        .map_err(|e| status::internal(&format!("Failed to serialize: {}", e)))?;

    // Extract the accumulator state (i.e. sum of KAHE ciphertexts and sum of AHE ct_0 ciphertexts).
    let accumulator_state_proto =
        accumulator.accumulator_state.to_proto(&accumulator.accumulator)?;
    let aggregation_config_proto = accumulator.aggregation_config.to_proto(())?;
    let final_result_decryptor_state = proto!(FinalResultDecryptorState {
        server_state: accumulator_state_proto,
        aggregation_config: aggregation_config_proto,
    });
    let serialized_final_result_decryptor_state = final_result_decryptor_state
        .serialize()
        .map_err(|e| status::internal(&format!("Failed to serialize: {}", e)))?;

    Ok((serialized_decryption_request, serialized_final_result_decryptor_state))
}

/// SAFETY: all pointer arguments (`out_decryption_request`, `out_final_result_decryptor_state`)
/// must be valid for writes.
pub unsafe fn finalize_accumulator_ffi(
    accumulator: Box<ServerAccumulator>,
    out_decryption_request: *mut Vec<u8>,
    out_final_result_decryptor_state: *mut Vec<u8>,
) -> ffi::FfiStatus {
    finalize_accumulator(*accumulator)
        .map(|(decryption_request, final_result_decryptor_state)| unsafe {
            *out_decryption_request = decryption_request;
            *out_final_result_decryptor_state = final_result_decryptor_state;
        })
        .into()
}

impl FinalResultDecryptor {
    fn new_from_serialized(
        serialized_proto: cxx::UniquePtr<cxx::CxxString>,
    ) -> Result<Self, StatusError> {
        // Parse aggregation config and accumulator state protos.
        let final_result_decryptor_state_proto =
            FinalResultDecryptorState::parse(serialized_proto.as_bytes()).map_err(|e| {
                status::internal(&format!("Failed to parse FinalResultDecryptorState: {}", e))
            })?;
        let accumulator_state_proto = final_result_decryptor_state_proto.server_state();
        let aggregation_config_proto = final_result_decryptor_state_proto.aggregation_config();

        // Build accumulator that holds the necessary KAHE and AHE contexts, and recover accumulator state.
        let aggregation_config = AggregationConfig::from_proto(aggregation_config_proto, ())?;
        let (kahe_config, vahe_config) = create_shell_configs(&aggregation_config)?;
        let context_bytes = &aggregation_config.key_id;
        let kahe = Rc::new(ShellKahe::new(kahe_config, context_bytes)?);
        let vahe = Rc::new(ShellVahe::new(vahe_config, context_bytes)?);
        let accumulator = DefaultCiphertextAccumulator { kahe, vahe };
        let accumulator_state =
            CiphertextAccumulatorState::from_proto(accumulator_state_proto, &accumulator)?;

        Ok(FinalResultDecryptor { accumulator_state, accumulator })
    }

    fn decrypt(
        &mut self,
        serialized_partial_decryption_response: cxx::UniquePtr<cxx::CxxString>,
    ) -> Result<Vec<ffi::EncodedDataEntry>, StatusError> {
        let pd_proto = PartialDecryptionResponseProto::parse(
            serialized_partial_decryption_response.as_bytes(),
        )
        .map_err(|e| {
            status::internal(&format!("Failed to parse PartialDecryptionResponse: {}", e))
        })?;
        let pd = PartialDecryptionResponse::from_proto(pd_proto, &self.accumulator)?;

        // Receives a single partial decryption response and attempts to recover right away.
        // This only works in the single-decryptor case.
        let finalized_pd =
            FinalizedPartialDecryption { partial_decryption_sum: pd.partial_decryption };
        let aggregation_result =
            self.accumulator.recover_aggregation_result(&self.accumulator_state, &finalized_pd)?;

        // `aggregation_result` is a Kahe::Plaintext, i.e. HashMap<String, Vec<u64>>
        // Flatten hashmap for FFI like in shell_testing_decryptor.rs
        let entries = aggregation_result
            .into_iter()
            .map(|(key, values)| ffi::EncodedDataEntry { key, values })
            .collect();
        Ok(entries)
    }

    /// SAFETY: `out` must be valid for writes.
    pub unsafe fn decrypt_ffi(
        &mut self,
        serialized_partial_decryption_response: cxx::UniquePtr<cxx::CxxString>,
        out: *mut Vec<ffi::EncodedDataEntry>,
    ) -> ffi::FfiStatus {
        self.decrypt(serialized_partial_decryption_response)
            .map(|result| unsafe { *out = result })
            .into()
    }
}

/// SAFETY: `out` must be valid for writes.
unsafe fn create_final_result_decryptor_from_serialized(
    serialized_proto: cxx::UniquePtr<cxx::CxxString>,
    out: *mut *mut FinalResultDecryptor,
) -> ffi::FfiStatus {
    FinalResultDecryptor::new_from_serialized(serialized_proto)
        .map(|result| unsafe { *out = Box::into_raw(Box::new(result)) })
        .into()
}
