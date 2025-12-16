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

// This is the API for Willow verifiers.
//
// Each function except for VerifyContribution should be called once by the verifier. The
// VerifyContribution function should be called by the verifier once for each client contribution.
//
// If a verifier function returns an error, that error can be logged and the aggregation should be
// considered to have failed.

use aggregation_config::AggregationConfig;
use aggregation_config_rust_proto::{
    VerificationRequest, VerificationResponse, VerificationSummaryRequest,
    VerificationSummaryResponse,
};

pub struct Verifier {}

pub struct VerifierState {}

impl VerifierState {
    fn serialize() -> Vec<u8> {
        unimplemented!()
    }

    fn deserialize(serialized: &[u8]) -> Result<VerifierState, status::StatusError> {
        unimplemented!()
    }
}

pub trait VerifierAPI {
    /// Initializes the verifier at the beginning of an aggregation.
    /// Returns the verifier state to be used for subsequent calls to the verifier.
    /// config: The configuration of the aggregation.
    fn initialize_verifier(config: AggregationConfig)
        -> Result<VerifierState, status::StatusError>;

    /// Run by the verifier to process the verification of client contributions.
    /// The proofs are checked for correctness. The output is a vector of bools indicating whether
    /// each contribution was valid. Note this function can be called multiple times with different
    /// contributions if processing all contributions isn't possible in one call.
    /// verifier_state: The state of the verifier which will be updated.
    /// client_contributions: The contributions to be processed.
    fn verify_contributions(
        verifier_state: &mut VerifierState,
        client_contribution: VerificationRequest,
    ) -> Result<VerificationResponse, status::StatusError>;

    /// Run by the verifier once all client contributions have been processed.
    /// Returns the decryption request to be sent to the decryptors.
    /// verifier_state: The state of the verifier which will be updated.
    /// request: This carries no information except that a verification summary is wanted.
    fn handle_verification_summary_request(
        verifier_state: &mut VerifierState,
        request: VerificationSummaryRequest,
    ) -> Result<VerificationSummaryResponse, status::StatusError>;
}
