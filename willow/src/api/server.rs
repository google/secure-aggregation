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

// This is the API for Willow servers.
//
// Each function except for ProcessContribution should be called once by the server. The
// ProcessContribution function should be called by the server once for each client contribution.
//
// If a server function returns an error, that error can be logged and the aggregation should be
// considered to have failed.

use aggregation_config::AggregationConfig;
use aggregation_config_rust_proto::{
    Contribution, ContributionToServer, ContributionToVerifier, DecryptionRequest,
    DecryptionResponse, DropoutRecoveryRequest, KeyGenRequest,
};

pub struct Server {}

pub struct ServerState {}

impl ServerState {
    fn serialize() -> Vec<u8> {
        unimplemented!()
    }

    fn deserialize(serialized: &[u8]) -> Result<ServerState, status::StatusError> {
        unimplemented!()
    }
}

pub trait ServerAPI {
    /// Initializes the server at the beginning of an aggregation.
    /// Returns the server state to be used for subsequent calls to the server and a KeyGenRequest.
    /// config: The configuration of the aggregation.
    fn initialize_server(
        config: AggregationConfig,
    ) -> Result<(ServerState, KeyGenRequest), status::StatusError>;

    /// Run by the server to process the parts of the client input that aren't used for
    /// verification.
    /// If any contribution given here is invalid, the aggregation will have to
    /// be aborted.
    /// server_state: The state of the server which will be updated.
    /// client_contributions: The contributions to be processed.
    fn handle_contributions(
        server_state: &mut ServerState,
        client_contributions: &[ContributionToServer],
    ) -> Result<(), status::StatusError>;

    /// Run by the server to process the partial decryptions from the decryptors.
    /// If no dropouts have occurred returns None. Otherwise returns a request for the
    /// decryptors to recover the dropouts.
    /// Always returns None or an error in the single decryptor case.
    /// server_state: The state of the server which will be updated.
    /// decryption_responses: The partial decryption information from the decryptors.
    fn handle_decryption_responses(
        server_state: &mut ServerState,
        decryption_responses: &[DecryptionResponse],
    ) -> Result<Option<DropoutRecoveryRequest>, status::StatusError>;

    /// Run by the server to generate the output of the aggregation.
    /// server_state: The state of the server which will be updated.
    fn generate_output(server_state: &mut ServerState) -> Result<Vec<i64>, status::StatusError>;
}
