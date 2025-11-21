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

use kahe_traits::KaheBase;
use messages::{
    CiphertextContribution, ClientMessage, DecryptionRequestContribution, DecryptorPublicKey,
    DecryptorPublicKeyShare, PartialDecryptionResponse,
};
use status::StatusError;
use vahe_traits::VaheBase;

/// Base trait for the secure aggregation server. Also includes the Coordinator
/// functionality of the threshold AHE scheme.
///
pub trait SecureAggregationServer<Kahe: KaheBase, Vahe: VaheBase> {
    /// The state held by the server between messages.
    type ServerState: Default + Clone;
    /// The result of the aggregation.
    type AggregationResult;

    /// Handles a public key share received from a Decryptor, updating the
    /// server state.
    fn handle_decryptor_public_key_share(
        &self,
        key_share: DecryptorPublicKeyShare<Vahe>,
        server_state: &mut Self::ServerState,
    ) -> Result<(), StatusError>;

    /// Returns the public key to be sent to the client after enough shares have
    /// been received from Decryptors.
    fn create_decryptor_public_key(
        &self,
        server_state: &Self::ServerState,
    ) -> Result<DecryptorPublicKey<Vahe>, StatusError>;

    /// Splits a client message into the ciphertext contribution and the
    /// decryption request contribution.
    fn split_client_message(
        &self,
        client_message: ClientMessage<Kahe, Vahe>,
    ) -> Result<
        (CiphertextContribution<Kahe, Vahe>, DecryptionRequestContribution<Vahe>),
        StatusError,
    >;

    /// Handles a single client message, updating the server state.
    fn handle_ciphertext_contribution(
        &self,
        ciphertext_contribution: CiphertextContribution<Kahe, Vahe>,
        server_state: &mut Self::ServerState,
    ) -> Result<(), StatusError>;

    /// Handles a partial decryption received from a Decryptor, updating the
    /// server state.
    fn handle_partial_decryption(
        &self,
        partial_decryption_response: PartialDecryptionResponse<Vahe>,
        server_state: &mut Self::ServerState,
    ) -> Result<(), StatusError>;

    /// Recovers the aggregation result after enough partial decryptions have
    /// been received from Decryptors.
    fn recover_aggregation_result(
        &self,
        server_state: &Self::ServerState,
    ) -> Result<Self::AggregationResult, StatusError>;
}
