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

use ahe_traits::AheBase;
use kahe_traits::KaheBase;
use messages::{
    DecryptorPublicKey, DecryptorPublicKeyShare, FinalizedPartialDecryption,
    PartialDecryptionRequest, PartialDecryptionResponse, RecoveryRequest, RecoveryResponse,
    SetupContribution, VerifyKeyContributionsRequest,
};
use status::StatusError;
use vahe_traits::HasVahe;

/// Base trait for the Decryptor.
pub trait SecureAggregationDecryptor: HasVahe {
    /// The state held by the Decryptor between messages.
    type DecryptorState: Default;

    /// Creates a public key share to be sent to the Server, updating the
    /// decryptor state.
    fn create_public_key_share(
        &self,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<DecryptorPublicKeyShare<<Self as HasVahe>::Vahe>, StatusError>;

    type Kahe: KaheBase;

    /// Handles a partial decryption request received from the Server. Returns a
    /// partial decryption to the Server.
    fn handle_partial_decryption_request(
        &self,
        partial_decryption_request: PartialDecryptionRequest<<Self as HasVahe>::Vahe>,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<PartialDecryptionResponse<Self::Kahe, <Self as HasVahe>::Vahe>, StatusError>;
}

/// Trait for reputable/non-recoverable decryptors (e.g. TEEs) in a multi-decryptor committee.
pub trait SecureAggregationBaseMultiDecryptor: HasVahe {
    /// The state held by the Decryptor between messages.
    type DecryptorState: Default;

    /// Creates a public key share, a ZK proof of knowledge of the secret key,
    /// and encrypted shares of the randomness used for key generation.
    ///
    /// The randomness shares are encrypted for other committee members.
    fn create_setup_contribution(
        &self,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<SetupContribution<Self::Vahe>, StatusError>;

    /// Handles a partial decryption request received from the Server. Returns a
    /// partial decryption to the Server.
    fn handle_partial_decryption_request<Kahe: KaheBase>(
        &self,
        partial_decryption_request: PartialDecryptionRequest<<Self as HasVahe>::Vahe>,
        kahe: Option<&Kahe>,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<PartialDecryptionResponse<Kahe, <Self as HasVahe>::Vahe>, StatusError>;
}

/// Trait for the reputable decryptors in a multi-decryptor committee.
///
/// Reputable decryptors are assumed to be stable and do not share their
/// randomness for recovery.
pub trait SecureAggregationReputableDecryptor: SecureAggregationBaseMultiDecryptor {
    /// Verifies the ZK proofs of knowledge of the secret key for all public key
    /// shares, and returns the aggregated public key. Calling code should sign
    /// the aggregated public key for the aggregation.
    ///
    /// Note: This method fails if any single contribution has an invalid proof,
    /// aborting the entire key generation. This is acceptable because the
    /// protocol does not guarantee output delivery against malicious decryptors
    /// or a malicious coordinator — a malicious participant could equally cause
    /// failure by refusing to provide partial decryptions and secret-sharing an
    /// invalid state in the setup contribution.
    fn verify_and_aggregate_key_contributions(
        &self,
        request: VerifyKeyContributionsRequest<<Self as HasVahe>::Vahe>,
    ) -> Result<DecryptorPublicKey<<Self as HasVahe>::Vahe>, StatusError>;
}

/// Trait for the non-reputable decryptors in a multi-decryptor committee.
pub trait SecureAggregationNonReputableMultiDecryptor: SecureAggregationBaseMultiDecryptor {
    /// Handles a request to decrypt shares of dropped decryptors.
    ///
    /// The decryptor should verify they are not being asked to decrypt more than
    /// the allowed threshold of shares.
    fn handle_recovery_request(
        &self,
        recovery_request: RecoveryRequest,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<RecoveryResponse, StatusError>;
}
