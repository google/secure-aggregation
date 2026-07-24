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

use kahe_traits::HasKahe;
use messages::{
    CiphertextContribution, ClientMessage, DecryptionRequestContribution,
    FinalizedPartialDecryption,
};
use status::StatusError;
use vahe_traits::HasVahe;

// Helper aliases for the generic types.
type Kahe<T> = <T as HasKahe>::Kahe;
type Vahe<T> = <T as HasVahe>::Vahe;

/// Base trait for the secure aggregation accumulator. Also includes the Coordinator
/// functionality of the threshold AHE scheme.
pub trait SecureAggregationCiphertextAccumulator: HasKahe + HasVahe {
    /// The state held by the accumulator between messages.
    type CiphertextAccumulatorState: Default + Clone;
    /// The result of the aggregation.
    type AggregationResult;

    /// Splits a client message into the ciphertext contribution and the
    /// decryption request contribution.
    fn split_client_message(
        &self,
        client_message: ClientMessage<Kahe<Self>, Vahe<Self>>,
    ) -> Result<
        (CiphertextContribution<Kahe<Self>, Vahe<Self>>, DecryptionRequestContribution<Vahe<Self>>),
        StatusError,
    >;

    /// Accumulates a single client ciphertext contribution into the accumulator state.
    fn accumulate_ciphertext_contribution(
        &self,
        ciphertext_contribution: CiphertextContribution<Kahe<Self>, Vahe<Self>>,
        accumulator_state: &mut Self::CiphertextAccumulatorState,
    ) -> Result<(), StatusError>;

    /// Recovers the aggregation result from the accumulated ciphertext contributions
    /// and the finalized partial decryption.
    fn recover_aggregation_result(
        &self,
        accumulator_state: &Self::CiphertextAccumulatorState,
        finalized_partial_decryption: &FinalizedPartialDecryption<Vahe<Self>>,
    ) -> Result<Self::AggregationResult, StatusError>;

    /// Merges two accumulator states into one.
    fn merge_states(
        &self,
        accumulator_state_1: Self::CiphertextAccumulatorState,
        accumulator_state_2: Self::CiphertextAccumulatorState,
    ) -> Result<Self::CiphertextAccumulatorState, StatusError>;
}
