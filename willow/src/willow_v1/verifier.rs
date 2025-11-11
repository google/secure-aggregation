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

use ahe_traits::AheBase;
use kahe_traits::KaheBase;
use vahe_traits::{EncryptVerify, VaheBase};
use verifier_traits::SecureAggregationVerifier;
use willow_v1_common::{DecryptionRequestContribution, PartialDecryptionRequest, WillowCommon};

/// The verifier struct, containing a WillowCommon instance.
pub struct WillowV1Verifier<Kahe: KaheBase, Vahe: VaheBase> {
    pub common: WillowCommon<Kahe, Vahe>,
}

// State for the verifier after the first contribution is received.
struct NonemptyVerifierState<Vahe: VaheBase> {
    partial_dec_ciphertext_sum: Vahe::PartialDecCiphertext,
    nonce_bounds: (Vec<u8>, Vec<u8>),
}

impl<Vahe: VaheBase> NonemptyVerifierState<Vahe> {
    /// Ensures that the nonce bounds are valid.
    pub fn validate(&self) -> status::Status {
        if self.nonce_bounds.0 > self.nonce_bounds.1 {
            return Err(status::invalid_argument(
                "`nonce_bounds.0` must be less than or equal to `nonce_bounds.1`",
            ))?;
        }
        Ok(())
    }
}

impl<Vahe: VaheBase> Clone for NonemptyVerifierState<Vahe> {
    fn clone(&self) -> Self {
        Self {
            partial_dec_ciphertext_sum: self.partial_dec_ciphertext_sum.clone(),
            nonce_bounds: self.nonce_bounds.clone(),
        }
    }
}

/// State for the verifier.
pub struct VerifierState<Vahe: VaheBase> {
    maybe_state: Option<NonemptyVerifierState<Vahe>>,
}

impl<Vahe: VaheBase> VerifierState<Vahe> {
    /// Ensures that the wrapped state is valid, if it exists.
    pub fn validate(&self) -> status::Status {
        if let Some(state) = &self.maybe_state {
            state.validate()
        } else {
            Ok(())
        }
    }
}

impl<Vahe: VaheBase> Default for VerifierState<Vahe> {
    fn default() -> Self {
        Self { maybe_state: None }
    }
}

impl<Vahe: VaheBase> Clone for VerifierState<Vahe> {
    fn clone(&self) -> Self {
        Self { maybe_state: self.maybe_state.clone() }
    }
}

impl<Kahe, Vahe> SecureAggregationVerifier<WillowCommon<Kahe, Vahe>>
    for WillowV1Verifier<Kahe, Vahe>
where
    Vahe: EncryptVerify,
    Kahe: KaheBase,
{
    type VerifierState = VerifierState<Vahe>;

    /// Verifies the proof and if verification succeeds, adds the partial decryption ciphertext to the sum. If verification fails, returns a PermissionDenied error and does not modify the state.
    /// On success, expands the interval `state.nonce_bounds` to include `contribution.nonce`. Fails if `state.nonce_bounds` already contains `contribution.nonce`.
    /// It is therefore best to call this function on contributions in nonce order.
    fn verify_and_include(
        &self,
        contribution: DecryptionRequestContribution<Vahe>,
        state: &mut Self::VerifierState,
    ) -> Result<(), status::StatusError> {
        self.common.vahe.verify_encrypt(
            &contribution.proof,
            &contribution.partial_dec_ciphertext,
            &contribution.nonce,
        )?;
        if let Some(ref mut state) = state.maybe_state {
            state.validate()?;
            let smaller_than_left = &contribution.nonce < &state.nonce_bounds.0;
            let larger_than_right = &contribution.nonce > &state.nonce_bounds.1;
            if smaller_than_left {
                state.nonce_bounds.0 = contribution.nonce;
            } else if larger_than_right {
                state.nonce_bounds.1 = contribution.nonce;
            } else {
                return Err(status::failed_precondition("`contribution.nonce` lies within the interval of nonces already processed. To avoid this, sort contributions by nonce."))?;
            }
            self.common.vahe.add_pd_ciphertexts_in_place(
                &contribution.partial_dec_ciphertext,
                &mut state.partial_dec_ciphertext_sum,
            )?;
        } else {
            state.maybe_state = Some(NonemptyVerifierState {
                partial_dec_ciphertext_sum: contribution.partial_dec_ciphertext,
                nonce_bounds: (contribution.nonce.clone(), contribution.nonce),
            });
        }
        Ok(())
    }

    /// Merges two states into one. Fails if the intervals in the two states overlap.
    fn merge_states(
        &self,
        state1: &Self::VerifierState,
        state2: &Self::VerifierState,
    ) -> Result<Self::VerifierState, status::StatusError> {
        match (&state1.maybe_state, &state2.maybe_state) {
            (Some(state1), Some(state2)) => {
                state1.validate()?;
                state2.validate()?;
                // Check for overlap between nonce intervals. Overlap occurs if
                // state1.nonce_bounds.0 <= state2.nonce_bounds.1 AND state2.nonce_bounds.0 <= state1.nonce_bounds.1.
                if state1.nonce_bounds.0 <= state2.nonce_bounds.1
                    && state2.nonce_bounds.0 <= state1.nonce_bounds.1
                {
                    return Err(status::failed_precondition(
                        "The nonce intervals of the two states overlap. Cannot merge states with overlapping nonce ranges.",
                    ))?;
                }
                let bounds = if state1.nonce_bounds.0 < state2.nonce_bounds.0 {
                    (state1.nonce_bounds.0.clone(), state2.nonce_bounds.1.clone())
                } else {
                    (state2.nonce_bounds.0.clone(), state1.nonce_bounds.1.clone())
                };
                let mut sum = state1.partial_dec_ciphertext_sum.clone();
                self.common
                    .vahe
                    .add_pd_ciphertexts_in_place(&state2.partial_dec_ciphertext_sum, &mut sum)?;
                Ok(VerifierState {
                    maybe_state: Some(NonemptyVerifierState {
                        partial_dec_ciphertext_sum: sum,
                        nonce_bounds: bounds,
                    }),
                })
            }
            (None, Some(state)) | (Some(state), None) => {
                state.validate()?;
                Ok(VerifierState { maybe_state: Some((*state).clone()) })
            }
            (None, None) => Ok(VerifierState { maybe_state: None }),
        }
    }

    /// Returns a partial decryption request for the sum of the contributions, consumes the state.
    fn create_partial_decryption_request(
        &self,
        state: Self::VerifierState,
    ) -> Result<PartialDecryptionRequest<Vahe>, status::StatusError> {
        if let Some(state) = state.maybe_state {
            state.validate()?;
            Ok(PartialDecryptionRequest {
                partial_dec_ciphertext: state.partial_dec_ciphertext_sum,
            })
        } else {
            Err(status::failed_precondition(
                "Must handle at least one client message before requesting partial decryption",
            ))?
        }
    }
}
