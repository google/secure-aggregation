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

use messages::{DecryptionRequestContribution, PartialDecryptionRequest};
use messages_rust_proto::VerifierState as VerifierStateProto;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::{proto, AsView};
use shell_ciphertexts_rust_proto::ShellAhePartialDecCiphertext;
use status::StatusError;
use std::fmt::Debug;
use std::rc::Rc;
use vahe_traits::{EncryptVerify, HasVahe, VaheBase};
use verifier_traits::SecureAggregationVerifier;

/// The verifier struct, containing a WillowCommon instance.
pub struct WillowV1Verifier<Vahe: VaheBase> {
    pub vahe: Rc<Vahe>,
}

impl<Vahe: VaheBase> HasVahe for WillowV1Verifier<Vahe> {
    type Vahe = Vahe;
    fn vahe(&self) -> &Self::Vahe {
        &self.vahe
    }
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
            ));
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

impl<Vahe: VaheBase> Debug for NonemptyVerifierState<Vahe> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("NonemptyVerifierState")
            .field("partial_dec_ciphertext_sum", &"(OMITTED)")
            .field("nonce_bounds", &self.nonce_bounds)
            .finish()
    }
}

/// State for the verifier.
pub struct VerifierState<Vahe: VaheBase>(Option<NonemptyVerifierState<Vahe>>);

impl<Vahe: VaheBase> Debug for VerifierState<Vahe> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_tuple("VerifierState").field(&self.0).finish()
    }
}

impl<Vahe: VaheBase> VerifierState<Vahe> {
    /// Ensures that the wrapped state is valid, if it exists.
    pub fn validate(&self) -> status::Status {
        if let Some(state) = &self.0 {
            state.validate()
        } else {
            Ok(())
        }
    }
}

impl<Vahe: VaheBase> Default for VerifierState<Vahe> {
    fn default() -> Self {
        Self(None)
    }
}

impl<Vahe: VaheBase> Clone for VerifierState<Vahe> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<'a, C, Vahe> ToProto<&'a C> for VerifierState<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: ToProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
{
    type Proto = VerifierStateProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        if let Some(state) = &self.0 {
            Ok(proto!(VerifierStateProto {
                partial_dec_ciphertext_sum: state
                    .partial_dec_ciphertext_sum
                    .to_proto(context.vahe())?,
                nonce_lower_bound: state.nonce_bounds.0.clone(),
                nonce_upper_bound: state.nonce_bounds.1.clone(),
            }))
        } else {
            Ok(proto!(VerifierStateProto {}))
        }
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for VerifierState<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: FromProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
{
    type Proto = VerifierStateProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        if proto.has_partial_dec_ciphertext_sum() {
            let state = VerifierState(Some(NonemptyVerifierState {
                partial_dec_ciphertext_sum: Vahe::PartialDecCiphertext::from_proto(
                    proto.partial_dec_ciphertext_sum(),
                    context.vahe(),
                )?,
                nonce_bounds: (
                    proto.nonce_lower_bound().to_vec(),
                    proto.nonce_upper_bound().to_vec(),
                ),
            }));
            state.validate()?;
            Ok(state)
        } else {
            Ok(VerifierState(None))
        }
    }
}

impl<Vahe> SecureAggregationVerifier for WillowV1Verifier<Vahe>
where
    Vahe: EncryptVerify,
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
        self.vahe.verify_encrypt(
            &contribution.proof,
            &contribution.partial_dec_ciphertext,
            &contribution.nonce,
        )?;
        if let Some(ref mut state) = state.0 {
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
            self.vahe.add_pd_ciphertexts_in_place(
                &contribution.partial_dec_ciphertext,
                &mut state.partial_dec_ciphertext_sum,
            )?;
        } else {
            state.0 = Some(NonemptyVerifierState {
                partial_dec_ciphertext_sum: contribution.partial_dec_ciphertext,
                nonce_bounds: (contribution.nonce.clone(), contribution.nonce),
            });
        }
        Ok(())
    }

    /// Merges two states into one. Fails if the intervals in the two states overlap.
    fn merge_states(
        &self,
        state1: Self::VerifierState,
        state2: Self::VerifierState,
    ) -> Result<Self::VerifierState, status::StatusError> {
        match (&state1.0, &state2.0) {
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
                self.vahe
                    .add_pd_ciphertexts_in_place(&state2.partial_dec_ciphertext_sum, &mut sum)?;
                Ok(VerifierState(Some(NonemptyVerifierState {
                    partial_dec_ciphertext_sum: sum,
                    nonce_bounds: bounds,
                })))
            }
            (None, Some(state)) | (Some(state), None) => {
                state.validate()?;
                Ok(VerifierState(Some((*state).clone())))
            }
            (None, None) => Ok(VerifierState(None)),
        }
    }

    /// Returns a partial decryption request for the sum of the contributions, consumes the state.
    fn create_partial_decryption_request(
        &self,
        state: Self::VerifierState,
    ) -> Result<PartialDecryptionRequest<Vahe>, status::StatusError> {
        if let Some(state) = state.0 {
            state.validate()?;
            Ok(PartialDecryptionRequest {
                partial_dec_ciphertext: state.partial_dec_ciphertext_sum,
                aggregation_config: None,
            })
        } else {
            Err(status::failed_precondition(
                "Must handle at least one client message before requesting partial decryption",
            ))?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ahe_traits::AheBase;
    use client_traits::SecureAggregationClient;

    use accumulator_traits::SecureAggregationCiphertextAccumulator;
    use decryptor_traits::SecureAggregationDecryptor;
    use googletest::prelude::{
        contains_substring, eq, err, gtest, verify_eq, verify_that, verify_true,
    };
    use kahe_traits::KaheBase;
    use proto_serialization_traits::{FromProto, ToProto};
    use shell_kahe::ShellKahe;
    use shell_parameters::{create_shell_ahe_config, create_shell_kahe_config};
    use shell_vahe::ShellVahe;
    use status_matchers_rs::status_is;
    use std::collections::HashMap;
    use testing_utils::{generate_aggregation_config, generate_random_nonce};
    use willow_v1_accumulator::WillowV1CiphertextAccumulator;
    use willow_v1_client::WillowV1Client;
    use willow_v1_decryptor::{DecryptorState, WillowV1Decryptor};

    const CONTEXT_STRING: &[u8] = b"testing_context_string";
    const DEFAULT_VECTOR_ID: &str = "default";

    struct VerifierTestSetup {
        verifier: WillowV1Verifier<ShellVahe>,
        decryption_request_contribution: DecryptionRequestContribution<ShellVahe>,
    }

    fn setup() -> Result<VerifierTestSetup, status::StatusError> {
        let aggregation_config =
            generate_aggregation_config(DEFAULT_VECTOR_ID.to_string(), 16, 10, 1, 1);
        let max_number_of_decryptors = aggregation_config.max_number_of_decryptors;

        // Create common KAHE/VAHE instances.
        let kahe = Rc::new(
            ShellKahe::new(create_shell_kahe_config(&aggregation_config).unwrap(), CONTEXT_STRING)
                .unwrap(),
        );
        let vahe = Rc::new(
            ShellVahe::new(
                create_shell_ahe_config(max_number_of_decryptors).unwrap(),
                CONTEXT_STRING,
            )
            .unwrap(),
        );

        // Create client.
        let client =
            WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))
                .unwrap();

        // Create decryptor.
        let mut decryptor_state = DecryptorState::default();
        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe))?;

        // Create accumulator.
        let accumulator =
            WillowV1CiphertextAccumulator { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };

        // Create verifier.
        let verifier = WillowV1Verifier { vahe: Rc::clone(&vahe) };

        // Decryptor generates public key share.
        let public_key_share = decryptor.create_public_key_share(&mut decryptor_state)?;

        // Aggregate public key share directly.
        let public_key = vahe.aggregate_public_key_shares(std::iter::once(&public_key_share))?;

        // Client encrypts.
        let client_plaintext = HashMap::from([(
            DEFAULT_VECTOR_ID,
            [1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1].as_slice(),
        )]);
        let nonce = generate_random_nonce();
        let client_message =
            client.create_client_message(&client_plaintext, &public_key, &nonce)?;

        // The client message is split and handled by the accumulator and verifier.
        let (_, decryption_request_contribution) =
            accumulator.split_client_message(client_message)?;

        Ok(VerifierTestSetup { verifier, decryption_request_contribution })
    }

    #[gtest]
    fn verify_and_include_fails_if_nonce_already_processed() -> googletest::Result<()> {
        let setup = setup()?;
        let mut verifier_state = VerifierState::default();
        setup.verifier.verify_and_include(
            setup.decryption_request_contribution.clone(),
            &mut verifier_state,
        )?;

        // Verify again, should fail.
        verify_that!(
            setup
                .verifier
                .verify_and_include(setup.decryption_request_contribution, &mut verifier_state,),
            status_is(status::StatusErrorCode::FAILED_PRECONDITION)
                .with_message(contains_substring("already processed."))
        )
    }

    #[gtest]
    fn verify_and_include_fails_if_state_is_invalid() -> googletest::Result<()> {
        let setup = setup()?;
        let mut verifier_state = VerifierState::default();
        setup.verifier.verify_and_include(
            setup.decryption_request_contribution.clone(),
            &mut verifier_state,
        )?;

        verifier_state.0.as_mut().unwrap().nonce_bounds.0 = b"2222".to_vec();
        verifier_state.0.as_mut().unwrap().nonce_bounds.1 = b"1111".to_vec();

        // Verify again, should fail.
        verify_that!(
            setup
                .verifier
                .verify_and_include(setup.decryption_request_contribution, &mut verifier_state,),
            status_is(status::StatusErrorCode::INVALID_ARGUMENT).with_message(eq(
                "`nonce_bounds.0` must be less than or equal to `nonce_bounds.1`"
            ))
        )
    }

    #[gtest]
    fn merge_states_fails_if_state_is_invalid() -> googletest::Result<()> {
        let setup = setup()?;
        let mut verifier_state_1 = VerifierState::default();
        let verifier_state_2 = VerifierState::default();
        setup.verifier.verify_and_include(
            setup.decryption_request_contribution.clone(),
            &mut verifier_state_1,
        )?;

        verifier_state_1.0.as_mut().unwrap().nonce_bounds.0 = b"2222".to_vec();
        verifier_state_1.0.as_mut().unwrap().nonce_bounds.1 = b"1111".to_vec();

        // Try to merge the states, should fail.
        verify_that!(
            setup.verifier.merge_states(verifier_state_1, verifier_state_2),
            err(status_is(status::StatusErrorCode::INVALID_ARGUMENT).with_message(eq(
                "`nonce_bounds.0` must be less than or equal to `nonce_bounds.1`"
            )))
        )
    }

    #[gtest]
    fn merge_with_empty_state_preserves_nonce_bounds() -> googletest::Result<()> {
        let setup = setup()?;
        let mut verifier_state_1 = VerifierState::default();
        let verifier_state_2 = VerifierState::default();
        setup.verifier.verify_and_include(
            setup.decryption_request_contribution.clone(),
            &mut verifier_state_1,
        )?;

        // Merge with empty state, should preserve nonce bounds.
        let verifier_state_3 =
            setup.verifier.merge_states(verifier_state_1.clone(), verifier_state_2.clone())?;
        let verifier_state_4 =
            setup.verifier.merge_states(verifier_state_2.clone(), verifier_state_1.clone())?;

        // Nonce bounds should be the same as in verifier_state_1.
        verify_true!(verifier_state_3.0.is_some())?;
        verify_eq!(
            verifier_state_3.0.as_ref().unwrap().nonce_bounds,
            verifier_state_1.0.as_ref().unwrap().nonce_bounds
        )?;
        verify_true!(verifier_state_4.0.is_some())?;
        verify_eq!(
            verifier_state_4.0.as_ref().unwrap().nonce_bounds,
            verifier_state_1.0.as_ref().unwrap().nonce_bounds
        )
    }

    #[gtest]
    fn merge_empty_states_returns_empty_state() -> googletest::Result<()> {
        let setup = setup()?;
        let verifier_state_1 = VerifierState::default();
        let verifier_state_2 = VerifierState::default();

        let verifier_state_3 = setup.verifier.merge_states(verifier_state_1, verifier_state_2)?;
        verify_true!(verifier_state_3.0.is_none())
    }

    #[gtest]
    fn create_partial_decryption_request_fails_if_no_contributions() -> googletest::Result<()> {
        let setup = setup()?;
        let verifier_state = VerifierState::default();

        verify_that!(
            &setup.verifier.create_partial_decryption_request(verifier_state),
            err(status_is(status::StatusErrorCode::FAILED_PRECONDITION)
                .with_message(contains_substring("at least one client message ")))
        )
    }

    #[gtest]
    fn verifier_state_serialization_roundtrip() -> googletest::Result<()> {
        let setup = setup()?;
        let mut verifier_state = VerifierState::default();

        // Check empty state serialization
        let verifier_state_proto = verifier_state.to_proto(&setup.verifier)?;
        let verifier_state_roundtrip =
            VerifierState::from_proto(verifier_state_proto, &setup.verifier)?;
        verify_true!(verifier_state_roundtrip.0.is_none())?;

        // Check populated state serialization
        setup.verifier.verify_and_include(
            setup.decryption_request_contribution.clone(),
            &mut verifier_state,
        )?;
        let nonce_bounds_before = verifier_state.0.as_ref().unwrap().nonce_bounds.clone();
        let verifier_state_proto = verifier_state.to_proto(&setup.verifier)?;
        let verifier_state_roundtrip =
            VerifierState::from_proto(verifier_state_proto, &setup.verifier)?;
        verify_true!(verifier_state_roundtrip.0.is_some())?;
        verify_eq!(verifier_state_roundtrip.0.as_ref().unwrap().nonce_bounds, nonce_bounds_before)?;

        Ok(())
    }
}
