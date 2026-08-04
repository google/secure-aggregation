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

use ahe_traits::{AheBase, PartialDec};
use kahe_traits::KaheBase;
use messages::{
    CoordinatorState, CoordinatorStatus, FinalizedPartialDecryption, PartialDecryptionRequest,
    PartialDecryptionResponse, RecoveryRequest, RecoveryResponse, SetupContribution,
    VerifyKeyContributionsRequest,
};
use status::StatusError;
use std::rc::Rc;
use vahe_traits::{HasVahe, VaheBase};

/// Coordinator implementation for the multi-decryptor Willow protocol.
///
/// The coordinator manages protocol flow and aggregates messages from all
/// decryptors. The coordinator itself does not contribute to the public key.
///
/// The coordinator is not trusted for security at all, it does not hold any secrets and the
/// protocol is secure even if it behaves arbitrarily.
/// As such it need not be run on secure hardware, however it does need access to the
/// cryptographic library for most of these functions.
pub struct WillowV1Coordinator<Vahe: VaheBase> {
    pub vahe: Rc<Vahe>,
}

impl<Vahe: VaheBase> HasVahe for WillowV1Coordinator<Vahe> {
    type Vahe = Vahe;
    fn vahe(&self) -> &Self::Vahe {
        &self.vahe
    }
}

impl<Vahe: VaheBase + PartialDec> WillowV1Coordinator<Vahe> {
    /// Stores setup contributions from all decryptors and creates a request to verify the
    /// contributions.
    pub fn handle_setup_submissions(
        &self,
        non_reputable_contributions: Vec<SetupContribution<Vahe>>,
        reputable_contributions: Vec<SetupContribution<Vahe>>,
        coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<VerifyKeyContributionsRequest<Vahe>, StatusError> {
        if coordinator_state.status != CoordinatorStatus::PreSetup {
            return Err(status::failed_precondition("Coordinator is not in PreSetup state"));
        }

        let mut all_key_contributions = Vec::new();

        // Collect contributions. The coordinator does not verify proofs — that is the
        // reputable decryptor's responsibility (the coordinator is untrusted).
        for contribution in non_reputable_contributions.into_iter().chain(reputable_contributions) {
            // Store encrypted randomness shares from non-reputable decryptors.
            if let Some(shares) = contribution.encrypted_randomness_shares {
                coordinator_state.encrypted_randomness_shares.push(shares);
            }

            all_key_contributions.push(contribution.key_contribution);
        }

        coordinator_state.status = CoordinatorStatus::KeySharesReceived;

        Ok(VerifyKeyContributionsRequest { key_contributions: all_key_contributions })
    }

    /// Combines the verifier's ciphertext half with the accumulated AHE components.
    ///
    /// The result should be forwarded to decryptors for partial decryption.
    pub fn prepare_decryption_request(
        &self,
        verifier_ciphertext: &<Vahe as AheBase>::PartialDecCiphertext,
        coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<PartialDecryptionRequest<Vahe>, StatusError> {
        if coordinator_state.status != CoordinatorStatus::KeySharesReceived {
            return Err(status::failed_precondition(
                "Coordinator is not in KeySharesReceived state. \
                 Call handle_setup_submissions first.",
            ));
        }

        let partial_dec_ciphertext = verifier_ciphertext.clone();

        coordinator_state.status = CoordinatorStatus::AwaitingPartialDecryptions;

        Ok(PartialDecryptionRequest { partial_dec_ciphertext, aggregation_config: None })
    }

    /// Accumulates partial decryptions from responding decryptors.
    pub fn aggregate_partial_decryptions<Kahe: KaheBase>(
        &self,
        partial_responses: Vec<PartialDecryptionResponse<Kahe, Vahe>>,
        _kahe: Option<&Kahe>,
        coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<(), StatusError> {
        if coordinator_state.status != CoordinatorStatus::AwaitingPartialDecryptions {
            return Err(status::failed_precondition(
                "Coordinator is not in AwaitingPartialDecryptions state",
            ));
        }
        // Accumulate partial decryptions into a local sum, then update coordinator_state once.
        let mut partial_responses_iter = partial_responses.into_iter();
        let mut sum = partial_responses_iter
            .next()
            .expect("No partial decryptions provided")
            .partial_decryption;
        for response in partial_responses_iter {
            self.vahe.add_partial_decryptions_in_place(&response.partial_decryption, &mut sum)?;
        }

        coordinator_state.partial_decryption_sum = Some(sum);
        coordinator_state.status = CoordinatorStatus::OutputReady;

        Ok(())
    }

    /// Creates recovery requests for surviving decryptors to decrypt shares of dropped client
    /// decryptors.
    ///
    /// If the vector is empty, there are no dropped decryptors to recover and
    /// recover_dropped_decryptors can be called immediately with an empty vector.
    pub fn create_recovery_requests(
        &self,
        _coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<Vec<RecoveryRequest>, StatusError> {
        Err(status::unimplemented("Dropout recovery is not yet implemented"))
    }

    /// Recovers randomness from dropped decryptors.
    ///
    /// Uses decrypted shares from survivors to simulate missing partial decryptions.
    pub fn recover_dropped_decryptors(
        &self,
        _recovery_responses: Vec<RecoveryResponse>,
        _coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<(), StatusError> {
        Err(status::unimplemented("Dropout recovery is not yet implemented"))
    }

    /// Returns the finalized partial decryption.
    ///
    /// This can be combined with the aggregated client
    /// CiphertextContributions (KAHE ciphertext and AHE recover_plaintext ct_0) to
    /// obtain the final noisy KAHE plaintext.
    pub fn finalize_partial_decryption(
        &self,
        coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<FinalizedPartialDecryption<Vahe>, StatusError> {
        if coordinator_state.status != CoordinatorStatus::OutputReady {
            return Err(status::failed_precondition("Coordinator is not in OutputReady state"));
        }
        Ok(FinalizedPartialDecryption {
            partial_decryption_sum: coordinator_state
                .partial_decryption_sum
                .clone()
                .expect("partial_decryption_sum should be set"),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::WillowV1Coordinator;
    use ahe_traits::AheBase;

    use googletest::gtest;
    use googletest::prelude::*;
    use messages::{CoordinatorState, CoordinatorStatus};
    use prng_traits::SecurePrng;
    use shell_kahe::ShellKahe;
    use shell_parameters::create_shell_ahe_config;
    use shell_vahe::ShellVahe;
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use std::rc::Rc;
    use vahe_traits::{Recover, VerifiableEncrypt};
    use willow_v1_decryptor::{DecryptorState, WillowV1Decryptor};

    const CONTEXT_STRING: &[u8] = b"testing_context_string";

    #[gtest]
    fn coordinator_handles_setup_and_creates_verification_request() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);

        // Create two decryptors.
        let decryptor1 = WillowV1Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let decryptor2 = WillowV1Decryptor::new_with_randomly_generated_seed(vahe.clone())?;

        let mut state1 = DecryptorState::default();
        let mut state2 = DecryptorState::default();
        let contribution1 = decryptor1.create_setup_contribution(&mut state1)?;
        let contribution2 = decryptor2.create_setup_contribution(&mut state2)?;

        // Create coordinator.
        let coordinator = WillowV1Coordinator { vahe: vahe.clone() };
        let mut coord_state = CoordinatorState::default();

        // Handle setup submissions.
        let verify_request = coordinator.handle_setup_submissions(
            vec![],
            vec![contribution1, contribution2],
            &mut coord_state,
        )?;

        verify_true!(verify_request.key_contributions.len() == 2)?;
        verify_true!(coord_state.status == CoordinatorStatus::KeySharesReceived)?;

        Ok(())
    }

    #[gtest]
    fn coordinator_setup_fails_when_not_pre_setup() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);

        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let mut state = DecryptorState::default();
        let contribution = decryptor.create_setup_contribution(&mut state)?;

        let coordinator = WillowV1Coordinator { vahe: vahe.clone() };
        let mut coord_state = CoordinatorState::default();

        // First call succeeds.
        coordinator.handle_setup_submissions(vec![], vec![contribution], &mut coord_state)?;

        // Second call should fail.
        let decryptor2 = WillowV1Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let mut state2 = DecryptorState::default();
        let contribution2 = decryptor2.create_setup_contribution(&mut state2)?;
        let result =
            coordinator.handle_setup_submissions(vec![], vec![contribution2], &mut coord_state);
        verify_true!(result.is_err())?;

        Ok(())
    }

    /// End-to-end test: setup -> encryption -> partial decryption -> recovery
    /// using the multi-decryptor protocol with a coordinator and reputable decryptor.
    #[gtest]
    fn end_to_end_multi_decryptor_protocol() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);

        // Create two multi-decryptors (same struct, using multi-decryptor traits).
        let decryptor1 = WillowV1Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let decryptor2 = WillowV1Decryptor::new_with_randomly_generated_seed(vahe.clone())?;

        let mut dec_state1 = DecryptorState::default();
        let mut dec_state2 = DecryptorState::default();

        // --- Setup phase ---

        // Each decryptor generates its setup contribution.
        let contribution1 = decryptor1.create_setup_contribution(&mut dec_state1)?;
        let contribution2 = decryptor2.create_setup_contribution(&mut dec_state2)?;

        // Coordinator processes setup.
        let coordinator = WillowV1Coordinator { vahe: vahe.clone() };
        let mut coord_state = CoordinatorState::default();
        let verify_request = coordinator.handle_setup_submissions(
            vec![],
            vec![contribution1, contribution2],
            &mut coord_state,
        )?;

        // Reputable decryptor verifies and aggregates the public key.
        let public_key = decryptor1.verify_and_aggregate_key_contributions(verify_request)?;

        // --- Encryption phase ---
        // Create a fake ciphertext by encrypting a known plaintext.
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let plaintext = vec![42i64; 8];
        let nonce = b"0123456789ABCDEF";
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&plaintext, &public_key, nonce, &mut prng)?;
        let partial_dec_ciphertext = vahe.get_partial_dec_ciphertext(&ciphertext)?;
        let recover_ciphertext = vahe.get_recover_ciphertext(&ciphertext)?;

        // --- Decryption phase ---

        // Coordinator prepares decryption request.
        let pd_request =
            coordinator.prepare_decryption_request(&partial_dec_ciphertext, &mut coord_state)?;

        // Each decryptor computes a partial decryption.
        let pd_response1: messages::PartialDecryptionResponse<ShellKahe, ShellVahe> = decryptor1
            .handle_partial_decryption_request(pd_request.clone(), None, &mut dec_state1)?;
        let pd_response2: messages::PartialDecryptionResponse<ShellKahe, ShellVahe> =
            decryptor2.handle_partial_decryption_request(pd_request, None, &mut dec_state2)?;

        // Coordinator aggregates partial decryptions.
        coordinator.aggregate_partial_decryptions::<ShellKahe>(
            vec![pd_response1, pd_response2],
            None,
            &mut coord_state,
        )?;

        verify_true!(coord_state.status == CoordinatorStatus::OutputReady)?;

        // Recover the plaintext using the finalized state.
        let finalized_state = coordinator.finalize_partial_decryption(&mut coord_state)?;
        let recovered = vahe.recover(
            &finalized_state.partial_decryption_sum,
            &recover_ciphertext,
            Some(plaintext.len()),
        )?;

        verify_that!(&recovered[..], eq(&plaintext[..]))?;

        Ok(())
    }
}
