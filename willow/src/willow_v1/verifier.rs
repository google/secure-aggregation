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

/// State for the verifier.
pub struct VerifierState<Vahe: VaheBase> {
    partial_dec_ciphertext_sum: Option<Vahe::PartialDecCiphertext>,
}

impl<Vahe: VaheBase> VerifierState<Vahe> {
    pub fn new() -> Self {
        Self { partial_dec_ciphertext_sum: None }
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
        if let Some(ref mut sum) = state.partial_dec_ciphertext_sum {
            self.common
                .vahe
                .add_pd_ciphertexts_in_place(&contribution.partial_dec_ciphertext, sum)?;
        } else {
            state.partial_dec_ciphertext_sum = Some(contribution.partial_dec_ciphertext);
        }
        Ok(())
    }

    /// Returns a partial decryption request for the sum of the contributions, consumes the state.
    fn create_partial_decryption_request(
        &self,
        state: Self::VerifierState,
    ) -> Result<PartialDecryptionRequest<Vahe>, status::StatusError> {
        if let Some(sum) = state.partial_dec_ciphertext_sum {
            Ok(PartialDecryptionRequest { partial_dec_ciphertext: sum })
        } else {
            Err(status::failed_precondition(
                "Must handle at least one client message before requesting partial decryption",
            ))?
        }
    }
}
