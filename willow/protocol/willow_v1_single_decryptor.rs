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

use ahe_traits::{AheKeygen, PartialDec};
use messages::{DecryptorPublicKeyShare, PartialDecryptionRequest, PartialDecryptionResponse};
use shell_kahe::ShellKahe;
use status::StatusError;
use std::rc::Rc;
use vahe_traits::{HasVahe, VaheBase, VerifiableKeyGen};
use willow_v1_decryptor::{DecryptorState, WillowV1Decryptor};

/// Concrete decryptor struct optimized for single-decryptor workflows.
///
/// Wraps a [`WillowV1Decryptor`] to provide a simplified, streamlined API for
/// single-decryptor workflows without exposing committee setup contribution envelopes
/// or unused DP noise parameters.
pub struct WillowV1SingleDecryptor<Vahe: VaheBase> {
    pub decryptor: WillowV1Decryptor<Vahe>,
}

impl<Vahe: VaheBase> HasVahe for WillowV1SingleDecryptor<Vahe> {
    type Vahe = Vahe;
    fn vahe(&self) -> &Self::Vahe {
        self.decryptor.vahe()
    }
}

impl<Vahe: VaheBase> WillowV1SingleDecryptor<Vahe> {
    /// Creates a new `WillowV1SingleDecryptor` with a randomly generated seed.
    pub fn new_with_randomly_generated_seed(vahe: Rc<Vahe>) -> Result<Self, StatusError> {
        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(vahe)?;
        Ok(Self { decryptor })
    }

    /// Wraps an existing [`WillowV1Decryptor`].
    pub fn new(decryptor: WillowV1Decryptor<Vahe>) -> Self {
        Self { decryptor }
    }
}

impl<Vahe> WillowV1SingleDecryptor<Vahe>
where
    Vahe: VaheBase + VerifiableKeyGen + PartialDec + AheKeygen,
{
    /// Creates a public key share directly without `SetupContribution` wrapping.
    pub fn create_public_key_share(
        &self,
        decryptor_state: &mut DecryptorState<Vahe>,
    ) -> Result<DecryptorPublicKeyShare<Vahe>, StatusError> {
        let setup_contribution = self.decryptor.create_setup_contribution(decryptor_state)?;
        Ok(setup_contribution.key_contribution.public_key_share)
    }

    /// Handles a partial decryption request received from the Server.
    /// Returns a partial decryption response without exposing unused DP noise parameters.
    pub fn handle_partial_decryption_request(
        &self,
        partial_decryption_request: PartialDecryptionRequest<Vahe>,
        decryptor_state: &mut DecryptorState<Vahe>,
    ) -> Result<PartialDecryptionResponse<ShellKahe, Vahe>, StatusError> {
        self.decryptor.handle_partial_decryption_request(
            partial_decryption_request,
            None::<&ShellKahe>,
            decryptor_state,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahe_traits::AheBase;
    use googletest::{gtest, verify_true};
    use prng_traits::SecurePrng;
    use shell_parameters::create_shell_ahe_config;
    use shell_vahe::ShellVahe;
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use vahe_traits::{Recover, VerifiableEncrypt};

    const CONTEXT_STRING: &[u8] = b"testing_context_string";

    #[gtest]
    fn single_decryptor_key_gen_and_decryption_works() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let decryptor = WillowV1SingleDecryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let mut state = DecryptorState::default();

        let public_key_share = decryptor.create_public_key_share(&mut state)?;
        verify_true!(state.sk_share.is_some())?;

        let public_key = vahe.aggregate_public_key_shares(std::iter::once(&public_key_share))?;

        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let plaintext = vec![42i64; 8];
        let nonce = b"0123456789ABCDEF";
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&plaintext, &public_key, nonce, &mut prng)?;
        let partial_dec_ciphertext = vahe.get_partial_dec_ciphertext(&ciphertext)?;

        let pd_request =
            PartialDecryptionRequest { partial_dec_ciphertext, aggregation_config: None };

        let pd_response = decryptor.handle_partial_decryption_request(pd_request, &mut state)?;

        let recover_ciphertext = vahe.get_recover_ciphertext(&ciphertext)?;
        let recovered = vahe.recover(
            &pd_response.partial_decryption,
            &recover_ciphertext,
            Some(plaintext.len()),
        )?;
        verify_true!(recovered == plaintext)?;

        Ok(())
    }
}
