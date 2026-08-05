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
use decryptor::{Decryptor, DecryptorState};
use messages::{DecryptorPublicKey, PartialDecryptionRequest, PartialDecryptionResponse};
use shell_kahe::ShellKahe;
use status::StatusError;
use std::rc::Rc;
use vahe_traits::{HasVahe, KeyGenVerify, VaheBase, VerifiableKeyGen};

/// Concrete decryptor struct optimized for single-decryptor workflows.
///
/// Wraps a multi-decryptor `Decryptor` to provide a simplified, streamlined API for
/// single-decryptor workflows without exposing committee setup contribution envelopes
/// or unused DP noise parameters.
pub struct SingleDecryptor<Vahe: VaheBase> {
    decryptor: Decryptor<Vahe>,
}

impl<Vahe: VaheBase> HasVahe for SingleDecryptor<Vahe> {
    type Vahe = Vahe;
    fn vahe(&self) -> &Self::Vahe {
        self.decryptor.vahe()
    }
}

impl<Vahe: VaheBase> SingleDecryptor<Vahe> {
    /// Creates a new `SingleDecryptor` with a randomly generated seed.
    pub fn new_with_randomly_generated_seed(vahe: Rc<Vahe>) -> Result<Self, StatusError> {
        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe)?;
        Ok(Self { decryptor })
    }
}

impl<Vahe> SingleDecryptor<Vahe>
where
    Vahe: VaheBase + VerifiableKeyGen + KeyGenVerify + PartialDec + AheKeygen,
{
    /// Generates the public key directly for single-decryptor mode.
    ///
    /// This method bypasses the committee setup contribution to avoid computing an expensive
    /// zero-knowledge proof that is not verified by anyone in the single-decryptor setting.
    pub fn create_public_key(
        &self,
        decryptor_state: &mut DecryptorState<Vahe>,
    ) -> Result<DecryptorPublicKey<Vahe>, StatusError> {
        let (sk_share, pk_share, _) =
            self.decryptor.vahe().key_gen(&mut self.decryptor.prng.borrow_mut())?;
        decryptor_state.sk_share = Some(sk_share);
        self.decryptor.vahe().aggregate_public_key_shares(std::iter::once(&pk_share))
    }

    /// Handles a partial decryption request by decrypting the accumulated partial dec ciphertexts.
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
    use googletest::{gtest, verify_eq, verify_true};
    use prng_traits::SecurePrng;
    use proto_serialization_traits::{FromProto, ToProto};
    use shell_parameters::create_shell_ahe_config;
    use shell_vahe::ShellVahe;
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use vahe_traits::{Recover, VerifiableEncrypt};

    const CONTEXT_STRING: &[u8] = b"testing_context_string";

    #[gtest]
    fn single_decryptor_state_proto_roundtrip() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let decryptor = SingleDecryptor::new_with_randomly_generated_seed(vahe)?;
        let mut state = DecryptorState::default();

        let _public_key = decryptor.create_public_key(&mut state)?;
        verify_true!(state.sk_share.is_some())?;

        let proto = state.to_proto(&decryptor)?;
        let roundtrip_state = DecryptorState::from_proto(proto, &decryptor)?;
        verify_true!(roundtrip_state.sk_share.is_some())?;

        Ok(())
    }

    #[gtest]
    fn single_decryptor_key_gen_and_decryption_works() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let decryptor = SingleDecryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let mut state = DecryptorState::default();

        let public_key = decryptor.create_public_key(&mut state)?;
        verify_true!(state.sk_share.is_some())?;

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
        verify_eq!(recovered, plaintext)?;

        Ok(())
    }
}
