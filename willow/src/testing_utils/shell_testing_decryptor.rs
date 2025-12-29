/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use aggregation_config::AggregationConfig;
use ahe_traits::{AheBase, AheKeygen, PartialDec};
use kahe_shell::ShellKahe;
use kahe_traits::{KaheBase, KaheDecrypt, TrySecretKeyFrom};
use messages::ClientMessage;
use parameters_shell::create_shell_configs;
use prng_traits::SecurePrng;
use single_thread_hkdf::SingleThreadHkdfPrng;
use status::{StatusError, StatusErrorCode};
use vahe_shell::ShellVahe;
use vahe_traits::Recover;

/// Basic implementation of a single decryptor that uses Shell operations directly. Useful for
/// testing Shell clients, by checking that encrypted messages can be decrypted properly.
pub struct ShellTestingDecryptor {
    kahe: ShellKahe,
    vahe: ShellVahe,
    prng: SingleThreadHkdfPrng,
    secret_key: Option<<ShellVahe as AheBase>::SecretKeyShare>,
}

impl ShellTestingDecryptor {
    /// Creates a new ShellTestingDecryptor, using the given context string to seed KAHE and AHE
    /// public parameters.
    pub fn new(
        aggregation_config: &AggregationConfig,
        context_string: &[u8],
    ) -> Result<ShellTestingDecryptor, StatusError> {
        let (kahe_config, ahe_config) = create_shell_configs(aggregation_config)?;
        let kahe = ShellKahe::new(kahe_config, context_string)?;
        let vahe = ShellVahe::new(ahe_config, context_string)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let prng = SingleThreadHkdfPrng::create(&seed)?;
        Ok(ShellTestingDecryptor { kahe, vahe, prng, secret_key: None })
    }

    /// Generates a new AHE public key, and stores the corresponding secret key.
    pub fn generate_public_key(
        &mut self,
    ) -> Result<<ShellVahe as AheBase>::PublicKey, StatusError> {
        let (sk_share, pk_share, _) = self.vahe.key_gen(&mut self.prng)?;
        self.secret_key = Some(sk_share);
        let public_key = self.vahe.aggregate_public_key_shares(&[pk_share])?;
        Ok(public_key)
    }

    /// Decrypts a client message using the stored AHE secret key, by recovering the KAHE key from
    /// the AHE ciphertext and then decrypting the KAHE ciphertext. Does not verify the client proof
    /// contained in the message.
    pub fn decrypt(
        &mut self,
        client_message: &ClientMessage<ShellKahe, ShellVahe>,
    ) -> Result<<ShellKahe as KaheBase>::Plaintext, StatusError> {
        let decryption_request =
            self.vahe.get_partial_dec_ciphertext(&client_message.ahe_ciphertext)?;
        let rest_of_ciphertext =
            self.vahe.get_recover_ciphertext(&client_message.ahe_ciphertext)?;
        match &self.secret_key {
            None => Err(StatusError::new_with_current_location(
                StatusErrorCode::InvalidArgument,
                "No secret key available",
            )),
            Some(sk_share) => {
                let partial_decryption =
                    self.vahe.partial_decrypt(&decryption_request, sk_share, &mut self.prng)?;
                let decrypted_kahe_key =
                    self.vahe.recover(&partial_decryption, &rest_of_ciphertext, None)?;
                let decrypted_kahe_key = self.kahe.try_secret_key_from(decrypted_kahe_key)?;
                let decrypted_plaintext =
                    self.kahe.decrypt(&client_message.kahe_ciphertext, &decrypted_kahe_key)?;
                Ok(decrypted_plaintext)
            }
        }
    }
}
