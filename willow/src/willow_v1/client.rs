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

use client_traits::SecureAggregationClient;
use kahe_traits::{HasKahe, KaheBase, KaheEncrypt, KaheKeygen, TrySecretKeyInto};
use messages::{ClientMessage, DecryptorPublicKey};
use prng_traits::SecurePrng;
use std::cell::RefCell;
use vahe_traits::{HasVahe, VaheBase, VerifiableEncrypt};

/// Lightweight client directly exposing KAHE/VAHE types.
pub struct WillowV1Client<Kahe: KaheBase, Vahe: VaheBase> {
    pub kahe: Kahe,
    pub vahe: Vahe,
    pub prng: RefCell<Kahe::Rng>, // Using a single PRNG for both VAHE and KAHE.
}

impl<Kahe: KaheBase, Vahe: VaheBase> HasKahe for WillowV1Client<Kahe, Vahe> {
    type Kahe = Kahe;
    fn kahe(&self) -> &Self::Kahe {
        &self.kahe
    }
}

impl<Kahe: KaheBase, Vahe: VaheBase> HasVahe for WillowV1Client<Kahe, Vahe> {
    type Vahe = Vahe;
    fn vahe(&self) -> &Self::Vahe {
        &self.vahe
    }
}

impl<Kahe: KaheBase, Vahe: VaheBase> WillowV1Client<Kahe, Vahe> {
    pub fn new_with_randomly_generated_seed(
        kahe: Kahe,
        vahe: Vahe,
    ) -> Result<Self, status::StatusError> {
        let seed = Kahe::Rng::generate_seed()?;
        let prng = RefCell::new(Kahe::Rng::create(&seed)?);
        Ok(Self { kahe, vahe, prng })
    }
}

/// Implementation of the `SecureAggregationClient` trait for the generic
/// KAHE/VAHE client, using WillowCommon as the common types (e.g. protocol
/// messages are directly the AHE public key and ciphertexts).
impl<Kahe, Vahe> SecureAggregationClient for WillowV1Client<Kahe, Vahe>
where
    Vahe: VaheBase + VerifiableEncrypt,
    // Reusing the same PRNG for both AHE and KAHE.
    Kahe: KaheBase<Rng = Vahe::Rng> + KaheEncrypt + KaheKeygen + TrySecretKeyInto<Vahe::Plaintext>,
{
    type Plaintext = Kahe::Plaintext;
    type PlaintextSlice<'a> = <Kahe as KaheBase>::PlaintextSlice<'a>;

    fn create_client_message(
        &self,
        plaintext: &Self::PlaintextSlice<'_>,
        signed_public_key: &DecryptorPublicKey<Vahe>,
        nonce: &[u8],
    ) -> Result<ClientMessage<Kahe, Vahe>, status::StatusError> {
        // Generate a new KAHE key.
        let kahe_secret_key = self.kahe.key_gen(&mut self.prng.borrow_mut())?;

        // Encrypt long plaintext with KAHE.
        let kahe_ciphertext =
            self.kahe.encrypt(plaintext, &kahe_secret_key, &mut self.prng.borrow_mut())?;

        // Convert KAHE secret key into short AHE plaintext.
        let ahe_plaintext: Vahe::Plaintext = self.kahe.try_secret_key_into(kahe_secret_key)?;

        // Encrypt AHE plaintext with public key.
        let (ahe_ciphertext, proof) = self.vahe.verifiable_encrypt(
            &ahe_plaintext,
            signed_public_key,
            nonce,
            &mut self.prng.borrow_mut(),
        )?;

        // Keep a copy of the nonce so the message can be forwarded as-is.
        Ok(ClientMessage { kahe_ciphertext, ahe_ciphertext, proof, nonce: nonce.to_vec() })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use aggregation_config::AggregationConfig;
    use ahe_traits::AheBase;
    use googletest::prelude::container_eq;
    use googletest::{gtest, verify_eq, verify_that};
    use kahe_shell::ShellKahe;
    use parameters_shell::create_shell_configs;
    use shell_testing_decryptor::ShellTestingDecryptor;
    use std::collections::HashMap;
    use testing_utils::generate_random_nonce;
    use vahe_shell::ShellVahe;

    const CONTEXT_STRING: &[u8] = b"test_context_string";

    #[gtest]
    fn test_create_client_message() -> googletest::Result<()> {
        let default_id = String::from("default");
        let aggregation_config = AggregationConfig {
            vector_lengths_and_bounds: HashMap::from([(default_id.clone(), (16, 10))]),
            max_number_of_decryptors: 1,
            max_number_of_clients: 1,
            max_decryptor_dropouts: 0,
            key_id: b"test".to_vec(),
        };

        // Create a client.
        let (kahe_config, ahe_config) = create_shell_configs(&aggregation_config)?;
        let kahe = ShellKahe::new(kahe_config, CONTEXT_STRING)?;
        let vahe = ShellVahe::new(ahe_config, CONTEXT_STRING)?;
        let client = WillowV1Client::new_with_randomly_generated_seed(kahe, vahe)?;

        // Generate AHE keys.
        let mut testing_decryptor =
            ShellTestingDecryptor::new(&aggregation_config, CONTEXT_STRING)?;
        let public_key = testing_decryptor.generate_public_key()?;

        // Create client message.
        let input_values = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
        let client_plaintext = HashMap::from([(default_id.as_str(), input_values.as_slice())]);
        let nonce = generate_random_nonce();
        let client_message =
            client.create_client_message(&client_plaintext, &public_key, &nonce)?;

        // Decrypt client message.
        let decrypted_plaintext = testing_decryptor.decrypt(&client_message)?;
        verify_that!(decrypted_plaintext.keys().collect::<Vec<_>>(), container_eq([&default_id]))?;
        let client_plaintext_length = client_plaintext.get(default_id.as_str()).unwrap().len();
        verify_eq!(
            decrypted_plaintext.get(default_id.as_str()).unwrap()[..client_plaintext_length],
            client_plaintext.get(default_id.as_str()).unwrap()[..]
        )
    }

    #[gtest]
    fn test_client_messages_are_aggregatable() -> googletest::Result<()> {
        let default_id = String::from("default");
        let aggregation_config = AggregationConfig {
            vector_lengths_and_bounds: HashMap::from([(default_id.clone(), (16, 10))]),
            max_number_of_decryptors: 1,
            max_number_of_clients: 2,
            max_decryptor_dropouts: 0,
            key_id: b"test".to_vec(),
        };

        // Create a client.
        let (kahe_config, ahe_config) = create_shell_configs(&aggregation_config)?;
        let kahe = ShellKahe::new(kahe_config, CONTEXT_STRING)?;
        let vahe = ShellVahe::new(ahe_config, CONTEXT_STRING)?;
        let client1 = WillowV1Client::new_with_randomly_generated_seed(kahe, vahe)?;

        // Create a second client.
        let (kahe_config, ahe_config) = create_shell_configs(&aggregation_config)?;
        let kahe = ShellKahe::new(kahe_config, CONTEXT_STRING)?;
        let vahe = ShellVahe::new(ahe_config, CONTEXT_STRING)?;
        let client2 = WillowV1Client::new_with_randomly_generated_seed(kahe, vahe)?;

        // Generate AHE keys.
        let mut testing_decryptor =
            ShellTestingDecryptor::new(&aggregation_config, CONTEXT_STRING)?;
        let public_key = testing_decryptor.generate_public_key()?;

        // Create client messages.
        let input_values1 = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
        let client1_plaintext = HashMap::from([(default_id.as_str(), input_values1.as_slice())]);
        let input_values2 = vec![1, 1, 2, 3, 5, 8, 3, 1, 4, 5, 9, 4, 3, 7, 0];
        let client2_plaintext = HashMap::from([(default_id.as_str(), input_values2.as_slice())]);
        let expected_output = vec![2, 3, 5, 7, 10, 14, 10, 9, 11, 11, 14, 8, 6, 9, 1];
        let nonce1 = generate_random_nonce();
        let mut client_message =
            client1.create_client_message(&client1_plaintext, &public_key, &nonce1)?;
        let nonce2 = generate_random_nonce();
        let extra_message =
            client2.create_client_message(&client2_plaintext, &public_key, &nonce2)?;

        // Add extra message to the first client message.
        client2.kahe.add_ciphertexts_in_place(
            &extra_message.kahe_ciphertext,
            &mut client_message.kahe_ciphertext,
        )?;
        client2.vahe.add_ciphertexts_in_place(
            &extra_message.ahe_ciphertext,
            &mut client_message.ahe_ciphertext,
        )?;

        // Decrypt client message.
        let decrypted_plaintext = testing_decryptor.decrypt(&client_message)?;
        verify_that!(decrypted_plaintext.keys().collect::<Vec<_>>(), container_eq([&default_id]))?;
        let client_plaintext_length = client1_plaintext.get(default_id.as_str()).unwrap().len();
        verify_eq!(
            decrypted_plaintext.get(default_id.as_str()).unwrap()[..client_plaintext_length],
            expected_output
        )
    }
}
