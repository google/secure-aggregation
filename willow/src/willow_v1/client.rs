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
use client_traits::SecureAggregationClient;
use kahe_traits::{KaheBase, KaheEncrypt, KaheKeygen, TrySecretKeyInto};
use prng_traits::SecurePrng;
use vahe_traits::{VaheBase, VerifiableEncrypt};
use willow_v1_common::{WillowClientMessage, WillowCommon};

/// Lightweight client directly exposing KAHE/VAHE types.
pub struct WillowV1Client<Kahe: KaheBase, Vahe: VaheBase> {
    pub common: WillowCommon<Kahe, Vahe>,
    pub prng: Kahe::Rng, // Using a single PRNG for both VAHE and KAHE.
}

/// Implementation of the `SecureAggregationClient` trait for the generic
/// KAHE/VAHE client, using WillowCommon as the common types (e.g. protocol
/// messages are directly the AHE public key and ciphertexts).
impl<Kahe, Vahe> SecureAggregationClient<WillowCommon<Kahe, Vahe>> for WillowV1Client<Kahe, Vahe>
where
    Vahe: VaheBase + VerifiableEncrypt,
    // Reusing the same PRNG for both AHE and KAHE.
    Kahe: KaheBase<Rng = Vahe::Rng> + KaheEncrypt + KaheKeygen + TrySecretKeyInto<Vahe::Plaintext>,
{
    type Plaintext = Kahe::Plaintext;

    fn create_client_message(
        &mut self,
        plaintext: &Self::Plaintext,
        signed_public_key: &Vahe::PublicKey,
    ) -> Result<WillowClientMessage<Kahe, Vahe>, status::StatusError> {
        // Generate a new KAHE key.
        let kahe_secret_key = self.common.kahe.key_gen(&mut self.prng)?;

        // Encrypt long plaintext with KAHE.
        let kahe_ciphertext =
            self.common.kahe.encrypt(plaintext, &kahe_secret_key, &mut self.prng)?;

        // Convert KAHE secret key into short AHE plaintext.
        let ahe_plaintext: Vahe::Plaintext =
            self.common.kahe.try_secret_key_into(kahe_secret_key)?;

        // Generate a nonce for the VAHE encryption.
        let nonce =
            (0..16).map(|_| self.prng.rand8()).collect::<Result<Vec<u8>, status::StatusError>>()?;

        // Encrypt AHE plaintext with public key.
        let (ahe_ciphertext, proof) = self.common.vahe.verifiable_encrypt(
            &ahe_plaintext,
            signed_public_key,
            &nonce,
            &mut self.prng,
        )?;
        Ok(WillowClientMessage { kahe_ciphertext, ahe_ciphertext, proof, nonce })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ahe_traits::{AheKeygen, PartialDec};
    use googletest::prelude::container_eq;
    use googletest::{gtest, verify_eq, verify_that};
    use kahe_traits::{KaheDecrypt, TrySecretKeyFrom};
    use prng_traits::SecurePrng;
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use std::collections::HashMap;
    use testing_utils::create_willow_common;
    use vahe_traits::{Recover, VaheBase};
    use willow_api_common::AggregationConfig;

    const CONTEXT_STRING: &[u8] = b"test_context_string";

    #[gtest]
    fn test_create_client_message() -> googletest::Result<()> {
        let default_id = String::from("default");
        let aggregation_config = AggregationConfig {
            vector_lengths_and_bounds: HashMap::from([(default_id.clone(), (16, 10))]),
            max_number_of_decryptors: 1,
            max_number_of_clients: 1,
            max_decryptor_dropouts: 0,
            session_id: String::from("test"),
            willow_version: (1, 0),
        };
        // Generate public parameters for KAHE and AHE.
        let public_kahe_seed = SingleThreadHkdfPrng::generate_seed()?;

        // Create a client.
        let common = create_willow_common(&aggregation_config, CONTEXT_STRING);
        let client_seed = SingleThreadHkdfPrng::generate_seed()?;
        let prng = SingleThreadHkdfPrng::create(&client_seed)?;
        let mut client = WillowV1Client { common: common, prng: prng };

        // Generate AHE keys.
        let common = create_willow_common(&aggregation_config, CONTEXT_STRING);
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (sk_share, pk_share, _) = common.vahe.key_gen(&mut prng)?;
        let public_key = common.vahe.aggregate_public_key_shares(&[pk_share])?;

        // Create client message.
        let client_plaintext = HashMap::from([(
            default_id.clone(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1],
        )]);
        let client_message = client.create_client_message(&client_plaintext, &public_key)?;

        // Decrypt client message.
        let decryption_request =
            common.vahe.get_partial_dec_ciphertext(&client_message.ahe_ciphertext)?;
        let rest_of_ciphertext =
            common.vahe.get_recover_ciphertext(&client_message.ahe_ciphertext)?;
        let partial_decryption =
            common.vahe.partial_decrypt(&decryption_request, &sk_share, &mut prng)?;
        let decrypted_kahe_key =
            common.vahe.recover(&partial_decryption, &rest_of_ciphertext, None)?;
        let decrypted_kahe_key = common.kahe.try_secret_key_from(decrypted_kahe_key)?;
        let decrypted_plaintext =
            common.kahe.decrypt(&client_message.kahe_ciphertext, &decrypted_kahe_key)?;

        verify_that!(decrypted_plaintext.keys().collect::<Vec<_>>(), container_eq([&default_id]))?;
        let client_plaintext_length = client_plaintext.get(&default_id).unwrap().len();
        verify_eq!(
            decrypted_plaintext.get(&default_id).unwrap()[..client_plaintext_length],
            client_plaintext.get(&default_id).unwrap()[..]
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
            session_id: String::from("test"),
            willow_version: (1, 0),
        };

        // Generate public parameters for KAHE and AHE.
        let public_kahe_seed = SingleThreadHkdfPrng::generate_seed()?;

        // Create a client.
        let common = create_willow_common(&aggregation_config, CONTEXT_STRING);
        let client1_seed = SingleThreadHkdfPrng::generate_seed()?;
        let prng = SingleThreadHkdfPrng::create(&client1_seed)?;
        let mut client1 = WillowV1Client { common: common, prng: prng };

        // Create a second client.
        let common = create_willow_common(&aggregation_config, CONTEXT_STRING);
        let client2_seed = SingleThreadHkdfPrng::generate_seed()?;
        let prng = SingleThreadHkdfPrng::create(&client2_seed)?;
        let mut client2 = WillowV1Client { common: common, prng: prng };

        // Generate AHE keys.
        let common = create_willow_common(&aggregation_config, CONTEXT_STRING);
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (sk_share, pk_share, _) = common.vahe.key_gen(&mut prng)?;
        let public_key = common.vahe.aggregate_public_key_shares(&[pk_share])?;

        // Create client messages.
        let client1_plaintext = HashMap::from([(
            default_id.clone(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1],
        )]);
        let client2_plaintext = HashMap::from([(
            default_id.clone(),
            vec![1, 1, 2, 3, 5, 8, 3, 1, 4, 5, 9, 4, 3, 7, 0],
        )]);
        let expected_output = vec![2, 3, 5, 7, 10, 14, 10, 9, 11, 11, 14, 8, 6, 9, 1];
        let mut client_message = client1.create_client_message(&client1_plaintext, &public_key)?;
        let extra_message = client2.create_client_message(&client2_plaintext, &public_key)?;

        // Add extra message to the first client message.
        common.kahe.add_ciphertexts_in_place(
            &extra_message.kahe_ciphertext,
            &mut client_message.kahe_ciphertext,
        )?;
        common.vahe.add_ciphertexts_in_place(
            &extra_message.ahe_ciphertext,
            &mut client_message.ahe_ciphertext,
        )?;

        // Decrypt client message.
        let decryption_request =
            common.vahe.get_partial_dec_ciphertext(&client_message.ahe_ciphertext)?;
        let rest_of_ciphertext =
            common.vahe.get_recover_ciphertext(&client_message.ahe_ciphertext)?;
        let partial_decryption =
            common.vahe.partial_decrypt(&decryption_request, &sk_share, &mut prng)?;
        let decrypted_kahe_key =
            common.vahe.recover(&partial_decryption, &rest_of_ciphertext, None)?;
        let decrypted_kahe_key = common.kahe.try_secret_key_from(decrypted_kahe_key)?;
        let decrypted_plaintext =
            common.kahe.decrypt(&client_message.kahe_ciphertext, &decrypted_kahe_key)?;

        verify_that!(decrypted_plaintext.keys().collect::<Vec<_>>(), container_eq([&default_id]))?;
        let client_plaintext_length = client1_plaintext.get(&default_id).unwrap().len();
        verify_eq!(
            decrypted_plaintext.get(&default_id).unwrap()[..client_plaintext_length],
            expected_output
        )
    }
}
