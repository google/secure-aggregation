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

use ahe_traits::{AheBase, PartialDec};
use kahe_traits::{KaheBase, KaheDecrypt, TrySecretKeyFrom};
use server_traits::SecureAggregationServer;
use vahe_traits::{EncryptVerify, Recover, VaheBase};
use willow_v1_common::{
    CiphertextContribution, DecryptionRequestContribution, DecryptorPublicKey,
    DecryptorPublicKeyShare, PartialDecryptionResponse, WillowClientMessage, WillowCommon,
};

/// The server struct, containing a WillowCommon instance. Only the clients messages are verified,
/// not the key generation or partial decryptions.
pub struct WillowV1Server<Kahe, Vahe: VaheBase> {
    pub common: WillowCommon<Kahe, Vahe>,
}

/// State for the server.
pub struct ServerState<Kahe: KaheBase, Vahe: VaheBase + PartialDec> {
    decryptor_public_key_shares: Vec<DecryptorPublicKeyShare<Vahe>>,
    client_sum: Option<(Kahe::Ciphertext, Vahe::RecoverCiphertext)>,
    partial_decryption_sum: Option<Vahe::PartialDecryption>,
}

impl<Kahe: KaheBase, Vahe: VaheBase + PartialDec> Default for ServerState<Kahe, Vahe> {
    fn default() -> Self {
        Self { decryptor_public_key_shares: vec![], client_sum: None, partial_decryption_sum: None }
    }
}

impl<Kahe: KaheBase, Vahe: VaheBase + PartialDec> Clone for ServerState<Kahe, Vahe> {
    fn clone(&self) -> Self {
        Self {
            decryptor_public_key_shares: self.decryptor_public_key_shares.clone(),
            client_sum: self.client_sum.clone(),
            partial_decryption_sum: self.partial_decryption_sum.clone(),
        }
    }
}

impl<Kahe, Vahe> SecureAggregationServer<WillowCommon<Kahe, Vahe>> for WillowV1Server<Kahe, Vahe>
where
    Vahe: EncryptVerify + PartialDec + Recover,
    Kahe: KaheBase + TrySecretKeyFrom<Vahe::Plaintext> + KaheDecrypt,
{
    /// The state held by the server between messages.
    type ServerState = ServerState<Kahe, Vahe>;
    /// The result of the aggregation.
    type AggregationResult = Kahe::Plaintext;

    /// Handles a public key share received from a Decryptor, updating the
    /// server state.
    fn handle_decryptor_public_key_share(
        &self,
        key_share: DecryptorPublicKeyShare<Vahe>,
        server_state: &mut Self::ServerState,
    ) -> Result<(), status::StatusError> {
        server_state.decryptor_public_key_shares.push(key_share);
        Ok(())
    }

    /// Returns the public key to be sent to the client after enough shares have
    /// been received from Decryptors.
    fn create_decryptor_public_key(
        &self,
        server_state: &Self::ServerState,
    ) -> Result<DecryptorPublicKey<Vahe>, status::StatusError> {
        Ok(self
            .common
            .vahe
            .aggregate_public_key_shares(&server_state.decryptor_public_key_shares)?)
    }

    /// Splits a client message into the ciphertext contribution and the
    /// decryption request contribution.
    fn split_client_message(
        &self,
        client_message: WillowClientMessage<Kahe, Vahe>,
    ) -> Result<
        (CiphertextContribution<Kahe, Vahe>, DecryptionRequestContribution<Vahe>),
        status::StatusError,
    > {
        let partial_dec_ciphertext =
            self.common.vahe.get_partial_dec_ciphertext(&client_message.ahe_ciphertext)?;
        let ahe_recover_ciphertext =
            self.common.vahe.get_recover_ciphertext(&client_message.ahe_ciphertext)?;
        Ok((
            CiphertextContribution {
                kahe_ciphertext: client_message.kahe_ciphertext,
                ahe_recover_ciphertext,
            },
            DecryptionRequestContribution {
                partial_dec_ciphertext,
                proof: client_message.proof,
                nonce: client_message.nonce,
            },
        ))
    }

    /// Handles a single client's ciphertext contribution, updating the server state.
    fn handle_ciphertext_contribution(
        &self,
        contribution: CiphertextContribution<Kahe, Vahe>,
        server_state: &mut Self::ServerState,
    ) -> Result<(), status::StatusError> {
        if let Some((ref mut kahe_ciphertext, ref mut ahe_recover_ciphertext)) =
            server_state.client_sum
        {
            self.common
                .kahe
                .add_ciphertexts_in_place(&contribution.kahe_ciphertext, kahe_ciphertext)?;
            self.common.vahe.add_recover_ciphertexts_in_place(
                &contribution.ahe_recover_ciphertext,
                ahe_recover_ciphertext,
            )?;
        } else {
            server_state.client_sum =
                Some((contribution.kahe_ciphertext, contribution.ahe_recover_ciphertext));
        }
        Ok(())
    }

    /// Handles a partial decryption response received from a Decryptor, updating the
    /// server state.
    fn handle_partial_decryption(
        &self,
        partial_decryption_response: PartialDecryptionResponse<Vahe>,
        server_state: &mut Self::ServerState,
    ) -> Result<(), status::StatusError> {
        let partial_decryption = partial_decryption_response.partial_decryption;
        if let Some(ref mut partial_decryption_sum) = server_state.partial_decryption_sum {
            self.common
                .vahe
                .add_partial_decryptions_in_place(&partial_decryption, partial_decryption_sum)?;
        } else {
            server_state.partial_decryption_sum = Some(partial_decryption);
        }
        Ok(())
    }

    /// Recovers the aggregation result after enough partial decryptions have
    /// been received from Decryptors.
    fn recover_aggregation_result(
        &self,
        server_state: &Self::ServerState,
    ) -> Result<Self::AggregationResult, status::StatusError> {
        if let Some((ref kahe_ciphertext, ref recover_ciphertext)) = server_state.client_sum {
            if let Some(ref partial_decryption_sum) = server_state.partial_decryption_sum {
                let ahe_plaintext =
                    self.common.vahe.recover(&partial_decryption_sum, &recover_ciphertext, None)?;
                let kahe_secret_key = self.common.kahe.try_secret_key_from(ahe_plaintext)?;
                let kahe_plaintext = self.common.kahe.decrypt(kahe_ciphertext, &kahe_secret_key)?;
                Ok(kahe_plaintext)
            } else {
                Err(status::failed_precondition(
                    "Must handle at least one partial decryption before requesting recovery",
                ))?
            }
        } else {
            Err(status::failed_precondition(
                "Must handle at least one client message before requesting recovery",
            ))?
        }
    }
}
