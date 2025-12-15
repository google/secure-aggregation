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

use ahe_traits::PartialDec;
use kahe_traits::{HasKahe, KaheBase, KaheDecrypt, TrySecretKeyFrom};
use messages::{
    CiphertextContribution, ClientMessage, DecryptionRequestContribution, DecryptorPublicKey,
    DecryptorPublicKeyShare, PartialDecryptionResponse,
};
use messages_rust_proto::ServerStateProto;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::AsView;
use server_traits::SecureAggregationServer;
use shell_ciphertexts_rust_proto::{
    ShellAhePartialDecryption, ShellAhePublicKeyShare, ShellAheRecoverCiphertext,
    ShellKaheCiphertext,
};
use status::StatusError;
use std::collections::HashMap;
use vahe_traits::{EncryptVerify, HasVahe, Recover, VaheBase};

/// Implements the `server` role in the Willow protocol. This includes aggregating public key shares
/// from the decryptors, aggregating client ciphertexts, and recovering the aggregation result after
/// receiving partial decryption responses from the decryptors.
pub struct WillowV1Server<Kahe: KaheBase, Vahe: VaheBase> {
    pub kahe: Kahe,
    pub vahe: Vahe,
}

impl<Kahe: KaheBase, Vahe: VaheBase> HasKahe for WillowV1Server<Kahe, Vahe> {
    type Kahe = Kahe;
    fn kahe(&self) -> &Self::Kahe {
        &self.kahe
    }
}

impl<Kahe: KaheBase, Vahe: VaheBase> HasVahe for WillowV1Server<Kahe, Vahe> {
    type Vahe = Vahe;
    fn vahe(&self) -> &Self::Vahe {
        &self.vahe
    }
}

/// State for the server.
pub struct ServerState<Kahe: KaheBase, Vahe: VaheBase + PartialDec> {
    /// The public key shares received from Decryptors. The key is the ID of the Decryptor.
    decryptor_public_key_shares: HashMap<String, DecryptorPublicKeyShare<Vahe>>,
    /// Running sum of client ciphertexts.
    client_sum: Option<(Kahe::Ciphertext, Vahe::RecoverCiphertext)>,
    /// Running sum of partial decryption ciphertexts.
    partial_decryption_sum: Option<Vahe::PartialDecryption>,
}

impl<Kahe: KaheBase, Vahe: VaheBase + PartialDec> Default for ServerState<Kahe, Vahe> {
    fn default() -> Self {
        Self {
            decryptor_public_key_shares: HashMap::new(),
            client_sum: None,
            partial_decryption_sum: None,
        }
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

impl<'a, C, Kahe, Vahe> ToProto<&'a C> for ServerState<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + PartialDec + 'a,
    Kahe::Ciphertext: ToProto<&'a Kahe, Proto = ShellKaheCiphertext>, // TODO: Rename protos to be generic once cl/836370582 has landed.
    Vahe::RecoverCiphertext: ToProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
    Vahe::PartialDecryption: ToProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
    Vahe::PublicKeyShare: ToProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
{
    type Proto = ServerStateProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = ServerStateProto::new();

        if let Some((kahe, ahe)) = &self.client_sum {
            proto.set_client_sum_kahe(kahe.to_proto(context.kahe())?);
            proto.set_client_sum_ahe_recover(ahe.to_proto(context.vahe())?);
        }

        for (k, v) in &self.decryptor_public_key_shares {
            proto.decryptor_public_key_shares_mut().insert(k.as_str(), v.to_proto(context.vahe())?);
        }

        if let Some(pd) = &self.partial_decryption_sum {
            proto.set_partial_decryption_sum(pd.to_proto(context.vahe())?);
        }

        Ok(proto)
    }
}

impl<'a, C, Kahe, Vahe> FromProto<&'a C> for ServerState<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + PartialDec + 'a,
    Kahe::Ciphertext: FromProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::RecoverCiphertext: FromProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
    Vahe::PartialDecryption: FromProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
    Vahe::PublicKeyShare: FromProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
{
    type Proto = ServerStateProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();

        let client_sum = if proto.has_client_sum_kahe() && proto.has_client_sum_ahe_recover() {
            Some((
                Kahe::Ciphertext::from_proto(proto.client_sum_kahe(), context.kahe())?,
                Vahe::RecoverCiphertext::from_proto(
                    proto.client_sum_ahe_recover(),
                    context.vahe(),
                )?,
            ))
        } else if !proto.has_client_sum_kahe() && !proto.has_client_sum_ahe_recover() {
            None
        } else {
            return Err(status::invalid_argument(
                "ServerStateProto must have both or neither of client_sum_kahe and \
                 client_sum_ahe_recover",
            ));
        };

        let mut decryptor_public_key_shares = HashMap::new();
        for (k, v) in proto.decryptor_public_key_shares() {
            decryptor_public_key_shares
                .insert(k.to_string(), Vahe::PublicKeyShare::from_proto(v, context.vahe())?);
        }

        let partial_decryption_sum = if proto.has_partial_decryption_sum() {
            Some(Vahe::PartialDecryption::from_proto(
                proto.partial_decryption_sum(),
                context.vahe(),
            )?)
        } else {
            None
        };

        Ok(ServerState { decryptor_public_key_shares, client_sum, partial_decryption_sum })
    }
}

impl<Kahe, Vahe> SecureAggregationServer for WillowV1Server<Kahe, Vahe>
where
    Vahe: EncryptVerify + PartialDec + Recover,
    Kahe: KaheBase + TrySecretKeyFrom<Vahe::Plaintext> + KaheDecrypt,
{
    /// The state held by the server between messages.
    type ServerState = ServerState<Kahe, Vahe>;
    /// The result of the aggregation.
    type AggregationResult = Kahe::Plaintext;

    /// Handles a public key share received from a Decryptor, updating the
    /// server state. `decryptor_id` is an arbitrary string and is used to deduplicate public key
    /// shares when merging server states.
    fn handle_decryptor_public_key_share(
        &self,
        key_share: DecryptorPublicKeyShare<Vahe>,
        decryptor_id: &str,
        server_state: &mut Self::ServerState,
    ) -> Result<(), status::StatusError> {
        if server_state.decryptor_public_key_shares.contains_key(decryptor_id) {
            return Err(status::failed_precondition(format!(
                "Public key share for decryptor with ID '{decryptor_id}' has already been handled."
            )));
        }
        server_state.decryptor_public_key_shares.insert(decryptor_id.to_string(), key_share);
        Ok(())
    }

    /// Returns the public key to be sent to the client after enough shares have
    /// been received from Decryptors.
    fn create_decryptor_public_key(
        &self,
        server_state: &Self::ServerState,
    ) -> Result<DecryptorPublicKey<Vahe>, status::StatusError> {
        Ok(self
            .vahe
            .aggregate_public_key_shares(server_state.decryptor_public_key_shares.values())?)
    }

    /// Splits a client message into the ciphertext contribution and the
    /// decryption request contribution.
    fn split_client_message(
        &self,
        client_message: ClientMessage<Kahe, Vahe>,
    ) -> Result<
        (CiphertextContribution<Kahe, Vahe>, DecryptionRequestContribution<Vahe>),
        status::StatusError,
    > {
        let partial_dec_ciphertext =
            self.vahe.get_partial_dec_ciphertext(&client_message.ahe_ciphertext)?;
        let ahe_recover_ciphertext =
            self.vahe.get_recover_ciphertext(&client_message.ahe_ciphertext)?;
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
            self.kahe.add_ciphertexts_in_place(&contribution.kahe_ciphertext, kahe_ciphertext)?;
            self.vahe.add_recover_ciphertexts_in_place(
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
            self.vahe
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
                    self.vahe.recover(&partial_decryption_sum, &recover_ciphertext, None)?;
                let kahe_secret_key = self.kahe.try_secret_key_from(ahe_plaintext)?;
                let kahe_plaintext = self.kahe.decrypt(kahe_ciphertext, &kahe_secret_key)?;
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

    /// Merges two server states into one. The resulting state will contain the sums of the two
    /// client sums and partial decryption sums. The public key shares will be merged by joining all
    /// public key shares with unique IDs. In case IDs are present in both server states, the public
    /// key share from `server_state_1` will be used.
    fn merge_server_states(
        &self,
        server_state_1: &Self::ServerState,
        server_state_2: &Self::ServerState,
    ) -> Result<Self::ServerState, status::StatusError> {
        let mut merged_server_state = ServerState::default();
        // Merge public key shares.
        merged_server_state.decryptor_public_key_shares =
            server_state_1.decryptor_public_key_shares.clone();
        for (id, key_share) in server_state_2.decryptor_public_key_shares.iter() {
            if !merged_server_state.decryptor_public_key_shares.contains_key(id) {
                merged_server_state
                    .decryptor_public_key_shares
                    .insert(id.to_string(), key_share.clone());
            }
        }

        merged_server_state.client_sum =
            match (&server_state_1.client_sum, &server_state_2.client_sum) {
                (
                    Some((kahe_ciphertext_1, ahe_recover_ciphertext_1)),
                    Some((kahe_ciphertext_2, ahe_recover_ciphertext_2)),
                ) => {
                    let mut merged_kahe_ciphertext = kahe_ciphertext_1.clone();
                    let mut merged_ahe_recover_ciphertext = ahe_recover_ciphertext_1.clone();
                    self.kahe
                        .add_ciphertexts_in_place(kahe_ciphertext_2, &mut merged_kahe_ciphertext)?;
                    self.vahe.add_recover_ciphertexts_in_place(
                        ahe_recover_ciphertext_2,
                        &mut merged_ahe_recover_ciphertext,
                    )?;
                    Some((merged_kahe_ciphertext, merged_ahe_recover_ciphertext))
                }
                (Some(s), None) | (None, Some(s)) => Some(s.clone()),
                (None, None) => None,
            };

        merged_server_state.partial_decryption_sum = match (
            &server_state_1.partial_decryption_sum,
            &server_state_2.partial_decryption_sum,
        ) {
            (Some(sum1), Some(sum2)) => {
                let mut merged_sum = sum1.clone();
                self.vahe.add_partial_decryptions_in_place(sum2, &mut merged_sum)?;
                Some(merged_sum)
            }
            (Some(s), None) | (None, Some(s)) => Some(s.clone()),
            (None, None) => None,
        };

        Ok(merged_server_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServerState, WillowV1Server};
    use ahe_traits::AheBase;
    use client_traits::SecureAggregationClient;
    use decryptor_traits::SecureAggregationDecryptor;
    use googletest::{gtest, verify_true};
    use kahe_shell::ShellKahe;
    use parameters_shell::{create_shell_ahe_config, create_shell_kahe_config};
    use prng_traits::SecurePrng;
    use proto_serialization_traits::{FromProto, ToProto};
    use server_traits::SecureAggregationServer;
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use std::collections::HashMap;
    use testing_utils::{generate_aggregation_config, generate_random_nonce};
    use vahe_shell::ShellVahe;
    use verifier_traits::SecureAggregationVerifier;
    use willow_v1_client::WillowV1Client;
    use willow_v1_decryptor::{DecryptorState, WillowV1Decryptor};
    use willow_v1_verifier::{VerifierState, WillowV1Verifier};

    const CONTEXT_STRING: &[u8] = b"testing_context_string";
    const DEFAULT_VECTOR_ID: &str = "default";

    #[gtest]
    fn server_state_serialization_roundtrip() -> googletest::Result<()> {
        let aggregation_config =
            generate_aggregation_config(DEFAULT_VECTOR_ID.to_string(), 16, 10, 1, 1);
        let max_number_of_decryptors = aggregation_config.max_number_of_decryptors;

        // Create client.
        let kahe =
            ShellKahe::new(create_shell_kahe_config(&aggregation_config).unwrap(), CONTEXT_STRING)
                .unwrap();
        let vahe = ShellVahe::new(
            create_shell_ahe_config(max_number_of_decryptors).unwrap(),
            CONTEXT_STRING,
        )
        .unwrap();
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let prng = SingleThreadHkdfPrng::create(&seed)?;
        let mut client = WillowV1Client { kahe, vahe, prng };

        // Create decryptor.
        let vahe = ShellVahe::new(
            create_shell_ahe_config(max_number_of_decryptors).unwrap(),
            CONTEXT_STRING,
        )
        .unwrap();
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let prng = SingleThreadHkdfPrng::create(&seed)?;
        let mut decryptor_state = DecryptorState::default();
        let mut decryptor = WillowV1Decryptor { vahe, prng };

        // Create server.
        let kahe =
            ShellKahe::new(create_shell_kahe_config(&aggregation_config).unwrap(), CONTEXT_STRING)
                .unwrap();
        let vahe = ShellVahe::new(
            create_shell_ahe_config(max_number_of_decryptors).unwrap(),
            CONTEXT_STRING,
        )
        .unwrap();
        let server = WillowV1Server { kahe, vahe };
        let mut server_state = ServerState::default();

        // Create verifier.
        let vahe = ShellVahe::new(
            create_shell_ahe_config(max_number_of_decryptors).unwrap(),
            CONTEXT_STRING,
        )
        .unwrap();
        let verifier = WillowV1Verifier { vahe };
        let mut verifier_state = VerifierState::default();

        // Check empty state serialization
        let server_state_proto = server_state.to_proto(&server)?;
        let server_state_roundtrip = ServerState::from_proto(server_state_proto, &server)?;
        verify_true!(server_state_roundtrip.decryptor_public_key_shares.is_empty())?;
        verify_true!(server_state_roundtrip.client_sum.is_none())?;
        verify_true!(server_state_roundtrip.partial_decryption_sum.is_none())?;

        // Populate server state.
        let public_key_share = decryptor.create_public_key_share(&mut decryptor_state)?;
        server.handle_decryptor_public_key_share(
            public_key_share,
            "Decryptor 0",
            &mut server_state,
        )?;
        let public_key = server.create_decryptor_public_key(&server_state)?;
        let client_plaintext = HashMap::from([(
            DEFAULT_VECTOR_ID.to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1],
        )]);
        let nonce = generate_random_nonce();
        let client_message = client.create_client_message(
            &ShellKahe::plaintext_as_slice(&client_plaintext),
            &public_key,
            &nonce,
        )?;
        let (ciphertext_contribution, decryption_request_contribution) =
            server.split_client_message(client_message)?;
        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state)?;
        server.handle_ciphertext_contribution(ciphertext_contribution, &mut server_state)?;
        let pd_ct = verifier.create_partial_decryption_request(verifier_state)?;
        let pd = decryptor.handle_partial_decryption_request(pd_ct, &decryptor_state)?;
        server.handle_partial_decryption(pd, &mut server_state)?;

        // Check populated state serialization
        verify_true!(!server_state.decryptor_public_key_shares.is_empty())?;
        verify_true!(server_state.client_sum.is_some())?;
        verify_true!(server_state.partial_decryption_sum.is_some())?;
        let server_state_proto = server_state.to_proto(&server)?;
        let server_state_roundtrip = ServerState::from_proto(server_state_proto, &server)?;
        verify_true!(!server_state_roundtrip.decryptor_public_key_shares.is_empty())?;
        verify_true!(server_state_roundtrip.client_sum.is_some())?;
        verify_true!(server_state_roundtrip.partial_decryption_sum.is_some())?;

        Ok(())
    }
}
