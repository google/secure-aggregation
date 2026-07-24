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

use accumulator_traits::SecureAggregationCiphertextAccumulator;
use ahe_traits::PartialDec;
use kahe_traits::{HasKahe, KaheBase, KaheDecrypt, TrySecretKeyFrom};
use messages::{
    CiphertextContribution, ClientMessage, DecryptionRequestContribution,
    FinalizedPartialDecryption,
};
use messages_rust_proto::ServerState as ServerStateProto;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::AsView;
use shell_ciphertexts_rust_proto::{
    ShellAhePartialDecryption, ShellAheRecoverCiphertext, ShellKaheCiphertext,
};
use status::StatusError;
use std::rc::Rc;
use vahe_traits::{EncryptVerify, HasVahe, Recover, VaheBase};

/// Implements the `accumulator` role in the Willow protocol. This includes
/// aggregating client ciphertexts, and recovering the aggregation result after
/// receiving partial decryption responses from the decryptors.
pub struct WillowV1CiphertextAccumulator<Kahe: KaheBase, Vahe: VaheBase> {
    pub kahe: Rc<Kahe>,
    pub vahe: Rc<Vahe>,
}

impl<Kahe: KaheBase, Vahe: VaheBase> HasKahe for WillowV1CiphertextAccumulator<Kahe, Vahe> {
    type Kahe = Kahe;
    fn kahe(&self) -> &Self::Kahe {
        &self.kahe
    }
}

impl<Kahe: KaheBase, Vahe: VaheBase> HasVahe for WillowV1CiphertextAccumulator<Kahe, Vahe> {
    type Vahe = Vahe;
    fn vahe(&self) -> &Self::Vahe {
        &self.vahe
    }
}

/// State for the accumulator.
pub struct CiphertextAccumulatorState<Kahe: KaheBase, Vahe: VaheBase + PartialDec> {
    /// Running sum of client ciphertexts.
    client_sum: Option<(Kahe::Ciphertext, Vahe::RecoverCiphertext)>,
}

impl<Kahe: KaheBase, Vahe: VaheBase + PartialDec> Default
    for CiphertextAccumulatorState<Kahe, Vahe>
{
    fn default() -> Self {
        Self { client_sum: None }
    }
}

impl<Kahe: KaheBase, Vahe: VaheBase + PartialDec> Clone for CiphertextAccumulatorState<Kahe, Vahe> {
    fn clone(&self) -> Self {
        Self { client_sum: self.client_sum.clone() }
    }
}

impl<'a, C, Kahe, Vahe> ToProto<&'a C> for CiphertextAccumulatorState<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + PartialDec + 'a,
    Kahe::Ciphertext: ToProto<&'a Kahe, Proto = ShellKaheCiphertext>, // TODO: Rename protos to be generic once cl/836370582 has landed.
    Vahe::RecoverCiphertext: ToProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
{
    type Proto = ServerStateProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = ServerStateProto::new();

        if let Some((kahe, ahe)) = &self.client_sum {
            proto.set_client_sum_kahe(kahe.to_proto(context.kahe())?);
            proto.set_client_sum_ahe_recover(ahe.to_proto(context.vahe())?);
        }

        Ok(proto)
    }
}

impl<'a, C, Kahe, Vahe> FromProto<&'a C> for CiphertextAccumulatorState<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + PartialDec + 'a,
    Kahe::Ciphertext: FromProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::RecoverCiphertext: FromProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
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

        Ok(CiphertextAccumulatorState { client_sum })
    }
}

impl<Kahe, Vahe> SecureAggregationCiphertextAccumulator
    for WillowV1CiphertextAccumulator<Kahe, Vahe>
where
    Vahe: EncryptVerify + PartialDec + Recover,
    Kahe: KaheBase + TrySecretKeyFrom<Vahe::Plaintext> + KaheDecrypt,
{
    /// The state held by the accumulator between messages.
    type CiphertextAccumulatorState = CiphertextAccumulatorState<Kahe, Vahe>;
    /// The result of the aggregation.
    type AggregationResult = Kahe::Plaintext;

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

    /// Accumulates a single client's ciphertext contribution, updating the accumulator state.
    fn accumulate_ciphertext_contribution(
        &self,
        contribution: CiphertextContribution<Kahe, Vahe>,
        accumulator_state: &mut Self::CiphertextAccumulatorState,
    ) -> Result<(), status::StatusError> {
        if let Some((ref mut kahe_ciphertext, ref mut ahe_recover_ciphertext)) =
            accumulator_state.client_sum
        {
            self.kahe.add_ciphertexts_in_place(&contribution.kahe_ciphertext, kahe_ciphertext)?;
            self.vahe.add_recover_ciphertexts_in_place(
                &contribution.ahe_recover_ciphertext,
                ahe_recover_ciphertext,
            )?;
        } else {
            accumulator_state.client_sum =
                Some((contribution.kahe_ciphertext, contribution.ahe_recover_ciphertext));
        }
        Ok(())
    }

    /// Recovers the aggregation result from the accumulated ciphertext contributions
    /// and the finalized partial decryption.
    fn recover_aggregation_result(
        &self,
        accumulator_state: &Self::CiphertextAccumulatorState,
        finalized_partial_decryption: &FinalizedPartialDecryption<Vahe>,
    ) -> Result<Self::AggregationResult, status::StatusError> {
        if let Some((ref kahe_ciphertext, ref recover_ciphertext)) = accumulator_state.client_sum {
            let partial_decryption_sum = &finalized_partial_decryption.partial_decryption_sum;
            let ahe_plaintext =
                self.vahe.recover(partial_decryption_sum, &recover_ciphertext, None)?;
            let kahe_secret_key = self.kahe.try_secret_key_from(ahe_plaintext)?;
            let kahe_plaintext = self.kahe.decrypt(kahe_ciphertext, &kahe_secret_key)?;
            Ok(kahe_plaintext)
        } else {
            Err(status::failed_precondition(
                "Must handle at least one client message before requesting recovery",
            ))?
        }
    }

    /// Merges two accumulator states into one. The resulting state will contain the sums of the two
    /// client sums and partial decryption sums.
    fn merge_states(
        &self,
        accumulator_state_1: Self::CiphertextAccumulatorState,
        accumulator_state_2: Self::CiphertextAccumulatorState,
    ) -> Result<Self::CiphertextAccumulatorState, status::StatusError> {
        let mut merged_accumulator_state = CiphertextAccumulatorState::default();

        merged_accumulator_state.client_sum =
            match (accumulator_state_1.client_sum, accumulator_state_2.client_sum) {
                (
                    Some((kahe_ciphertext_1, ahe_recover_ciphertext_1)),
                    Some((kahe_ciphertext_2, ahe_recover_ciphertext_2)),
                ) => {
                    let mut merged_kahe_ciphertext = kahe_ciphertext_1;
                    let mut merged_ahe_recover_ciphertext = ahe_recover_ciphertext_1;
                    self.kahe.add_ciphertexts_in_place(
                        &kahe_ciphertext_2,
                        &mut merged_kahe_ciphertext,
                    )?;
                    self.vahe.add_recover_ciphertexts_in_place(
                        &ahe_recover_ciphertext_2,
                        &mut merged_ahe_recover_ciphertext,
                    )?;
                    Some((merged_kahe_ciphertext, merged_ahe_recover_ciphertext))
                }
                (Some(s), None) | (None, Some(s)) => Some(s),
                (None, None) => None,
            };

        Ok(merged_accumulator_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use accumulator_traits::SecureAggregationCiphertextAccumulator;
    use ahe_traits::AheBase;
    use client_traits::SecureAggregationClient;
    use decryptor_traits::SecureAggregationDecryptor;
    use googletest::{gtest, verify_eq, verify_true};
    use proto_serialization_traits::{FromProto, ToProto};
    use shell_kahe::ShellKahe;
    use shell_parameters::{create_shell_ahe_config, create_shell_kahe_config};
    use shell_vahe::ShellVahe;
    use std::collections::HashMap;
    use testing_utils::{generate_aggregation_config, generate_random_nonce};
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

        // Create common KAHE/VAHE instances.
        let kahe = Rc::new(ShellKahe::new(
            create_shell_kahe_config(&aggregation_config)?,
            CONTEXT_STRING,
        )?);
        let vahe = Rc::new(ShellVahe::new(
            create_shell_ahe_config(max_number_of_decryptors)?,
            CONTEXT_STRING,
        )?);

        // Create client.
        let client = WillowV1Client::new_with_randomly_generated_seed(kahe.clone(), vahe.clone())?;

        // Create decryptor.
        let mut decryptor_state = DecryptorState::default();
        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe))?;

        // Create accumulator.
        let accumulator =
            WillowV1CiphertextAccumulator { kahe: kahe.clone(), vahe: Rc::clone(&vahe) };
        let mut accumulator_state = CiphertextAccumulatorState::default();

        // Create verifier.
        let verifier = WillowV1Verifier { vahe: vahe.clone() };
        let mut verifier_state = VerifierState::default();

        // Check empty state serialization
        let accumulator_state_proto = accumulator_state.to_proto(&accumulator)?;
        let accumulator_state_roundtrip =
            CiphertextAccumulatorState::from_proto(accumulator_state_proto, &accumulator)?;
        verify_true!(accumulator_state_roundtrip.client_sum.is_none())?;

        // Populate accumulator state.
        let public_key_share = decryptor.create_public_key_share(&mut decryptor_state)?;
        // Aggregate public key share directly.
        let public_key = vahe.aggregate_public_key_shares(std::iter::once(&public_key_share))?;
        let client_plaintext = HashMap::from([(
            DEFAULT_VECTOR_ID.to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1],
        )]);
        let nonce = generate_random_nonce();
        let client_message = client.create_client_message(
            &ShellKahe::plaintext_as_slice(&client_plaintext),
            &public_key,
            &nonce,
        )?;
        let (ciphertext_contribution, decryption_request_contribution) =
            accumulator.split_client_message(client_message)?;
        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state)?;
        accumulator
            .accumulate_ciphertext_contribution(ciphertext_contribution, &mut accumulator_state)?;
        let pd_ct = verifier.create_partial_decryption_request(verifier_state)?;
        let pd = decryptor.handle_partial_decryption_request(pd_ct, &mut decryptor_state)?;

        // Check populated state serialization
        verify_true!(accumulator_state.client_sum.is_some())?;
        let accumulator_state_proto = accumulator_state.to_proto(&accumulator)?;
        let accumulator_state_roundtrip =
            CiphertextAccumulatorState::from_proto(accumulator_state_proto, &accumulator)?;
        verify_true!(accumulator_state_roundtrip.client_sum.is_some())?;

        // Check recovery
        let finalized_pd =
            FinalizedPartialDecryption { partial_decryption_sum: pd.partial_decryption };
        let recovered =
            accumulator.recover_aggregation_result(&accumulator_state, &finalized_pd)?;
        verify_eq!(recovered, client_plaintext)?;

        Ok(())
    }
}
