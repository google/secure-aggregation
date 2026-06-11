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

use aggregation_config::AggregationConfig;
use ahe_traits::{AheKeygen, PartialDec};
use decryptor_traits::{
    SecureAggregationBaseMultiDecryptor, SecureAggregationDecryptor,
    SecureAggregationNonReputableMultiDecryptor, SecureAggregationReputableDecryptor,
};
use kahe_traits::KaheBase;
use messages::{
    DecryptorPublicKey, DecryptorPublicKeyShare, KeyContribution, PartialDecryptionRequest,
    PartialDecryptionResponse, RecoveryRequest, RecoveryResponse, SetupContribution,
    VerifyKeyContributionsRequest,
};
use messages_rust_proto::DecryptorState as DecryptorStateProto;
use prng_traits::SecurePrng;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::AsView;
use shell_ciphertexts_rust_proto::ShellAheSecretKeyShare;
use shell_kahe::ShellKahe;
use status::StatusError;
use std::cell::RefCell;
use std::rc::Rc;
use vahe_traits::{EncryptVerify, HasVahe, KeyGenVerify, VaheBase, VerifiableKeyGen};

/// Lightweight decryptor directly exposing VAHE types.
///
/// This struct supports both single-decryptor mode (via `SecureAggregationDecryptor`)
/// and multi-decryptor mode (via `SecureAggregationBaseMultiDecryptor`,
/// `SecureAggregationReputableDecryptor`, `SecureAggregationNonReputableMultiDecryptor`).
/// The difference between reputable and non-reputable is in which trait methods are called.
pub struct WillowV1Decryptor<Vahe: VaheBase> {
    pub vahe: Rc<Vahe>,
    pub prng: RefCell<Vahe::Rng>,
}

impl<Vahe: VaheBase> HasVahe for WillowV1Decryptor<Vahe> {
    type Vahe = Vahe;
    fn vahe(&self) -> &Self::Vahe {
        &self.vahe
    }
}

impl<Vahe: VaheBase> WillowV1Decryptor<Vahe> {
    pub fn new_with_randomly_generated_seed(vahe: Rc<Vahe>) -> Result<Self, status::StatusError> {
        let seed = Vahe::Rng::generate_seed()?;
        let prng = RefCell::new(Vahe::Rng::create(&seed)?);
        Ok(Self { vahe, prng })
    }
}

pub struct DecryptorState<Vahe: VaheBase> {
    pub sk_share: Option<Vahe::SecretKeyShare>,
    pub kahe: Option<Rc<ShellKahe>>,
    pub aggregation_config: Option<AggregationConfig>,
}

impl<Vahe: VaheBase> Default for DecryptorState<Vahe> {
    fn default() -> Self {
        Self { sk_share: None, kahe: None, aggregation_config: None }
    }
}

impl<'a, C, Vahe> ToProto<&'a C> for DecryptorState<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::SecretKeyShare: ToProto<&'a Vahe, Proto = ShellAheSecretKeyShare>,
{
    type Proto = DecryptorStateProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = DecryptorStateProto::new();
        if let Some(sk) = &self.sk_share {
            proto.set_sk_share(sk.to_proto(context.vahe())?);
        }
        if let Some(config) = &self.aggregation_config {
            proto.set_aggregation_config(config.to_proto(())?);
        }
        Ok(proto)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for DecryptorState<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::SecretKeyShare: FromProto<&'a Vahe, Proto = ShellAheSecretKeyShare>,
{
    type Proto = DecryptorStateProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let sk_share = if proto.has_sk_share() {
            Some(Vahe::SecretKeyShare::from_proto(proto.sk_share(), context.vahe())?)
        } else {
            None
        };
        let aggregation_config = if proto.has_aggregation_config() {
            Some(AggregationConfig::from_proto(proto.aggregation_config(), ())?)
        } else {
            None
        };
        let kahe = if let Some(config) = &aggregation_config {
            use shell_parameters::create_shell_configs;
            let (kahe_config, _) = create_shell_configs(config)?;
            Some(Rc::new(ShellKahe::new(kahe_config, &config.key_id)?))
        } else {
            None
        };
        Ok(DecryptorState { sk_share, kahe, aggregation_config })
    }
}

// Shared helpers used by both single- and multi-decryptor trait implementations.
impl<Vahe> WillowV1Decryptor<Vahe>
where
    Vahe: VaheBase + PartialDec,
{
    /// Computes a partial decryption using the secret key share from the decryptor state.
    fn compute_partial_decryption(
        &self,
        partial_dec_ciphertext: &Vahe::PartialDecCiphertext,
        decryptor_state: &DecryptorState<Vahe>,
    ) -> Result<Vahe::PartialDecryption, StatusError> {
        let sk_share = decryptor_state.sk_share.as_ref().ok_or_else(|| {
            status::failed_precondition("decryptor_state does not contain a secret key share")
        })?;
        // `borrow_mut()` will not panic here because `self.prng` is not
        // borrowed anywhere else in this call.
        self.vahe.partial_decrypt(partial_dec_ciphertext, sk_share, &mut self.prng.borrow_mut())
    }
}

/// Implementation of the `SecureAggregationDecryptor` trait for the generic
/// KAHE/AHE decryptor, using WillowCommon as the common types (e.g. protocol
/// messages are directly the AHE public key and ciphertexts).
///
impl<Vahe> SecureAggregationDecryptor for WillowV1Decryptor<Vahe>
where
    Vahe: VaheBase + EncryptVerify + PartialDec + AheKeygen,
{
    type DecryptorState = DecryptorState<Vahe>;
    type Kahe = ShellKahe;

    /// Creates a public key share to be sent to the Server, updating the
    /// decryptor state.
    fn create_public_key_share(
        &self,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<DecryptorPublicKeyShare<Vahe>, status::StatusError> {
        let (sk_share, pk_share, _) = self.vahe.key_gen(&mut self.prng.borrow_mut())?;
        decryptor_state.sk_share = Some(sk_share);
        Ok(pk_share)
    }

    /// Handles a partial decryption request received from the Server. Returns a
    /// partial decryption to the Server.
    fn handle_partial_decryption_request(
        &self,
        partial_decryption_request: PartialDecryptionRequest<Vahe>,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<PartialDecryptionResponse<ShellKahe, Vahe>, status::StatusError> {
        if let Some(config) = &partial_decryption_request.aggregation_config {
            if decryptor_state.kahe.is_none() {
                use shell_parameters::create_shell_configs;
                let (kahe_config, _) = create_shell_configs(config)?;
                decryptor_state.kahe = Some(Rc::new(ShellKahe::new(kahe_config, &config.key_id)?));
                decryptor_state.aggregation_config = Some(config.clone());
            }
        }
        let pd = self.compute_partial_decryption(
            &partial_decryption_request.partial_dec_ciphertext,
            decryptor_state,
        )?;
        Ok(PartialDecryptionResponse { partial_decryption: pd, dp_ciphertext_contribution: None })
    }
}

// --- Multi-decryptor trait implementations ---

impl<Vahe> SecureAggregationBaseMultiDecryptor for WillowV1Decryptor<Vahe>
where
    Vahe: VaheBase + VerifiableKeyGen + PartialDec + AheKeygen,
{
    type DecryptorState = DecryptorState<Vahe>;

    fn create_setup_contribution(
        &self,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<SetupContribution<Self::Vahe>, StatusError> {
        let (sk_share, pk_share, key_gen_proof) =
            self.vahe.verifiable_key_gen(&mut self.prng.borrow_mut())?;

        decryptor_state.sk_share = Some(sk_share);

        Ok(SetupContribution {
            key_contribution: KeyContribution {
                public_key_share: pk_share,
                proof: Some(key_gen_proof),
            },
            dp_setup: None,
            encrypted_randomness_shares: None,
        })
    }

    fn handle_partial_decryption_request<Kahe: KaheBase>(
        &self,
        partial_decryption_request: PartialDecryptionRequest<<Self as HasVahe>::Vahe>,
        _kahe: Option<&Kahe>,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<PartialDecryptionResponse<Kahe, <Self as HasVahe>::Vahe>, StatusError> {
        let pd = self.compute_partial_decryption(
            &partial_decryption_request.partial_dec_ciphertext,
            decryptor_state,
        )?;
        Ok(PartialDecryptionResponse { partial_decryption: pd, dp_ciphertext_contribution: None })
    }
}

impl<Vahe> SecureAggregationReputableDecryptor for WillowV1Decryptor<Vahe>
where
    Vahe: VaheBase + VerifiableKeyGen + KeyGenVerify + PartialDec + AheKeygen,
{
    fn verify_and_aggregate_key_contributions(
        &self,
        request: VerifyKeyContributionsRequest<<Self as HasVahe>::Vahe>,
    ) -> Result<DecryptorPublicKey<<Self as HasVahe>::Vahe>, StatusError> {
        if request.key_contributions.is_empty() {
            return Err(status::invalid_argument("key_contributions list is empty"));
        }

        // Verify all proofs.
        for key_contribution in &request.key_contributions {
            let proof = key_contribution.proof.as_ref().ok_or_else(|| {
                status::invalid_argument(
                    "Missing key generation proof in VerifyKeyContributionsRequest",
                )
            })?;
            self.vahe.verify_key_gen(proof, &key_contribution.public_key_share)?;
        }

        // Aggregate all public key shares into the final public key.
        let public_key_shares: Vec<_> =
            request.key_contributions.iter().map(|kc| &kc.public_key_share).collect();

        self.vahe.aggregate_public_key_shares(public_key_shares.into_iter())
    }
}

impl<Vahe> SecureAggregationNonReputableMultiDecryptor for WillowV1Decryptor<Vahe>
where
    Vahe: VaheBase + VerifiableKeyGen + PartialDec + AheKeygen,
{
    fn handle_recovery_request(
        &self,
        _recovery_request: RecoveryRequest,
        _decryptor_state: &mut Self::DecryptorState,
    ) -> Result<RecoveryResponse, StatusError> {
        // Secret sharing / dropout recovery is not yet implemented.
        Err(status::unimplemented("Dropout recovery is not yet implemented"))
    }
}

#[cfg(test)]
mod tests {
    use crate::{DecryptorState, WillowV1Decryptor};
    use ahe_traits::AheBase;
    use decryptor_traits::SecureAggregationDecryptor;
    use googletest::{gtest, verify_true};
    use proto_serialization_traits::{FromProto, ToProto};
    use shell_parameters::create_shell_ahe_config;
    use shell_vahe::ShellVahe;
    use std::rc::Rc;

    const CONTEXT_STRING: &[u8] = b"testing_context_string";

    #[gtest]
    fn decryptor_state_serialization_roundtrip() -> googletest::Result<()> {
        let vahe =
            Rc::new(ShellVahe::new(create_shell_ahe_config(1).unwrap(), CONTEXT_STRING).unwrap());
        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(vahe)?;
        let mut decryptor_state = DecryptorState::default();

        // Check empty state serialization.
        let decryptor_state_proto = decryptor_state.to_proto(&decryptor)?;
        let decryptor_state_roundtrip =
            DecryptorState::from_proto(decryptor_state_proto, &decryptor)?;
        verify_true!(decryptor_state_roundtrip.sk_share.is_none())?;

        // Check populated state serialization.
        decryptor.create_public_key_share(&mut decryptor_state)?;
        verify_true!(decryptor_state.sk_share.is_some())?;
        let decryptor_state_proto = decryptor_state.to_proto(&decryptor)?;
        let decryptor_state_roundtrip =
            DecryptorState::from_proto(decryptor_state_proto, &decryptor)?;
        verify_true!(decryptor_state_roundtrip.sk_share.is_some())?;

        Ok(())
    }

    #[gtest]
    fn decryptor_state_with_config_roundtrip() -> googletest::Result<()> {
        use kahe_traits::KaheBase;
        use shell_kahe::ShellKahe;
        use shell_parameters::create_shell_kahe_config;
        use testing_utils::generate_aggregation_config;

        let vahe =
            Rc::new(ShellVahe::new(create_shell_ahe_config(1).unwrap(), CONTEXT_STRING).unwrap());
        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(vahe)?;

        let config = generate_aggregation_config("default".to_string(), 16, 10, 1, 1);
        let kahe_config = create_shell_kahe_config(&config).unwrap();
        let kahe = Rc::new(ShellKahe::new(kahe_config, &config.key_id).unwrap());

        let mut decryptor_state = DecryptorState::default();
        decryptor.create_public_key_share(&mut decryptor_state)?;
        decryptor_state.kahe = Some(kahe);
        decryptor_state.aggregation_config = Some(config);

        verify_true!(decryptor_state.kahe.is_some())?;
        verify_true!(decryptor_state.aggregation_config.is_some())?;

        let decryptor_state_proto = decryptor_state.to_proto(&decryptor)?;
        let decryptor_state_roundtrip =
            DecryptorState::from_proto(decryptor_state_proto, &decryptor)?;

        verify_true!(decryptor_state_roundtrip.sk_share.is_some())?;
        verify_true!(decryptor_state_roundtrip.kahe.is_some())?;
        verify_true!(decryptor_state_roundtrip.aggregation_config.is_some())?;

        Ok(())
    }

    // --- Multi-decryptor tests ---

    #[gtest]
    fn create_setup_contribution_generates_key_share_and_proof() -> googletest::Result<()> {
        use decryptor_traits::SecureAggregationBaseMultiDecryptor;

        let vahe =
            Rc::new(ShellVahe::new(create_shell_ahe_config(1).unwrap(), CONTEXT_STRING).unwrap());
        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(vahe)?;
        let mut state = DecryptorState::default();

        let contribution = decryptor.create_setup_contribution(&mut state)?;

        verify_true!(contribution.key_contribution.proof.is_some())?;
        verify_true!(state.sk_share.is_some())?;
        verify_true!(contribution.encrypted_randomness_shares.is_none())?;
        verify_true!(contribution.dp_setup.is_none())?;

        Ok(())
    }

    #[gtest]
    fn verify_and_aggregate_key_contributions_succeeds() -> googletest::Result<()> {
        use decryptor_traits::{
            SecureAggregationBaseMultiDecryptor, SecureAggregationReputableDecryptor,
        };
        use messages::VerifyKeyContributionsRequest;

        let vahe =
            Rc::new(ShellVahe::new(create_shell_ahe_config(1).unwrap(), CONTEXT_STRING).unwrap());
        let decryptor1 = WillowV1Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let decryptor2 = WillowV1Decryptor::new_with_randomly_generated_seed(vahe.clone())?;

        let mut state1 = DecryptorState::default();
        let mut state2 = DecryptorState::default();
        let contribution1 = decryptor1.create_setup_contribution(&mut state1)?;
        let contribution2 = decryptor2.create_setup_contribution(&mut state2)?;

        let request = VerifyKeyContributionsRequest {
            key_contributions: vec![contribution1.key_contribution, contribution2.key_contribution],
        };
        let result = decryptor1.verify_and_aggregate_key_contributions(request);
        verify_true!(result.is_ok())?;

        Ok(())
    }

    #[gtest]
    fn verify_key_contributions_fails_with_missing_proof() -> googletest::Result<()> {
        use decryptor_traits::{
            SecureAggregationBaseMultiDecryptor, SecureAggregationReputableDecryptor,
        };
        use messages::VerifyKeyContributionsRequest;

        let vahe =
            Rc::new(ShellVahe::new(create_shell_ahe_config(1).unwrap(), CONTEXT_STRING).unwrap());
        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(vahe.clone())?;

        let mut state = DecryptorState::default();
        let mut contribution = decryptor.create_setup_contribution(&mut state)?;
        contribution.key_contribution.proof = None;

        let request = VerifyKeyContributionsRequest {
            key_contributions: vec![contribution.key_contribution],
        };
        let result = decryptor.verify_and_aggregate_key_contributions(request);
        verify_true!(result.is_err())?;

        Ok(())
    }

    #[gtest]
    fn verify_key_contributions_fails_with_empty_list() -> googletest::Result<()> {
        use decryptor_traits::SecureAggregationReputableDecryptor;
        use messages::VerifyKeyContributionsRequest;

        let vahe =
            Rc::new(ShellVahe::new(create_shell_ahe_config(1).unwrap(), CONTEXT_STRING).unwrap());
        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(vahe)?;

        let request = VerifyKeyContributionsRequest { key_contributions: vec![] };
        let result = decryptor.verify_and_aggregate_key_contributions(request);
        verify_true!(result.is_err())?;

        Ok(())
    }

    #[gtest]
    fn multi_decryptor_partial_decryption_works() -> googletest::Result<()> {
        use decryptor_traits::SecureAggregationBaseMultiDecryptor;
        use messages::PartialDecryptionResponse;
        use prng_traits::SecurePrng;
        use shell_kahe::ShellKahe;
        use single_thread_hkdf::SingleThreadHkdfPrng;
        use vahe_traits::{Recover, VerifiableEncrypt};

        let vahe =
            Rc::new(ShellVahe::new(create_shell_ahe_config(1).unwrap(), CONTEXT_STRING).unwrap());

        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let mut state = DecryptorState::default();
        let contribution = decryptor.create_setup_contribution(&mut state)?;

        // Create a public key from the contribution.
        let public_key = vahe.aggregate_public_key_shares(std::iter::once(
            &contribution.key_contribution.public_key_share,
        ))?;

        // Create a ciphertext.
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let plaintext = vec![42i64; 8];
        let nonce = b"0123456789ABCDEF";
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&plaintext, &public_key, nonce, &mut prng)?;
        let partial_dec_ciphertext = vahe.get_partial_dec_ciphertext(&ciphertext)?;

        let pd_request =
            messages::PartialDecryptionRequest { partial_dec_ciphertext, aggregation_config: None };

        let pd_response: PartialDecryptionResponse<ShellKahe, ShellVahe> =
            SecureAggregationBaseMultiDecryptor::handle_partial_decryption_request(
                &decryptor, pd_request, None, &mut state,
            )?;

        // Verify we can recover from the partial decryption.
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
