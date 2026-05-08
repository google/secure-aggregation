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

use aggregation_config::AggregationConfig;
use ahe_traits::AheBase;
use kahe_traits::{HasKahe, KaheBase};
use messages_rust_proto::{
    CiphertextContribution as CiphertextContributionProto, ClientMessage as ClientMessageProto,
    DecryptionRequestContribution as DecryptionRequestContributionProto,
    PartialDecryptionRequest as PartialDecryptionRequestProto,
    PartialDecryptionResponse as PartialDecryptionResponseProto,
};
use proofs_rust_proto::RlweRelationProofListProto;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::{proto, AsView};
use shell_ciphertexts_rust_proto::{
    ShellAheCiphertext, ShellAhePartialDecCiphertext, ShellAhePartialDecryption,
    ShellAheRecoverCiphertext, ShellKaheCiphertext,
};
use status::StatusError;
use std::fmt::Debug;
use vahe_traits::{HasVahe, VaheBase};

pub type DecryptorPublicKeyShare<Vahe> = <Vahe as AheBase>::PublicKeyShare;

pub type DecryptorPublicKey<Vahe> = <Vahe as AheBase>::PublicKey;

/// Message sent by a generic KAHE/AHE Willow client to the server.
#[derive(Debug)]
pub struct ClientMessage<Kahe: KaheBase, Vahe: VaheBase> {
    pub kahe_ciphertext: Kahe::Ciphertext,
    pub ahe_ciphertext: Vahe::Ciphertext,
    pub proof: Vahe::EncryptionProof,
    pub nonce: Vec<u8>,
}

impl<'a, C, Kahe, Vahe> ToProto<&'a C> for ClientMessage<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Kahe::Ciphertext: ToProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::Ciphertext: ToProto<&'a Vahe, Proto = ShellAheCiphertext>,
    Vahe::EncryptionProof: ToProto<Proto = RlweRelationProofListProto>,
{
    type Proto = ClientMessageProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        Ok(proto!(ClientMessageProto {
            kahe_ciphertext: self.kahe_ciphertext.to_proto(context.kahe())?,
            ahe_ciphertext: self.ahe_ciphertext.to_proto(context.vahe())?,
            proof: self.proof.to_proto(())?,
            nonce: self.nonce.clone(),
        }))
    }
}

impl<'a, C, Kahe, Vahe> FromProto<&'a C> for ClientMessage<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Kahe::Ciphertext: FromProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::Ciphertext: FromProto<&'a Vahe, Proto = ShellAheCiphertext>,
    Vahe::EncryptionProof: FromProto<Proto = RlweRelationProofListProto>,
{
    type Proto = ClientMessageProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        Ok(ClientMessage {
            kahe_ciphertext: Kahe::Ciphertext::from_proto(proto.kahe_ciphertext(), context.kahe())?,
            ahe_ciphertext: Vahe::Ciphertext::from_proto(proto.ahe_ciphertext(), context.vahe())?,
            proof: Vahe::EncryptionProof::from_proto(proto.proof(), ())?,
            nonce: proto.nonce().to_vec(),
        })
    }
}

impl<Kahe: KaheBase, Vahe: VaheBase> Clone for ClientMessage<Kahe, Vahe> {
    fn clone(self: &ClientMessage<Kahe, Vahe>) -> ClientMessage<Kahe, Vahe> {
        ClientMessage {
            kahe_ciphertext: self.kahe_ciphertext.clone(),
            ahe_ciphertext: self.ahe_ciphertext.clone(),
            proof: self.proof.clone(),
            nonce: self.nonce.clone(),
        }
    }
}

// Partial decryption request is an aggregated AHE ciphertext.
pub struct PartialDecryptionRequest<Vahe: VaheBase> {
    pub partial_dec_ciphertext: Vahe::PartialDecCiphertext,
    // Only set if the decryptor is adding DP noise.
    pub aggregation_config: Option<AggregationConfig>,
}

impl<'a, C, Vahe> ToProto<&'a C> for PartialDecryptionRequest<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: ToProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
{
    type Proto = PartialDecryptionRequestProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = proto!(PartialDecryptionRequestProto {
            partial_dec_ciphertext: self.partial_dec_ciphertext.to_proto(context.vahe())?,
        });
        if let Some(config) = &self.aggregation_config {
            proto.set_aggregation_config(config.to_proto(())?);
        }
        Ok(proto)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for PartialDecryptionRequest<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: FromProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
{
    type Proto = PartialDecryptionRequestProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let aggregation_config = if proto.has_aggregation_config() {
            Some(AggregationConfig::from_proto(proto.aggregation_config(), ())?)
        } else {
            None
        };
        Ok(PartialDecryptionRequest {
            partial_dec_ciphertext: Vahe::PartialDecCiphertext::from_proto(
                proto.partial_dec_ciphertext(),
                context.vahe(),
            )?,
            aggregation_config,
        })
    }
}

/// We manually implement clone for PartialDecryptionRequest because Vahe is not cloneable.
impl<Vahe: VaheBase> Clone for PartialDecryptionRequest<Vahe> {
    fn clone(&self) -> PartialDecryptionRequest<Vahe> {
        PartialDecryptionRequest {
            partial_dec_ciphertext: self.partial_dec_ciphertext.clone(),
            aggregation_config: self.aggregation_config.clone(),
        }
    }
}

impl<Vahe: VaheBase> Debug for PartialDecryptionRequest<Vahe> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("PartialDecryptionRequest")
            .field("partial_dec_ciphertext", &"(OMITTED)")
            .field("aggregation_config", &self.aggregation_config)
            .finish()
    }
}

pub struct PartialDecryptionResponse<Kahe: KaheBase, Vahe: VaheBase> {
    pub partial_decryption: Vahe::PartialDecryption,
    // This contribution just contains encrypted DP noise. The server will be forced to include this
    // contribution in the result because the randomness of the AHE encryption was included in the
    // partial decryption request.
    pub dp_ciphertext_contribution: Option<CiphertextContribution<Kahe, Vahe>>,
}

impl<'a, C, Kahe, Vahe> ToProto<(&'a C, Option<&'a Kahe>)> for PartialDecryptionResponse<Kahe, Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecryption: ToProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
    Kahe::Ciphertext: ToProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::RecoverCiphertext: ToProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
{
    type Proto = PartialDecryptionResponseProto;

    fn to_proto(
        &self,
        (context, kahe): (&'a C, Option<&'a Kahe>),
    ) -> Result<Self::Proto, StatusError> {
        let vahe = context.vahe();
        let mut proto = proto!(PartialDecryptionResponseProto {
            partial_decryption: self.partial_decryption.to_proto(vahe)?,
        });
        if let Some(dp_ct) = &self.dp_ciphertext_contribution {
            let kahe = kahe.ok_or_else(|| {
                status::failed_precondition("Missing Kahe context for DP ciphertext contribution")
            })?;
            proto.set_dp_ciphertext_contribution(proto!(
                messages_rust_proto::CiphertextContribution {
                    kahe_ciphertext: dp_ct.kahe_ciphertext.to_proto(kahe)?,
                    ahe_recover_ciphertext: dp_ct.ahe_recover_ciphertext.to_proto(vahe)?,
                }
            ));
        }
        Ok(proto)
    }
}

impl<'a, C, Kahe, Vahe> FromProto<&'a C> for PartialDecryptionResponse<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecryption: FromProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
    Kahe::Ciphertext: FromProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::RecoverCiphertext: FromProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
{
    type Proto = PartialDecryptionResponseProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let dp_ciphertext_contribution = if proto.has_dp_ciphertext_contribution() {
            Some(CiphertextContribution::from_proto(proto.dp_ciphertext_contribution(), context)?)
        } else {
            None
        };
        Ok(PartialDecryptionResponse {
            partial_decryption: Vahe::PartialDecryption::from_proto(
                proto.partial_decryption(),
                context.vahe(),
            )?,
            dp_ciphertext_contribution,
        })
    }
}

/// The part of the client message that the verifier needn't check
pub struct CiphertextContribution<Kahe: KaheBase, Vahe: VaheBase> {
    pub kahe_ciphertext: Kahe::Ciphertext,
    pub ahe_recover_ciphertext: Vahe::RecoverCiphertext,
}

impl<'a, C, Kahe, Vahe> ToProto<&'a C> for CiphertextContribution<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Kahe::Ciphertext: ToProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::RecoverCiphertext: ToProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
{
    type Proto = CiphertextContributionProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        Ok(proto!(CiphertextContributionProto {
            kahe_ciphertext: self.kahe_ciphertext.to_proto(context.kahe())?,
            ahe_recover_ciphertext: self.ahe_recover_ciphertext.to_proto(context.vahe())?,
        }))
    }
}

impl<'a, C, Kahe, Vahe> FromProto<&'a C> for CiphertextContribution<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Kahe::Ciphertext: FromProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::RecoverCiphertext: FromProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
{
    type Proto = CiphertextContributionProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        Ok(CiphertextContribution {
            kahe_ciphertext: Kahe::Ciphertext::from_proto(proto.kahe_ciphertext(), context.kahe())?,
            ahe_recover_ciphertext: Vahe::RecoverCiphertext::from_proto(
                proto.ahe_recover_ciphertext(),
                context.vahe(),
            )?,
        })
    }
}

impl<Kahe: KaheBase, Vahe: VaheBase> Clone for CiphertextContribution<Kahe, Vahe> {
    fn clone(&self) -> CiphertextContribution<Kahe, Vahe> {
        CiphertextContribution {
            kahe_ciphertext: self.kahe_ciphertext.clone(),
            ahe_recover_ciphertext: self.ahe_recover_ciphertext.clone(),
        }
    }
}

/// The material from the client that the verifier must check.
#[derive(Debug)]
pub struct DecryptionRequestContribution<Vahe: VaheBase> {
    pub partial_dec_ciphertext: Vahe::PartialDecCiphertext,
    pub proof: Vahe::EncryptionProof,
    pub nonce: Vec<u8>,
}

impl<'a, C, Vahe> ToProto<&'a C> for DecryptionRequestContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: ToProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::EncryptionProof: ToProto<Proto = RlweRelationProofListProto>,
{
    type Proto = DecryptionRequestContributionProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        Ok(proto!(DecryptionRequestContributionProto {
            partial_dec_ciphertext: self.partial_dec_ciphertext.to_proto(context.vahe())?,
            proof: self.proof.to_proto(())?,
            nonce: self.nonce.clone(),
        }))
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for DecryptionRequestContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: FromProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::EncryptionProof: FromProto<Proto = RlweRelationProofListProto>,
{
    type Proto = DecryptionRequestContributionProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        Ok(DecryptionRequestContribution {
            partial_dec_ciphertext: Vahe::PartialDecCiphertext::from_proto(
                proto.partial_dec_ciphertext(),
                context.vahe(),
            )?,
            proof: Vahe::EncryptionProof::from_proto(proto.proof(), ())?,
            nonce: proto.nonce().to_vec(),
        })
    }
}

impl<Vahe: VaheBase> Clone for DecryptionRequestContribution<Vahe> {
    fn clone(&self) -> DecryptionRequestContribution<Vahe> {
        DecryptionRequestContribution {
            partial_dec_ciphertext: self.partial_dec_ciphertext.clone(),
            proof: self.proof.clone(),
            nonce: self.nonce.clone(),
        }
    }
}

/// A public key share and proof of knowledge of the secret key from a decryptor.
pub struct KeyContribution<Vahe: VaheBase> {
    pub public_key_share: DecryptorPublicKeyShare<Vahe>,
    /// This is required unless this is the only reputable decryptor.
    pub proof: Option<Vahe::KeyGenProof>,
}

/// The initial contribution to the decryption key from a decryptor.
pub struct SetupContribution<Vahe: VaheBase> {
    pub key_contribution: KeyContribution<Vahe>,
    /// Only needed if we are adding DP noise.
    pub dp_setup: Option<DPSetupContribution<Vahe>>,
    /// Shares of the randomness (PRNG state) used for key generation, encrypted for other
    /// decryptors to enable recovery. Only used by non-reputable decryptors.
    pub encrypted_randomness_shares: Option<Vec<SecretSharingContribution>>,
}

/// Placeholder for an encrypted share of the PRNG state.
#[derive(Debug, Clone)]
pub struct SecretSharingContribution {
    pub encrypted_share: Vec<u8>,
}

/// Public key independent half of ciphertext for noise, only present for adding DP.
pub struct DPSetupContribution<Vahe: VaheBase> {
    /// The public-key-independent half of the DP noise ciphertext (component_a).
    /// This is also the half that must be sent to the verifier.
    pub dp_partial_dec_ciphertext: Vahe::PartialDecCiphertext,
    /// Proof of knowledge of the randomness used to create the ciphertext.
    pub dp_partial_dec_ciphertext_proof: Option<Vahe::EncryptionProof>,
}

/// A request to a surviving decryptor to decrypt shares of dropped decryptors.
#[derive(Debug)]
pub struct RecoveryRequest {
    /// The encrypted shares that this decryptor is being asked to decrypt.
    pub encrypted_shares: Vec<SecretSharingContribution>,
}

/// A response containing the decrypted shares of dropped decryptors.
#[derive(Debug)]
pub struct RecoveryResponse {
    /// The decrypted shares.
    pub decrypted_shares: Vec<Vec<u8>>,
}

/// A request from the coordinator to a reputable decryptor to verify setup contributions
/// and construct the aggregated public key.
pub struct VerifyKeyContributionsRequest<Vahe: VaheBase> {
    pub key_contributions: Vec<KeyContribution<Vahe>>,
}

/// Tracks a multi-decryptor's progress through the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecryptorStatus {
    #[default]
    PreSetup,
    AwaitingKeyVerificationRequest,
    AwaitingDecryptionRequest,
    AwaitingRecoveryRequest,
    Finished,
}

/// State stored by a multi-decryptor between protocol rounds.
pub struct MultiDecryptorState<Vahe: VaheBase> {
    /// The current status of the decryptor in the protocol.
    pub status: DecryptorStatus,
    /// The secret key share generated by the decryptor. None before setup.
    pub sk_share: Option<Vahe::SecretKeyShare>,
    /// The PRNG state / randomness used during the DP setup phase, if applicable.
    pub dp_randomness: Option<Vec<u8>>,
}

impl<Vahe: VaheBase> Default for MultiDecryptorState<Vahe> {
    fn default() -> Self {
        Self { status: DecryptorStatus::default(), sk_share: None, dp_randomness: None }
    }
}

/// Tracks the coordinator's progress through the multi-decryptor protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoordinatorStatus {
    #[default]
    PreSetup,
    KeySharesReceived,
    AwaitingContributions,
    AwaitingPartialDecryptions,
    AwaitingRecovery,
    OutputReady,
    Finished,
}

/// State stored by the coordinator between protocol rounds.
pub struct CoordinatorState<Vahe: VaheBase> {
    /// The current status of the coordinator in the protocol.
    pub status: CoordinatorStatus,
    /// The encrypted secret shares received from non-reputable decryptors during setup. Each inner
    /// `Vec` contains shares from one non-reputable decryptor, encrypted for each *other*
    /// decryptor. The outer index corresponds to the sender (the non-reputable decryptor), and
    /// the inner index corresponds to the recipient decryptor.
    pub encrypted_randomness_shares: Vec<Vec<SecretSharingContribution>>,
    /// The accumulated public key independent components (sum of A*r+e) for DP noise, if
    /// applicable.
    pub dp_noise_component_sum: Option<Vahe::PartialDecCiphertext>,
    /// The public key shares and proofs from all contributions, for sending back to decryptors for
    ///  signing requests. Only applicable in multiple reputable decryptor case and until used.
    pub setup_contributions: Option<Vec<SetupContribution<Vahe>>>,
}

impl<Vahe: VaheBase> Default for CoordinatorState<Vahe> {
    fn default() -> Self {
        Self {
            status: CoordinatorStatus::default(),
            encrypted_randomness_shares: Vec::new(),
            dp_noise_component_sum: None,
            setup_contributions: None,
        }
    }
}
