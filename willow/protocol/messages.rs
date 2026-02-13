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
}

impl<'a, C, Vahe> ToProto<&'a C> for PartialDecryptionRequest<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: ToProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
{
    type Proto = PartialDecryptionRequestProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        Ok(proto!(PartialDecryptionRequestProto {
            partial_dec_ciphertext: self.partial_dec_ciphertext.to_proto(context.vahe())?,
        }))
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
        Ok(PartialDecryptionRequest {
            partial_dec_ciphertext: Vahe::PartialDecCiphertext::from_proto(
                proto.partial_dec_ciphertext(),
                context.vahe(),
            )?,
        })
    }
}

/// We manually implement clone for PartialDecryptionRequest because Vahe is not cloneable.
impl<Vahe: VaheBase> Clone for PartialDecryptionRequest<Vahe> {
    fn clone(self: &PartialDecryptionRequest<Vahe>) -> PartialDecryptionRequest<Vahe> {
        PartialDecryptionRequest { partial_dec_ciphertext: self.partial_dec_ciphertext.clone() }
    }
}

impl<Vahe: VaheBase> Debug for PartialDecryptionRequest<Vahe> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("PartialDecryptionRequest")
            .field("partial_dec_ciphertext", &"(OMITTED)")
            .finish()
    }
}

pub struct PartialDecryptionResponse<Vahe: VaheBase> {
    pub partial_decryption: Vahe::PartialDecryption,
}

impl<'a, C, Vahe> ToProto<&'a C> for PartialDecryptionResponse<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecryption: ToProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
{
    type Proto = PartialDecryptionResponseProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        Ok(proto!(PartialDecryptionResponseProto {
            partial_decryption: self.partial_decryption.to_proto(context.vahe())?,
        }))
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for PartialDecryptionResponse<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecryption: FromProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
{
    type Proto = PartialDecryptionResponseProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        Ok(PartialDecryptionResponse {
            partial_decryption: Vahe::PartialDecryption::from_proto(
                proto.partial_decryption(),
                context.vahe(),
            )?,
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
