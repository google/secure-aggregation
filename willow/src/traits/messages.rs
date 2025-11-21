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
use kahe_traits::KaheBase;
use std::fmt::Debug;
use vahe_traits::VaheBase;

pub type DecryptorPublicKeyShare<Vahe: VaheBase> = <Vahe as AheBase>::PublicKeyShare;

pub type DecryptorPublicKey<Vahe: VaheBase> = <Vahe as AheBase>::PublicKey;

/// Message sent by a generic KAHE/AHE Willow client to the server.
#[derive(Debug)]
pub struct ClientMessage<Kahe: KaheBase, Vahe: VaheBase> {
    pub kahe_ciphertext: Kahe::Ciphertext,
    pub ahe_ciphertext: Vahe::Ciphertext,
    pub proof: Vahe::EncryptionProof,
    pub nonce: Vec<u8>,
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

/// The part of the client message that the verifier needn't check
pub struct CiphertextContribution<Kahe: KaheBase, Vahe: VaheBase> {
    pub kahe_ciphertext: Kahe::Ciphertext,
    pub ahe_recover_ciphertext: Vahe::RecoverCiphertext,
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

impl<Vahe: VaheBase> Clone for DecryptionRequestContribution<Vahe> {
    fn clone(&self) -> DecryptionRequestContribution<Vahe> {
        DecryptionRequestContribution {
            partial_dec_ciphertext: self.partial_dec_ciphertext.clone(),
            proof: self.proof.clone(),
            nonce: self.nonce.clone(),
        }
    }
}
