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
use common_traits::SecureAggregationCommon;
use kahe_traits::KaheBase;
use vahe_traits::VaheBase;

/// Common types for a generic lightweight KAHE/AHE-based implementation of the
/// `SecureAggregationCommon` trait.
#[derive(Debug)]
pub struct WillowCommon<Kahe, Vahe> {
    pub kahe: Kahe,
    pub vahe: Vahe,
}

pub type DecryptorPublicKeyShare<Vahe> = <Vahe as AheBase>::PublicKeyShare;

pub type DecryptorPublicKey<Vahe> = <Vahe as AheBase>::PublicKey;

/// Message sent by a generic KAHE/AHE Willow client to the server.
#[derive(Debug)]
pub struct WillowClientMessage<Kahe: KaheBase, Vahe: VaheBase> {
    pub kahe_ciphertext: Kahe::Ciphertext,
    pub ahe_ciphertext: Vahe::Ciphertext,
    pub proof: Vahe::EncryptionProof,
    pub nonce: Vec<u8>,
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

pub struct PartialDecryptionResponse<Vahe: VaheBase> {
    pub partial_decryption: Vahe::PartialDecryption,
}

/// The part of the client message that the verifier needn't check
#[derive(Debug, Clone)]
pub struct CiphertextContribution<Kahe: KaheBase, Vahe: VaheBase> {
    pub kahe_ciphertext: Kahe::Ciphertext,
    pub ahe_recover_ciphertext: Vahe::RecoverCiphertext,
}

/// The material from the client that the verifier must check.
#[derive(Debug, Clone)]
pub struct DecryptionRequestContribution<Vahe: VaheBase> {
    pub partial_dec_ciphertext: Vahe::PartialDecCiphertext,
    pub proof: Vahe::EncryptionProof,
    pub nonce: Vec<u8>,
}

impl<Kahe: KaheBase, Vahe: VaheBase> SecureAggregationCommon for WillowCommon<Kahe, Vahe> {
    type DecryptorPublicKeyShare = DecryptorPublicKeyShare<Vahe>;

    // Server directly sends the public key, without signatures.
    type DecryptorPublicKey = DecryptorPublicKey<Vahe>;

    type ClientMessage = WillowClientMessage<Kahe, Vahe>;

    type CiphertextContribution = CiphertextContribution<Kahe, Vahe>;

    type DecryptionRequestContribution = DecryptionRequestContribution<Vahe>;

    // Partial decryption request is an aggregated AHE ciphertext.
    type PartialDecryptionRequest = PartialDecryptionRequest<Vahe>;

    type PartialDecryptionResponse = PartialDecryptionResponse<Vahe>;
}
