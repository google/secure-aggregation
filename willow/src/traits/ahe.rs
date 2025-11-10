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

use prng_traits::SecurePrng;
use status::StatusError;

/// Base trait for (Asymmetric) multiparty Additive Homomorphic Encryption (AHE)
/// schemes. Mostly contains types that are shared across all roles.
pub trait AheBase: Sized {
    type Config;

    /// Creates an AHE instance. `context_string` is used for domain separation and must be unique
    /// to each instantiation of the AHE scheme.
    fn new(config: Self::Config, context_string: &[u8]) -> Result<Self, StatusError>;

    /// Secret key share.
    type SecretKeyShare;

    /// Public key share.
    type PublicKeyShare;

    type KeyGenMetadata;

    /// Public key. Can be obtained by aggregating public keyshares.
    type PublicKey;
    fn aggregate_public_key_shares(
        &self,
        public_key_shares: &[Self::PublicKeyShare],
    ) -> Result<Self::PublicKey, StatusError>;

    /// Plaintext. Supports addition.
    type Plaintext;
    fn add_plaintexts_in_place(
        &self,
        left: &Self::Plaintext,
        right: &mut Self::Plaintext,
    ) -> Result<(), StatusError>;

    /// Part of a ciphertext that is used for partial decryption.
    type PartialDecCiphertext: Clone;

    /// Part of a ciphertext that is used for recovery.
    type RecoverCiphertext;

    /// Full AHE ciphertext. Supports addition.
    type Ciphertext;
    fn add_ciphertexts_in_place(
        &self,
        left: &Self::Ciphertext,
        right: &mut Self::Ciphertext,
    ) -> Result<(), StatusError>;
    fn add_pd_ciphertexts_in_place(
        &self,
        left: &Self::PartialDecCiphertext,
        right: &mut Self::PartialDecCiphertext,
    ) -> Result<(), StatusError>;
    fn add_recover_ciphertexts_in_place(
        &self,
        left: &Self::RecoverCiphertext,
        right: &mut Self::RecoverCiphertext,
    ) -> Result<(), StatusError>;
    fn get_partial_dec_ciphertext(
        &self,
        ct: &Self::Ciphertext,
    ) -> Result<Self::PartialDecCiphertext, StatusError>;
    fn get_recover_ciphertext(
        &self,
        ct: &Self::Ciphertext,
    ) -> Result<Self::RecoverCiphertext, StatusError>;

    /// Metadata associated with an encryption.
    type EncryptionMetadata;

    /// A partial decryption. Supports addition.
    type PartialDecryption;

    /// Metadata associated with a partial decryption.
    type PartialDecryptionMetadata;

    fn add_partial_decryptions_in_place(
        &self,
        left: &Self::PartialDecryption,
        right: &mut Self::PartialDecryption,
    ) -> Result<(), StatusError>;

    /// Randomness source, typically a SecurePrng.
    type Rng: SecurePrng;
}

pub trait AheKeygen: AheBase {
    /// Sample a new secret key and public key share.
    fn key_gen(
        &self,
        prng: &mut Self::Rng,
    ) -> Result<(Self::SecretKeyShare, Self::PublicKeyShare, Self::KeyGenMetadata), StatusError>;
}

pub trait AheEncrypt: AheBase {
    /// Encrypt a plaintext.
    fn encrypt(
        &self,
        plaintext: &Self::Plaintext,
        pk: &Self::PublicKey,
        prng: &mut Self::Rng,
    ) -> Result<(Self::Ciphertext, Self::EncryptionMetadata), StatusError>;
}

pub trait PartialDec: AheBase {
    /// Partial decryption.
    fn partial_decrypt(
        &self,
        ct_1: &Self::PartialDecCiphertext,
        sk: &Self::SecretKeyShare,
        prng: &mut Self::Rng,
    ) -> Result<Self::PartialDecryption, StatusError>;
}

pub trait Recover: AheBase {
    /// Decrypt a ciphertext with aggregated partial decryptions. We expect the
    /// partial decryptions and ciphertexts to be already summed (e.g. to
    /// let the server accumulate as they wish).
    fn recover(
        &self,
        pd: &Self::PartialDecryption,
        ct_0: &Self::RecoverCiphertext,
        plaintex_len: Option<usize>,
    ) -> Result<Self::Plaintext, StatusError>;
}

pub trait ExportPublicParameters<T>: AheBase {
    /// Exports public parameters of the AHE scheme. Useful for generating
    /// zero-knowledge proofs of correct encryption / decryption.
    fn export_public_parameters(&self) -> Result<T, StatusError>;
}

pub trait ExportCiphertext<C, T>: AheBase {
    /// Exports a (PartialDecrypt|Recover)?Ciphertext. Useful for generating
    /// zero-knowledge proofs.
    fn export_ciphertext(&self, ct: C) -> Result<T, StatusError>;
}

pub trait ExportEncryptionMetadata<T>: AheBase {
    /// Exports encryption metadata. Useful for generating zero-knowledge
    /// proofs.
    fn export_encryption_metadata(
        &self,
        metadata: &Self::EncryptionMetadata,
    ) -> Result<T, StatusError>;
}
