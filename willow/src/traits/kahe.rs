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

//! Traits for Key Additive Homomorphic Encryption (KAHE) schemes.
use prng_traits::SecurePrng;
use status::StatusError;

/// Base trait for KAHE primitives, containing types that are shared across all
/// primitives. Types implementing this trait can also store public parameters
/// shared across primitives.
pub trait KaheBase: Sized {
    type Config;

    /// Creates a KAHE instance. `context_string` is used for domain separation and must be unique
    /// to each instantiation of the KAHE scheme.
    fn new(config: Self::Config, context_string: &[u8]) -> Result<Self, StatusError>;

    /// Secret key for symmetric encryption. Supports addition (key
    /// homomorphism). Addition needs additional context and works on
    /// types defined outside this crate, so we use functions instead of
    /// implementing the `Add` trait.
    type SecretKey;
    fn add_keys_in_place(
        &self,
        left: &Self::SecretKey,
        right: &mut Self::SecretKey,
    ) -> Result<(), StatusError>;

    /// Plaintext, e.g. a polynomial representing a properly encoded message.
    /// Supports addition.
    type Plaintext;
    fn add_plaintexts_in_place(
        &self,
        left: &Self::Plaintext,
        right: &mut Self::Plaintext,
    ) -> Result<(), StatusError>;

    /// Ciphertext. Supports addition.
    type Ciphertext: Clone;
    fn add_ciphertexts_in_place(
        &self,
        left: &Self::Ciphertext,
        right: &mut Self::Ciphertext,
    ) -> Result<(), StatusError>;

    /// Randomness source, typically a SecurePrng.
    type Rng: SecurePrng;
}

/// Key generation
pub trait KaheKeygen: KaheBase {
    /// Sample a new secret key.
    fn key_gen(&self, r: &mut Self::Rng) -> Result<Self::SecretKey, StatusError>;
}

/// Encryption
pub trait KaheEncrypt: KaheBase {
    /// Encrypt a plaintext `pt` with the secret key `sk`.
    fn encrypt(
        &self,
        pt: &Self::Plaintext,
        sk: &Self::SecretKey,
        r: &mut Self::Rng,
    ) -> Result<Self::Ciphertext, StatusError>;
}

/// Decryption
pub trait KaheDecrypt: KaheBase {
    /// Decrypt the ciphertext `ct`, using `sk` recovered from the Decryptor.
    fn decrypt(
        &self,
        ct: &Self::Ciphertext,
        sk: &Self::SecretKey,
    ) -> Result<Self::Plaintext, StatusError>;
}

/// Try to convert a `SecretKey` to a different type `T`, using information from
/// `self`, e.g. the RNS moduli. Can't directly use `TryInto` because we need
/// some extra context.
pub trait TrySecretKeyInto<T>: KaheBase {
    fn try_secret_key_into(&self, sk: Self::SecretKey) -> Result<T, StatusError>;
}

/// Try to obtain a `SecretKey` from a different type `T`, using information
/// from `self`, e.g. the RNS moduli. Can't directly use `TryFrom` because we
/// need some extra context.
pub trait TrySecretKeyFrom<T>: KaheBase {
    fn try_secret_key_from(&self, sk: T) -> Result<Self::SecretKey, StatusError>;
}
