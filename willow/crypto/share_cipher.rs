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

//! Peer share encryption (`ShareCipher`) for Willow multi-decryptor dropout recovery
//! over Tink C++ HPKE (`DHKEM_X25519_HKDF_SHA256`, `HKDF_SHA256`, `AES_128_GCM`).

use curve25519_dalek::scalar::Scalar;
pub use feldman_vss::{
    derive_keygen_seed, SecretScalar, Share, KEYGEN_SEED_HKDF_INFO_PREFIX, MAX_SHARES,
    ROSTER_HASH_BYTE_LEN, SCALAR_BYTE_LEN,
};
use status::StatusError;
use std::num::NonZeroU32;

/// Canonical domain-separation prefix for HPKE `context_info` when encrypting
/// Feldman VSS shares between committee members.
pub const SHARE_HPKE_CONTEXT_INFO_PREFIX: &[u8] = b"willow_share_hpke_v1";

/// Builds the canonical length-prefixed HPKE `context_info`:
/// `"willow_share_hpke_v1" || u32_le(session_context.len()) || session_context || roster_hash (32B)
/// || u32_le(dealer_index) || u32_le(recipient_index)`
///
/// Rejects `dealer_index > MAX_SHARES`, `recipient_index > MAX_SHARES`, or
/// `dealer_index == recipient_index`.
pub fn build_share_hpke_context_info(
    session_context: &[u8],
    roster_hash: &[u8; ROSTER_HASH_BYTE_LEN],
    dealer_index: NonZeroU32,
    recipient_index: NonZeroU32,
) -> Result<Vec<u8>, StatusError> {
    if dealer_index.get() > MAX_SHARES {
        return Err(status::invalid_argument(
            "build_share_hpke_context_info: dealer_index exceeds MAX_SHARES",
        ));
    }
    if recipient_index.get() > MAX_SHARES {
        return Err(status::invalid_argument(
            "build_share_hpke_context_info: recipient_index exceeds MAX_SHARES",
        ));
    }
    if dealer_index == recipient_index {
        return Err(status::invalid_argument(
            "build_share_hpke_context_info: dealer_index and recipient_index must be distinct",
        ));
    }
    let session_context_len = u32::try_from(session_context.len()).map_err(|_| {
        status::invalid_argument(
            "build_share_hpke_context_info: session_context length exceeds u32::MAX",
        )
    })?;

    let total_len = SHARE_HPKE_CONTEXT_INFO_PREFIX.len()
        + 4
        + session_context.len()
        + ROSTER_HASH_BYTE_LEN
        + 4
        + 4;
    let mut info = Vec::with_capacity(total_len);
    info.extend_from_slice(SHARE_HPKE_CONTEXT_INFO_PREFIX);
    info.extend_from_slice(&session_context_len.to_le_bytes());
    info.extend_from_slice(session_context);
    info.extend_from_slice(roster_hash);
    info.extend_from_slice(&dealer_index.get().to_le_bytes());
    info.extend_from_slice(&recipient_index.get().to_le_bytes());
    Ok(info)
}

/// Trait for encrypting and decrypting fixed 32-byte canonical Ristretto255 Feldman VSS
/// shares between committee members with domain-separated HPKE `context_info`.
pub trait ShareCipher {
    /// Serialized or typed recipient public key.
    type PublicKey: Clone + PartialEq + Eq + std::fmt::Debug;
    /// Recipient private decryption key handle.
    type PrivateKey: Clone + std::fmt::Debug;

    /// Generates a new `(PrivateKey, PublicKey)` pair.
    fn generate_keypair() -> Result<(Self::PrivateKey, Self::PublicKey), StatusError>;

    /// Validates that `public_key` is well-formed and usable for share encryption.
    fn validate_public_key(public_key: &Self::PublicKey) -> status::Status;

    /// Encrypts `share` (evaluated at `recipient_index = share.index`) from `dealer_index`
    /// under `recipient_public_key`, binding `(session_context, roster_hash, dealer_index,
    /// share.index)` in HPKE `context_info`.
    fn encrypt_share(
        recipient_public_key: &Self::PublicKey,
        share: &Share,
        session_context: &[u8],
        roster_hash: &[u8; ROSTER_HASH_BYTE_LEN],
        dealer_index: NonZeroU32,
    ) -> Result<Vec<u8>, StatusError>;

    /// Decrypts `ciphertext` sent by `dealer_index` to `recipient_index` under
    /// `recipient_private_key`, verifying the bound `(session_context, roster_hash, dealer_index,
    /// recipient_index)` in HPKE `context_info` and validating that the decrypted plaintext is a
    /// canonical non-zero 32-byte Ristretto255 scalar.
    ///
    /// # Security Contract (HPKE Base Mode & Broadcast Commitment Verification)
    ///
    /// `TinkHpkeShareCipher` uses HPKE Base Mode (`mode_base = 0x00`), which provides
    /// confidentiality and context-bound ciphertext integrity under `recipient_public_key`,
    /// but does **not** authenticate the sender (`dealer_index`): any party holding
    /// `recipient_public_key` (including an untrusted Coordinator) can construct a well-formed
    /// HPKE ciphertext for `(session_context, roster_hash, dealer_index, recipient_index)`.
    ///
    /// Therefore, after `decrypt_share` returns `Ok(share)`, the protocol layer **MUST**:
    /// 1. Verify that every committee member's broadcast `FeldmanCommitment` (together with their
    ///    `dealer_index` and `TinkHpkePublicKey`) is bound into the agreed `roster_hash` so an
    ///    untrusted Coordinator cannot equivocate on commitments across recipients (`A2`/`A6`), and
    ///    verify `dealer_commitment.threshold() == committee_config.threshold` (`A6`).
    /// 2. Call `FeldmanShareVerifier::verify_share(&share, &dealer_commitment)` and reject the
    ///    dealer (or abort setup) if `[s_{i->j}] * G != \sum_{k=0}^{t-1} (j)^k * C_{i,k}`.
    fn decrypt_share(
        recipient_private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        session_context: &[u8],
        roster_hash: &[u8; ROSTER_HASH_BYTE_LEN],
        dealer_index: NonZeroU32,
        recipient_index: NonZeroU32,
    ) -> Result<Share, StatusError>;
}

/// Serialized Tink HPKE public keyset (`ProtoKeysetFormat`, compatible with Android/C++ Tink
/// `HybridEncrypt` keysets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TinkHpkePublicKey(Vec<u8>);

impl TinkHpkePublicKey {
    /// Parses and validates a serialized Tink `HybridEncrypt` public keyset in `ProtoKeysetFormat`.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, StatusError> {
        hpke::validate_hpke_public_keyset(&bytes)?;
        Ok(Self(bytes))
    }

    /// Returns the serialized public keyset bytes in `ProtoKeysetFormat`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes `self` and returns the underlying serialized public keyset bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Opaque Tink HPKE private keyset handle (`KeysetHandle` for `HpkeX25519HkdfSha256Aes128Gcm`).
#[derive(Clone)]
pub struct TinkHpkePrivateKey(hpke::HpkeKeyset);

impl std::fmt::Debug for TinkHpkePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TinkHpkePrivateKey([REDACTED])")
    }
}

/// Opaque Tink AES-256-GCM AEAD keyset handle for encrypting/decrypting `TinkHpkePrivateKey`
/// via `SerializeKeysetToEncryptedKeysetFormat` / `ParseKeysetFromEncryptedKeysetFormat`.
#[derive(Clone)]
pub struct TinkHpkeKeysetWrappingKey(hpke::HpkeKeyset);

impl std::fmt::Debug for TinkHpkeKeysetWrappingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TinkHpkeKeysetWrappingKey([REDACTED])")
    }
}

impl TinkHpkeKeysetWrappingKey {
    /// Generates a new AES-256-GCM keyset wrapping key.
    pub fn generate() -> Result<Self, StatusError> {
        Ok(Self(hpke::generate_wrapping_aead()?))
    }
}

impl TinkHpkePrivateKey {
    /// Derives the corresponding `TinkHpkePublicKey` in Tink `ProtoKeysetFormat`.
    pub fn public_key(&self) -> Result<TinkHpkePublicKey, StatusError> {
        let bytes = hpke::get_public_keyset_from_private(&self.0)?;
        Ok(TinkHpkePublicKey(bytes))
    }

    /// Serializes this HPKE private keyset in Tink `EncryptedKeysetFormat` under `wrapping_key`
    /// and `associated_data` (`SerializeKeysetToEncryptedKeysetFormat`).
    pub fn to_encrypted_keyset(
        &self,
        wrapping_key: &TinkHpkeKeysetWrappingKey,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, StatusError> {
        hpke::serialize_hpke_private_keyset_encrypted(&self.0, &wrapping_key.0, associated_data)
    }

    /// Restores a `TinkHpkePrivateKey` from Tink `EncryptedKeysetFormat` under `wrapping_key`
    /// and `associated_data` (`ParseKeysetFromEncryptedKeysetFormat`).
    pub fn from_encrypted_keyset(
        encrypted_keyset: &[u8],
        wrapping_key: &TinkHpkeKeysetWrappingKey,
        associated_data: &[u8],
    ) -> Result<Self, StatusError> {
        let keyset = hpke::parse_hpke_private_keyset_encrypted(
            encrypted_keyset,
            &wrapping_key.0,
            associated_data,
        )?;
        Ok(Self(keyset))
    }
}

/// `@tink_cc` HPKE implementation of [`ShareCipher`] using
/// `DHKEM_X25519_HKDF_SHA256` / `HKDF_SHA256` / `AES_128_GCM`.
#[derive(Clone, Copy, Debug, Default)]
pub struct TinkHpkeShareCipher;

impl TinkHpkeShareCipher {
    /// Generates a new HPKE keypair using `HpkeX25519HkdfSha256Aes128GcmRaw()`
    /// (`OutputPrefixType::RAW`). Both `TINK`-prefixed and `RAW`-prefixed keysets are accepted by
    /// `encrypt_share` and `decrypt_share`.
    pub fn generate_raw_keypair() -> Result<(TinkHpkePrivateKey, TinkHpkePublicKey), StatusError> {
        let (sk, pk_bytes) = hpke::generate_hpke_keyset(true)?;
        Ok((TinkHpkePrivateKey(sk), TinkHpkePublicKey(pk_bytes)))
    }
}

impl ShareCipher for TinkHpkeShareCipher {
    type PublicKey = TinkHpkePublicKey;
    type PrivateKey = TinkHpkePrivateKey;

    fn generate_keypair() -> Result<(Self::PrivateKey, Self::PublicKey), StatusError> {
        let (sk, pk_bytes) = hpke::generate_hpke_keyset(false)?;
        Ok((TinkHpkePrivateKey(sk), TinkHpkePublicKey(pk_bytes)))
    }

    fn validate_public_key(public_key: &Self::PublicKey) -> status::Status {
        hpke::validate_hpke_public_keyset(public_key.as_bytes())
    }

    fn encrypt_share(
        recipient_public_key: &Self::PublicKey,
        share: &Share,
        session_context: &[u8],
        roster_hash: &[u8; ROSTER_HASH_BYTE_LEN],
        dealer_index: NonZeroU32,
    ) -> Result<Vec<u8>, StatusError> {
        if *share.value.as_scalar() == Scalar::ZERO {
            return Err(status::invalid_argument(
                "encrypt_share: share scalar value must be non-zero",
            ));
        }
        let context_info =
            build_share_hpke_context_info(session_context, roster_hash, dealer_index, share.index)?;
        let plaintext = share.value.to_bytes();
        hpke::hpke_encrypt(recipient_public_key.as_bytes(), &plaintext, &context_info)
    }

    fn decrypt_share(
        recipient_private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        session_context: &[u8],
        roster_hash: &[u8; ROSTER_HASH_BYTE_LEN],
        dealer_index: NonZeroU32,
        recipient_index: NonZeroU32,
    ) -> Result<Share, StatusError> {
        let context_info = build_share_hpke_context_info(
            session_context,
            roster_hash,
            dealer_index,
            recipient_index,
        )?;
        let plaintext = hpke::hpke_decrypt(&recipient_private_key.0, ciphertext, &context_info)?;
        if plaintext.len() != SCALAR_BYTE_LEN {
            return Err(status::invalid_argument(
                "decrypt_share: decrypted HPKE payload must be exactly 32 bytes",
            ));
        }
        let value = SecretScalar::from_canonical_bytes(&plaintext)?;
        if *value.as_scalar() == Scalar::ZERO {
            return Err(status::invalid_argument(
                "decrypt_share: decrypted share scalar must be non-zero",
            ));
        }
        Ok(Share { index: recipient_index, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use feldman_vss::{reconstruct, split, verify_share};
    use googletest::{gtest, verify_eq, verify_that, Result as GTestResult};
    use prng_traits::SecurePrng;
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use status::StatusErrorCode;
    use status_matchers_rs::status_is;

    fn create_test_prng() -> Result<SingleThreadHkdfPrng, StatusError> {
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        SingleThreadHkdfPrng::create(&seed)
    }

    #[gtest]
    fn test_context_info_canonical_encoding_and_length_prefixing() -> GTestResult<()> {
        let session_ctx = b"session-42";
        let roster_hash = [0xABu8; ROSTER_HASH_BYTE_LEN];
        let dealer = NonZeroU32::new(1).unwrap();
        let recipient = NonZeroU32::new(7).unwrap();

        let info = build_share_hpke_context_info(session_ctx, &roster_hash, dealer, recipient)?;
        let mut expected = Vec::new();
        expected.extend_from_slice(b"willow_share_hpke_v1");
        expected.extend_from_slice(&(session_ctx.len() as u32).to_le_bytes());
        expected.extend_from_slice(session_ctx);
        expected.extend_from_slice(&roster_hash);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&7u32.to_le_bytes());
        verify_eq!(info, expected)?;

        // Self-dealing (dealer == recipient) and out-of-range indices (> MAX_SHARES) are rejected.
        verify_that!(
            build_share_hpke_context_info(session_ctx, &roster_hash, dealer, dealer),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        let out_of_range = NonZeroU32::new(MAX_SHARES + 1).unwrap();
        verify_that!(
            build_share_hpke_context_info(session_ctx, &roster_hash, out_of_range, recipient),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        verify_that!(
            build_share_hpke_context_info(session_ctx, &roster_hash, dealer, out_of_range),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        Ok(())
    }

    #[gtest]
    fn test_hpke_share_cipher_roundtrip_and_vss_recovery() -> GTestResult<()> {
        let mut prng = create_test_prng()?;
        let session_ctx = b"willow-session-roundtrip";
        let roster_hash = [0x5Au8; ROSTER_HASH_BYTE_LEN];

        // 5-member committee; member 2 is the dropped dealer.
        let num_decryptors = 5u32;
        let threshold = 3u32;
        let dealer_index = NonZeroU32::new(2).unwrap();

        let mut keypairs = Vec::with_capacity(num_decryptors as usize);
        for i in 1..=num_decryptors {
            let kp = if i % 2 == 0 {
                TinkHpkeShareCipher::generate_raw_keypair()?
            } else {
                TinkHpkeShareCipher::generate_keypair()?
            };
            TinkHpkeShareCipher::validate_public_key(&kp.1)?;
            keypairs.push(kp);
        }

        let dealer_secret = SecretScalar::random(&mut prng)?;
        let expected_keygen_seed =
            derive_keygen_seed(&dealer_secret, session_ctx, &roster_hash, dealer_index)?;
        let (commitment, shares) = split(&dealer_secret, threshold, num_decryptors, &mut prng)?;

        // Dealer 2 encrypts shares for all n - 1 peers (skipping share.index == dealer_index).
        let mut encrypted_peer_shares = Vec::new();
        for share in &shares {
            if share.index == dealer_index {
                continue;
            }
            let recipient_idx = (share.index.get() - 1) as usize;
            let ct = TinkHpkeShareCipher::encrypt_share(
                &keypairs[recipient_idx].1,
                share,
                session_ctx,
                &roster_hash,
                dealer_index,
            )?;
            encrypted_peer_shares.push((share.index, ct));
        }
        verify_eq!(encrypted_peer_shares.len(), 4)?;

        // Survivors {1, 3, 5} decrypt their shares for dropped dealer 2.
        let mut decrypted_shares = Vec::new();
        for &(recipient_index, ref ct) in &[
            encrypted_peer_shares[0].clone(), // member 1
            encrypted_peer_shares[1].clone(), // member 3
            encrypted_peer_shares[3].clone(), // member 5
        ] {
            let sk = &keypairs[(recipient_index.get() - 1) as usize].0;
            let decrypted_share = TinkHpkeShareCipher::decrypt_share(
                sk,
                ct,
                session_ctx,
                &roster_hash,
                dealer_index,
                recipient_index,
            )?;
            verify_share(&commitment, &decrypted_share)?;
            decrypted_shares.push(decrypted_share);
        }

        let reconstructed_secret = reconstruct(&commitment, &decrypted_shares)?;
        verify_eq!(reconstructed_secret, dealer_secret)?;
        let reconstructed_seed =
            derive_keygen_seed(&reconstructed_secret, session_ctx, &roster_hash, dealer_index)?;
        verify_eq!(reconstructed_seed.as_bytes(), expected_keygen_seed.as_bytes())?;

        Ok(())
    }

    #[gtest]
    fn test_wrong_key_tampered_ciphertext_and_swapped_context_rejected() -> GTestResult<()> {
        let mut prng = create_test_prng()?;
        let session_ctx = b"willow-session-adversarial";
        let roster_hash = [0x3Cu8; ROSTER_HASH_BYTE_LEN];
        let dealer_1 = NonZeroU32::new(1).unwrap();
        let dealer_2 = NonZeroU32::new(2).unwrap();
        let recipient_3 = NonZeroU32::new(3).unwrap();
        let recipient_4 = NonZeroU32::new(4).unwrap();

        let (sk_3, pk_3) = TinkHpkeShareCipher::generate_keypair()?;
        let (sk_4, _pk_4) = TinkHpkeShareCipher::generate_keypair()?;

        let secret = SecretScalar::random(&mut prng)?;
        let (_commitment, shares) = split(&secret, 2, 4, &mut prng)?;
        let share_for_3 = &shares[2]; // index == 3
        verify_eq!(share_for_3.index, recipient_3)?;

        let ct = TinkHpkeShareCipher::encrypt_share(
            &pk_3,
            share_for_3,
            session_ctx,
            &roster_hash,
            dealer_1,
        )?;

        // 1. Wrong recipient private key (member 4 trying to decrypt share for member 3).
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk_4,
                &ct,
                session_ctx,
                &roster_hash,
                dealer_1,
                recipient_3
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // 2. Swapped dealer_index and recipient_index.
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk_3,
                &ct,
                session_ctx,
                &roster_hash,
                recipient_3,
                dealer_1
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // 3. Spliced dealer_index (Coordinator claiming dealer 1's share came from dealer 2).
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk_3,
                &ct,
                session_ctx,
                &roster_hash,
                dealer_2,
                recipient_3
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // 4. Spliced recipient_index (member 3 asked to decrypt with recipient_index = 4).
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk_3,
                &ct,
                session_ctx,
                &roster_hash,
                dealer_1,
                recipient_4
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // 5. Wrong session_context (including trailing NUL byte) or wrong roster_hash.
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk_3,
                &ct,
                b"willow-session-adversarial\x00",
                &roster_hash,
                dealer_1,
                recipient_3
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        let wrong_roster = [0x99u8; ROSTER_HASH_BYTE_LEN];
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk_3,
                &ct,
                session_ctx,
                &wrong_roster,
                dealer_1,
                recipient_3
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // 6. Tampered ciphertext byte and truncated ciphertext.
        let mut tampered_ct = ct.clone();
        let last_idx = tampered_ct.len() - 1;
        tampered_ct[last_idx] ^= 0x01;
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk_3,
                &tampered_ct,
                session_ctx,
                &roster_hash,
                dealer_1,
                recipient_3
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk_3,
                &ct[..10],
                session_ctx,
                &roster_hash,
                dealer_1,
                recipient_3
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // 7. Self-dealing (`share.index == dealer_index`) rejected on both encrypt and decrypt.
        let self_share = &shares[0]; // index == 1 == dealer_1
        verify_that!(
            TinkHpkeShareCipher::encrypt_share(
                &pk_3,
                self_share,
                session_ctx,
                &roster_hash,
                dealer_1
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk_3,
                &ct,
                session_ctx,
                &roster_hash,
                recipient_3,
                recipient_3
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        Ok(())
    }

    #[gtest]
    fn test_malformed_scalar_plaintext_inside_valid_hpke_ciphertext_rejected() -> GTestResult<()> {
        let session_ctx = b"willow-session-malformed-pt";
        let roster_hash = [0x7Eu8; ROSTER_HASH_BYTE_LEN];
        let dealer = NonZeroU32::new(1).unwrap();
        let recipient = NonZeroU32::new(2).unwrap();
        let (sk, pk) = TinkHpkeShareCipher::generate_keypair()?;
        let context_info =
            build_share_hpke_context_info(session_ctx, &roster_hash, dealer, recipient)?;

        // 31-byte plaintext.
        let ct_short = hpke::hpke_encrypt(pk.as_bytes(), &[1u8; 31], &context_info)?;
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk,
                &ct_short,
                session_ctx,
                &roster_hash,
                dealer,
                recipient
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // 32-byte all-0xFF non-canonical scalar (>= group order l).
        let ct_noncanonical = hpke::hpke_encrypt(pk.as_bytes(), &[0xFFu8; 32], &context_info)?;
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk,
                &ct_noncanonical,
                session_ctx,
                &roster_hash,
                dealer,
                recipient
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // 32-byte all-zero scalar.
        let ct_zero = hpke::hpke_encrypt(pk.as_bytes(), &[0u8; 32], &context_info)?;
        verify_that!(
            TinkHpkeShareCipher::decrypt_share(
                &sk,
                &ct_zero,
                session_ctx,
                &roster_hash,
                dealer,
                recipient
            ),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        Ok(())
    }

    #[gtest]
    fn test_encrypted_keyset_persistence_and_public_key_validation() -> GTestResult<()> {
        let (sk, pk) = TinkHpkeShareCipher::generate_keypair()?;
        let roundtrip_pk = TinkHpkePublicKey::from_bytes(pk.as_bytes().to_vec())?;
        verify_eq!(roundtrip_pk, pk)?;
        verify_eq!(sk.public_key()?, pk)?;

        // Invalid public keyset bytes rejected.
        verify_that!(
            TinkHpkePublicKey::from_bytes(vec![]),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        verify_that!(
            TinkHpkePublicKey::from_bytes(b"not-a-tink-keyset".to_vec()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // Encrypted private keyset persistence round-trip.
        let wrapping_key = TinkHpkeKeysetWrappingKey::generate()?;
        let ad = b"decryptor-state-v1";
        let encrypted_sk = sk.to_encrypted_keyset(&wrapping_key, ad)?;
        let restored_sk =
            TinkHpkePrivateKey::from_encrypted_keyset(&encrypted_sk, &wrapping_key, ad)?;
        verify_eq!(restored_sk.public_key()?, pk)?;

        // Debug redaction check.
        let dbg = format!("{:?} {:?}", sk, wrapping_key);
        verify_eq!(dbg.contains("REDACTED"), true)?;

        Ok(())
    }
}
