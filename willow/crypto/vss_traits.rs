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

//! Trait for non-interactive t-of-n Verifiable Secret Sharing (VSS), mirroring the
//! `:ahe_traits` / `:vahe_traits` / `:zk_traits` abstraction layer in `willow/crypto/`.

use rand::CryptoRng;
use status::StatusError;
use std::fmt::Debug;

/// Trait for non-interactive t-of-n Verifiable Secret Sharing (VSS) schemes.
///
/// In Willow, each committee decryptor secret-shares a uniform scalar from which its AHE
/// key-generation seed is derived (so the coordinator can re-derive dropped decryptors' keys from
/// `t` surviving peers).
///
/// - **Dealer:** Splits a secret into `n` shares and publishes a commitment to the sharing
///   polynomial so shares can be verified without revealing the secret.
/// - **Participant:** Receives one share `(i, y_i)` indexed by 1-based `std::num::NonZeroU32` `i`
///   in `1..=n` (for groups of prime order `l > u32::MAX`, `1 <= i <= u32::MAX < l` maps distinct
///   `NonZeroU32` indices injectively to distinct non-zero elements of `F_l`).
/// - **Commitment:** Public dealer output (such as `[C_0, ..., C_{t-1}]` where `C_k = a_k * G`)
///   whose elements bind the polynomial coefficients and whose length `t` fixes the reconstruction
///   threshold (bounding the sharing polynomial to degree `< t`).
/// - **Threshold (`t`):** Minimum number of valid, pairwise-distinct shares needed to reconstruct
///   the secret (`1 <= t <= n`).
pub trait VerifiableSecretSharing {
    /// Secret value being shared across participants.
    type Secret: Clone + PartialEq + Eq + Debug;

    /// Single secret share distributed to a participant.
    type Share: Clone + PartialEq + Eq + Debug;

    /// Public commitment broadcast by the dealer to allow share verification.
    ///
    /// Implementations validate commitment structure (non-empty coefficient list and valid group
    /// elements) at construction or deserialization time.
    type Commitment: Clone + PartialEq + Eq + Debug;

    /// Splits `secret` into `num_shares` shares with reconstruction threshold `threshold`
    /// (`1 <= threshold <= num_shares`), returning the dealer's public commitment and one share
    /// per participant (`1..=num_shares`).
    fn split<R: CryptoRng + ?Sized>(
        &self,
        secret: &Self::Secret,
        threshold: u32,
        num_shares: u32,
        rng: &mut R,
    ) -> Result<(Self::Commitment, Vec<Self::Share>), StatusError>;

    /// Verifies that `share` is consistent with the dealer's `commitment`.
    ///
    /// (In Willow recovery, surviving decryptors check before releasing a decrypted share to
    /// reject invalid shares from a malicious dealer, and the coordinator checks
    /// `RecoveryResponse` shares via [`Self::reconstruct`] to reject forged shares from malicious
    /// survivors.)
    fn verify_share(&self, commitment: &Self::Commitment, share: &Self::Share) -> status::Status;

    /// Verifies all supplied `shares` against `commitment` and reconstructs the shared
    /// secret when at least `threshold` valid, pairwise-distinct shares are provided.
    fn reconstruct(
        &self,
        commitment: &Self::Commitment,
        shares: &[Self::Share],
    ) -> Result<Self::Secret, StatusError>;
}
