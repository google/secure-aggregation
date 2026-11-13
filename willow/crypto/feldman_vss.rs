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

//! Minimal $t$-of-$n$ Feldman Verifiable Secret Sharing (VSS) over Ristretto255.
//!
//! In Willow's multi-decryptor protocol (ePrint 2024/936, Figure 10 & Appendix E.1),
//! each non-reputable decryptor samples a high-entropy seed scalar $s \in \mathbb{F}_\ell$,
//! derives its RLWE key-generation PRNG seed from $s$, and shares $s$ among the
//! decryptor committee using Feldman VSS over the prime-order Ristretto255 group.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use messages_rust_proto::{FeldmanCommitmentProto, FeldmanShareProto};
use prng_traits::SecurePrng;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::{proto, AsView};
use status::StatusError;
use std::collections::BTreeSet;
use std::num::NonZeroU32;

/// Maximum number of shares (and maximum threshold) supported by Feldman VSS.
/// Aligned with Willow's `MAX_NUM_DECRYPTORS = 100` ceiling in `shell_parameters.rs`.
pub const MAX_SHARES: u32 = 100;

/// Canonical byte length of a Ristretto255 scalar ($\mathbb{F}_\ell$).
pub const SCALAR_BYTE_LEN: usize = 32;

/// Canonical byte length of a compressed Ristretto255 point.
pub const COMMITMENT_POINT_BYTE_LEN: usize = 32;

/// A secret Ristretto255 scalar $\in \mathbb{F}_\ell$.
///
/// Note on computational hiding: Feldman VSS publishes $C_0 = s \cdot G$ without a
/// blinding factor. Callers must only share high-entropy secrets sampled via
/// [`SecretScalar::random`].
#[derive(Clone)]
pub struct SecretScalar(Scalar);

impl PartialEq for SecretScalar {
    fn eq(&self, other: &Self) -> bool {
        // `Scalar::eq` in `curve25519-dalek` delegates to `subtle::ConstantTimeEq::ct_eq`.
        self.0 == other.0
    }
}

impl Eq for SecretScalar {}

impl std::fmt::Debug for SecretScalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretScalar([REDACTED])")
    }
}

impl SecretScalar {
    /// Wraps an existing `Scalar` in a `SecretScalar`.
    pub fn new(scalar: Scalar) -> Self {
        Self(scalar)
    }

    /// Samples a uniform non-zero `SecretScalar` using wide 64-byte modular reduction
    /// (`Scalar::from_bytes_mod_order_wide`, bias $< 2^{-259}$).
    pub fn random<P: SecurePrng>(prng: &mut P) -> Result<Self, StatusError> {
        let mut wide_bytes = [0u8; 64];
        loop {
            for b in wide_bytes.iter_mut() {
                *b = prng.rand8()?;
            }
            let scalar = Scalar::from_bytes_mod_order_wide(&wide_bytes);
            if scalar != Scalar::ZERO {
                return Ok(Self(scalar));
            }
        }
    }

    /// Deserializes a `SecretScalar` from its canonical 32-byte little-endian encoding,
    /// rejecting non-canonical encodings ($\ge \ell$).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StatusError> {
        let arr: [u8; SCALAR_BYTE_LEN] = bytes.try_into().map_err(|_| {
            status::invalid_argument("SecretScalar byte slice must be exactly 32 bytes")
        })?;
        let opt: Option<Scalar> = Scalar::from_canonical_bytes(arr).into();
        opt.map(Self).ok_or_else(|| {
            status::invalid_argument("Non-canonical Ristretto255 scalar encoding (>= group order)")
        })
    }

    /// Returns the canonical 32-byte little-endian encoding of this scalar.
    pub fn to_bytes(&self) -> [u8; SCALAR_BYTE_LEN] {
        self.0.to_bytes()
    }

    /// Returns a reference to the canonical 32-byte little-endian encoding of this scalar.
    pub fn as_bytes(&self) -> &[u8; SCALAR_BYTE_LEN] {
        self.0.as_bytes()
    }

    /// Returns a reference to the underlying `Scalar`.
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }
}

/// A single Shamir/Feldman share $(i, f(i))$ evaluated at a 1-based index $i \in \{1, \dots, n\}$.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    pub index: NonZeroU32,
    pub value: SecretScalar,
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share").field("index", &self.index).field("value", &"[REDACTED]").finish()
    }
}

/// Public Feldman polynomial commitment $(C_0, C_1, \dots, C_{t-1})$ where $C_k = a_k \cdot G$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeldmanCommitment {
    commitments: Vec<CompressedRistretto>,
}

impl FeldmanCommitment {
    /// Constructs a `FeldmanCommitment` after verifying that `commitments` has length in
    /// `1..=MAX_SHARES` and every compressed point is a valid non-identity Ristretto255 point.
    pub fn new(commitments: Vec<CompressedRistretto>) -> Result<Self, StatusError> {
        if commitments.is_empty() || commitments.len() > MAX_SHARES as usize {
            return Err(status::invalid_argument(
                "FeldmanCommitment length must be in 1..=MAX_SHARES",
            ));
        }
        for c in &commitments {
            let pt = c.decompress().ok_or_else(|| {
                status::invalid_argument("Invalid compressed Ristretto255 point in commitment")
            })?;
            if pt.is_identity() {
                return Err(status::invalid_argument(
                    "FeldmanCommitment must not contain the identity point",
                ));
            }
        }
        Ok(Self { commitments })
    }

    /// Returns the reconstruction threshold $t$ (number of coefficient commitments).
    pub fn threshold(&self) -> usize {
        self.commitments.len()
    }

    /// Returns the slice of compressed Ristretto255 coefficient commitments $[C_0, \dots,
    /// C_{t-1}]$.
    pub fn commitments(&self) -> &[CompressedRistretto] {
        &self.commitments
    }
}

impl ToProto for Share {
    type Proto = FeldmanShareProto;

    fn to_proto(&self, _ctx: ()) -> Result<Self::Proto, StatusError> {
        if self.index.get() > MAX_SHARES {
            return Err(status::invalid_argument("Share index must be in 1..=MAX_SHARES"));
        }
        Ok(proto!(FeldmanShareProto {
            index: self.index.get(),
            value: self.value.as_bytes().to_vec(),
        }))
    }
}

impl FromProto for Share {
    type Proto = FeldmanShareProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        _ctx: (),
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let raw_index = proto.index();
        if raw_index == 0 || raw_index > MAX_SHARES {
            return Err(status::invalid_argument(
                "FeldmanShareProto index must be in 1..=MAX_SHARES",
            ));
        }
        let index = NonZeroU32::new(raw_index)
            .ok_or_else(|| status::invalid_argument("FeldmanShareProto index must be non-zero"))?;
        let value = SecretScalar::from_canonical_bytes(proto.value())?;
        if *value.as_scalar() == Scalar::ZERO {
            return Err(status::invalid_argument(
                "FeldmanShareProto scalar value must be non-zero",
            ));
        }
        Ok(Self { index, value })
    }
}

impl ToProto for FeldmanCommitment {
    type Proto = FeldmanCommitmentProto;

    fn to_proto(&self, _ctx: ()) -> Result<Self::Proto, StatusError> {
        if self.commitments.is_empty() || self.commitments.len() > MAX_SHARES as usize {
            return Err(status::invalid_argument(
                "FeldmanCommitment length must be in 1..=MAX_SHARES",
            ));
        }
        Ok(proto!(FeldmanCommitmentProto {
            commitments: self.commitments.iter().map(|c| c.as_bytes().to_vec()),
        }))
    }
}

impl FromProto for FeldmanCommitment {
    type Proto = FeldmanCommitmentProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        _ctx: (),
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let raw_commitments = proto.commitments();
        if raw_commitments.is_empty() || raw_commitments.len() > MAX_SHARES as usize {
            return Err(status::invalid_argument(
                "FeldmanCommitmentProto must have 1..=MAX_SHARES commitments",
            ));
        }
        let mut commitments = Vec::with_capacity(raw_commitments.len());
        for bytes in raw_commitments.iter() {
            let arr: [u8; COMMITMENT_POINT_BYTE_LEN] = bytes.try_into().map_err(|_| {
                status::invalid_argument("FeldmanCommitmentProto point must be exactly 32 bytes")
            })?;
            commitments.push(CompressedRistretto(arr));
        }
        Self::new(commitments)
    }
}

/// Splits `secret` into `num_shares` shares with reconstruction threshold `threshold` ($t$-of-$n$)
/// evaluated at 1-based indices $1, 2, \dots, \text{num\_shares}$.
///
/// Validates `1 <= threshold <= num_shares <= MAX_SHARES` and `*secret.as_scalar() !=
/// Scalar::ZERO`.
pub fn split<P: SecurePrng>(
    secret: &SecretScalar,
    threshold: u32,
    num_shares: u32,
    prng: &mut P,
) -> Result<(FeldmanCommitment, Vec<Share>), StatusError> {
    if threshold == 0 || threshold > num_shares || num_shares > MAX_SHARES {
        return Err(status::invalid_argument(
            "Invalid (threshold, num_shares): require 1 <= threshold <= num_shares <= MAX_SHARES",
        ));
    }
    if *secret.as_scalar() == Scalar::ZERO {
        return Err(status::invalid_argument("Secret scalar for Feldman VSS must be non-zero"));
    }

    let t = threshold as usize;
    let n = num_shares as usize;

    let mut coeffs = Vec::with_capacity(t);
    coeffs.push(*secret.as_scalar());
    for _ in 1..t {
        let c = SecretScalar::random(prng)?;
        coeffs.push(*c.as_scalar());
    }

    // Constant-time fixed-base scalar multiplication for all secret polynomial coefficients.
    let commitments: Vec<CompressedRistretto> =
        coeffs.iter().map(|a_k| RistrettoPoint::mul_base(a_k).compress()).collect();

    // Evaluate f(x) = sum_{k=0}^{t-1} a_k * x^k via Horner's method for x = 1..=num_shares.
    let mut shares = Vec::with_capacity(n);
    for i in 1..=num_shares {
        let index = NonZeroU32::new(i)
            .ok_or_else(|| status::internal("Share index in 1..=num_shares must be non-zero"))?;
        let x = Scalar::from(i);
        let mut y = Scalar::ZERO;
        for coeff in coeffs.iter().rev() {
            y = y * x + coeff;
        }
        shares.push(Share { index, value: SecretScalar::new(y) });
    }

    Ok((FeldmanCommitment { commitments }, shares))
}

/// Verifies a single `share` against `commitment` by checking
/// $y_i \cdot G \stackrel{?}{=} \sum_{k=0}^{t-1} x_i^k \cdot C_k$ in constant time.
pub fn verify_share(commitment: &FeldmanCommitment, share: &Share) -> status::Status {
    let t = commitment.commitments.len();
    if t == 0 || t > MAX_SHARES as usize {
        return Err(status::invalid_argument(
            "FeldmanCommitment threshold out of valid range 1..=MAX_SHARES",
        ));
    }
    if share.index.get() > MAX_SHARES {
        return Err(status::invalid_argument("Share index exceeds MAX_SHARES"));
    }
    if *share.value.as_scalar() == Scalar::ZERO {
        return Err(status::invalid_argument("Feldman VSS share value must be non-zero"));
    }

    let mut points = Vec::with_capacity(t);
    for c in &commitment.commitments {
        let pt = c.decompress().ok_or_else(|| {
            status::invalid_argument("Invalid compressed Ristretto255 point in FeldmanCommitment")
        })?;
        if pt.is_identity() {
            return Err(status::invalid_argument("Identity point in FeldmanCommitment"));
        }
        points.push(pt);
    }

    // Compute powers 1, x, x^2, ..., x^{t-1} directly in F_l to prevent u32/u64 overflow.
    let x = Scalar::from(share.index.get());
    let mut powers = Vec::with_capacity(t);
    let mut x_pow = Scalar::ONE;
    for _ in 0..t {
        powers.push(x_pow);
        x_pow *= x;
    }

    // Constant-time fixed-base multiplication on the secret share scalar `share.value`.
    let lhs = RistrettoPoint::mul_base(share.value.as_scalar());
    // Public-input multiscalar multiplication for the right-hand side.
    let rhs = RistrettoPoint::vartime_multiscalar_mul(powers.iter(), points.iter());

    // `RistrettoPoint::eq` uses `subtle::ConstantTimeEq::ct_eq` internally.
    if lhs == rhs {
        Ok(())
    } else {
        Err(status::invalid_argument("Feldman VSS share verification failed"))
    }
}

/// Reconstructs the shared `SecretScalar` $s = f(0)$ from `shares` after verifying every passed
/// share against `commitment`.
///
/// Fails fast with `INVALID_ARGUMENT` if `shares.len() < commitment.threshold()`,
/// `shares.len() > MAX_SHARES`, any two shares have the same `index`, or any share fails
/// [`verify_share`].
pub fn reconstruct(
    commitment: &FeldmanCommitment,
    shares: &[Share],
) -> Result<SecretScalar, StatusError> {
    let t = commitment.threshold();
    if t == 0 || t > MAX_SHARES as usize {
        return Err(status::invalid_argument(
            "FeldmanCommitment threshold out of valid range 1..=MAX_SHARES",
        ));
    }
    if shares.len() < t {
        return Err(status::invalid_argument("Insufficient shares to reconstruct secret"));
    }
    if shares.len() > MAX_SHARES as usize {
        return Err(status::invalid_argument("Number of shares exceeds MAX_SHARES"));
    }

    let mut seen_indices = BTreeSet::new();
    for share in shares {
        if !seen_indices.insert(share.index) {
            return Err(status::invalid_argument("Duplicate share index in reconstruct"));
        }
        verify_share(commitment, share)?;
    }

    let active_shares = &shares[..t];
    let xs: Vec<Scalar> = active_shares.iter().map(|s| Scalar::from(s.index.get())).collect();

    let mut numerators = Vec::with_capacity(t);
    let mut denominators = Vec::with_capacity(t);
    for j in 0..t {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for m in 0..t {
            if m != j {
                num *= xs[m];
                den *= xs[m] - xs[j];
            }
        }
        // Guard against zero denominators before calling `Scalar::batch_invert`, which panics
        // in debug builds and silently returns zero in release builds if any element is zero.
        if den == Scalar::ZERO {
            return Err(status::invalid_argument("Zero denominator in Lagrange interpolation"));
        }
        numerators.push(num);
        denominators.push(den);
    }

    Scalar::batch_invert(&mut denominators);

    let mut secret = Scalar::ZERO;
    for (j, share) in active_shares.iter().enumerate() {
        let lambda_j = numerators[j] * denominators[j];
        secret += share.value.as_scalar() * lambda_j;
    }

    Ok(SecretScalar::new(secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::{gtest, verify_eq, verify_that, Result as GTestResult};
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use status::StatusErrorCode;
    use status_matchers_rs::status_is;

    fn create_test_prng() -> Result<SingleThreadHkdfPrng, StatusError> {
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        SingleThreadHkdfPrng::create(&seed)
    }

    #[gtest]
    fn test_split_verify_and_reconstruct_roundtrip() -> GTestResult<()> {
        let mut prng = create_test_prng()?;
        let secret = SecretScalar::random(&mut prng)?;

        let (commitment, shares) = split(&secret, 3, 5, &mut prng)?;
        verify_eq!(commitment.threshold(), 3)?;
        verify_eq!(shares.len(), 5)?;

        for share in &shares {
            verify_share(&commitment, share)?;
        }

        // Any 3-share subset reconstructs the exact secret.
        let subset_a = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
        let subset_b = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let subset_c = vec![shares[4].clone(), shares[2].clone(), shares[0].clone()];
        verify_eq!(reconstruct(&commitment, &subset_a)?, secret)?;
        verify_eq!(reconstruct(&commitment, &subset_b)?, secret)?;
        verify_eq!(reconstruct(&commitment, &subset_c)?, secret)?;

        // Passing > t valid shares also reconstructs the exact secret.
        verify_eq!(reconstruct(&commitment, &shares)?, secret)?;
        Ok(())
    }

    #[gtest]
    fn test_boundary_thresholds_t1_t_eq_n_and_max_shares() -> GTestResult<()> {
        let mut prng = create_test_prng()?;
        let secret = SecretScalar::random(&mut prng)?;

        // t = 1, n = 1
        let (comm_1_1, shares_1_1) = split(&secret, 1, 1, &mut prng)?;
        verify_eq!(reconstruct(&comm_1_1, &shares_1_1)?, secret)?;

        // t = 1, n = 5
        let (comm_1_5, shares_1_5) = split(&secret, 1, 5, &mut prng)?;
        verify_eq!(reconstruct(&comm_1_5, &[shares_1_5[4].clone()])?, secret)?;

        // t = n = 5
        let (comm_5_5, shares_5_5) = split(&secret, 5, 5, &mut prng)?;
        verify_eq!(reconstruct(&comm_5_5, &shares_5_5)?, secret)?;

        // High degree & index x = 100 (verifies no u64 overflow when x^k > 2^64).
        let (comm_15_100, shares_15_100) = split(&secret, 15, MAX_SHARES, &mut prng)?;
        verify_share(&comm_15_100, &shares_15_100[99])?;
        let high_index_subset: Vec<Share> = shares_15_100[85..100].to_vec();
        verify_eq!(reconstruct(&comm_15_100, &high_index_subset)?, secret)?;

        Ok(())
    }

    #[gtest]
    fn test_invalid_split_parameters_rejected() -> GTestResult<()> {
        let mut prng = create_test_prng()?;
        let secret = SecretScalar::random(&mut prng)?;

        verify_that!(
            split(&secret, 0, 5, &mut prng),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        verify_that!(
            split(&secret, 6, 5, &mut prng),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        verify_that!(
            split(&secret, 3, MAX_SHARES + 1, &mut prng),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        let zero_secret = SecretScalar::new(Scalar::ZERO);
        verify_that!(
            split(&zero_secret, 2, 3, &mut prng),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        Ok(())
    }

    #[gtest]
    fn test_tampered_share_and_wrong_commitment_rejected() -> GTestResult<()> {
        let mut prng = create_test_prng()?;
        let secret = SecretScalar::random(&mut prng)?;
        let (commitment, shares) = split(&secret, 3, 5, &mut prng)?;

        // Tamper with share value.
        let mut bad_share = shares[0].clone();
        bad_share.value = SecretScalar::new(*bad_share.value.as_scalar() + Scalar::ONE);
        verify_that!(
            verify_share(&commitment, &bad_share),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // Even if bad_share is the (t+1)-th share passed to reconstruct, reconstruct must fail
        // fast.
        let mut shares_with_bad_tail =
            vec![shares[0].clone(), shares[1].clone(), shares[2].clone(), bad_share];
        verify_that!(
            reconstruct(&commitment, &shares_with_bad_tail),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;
        shares_with_bad_tail.pop();

        // Share from a different polynomial is rejected.
        let other_secret = SecretScalar::random(&mut prng)?;
        let (other_commitment, _) = split(&other_secret, 3, 5, &mut prng)?;
        verify_that!(
            verify_share(&other_commitment, &shares[0]),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // Out-of-range share index (> MAX_SHARES) is rejected.
        let out_of_range_share = Share {
            index: NonZeroU32::new(MAX_SHARES + 1).unwrap(),
            value: shares[0].value.clone(),
        };
        verify_that!(
            verify_share(&commitment, &out_of_range_share),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        Ok(())
    }

    #[gtest]
    fn test_reconstruct_rejects_fewer_than_t_and_duplicate_indices() -> GTestResult<()> {
        let mut prng = create_test_prng()?;
        let secret = SecretScalar::random(&mut prng)?;
        let (commitment, shares) = split(&secret, 3, 5, &mut prng)?;

        // Fewer than t shares.
        verify_that!(
            reconstruct(&commitment, &shares[..2]),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // Duplicate share indices (guards against batch_invert zero denominator).
        let duplicate_shares = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        verify_that!(
            reconstruct(&commitment, &duplicate_shares),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        Ok(())
    }

    #[gtest]
    fn test_canonical_scalar_and_debug_redaction() -> GTestResult<()> {
        let mut prng = create_test_prng()?;
        let secret = SecretScalar::random(&mut prng)?;
        let roundtrip = SecretScalar::from_canonical_bytes(&secret.to_bytes())?;
        verify_eq!(secret, roundtrip)?;

        // Non-canonical scalar bytes (0xFF..FF >= group order l) must be rejected.
        let non_canonical = [0xFFu8; SCALAR_BYTE_LEN];
        verify_that!(
            SecretScalar::from_canonical_bytes(&non_canonical),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // Wrong slice length must be rejected.
        verify_that!(
            SecretScalar::from_canonical_bytes(&[1u8; 31]),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // Debug output must redact secret scalar values.
        let share = Share { index: NonZeroU32::new(1).unwrap(), value: secret };
        let debug_str = format!("{:?} {:?}", share.value, share);
        verify_eq!(debug_str.contains("REDACTED"), true)?;

        Ok(())
    }

    #[gtest]
    fn test_commitment_validation_rejects_empty_noncanonical_and_identity() -> GTestResult<()> {
        // Empty commitment vector.
        verify_that!(FeldmanCommitment::new(vec![]), status_is(StatusErrorCode::INVALID_ARGUMENT))?;

        // Commitment vector exceeding MAX_SHARES.
        let valid_point = RistrettoPoint::mul_base(&Scalar::ONE).compress();
        verify_that!(
            FeldmanCommitment::new(vec![valid_point; (MAX_SHARES + 1) as usize]),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // Identity point must be rejected.
        verify_that!(
            FeldmanCommitment::new(vec![CompressedRistretto::default()]),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // Non-canonical / invalid compressed Ristretto255 point must be rejected.
        verify_that!(
            FeldmanCommitment::new(vec![CompressedRistretto([0xFFu8; 32])]),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        Ok(())
    }

    #[gtest]
    fn test_proto_serialization_roundtrip_and_malformed_inputs() -> GTestResult<()> {
        let mut prng = create_test_prng()?;
        let secret = SecretScalar::random(&mut prng)?;
        let (commitment, shares) = split(&secret, 3, 5, &mut prng)?;

        // Valid round-trip for FeldmanCommitment and Share.
        let comm_proto = commitment.to_proto(())?;
        let comm_roundtrip = FeldmanCommitment::from_proto(comm_proto, ())?;
        verify_eq!(comm_roundtrip, commitment)?;

        let mut shares_roundtrip = Vec::with_capacity(shares.len());
        for share in &shares {
            let share_proto = share.to_proto(())?;
            let decoded = Share::from_proto(share_proto, ())?;
            verify_eq!(&decoded, share)?;
            verify_share(&comm_roundtrip, &decoded)?;
            shares_roundtrip.push(decoded);
        }
        verify_eq!(reconstruct(&comm_roundtrip, &shares_roundtrip[..3])?, secret)?;

        // Malformed Share protos: index 0, index > MAX_SHARES, wrong byte length, non-canonical
        // scalar, zero scalar.
        let zero_idx_proto =
            proto!(FeldmanShareProto { index: 0, value: shares[0].value.as_bytes().to_vec() });
        verify_that!(
            Share::from_proto(zero_idx_proto, ()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        let high_idx_proto = proto!(FeldmanShareProto {
            index: MAX_SHARES + 1,
            value: shares[0].value.as_bytes().to_vec(),
        });
        verify_that!(
            Share::from_proto(high_idx_proto, ()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        let short_val_proto = proto!(FeldmanShareProto { index: 1, value: vec![1u8; 31] });
        verify_that!(
            Share::from_proto(short_val_proto, ()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        let non_canonical_val_proto =
            proto!(FeldmanShareProto { index: 1, value: vec![0xFFu8; 32] });
        verify_that!(
            Share::from_proto(non_canonical_val_proto, ()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        let zero_val_proto = proto!(FeldmanShareProto { index: 1, value: vec![0u8; 32] });
        verify_that!(
            Share::from_proto(zero_val_proto, ()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        // Malformed FeldmanCommitment protos: empty, > MAX_SHARES, wrong point byte length,
        // identity point, invalid curve point.
        let empty_comm_proto = proto!(FeldmanCommitmentProto {});
        verify_that!(
            FeldmanCommitment::from_proto(empty_comm_proto, ()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        let valid_pt_bytes = RistrettoPoint::mul_base(&Scalar::ONE).compress().to_bytes().to_vec();
        let oversized_comm_proto = proto!(FeldmanCommitmentProto {
            commitments: (0..=MAX_SHARES).map(|_| valid_pt_bytes.clone()),
        });
        verify_that!(
            FeldmanCommitment::from_proto(oversized_comm_proto, ()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        let short_pt_comm_proto = proto!(FeldmanCommitmentProto { commitments: [vec![1u8; 31]] });
        verify_that!(
            FeldmanCommitment::from_proto(short_pt_comm_proto, ()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        let identity_comm_proto =
            proto!(FeldmanCommitmentProto { commitments: [vec![0u8; 32], valid_pt_bytes.clone()] });
        verify_that!(
            FeldmanCommitment::from_proto(identity_comm_proto, ()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        let leading_identity_comm_proto =
            proto!(FeldmanCommitmentProto { commitments: [valid_pt_bytes, vec![0u8; 32]] });
        verify_that!(
            FeldmanCommitment::from_proto(leading_identity_comm_proto, ()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        let invalid_curve_comm_proto =
            proto!(FeldmanCommitmentProto { commitments: [vec![0xFFu8; 32]] });
        verify_that!(
            FeldmanCommitment::from_proto(invalid_curve_comm_proto, ()),
            status_is(StatusErrorCode::INVALID_ARGUMENT)
        )?;

        Ok(())
    }
}
