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

use ahe::{get_moduli, get_rns_context_ref, public_key_component_a, s_flood, AhePublicParameters};
use ahe_traits::{
    AheBase, AheEncrypt, AheKeygen, ExportCiphertext, ExportEncryptionMetadata,
    ExportPublicParameters, PartialDec, Recover,
};
use shell_types::{
    create_empty_rns_polynomial, write_rns_polynomial_to_buffer_128,
    write_small_rns_polynomial_to_buffer, RnsContextRef, RnsPolynomial,
};
use single_thread_hkdf::{Seed, SingleThreadHkdfPrng};

/// ShellAhe configuration. `log_n` is the number of plaintext bits. `t` is the
/// plaintext modulus, which must be an odd number. `qs` are the RNS moduli.
/// `s_flood` is the flooding noise.
#[derive(Debug, Clone)]
pub struct ShellAheConfig {
    pub log_n: u64,
    pub t: u64,
    pub qs: Vec<u64>,
    pub s_flood: f64,
}

/// `error_variance` and `s_base_flood` should not need to change.
const ERROR_VARIANCE: u64 = 8;
const S_BASE_FLOOD: f64 = 12.8;

fn check_vec_len<T>(left: &Vec<T>, right: &Vec<T>) -> Result<(), status::StatusError> {
    if left.len() != right.len() {
        return Err(status::invalid_argument(format!(
            "left and right must have the same length, got {} and {}",
            left.len(),
            right.len()
        )));
    }
    Ok(())
}

/// Base type holding public AHE configuration and C++ parameters.
pub struct ShellAhe {
    public_ahe_parameters: AhePublicParameters,
    num_coeffs: usize,
}

impl ShellAhe {
    /// Convenience function.
    fn add_vec_rns_polynomial_in_place(
        &self,
        left: &Vec<RnsPolynomial>,
        right: &mut Vec<RnsPolynomial>,
    ) -> status::Status {
        check_vec_len(&left, &right)?;
        let moduli = ahe::get_moduli(&self.public_ahe_parameters);
        for i in 0..left.len() {
            shell_types::add_in_place(&moduli, &left[i], &mut right[i])?;
        }
        Ok(())
    }

    /// Exports an RnsPolynomial as a vector of u128. Values are modulo q.
    pub fn export_rns_polynomial(
        &self,
        poly: &RnsPolynomial,
    ) -> Result<Vec<u128>, status::StatusError> {
        let mut out_u64 = vec![0u64; self.num_coeffs * 2];
        write_rns_polynomial_to_buffer_128(
            &get_rns_context_ref(&self.public_ahe_parameters),
            poly,
            &mut out_u64,
        )?;
        let mut out = vec![0u128; self.num_coeffs];
        for i in 0..out.len() {
            out[i] = out_u64[2 * i] as u128 | (out_u64[2 * i + 1] as u128) << 64;
        }
        Ok(out)
    }

    /// Exports a slice of RnsPolynomials as a vector of vectors.
    fn export_rns_polynomial_vec(
        &self,
        polys: &[RnsPolynomial],
    ) -> Result<Vec<Vec<u128>>, status::StatusError> {
        polys.iter().map(|x| self.export_rns_polynomial(x)).collect()
    }

    /// Exports a small RnsPolynomial as a vector of i64. Values are signed
    /// integers.
    fn export_small_rns_polynomial(
        &self,
        poly: &RnsPolynomial,
    ) -> Result<Vec<i64>, status::StatusError> {
        let mut out = vec![0i64; self.num_coeffs];
        write_small_rns_polynomial_to_buffer(
            poly,
            &get_moduli(&self.public_ahe_parameters),
            &mut out,
        )?;
        Ok(out)
    }

    /// Exports a slice of small RnsPolynomials as a vector of vectors.
    fn export_small_rns_polynomial_vec(
        &self,
        polys: &[RnsPolynomial],
    ) -> Result<Vec<Vec<i64>>, status::StatusError> {
        polys.iter().map(|x| self.export_small_rns_polynomial(x)).collect()
    }

    fn key_gen_impl(
        &self,
        prng: &mut <Self as AheBase>::Rng,
        wraparound: Option<&mut RnsPolynomial>,
    ) -> Result<
        (
            <ShellAhe as AheBase>::SecretKeyShare,
            <ShellAhe as AheBase>::PublicKeyShare,
            <ShellAhe as AheBase>::KeyGenMetadata,
        ),
        status::StatusError,
    > {
        // Generate secret key share. `prng` is a Rust-defined SingleThreadHkdfPrng
        // (tuple with a single element), but `generate_secret_key` expects an
        // ffi SingleThreadHkdfWrapper.
        let sk_share = ahe::generate_secret_key(&self.public_ahe_parameters, &mut prng.0)?;

        // Generate public key share.
        let mut pk_share_b = create_empty_rns_polynomial();
        let mut pk_share_error = create_empty_rns_polynomial();
        ahe::generate_public_key_share(
            &sk_share,
            &self.public_ahe_parameters,
            &mut prng.0,
            &mut pk_share_b,
            &mut pk_share_error,
            wraparound,
        )?;
        Ok((sk_share, pk_share_b, pk_share_error))
    }

    pub fn key_gen_with_verification_metadata(
        &self,
        prng: &mut <ShellAhe as AheBase>::Rng,
    ) -> Result<
        (
            <ShellAhe as AheBase>::SecretKeyShare,
            <ShellAhe as AheBase>::PublicKeyShare,
            <ShellAhe as AheBase>::KeyGenMetadata,
            RnsPolynomial,
        ),
        status::StatusError,
    > {
        let mut pk_wraparound = create_empty_rns_polynomial();
        let (sk_share, pk_share_b, pk_share_error) =
            self.key_gen_impl(prng, Some(&mut pk_wraparound))?;
        Ok((sk_share, pk_share_b, pk_share_error, pk_wraparound))
    }

    fn encrypt_impl(
        &self,
        plaintext: &<Self as AheBase>::Plaintext,
        pk: &<Self as AheBase>::PublicKey,
        prng: &mut <Self as AheBase>::Rng,
        compute_wraparounds: bool,
    ) -> Result<
        (
            <Self as AheBase>::Ciphertext,
            <Self as AheBase>::EncryptionMetadata,
            Option<Vec<RnsPolynomial>>,
        ),
        status::StatusError,
    > {
        let mut component_b = vec![];
        let mut component_a = vec![];
        let mut secret_r = vec![];
        let mut error_e = vec![];
        let mut wraparounds = vec![];

        let t = ahe::get_plaintext_modulus(&self.public_ahe_parameters) as i64;

        let num_polynomials = (plaintext.len() as f64 / self.num_coeffs as f64).ceil() as usize;
        for i in 0..num_polynomials {
            let mut ct_b = create_empty_rns_polynomial();
            let mut ct_a = create_empty_rns_polynomial();
            let mut ct_r = create_empty_rns_polynomial();
            let mut ct_e = create_empty_rns_polynomial();
            let mut ct_wraparound = create_empty_rns_polynomial();
            let mut ct_wraparound_option = None;
            if compute_wraparounds {
                ct_wraparound_option = Some(&mut ct_wraparound);
            }

            let start = i * self.num_coeffs;
            // Last polynomial might be incomplete.
            let end = std::cmp::min(start + self.num_coeffs, plaintext.len());
            let mut unsigned_plaintext = vec![0; end - start];
            for j in start..end {
                let v = plaintext[j];
                if v < 0 {
                    unsigned_plaintext[j - start] = (v + t) as u64;
                } else {
                    unsigned_plaintext[j - start] = v as u64;
                }
            }
            ahe::ahe_encrypt(
                &unsigned_plaintext,
                pk,
                &self.public_ahe_parameters,
                &mut prng.0,
                &mut ct_b,
                &mut ct_a,
                &mut ct_r,
                &mut ct_e,
                ct_wraparound_option,
            )?;
            component_b.push(ct_b);
            component_a.push(ct_a);
            secret_r.push(ct_r);
            error_e.push(ct_e);
            if compute_wraparounds {
                wraparounds.push(ct_wraparound);
            }
        }

        let ciphertext = Ciphertext {
            component_b: RecoverCiphertext(component_b),
            component_a: PartialDecCiphertext(component_a),
        };
        let metadata = EncryptionMetadata { secret_r, error_e };
        let wraparounds_option = if compute_wraparounds { Some(wraparounds) } else { None };
        Ok((ciphertext, metadata, wraparounds_option))
    }

    pub fn encrypt_with_verification_metadata(
        &self,
        plaintext: &<Self as AheBase>::Plaintext,
        pk: &<Self as AheBase>::PublicKey,
        prng: &mut <Self as AheBase>::Rng,
    ) -> Result<
        (<Self as AheBase>::Ciphertext, <Self as AheBase>::EncryptionMetadata, Vec<RnsPolynomial>),
        status::StatusError,
    > {
        let (ciphertext, metadata, wraparounds) = self.encrypt_impl(plaintext, pk, prng, true)?;
        if !wraparounds.is_some() {
            return Err(status::internal("Failed to compute wraparounds."));
        }
        Ok((ciphertext, metadata, wraparounds.unwrap()))
    }

    fn partial_decrypt_impl(
        &self,
        ct_a: &<Self as AheBase>::PartialDecCiphertext,
        sk_share: &<Self as AheBase>::SecretKeyShare,
        prng: &mut <Self as AheBase>::Rng,
        compute_metadata: bool,
    ) -> Result<
        (<Self as AheBase>::PartialDecryption, Option<PartialDecryptionMetadata>),
        status::StatusError,
    > {
        let mut pd = vec![];
        let mut errors = vec![];
        let mut wraparounds = vec![];
        for ct_a_polynomial in &ct_a.0 {
            let mut error = create_empty_rns_polynomial();
            let mut wraparound = create_empty_rns_polynomial();
            let mut error_option = None;
            let mut wraparound_option = None;
            if compute_metadata {
                error_option = Some(&mut error);
                wraparound_option = Some(&mut wraparound);
            }
            let pd_polynomial = ahe::partial_decrypt(
                &ct_a_polynomial,
                sk_share,
                &self.public_ahe_parameters,
                &mut prng.0,
                error_option,
                wraparound_option,
            )?;
            pd.push(pd_polynomial);
            if compute_metadata {
                errors.push(error);
                wraparounds.push(wraparound);
            }
        }
        let metadata_option = if compute_metadata {
            Some(PartialDecryptionMetadata { errors, wraparounds })
        } else {
            None
        };
        Ok((pd, metadata_option))
    }

    pub fn partial_decrypt_with_verification_metadata(
        &self,
        ct_a: &<Self as AheBase>::PartialDecCiphertext,
        sk_share: &<Self as AheBase>::SecretKeyShare,
        prng: &mut <Self as AheBase>::Rng,
    ) -> Result<
        (<Self as AheBase>::PartialDecryption, PartialDecryptionMetadata),
        status::StatusError,
    > {
        let (pd, metadata) =
            self.partial_decrypt_impl(ct_a, sk_share, prng, /*compute_metadata=*/ true)?;
        if !metadata.is_some() {
            return Err(status::internal("Failed to compute metadata."));
        }
        Ok((pd, metadata.unwrap()))
    }

    pub fn num_coeffs(&self) -> usize {
        self.num_coeffs
    }

    pub fn rns_context(&self) -> RnsContextRef {
        get_rns_context_ref(&self.public_ahe_parameters)
    }

    pub fn public_key_component_a(&self) -> Result<RnsPolynomial, status::StatusError> {
        public_key_component_a(&self.public_ahe_parameters)
    }

    pub fn flood_bound(&self) -> Result<u128, status::StatusError> {
        let sd = s_flood(&self.public_ahe_parameters)?;
        if sd < 0.0 {
            return Err(status::internal("Flood error standard deviation cannot be negative"));
        }
        let bound = (10.0 * sd).ceil();
        if bound > (1u128 << 127) as f64 {
            return Err(status::internal("Flood bound is too large."));
        }
        Ok(bound as u128)
    }
}

#[derive(Clone)]
pub struct PartialDecCiphertext(pub Vec<RnsPolynomial>);
#[derive(Clone)]
pub struct RecoverCiphertext(pub Vec<RnsPolynomial>);

/// A plaintext gets encrypted into two components, usually denoted as `ct_0`
/// (a.k.a. compontent B) and `c_1` (a.k.a. component A) -- note the reverse
/// alphabetical order. Supports addition.
#[derive(Clone)]
pub struct Ciphertext {
    pub component_b: RecoverCiphertext,
    pub component_a: PartialDecCiphertext,
}

pub struct EncryptionMetadata {
    pub secret_r: Vec<RnsPolynomial>,
    pub error_e: Vec<RnsPolynomial>,
}

pub struct PartialDecryptionMetadata {
    pub errors: Vec<RnsPolynomial>,
    pub wraparounds: Vec<RnsPolynomial>,
}

impl AheBase for ShellAhe {
    type SecretKeyShare = RnsPolynomial;
    type PublicKeyShare = RnsPolynomial;
    type KeyGenMetadata = RnsPolynomial;
    type PublicKey = RnsPolynomial;

    type Plaintext = Vec<i64>;

    type Ciphertext = Ciphertext;
    type EncryptionMetadata = EncryptionMetadata;
    type PartialDecryptionMetadata = PartialDecryptionMetadata;
    type PartialDecCiphertext = PartialDecCiphertext;
    type RecoverCiphertext = RecoverCiphertext;
    type PartialDecryption = Vec<RnsPolynomial>;

    type Rng = SingleThreadHkdfPrng;

    type Config = ShellAheConfig;

    fn new(config: Self::Config, context_string: &[u8]) -> Result<Self, status::StatusError> {
        let num_coeffs = 1 << config.log_n;
        let public_seed = single_thread_hkdf::compute_hkdf(
            context_string,
            b"",
            b"ShellAhe.public_seed",
            single_thread_hkdf::seed_length(),
        )?;
        let public_ahe_parameters = ahe::create_public_parameters(
            config.log_n,
            config.t,
            &config.qs,
            /* error_variance= */ ERROR_VARIANCE,
            /* s_base_flood= */ S_BASE_FLOOD,
            config.s_flood,
            &public_seed,
        )?;

        Ok(Self { public_ahe_parameters, num_coeffs })
    }

    fn aggregate_public_key_shares(
        &self,
        public_key_shares: &[Self::PublicKeyShare],
    ) -> Result<Self::PublicKey, status::StatusError> {
        let moduli = ahe::get_moduli(&self.public_ahe_parameters);

        let mut public_key = ahe::create_zero_rns_polynomial(&self.public_ahe_parameters)?;
        for public_key_share in public_key_shares {
            shell_types::add_in_place(&moduli, &public_key_share, &mut public_key)?;
        }
        Ok(public_key)
    }

    fn add_plaintexts_in_place(
        &self,
        left: &Self::Plaintext,
        right: &mut Self::Plaintext,
    ) -> status::Status {
        check_vec_len(left, right)?;
        for (i, v) in left.iter().enumerate() {
            right[i] += v;
        }
        Ok(())
    }

    fn add_ciphertexts_in_place(
        &self,
        left: &Self::Ciphertext,
        right: &mut Self::Ciphertext,
    ) -> status::Status {
        self.add_vec_rns_polynomial_in_place(&left.component_a.0, &mut right.component_a.0)?;
        self.add_vec_rns_polynomial_in_place(&left.component_b.0, &mut right.component_b.0)?;
        Ok(())
    }

    fn add_pd_ciphertexts_in_place(
        &self,
        left: &Self::PartialDecCiphertext,
        right: &mut Self::PartialDecCiphertext,
    ) -> status::Status {
        self.add_vec_rns_polynomial_in_place(&left.0, &mut right.0)?;
        Ok(())
    }

    fn add_recover_ciphertexts_in_place(
        &self,
        left: &Self::RecoverCiphertext,
        right: &mut Self::RecoverCiphertext,
    ) -> status::Status {
        self.add_vec_rns_polynomial_in_place(&left.0, &mut right.0)?;
        Ok(())
    }

    fn get_partial_dec_ciphertext(
        &self,
        ct: &Self::Ciphertext,
    ) -> Result<Self::PartialDecCiphertext, status::StatusError> {
        Ok(ct.component_a.clone())
    }

    fn get_recover_ciphertext(
        &self,
        ct: &Self::Ciphertext,
    ) -> Result<Self::RecoverCiphertext, status::StatusError> {
        Ok(ct.component_b.clone())
    }

    fn add_partial_decryptions_in_place(
        &self,
        left: &Self::PartialDecryption,
        right: &mut Self::PartialDecryption,
    ) -> status::Status {
        self.add_vec_rns_polynomial_in_place(left, right)
    }
}

impl AheKeygen for ShellAhe {
    fn key_gen(
        &self,
        prng: &mut Self::Rng,
    ) -> Result<
        (Self::SecretKeyShare, Self::PublicKeyShare, Self::KeyGenMetadata),
        status::StatusError,
    > {
        let (sk_share, pk_share_b, pk_share_error) = self.key_gen_impl(prng, None)?;
        Ok((sk_share, pk_share_b, pk_share_error))
    }
}

impl AheEncrypt for ShellAhe {
    fn encrypt(
        &self,
        plaintext: &Self::Plaintext,
        pk: &Self::PublicKey,
        prng: &mut Self::Rng,
    ) -> Result<(Self::Ciphertext, Self::EncryptionMetadata), status::StatusError> {
        let (ciphertext, metadata, _) = self.encrypt_impl(plaintext, pk, prng, false)?;
        Ok((ciphertext, metadata))
    }
}

impl PartialDec for ShellAhe {
    fn partial_decrypt(
        &self,
        ct_a: &Self::PartialDecCiphertext,
        sk_share: &Self::SecretKeyShare,
        prng: &mut Self::Rng,
    ) -> Result<Self::PartialDecryption, status::StatusError> {
        let (pd, _) =
            self.partial_decrypt_impl(&ct_a, sk_share, prng, /*compute_metadata=*/ false)?;
        Ok(pd)
    }
}

impl Recover for ShellAhe {
    fn recover(
        &self,
        pd: &Self::PartialDecryption,
        ct_b: &Self::RecoverCiphertext,
        plaintext_len: Option<usize>,
    ) -> Result<Self::Plaintext, status::StatusError> {
        check_vec_len(&pd, &ct_b.0)?;

        // Allow the buffer to be shorter, in case the last polynomial is padded.
        let buffer_len;
        if let Some(l) = plaintext_len {
            let min_buffer_len = (pd.len() - 1) * self.num_coeffs;
            if l < min_buffer_len {
                return Err(status::invalid_argument(format!(
                    "received plaintext_len = {}, but the ciphertexts contain at least {} values",
                    l, min_buffer_len
                )));
            }
            buffer_len = l;
        } else {
            buffer_len = pd.len() * self.num_coeffs;
        }

        let mut unsigned_values = vec![0; buffer_len];
        for i in 0..pd.len() {
            let start = i * self.num_coeffs;
            // Last polynomial might be incomplete.
            let end = std::cmp::min(start + self.num_coeffs, buffer_len);

            let n_written = ahe::recover_messages(
                &ct_b.0[i],
                &pd[i],
                &self.public_ahe_parameters,
                &mut unsigned_values[start..end],
            )?;
            if n_written != end - start {
                return Err(status::internal(format!(
                    "Expected {} recovered messages, but got {}",
                    end - start,
                    n_written,
                )));
            }
        }

        let t = ahe::get_plaintext_modulus(&self.public_ahe_parameters) as i64;
        let mut output_values = vec![0; buffer_len];
        for i in 0..buffer_len {
            output_values[i] = unsigned_values[i] as i64;
            if output_values[i] > t / 2 {
                output_values[i] -= t;
            }
        }
        Ok(output_values)
    }
}

/// Exports the public key component A (a single RnsPolynomial) as a vector of
/// u128. Values are integers modulo q, i.e., the product of the RNS moduli.
impl ExportPublicParameters<Vec<u128>> for ShellAhe {
    fn export_public_parameters(&self) -> Result<Vec<u128>, status::StatusError> {
        self.export_rns_polynomial(&ahe::public_key_component_a(&self.public_ahe_parameters)?)
    }
}

/// Export a PartialDecCiphertext as vector of vectors, each representing a
/// single RnsPolynomial. Values are integers modulo q, i.e., the product of the
/// RNS moduli.
impl ExportCiphertext<&PartialDecCiphertext, Vec<Vec<u128>>> for ShellAhe {
    fn export_ciphertext(
        &self,
        ct: &Self::PartialDecCiphertext,
    ) -> Result<Vec<Vec<u128>>, status::StatusError> {
        self.export_rns_polynomial_vec(&ct.0)
    }
}

/// Export a RecoverCiphertext as vector of vectors, each representing a single
/// RnsPolynomial. Values are integers modulo q, i.e., the product of the RNS
/// moduli.
impl ExportCiphertext<&RecoverCiphertext, Vec<Vec<u128>>> for ShellAhe {
    fn export_ciphertext(
        &self,
        ct: &Self::RecoverCiphertext,
    ) -> Result<Vec<Vec<u128>>, status::StatusError> {
        self.export_rns_polynomial_vec(&ct.0)
    }
}

/// Export a Ciphertext as a pair of vectors of vectors. The first element
/// contains the ciphertext compenent b (aka ct_0), the second element contains
/// component a (aka ct_1). Values are integers modulo q, i.e., the product of
/// the RNS moduli.
impl ExportCiphertext<&Ciphertext, (Vec<Vec<u128>>, Vec<Vec<u128>>)> for ShellAhe {
    fn export_ciphertext(
        &self,
        ct: &Self::Ciphertext,
    ) -> Result<(Vec<Vec<u128>>, Vec<Vec<u128>>), status::StatusError> {
        Ok((self.export_ciphertext(&ct.component_b)?, self.export_ciphertext(&ct.component_a)?))
    }
}

/// Export EncryptionMetadata as a pair of vectors of vectors. The first element
/// contains the encryption randomness (secret_r), while the second contains the
/// RLWE error (error_e). Values are (small) signed integers.
impl ExportEncryptionMetadata<(Vec<Vec<i64>>, Vec<Vec<i64>>)> for ShellAhe {
    fn export_encryption_metadata(
        &self,
        metadata: &Self::EncryptionMetadata,
    ) -> Result<(Vec<Vec<i64>>, Vec<Vec<i64>>), status::StatusError> {
        Ok((
            self.export_small_rns_polynomial_vec(&metadata.secret_r)?,
            self.export_small_rns_polynomial_vec(&metadata.error_e)?,
        ))
    }
}

#[cfg(test)]
mod test {
    // Instead of `super::*` because we consume types from other testing crates.
    use ahe_shell::*;

    use ahe_traits::{
        AheBase, AheEncrypt, AheKeygen, ExportCiphertext, ExportEncryptionMetadata,
        ExportPublicParameters, PartialDec, Recover,
    };
    use googletest::{expect_eq, gtest, matchers::eq, verify_eq, verify_false, verify_that};
    use prng_traits::SecurePrng;
    use shell_testing_parameters::make_ahe_config;
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use status::StatusErrorCode;
    use status_matchers_rs::status_is;
    use testing_utils::generate_random_signed_vector;

    const NUM_DECRYPTORS: usize = 3;
    const NUM_CLIENTS: usize = 1000;
    const MAX_ABSOLUTE_VALUE: i64 = 72;
    const CONTEXT_STRING: &[u8] = b"test_context_string";

    #[gtest]
    fn test_encrypt_decrypt_one() -> googletest::Result<()> {
        const NUM_VALUES: usize = 100;

        let ahe = ShellAhe::new(make_ahe_config(), CONTEXT_STRING)?;

        let pt = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;

        let (sk_share, pk_share, _) = ahe.key_gen(&mut prng)?;
        let pk = ahe.aggregate_public_key_shares(&[pk_share])?;
        let (ciphertext, _) = ahe.encrypt(&pt, &pk, &mut prng)?;

        let ct_1 = ahe.get_partial_dec_ciphertext(&ciphertext)?;
        let ct_0 = ahe.get_recover_ciphertext(&ciphertext)?;

        let partial_decryption = ahe.partial_decrypt(&ct_1, &sk_share, &mut prng)?;
        let decrypted = ahe.recover(&partial_decryption, &ct_0, Some(NUM_VALUES))?;
        verify_that!(&pt, eq(&decrypted[..pt.len()]))
    }

    #[gtest]
    fn test_encrypt_decrypt_sum() -> googletest::Result<()> {
        // Handle empty, short and long plaintexts. num_coeffs is 2048.
        for num_values in [0, 100, 3_000] {
            let config = make_ahe_config();
            let t = config.t; // Keep a copy of the plaintext modulus.

            let ahe = ShellAhe::new(config, CONTEXT_STRING)?;
            let seed = SingleThreadHkdfPrng::generate_seed()?;
            let mut prng = SingleThreadHkdfPrng::create(&seed)?;

            // Distributed key generation.
            let mut secret_key_shares = Vec::new();
            let mut public_key_shares = Vec::new();
            for _ in 0..NUM_DECRYPTORS {
                let (sk_share, pk_share, _) = ahe.key_gen(&mut prng)?;
                secret_key_shares.push(sk_share);
                public_key_shares.push(pk_share);
            }
            let pk = ahe.aggregate_public_key_shares(&public_key_shares)?;

            // Generate random messages.
            let mut plaintexts = Vec::new();
            for _ in 0..NUM_CLIENTS {
                plaintexts.push(generate_random_signed_vector(num_values, MAX_ABSOLUTE_VALUE));
            }

            // Encrypt messages.
            let mut ciphertexts = Vec::new();
            for pt in &plaintexts {
                let (ciphertext, _) = ahe.encrypt(&pt, &pk, &mut prng)?;
                ciphertexts.push(ciphertext);
            }

            // Accumulate ciphertexts.
            verify_false!(ciphertexts.is_empty())?;
            let mut ct_sum = ciphertexts.pop().unwrap();
            for ct in ciphertexts {
                ahe.add_ciphertexts_in_place(&ct, &mut ct_sum)?;
            }

            // Partial decryption.
            let mut partial_decryptions = Vec::new();
            for sk_share in secret_key_shares {
                partial_decryptions.push(ahe.partial_decrypt(
                    &ct_sum.component_a,
                    &sk_share,
                    &mut prng,
                )?);
            }
            verify_false!(partial_decryptions.is_empty())?;
            let mut partial_decryption = partial_decryptions.pop().unwrap();
            for pd in partial_decryptions {
                ahe.add_partial_decryptions_in_place(&pd, &mut partial_decryption)?;
            }

            // Recovery.
            let decrypted = ahe.recover(&partial_decryption, &ct_sum.component_b, None)?;

            // Compare decryption to sum modulo T.
            let mut pt_sum = vec![0; num_values];
            for pt in plaintexts {
                ahe.add_plaintexts_in_place(&pt, &mut pt_sum)?;
            }
            for i in 0..num_values {
                pt_sum[i] = pt_sum[i] % (t as i64);
            }
            verify_that!(&pt_sum, eq(&decrypted[..num_values]))?;
        }
        Ok(())
    }

    #[gtest]
    fn test_errors() -> googletest::Result<()> {
        let ahe = ShellAhe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;

        // Distributed key generation.
        let mut secret_key_shares = Vec::new();
        let mut public_key_shares = Vec::new();
        for _ in 0..NUM_DECRYPTORS {
            let (sk_share, pk_share, _) = ahe.key_gen(&mut prng)?;
            secret_key_shares.push(sk_share);
            public_key_shares.push(pk_share);
        }
        let pk = ahe.aggregate_public_key_shares(&public_key_shares)?;

        // Check that mismatch in length causes error.
        const NUM_VALUES_1: usize = 100;
        const NUM_VALUES_2: usize = 5000;
        let pt_1 = generate_random_signed_vector(NUM_VALUES_1, MAX_ABSOLUTE_VALUE);
        let mut pt_2 = generate_random_signed_vector(NUM_VALUES_2, MAX_ABSOLUTE_VALUE);
        let res = ahe.add_plaintexts_in_place(&pt_1, &mut pt_2);
        verify_that!(res, status_is(StatusErrorCode::InvalidArgument))?;

        // Create new plaintexts.
        let pt_1 = generate_random_signed_vector(NUM_VALUES_1, MAX_ABSOLUTE_VALUE);
        let pt_2 = generate_random_signed_vector(NUM_VALUES_2, MAX_ABSOLUTE_VALUE);

        // Encrypt messages, check that we can't accumulate ciphertexts with different
        // numbers of polynomials.
        let (ct_1, _) = ahe.encrypt(&pt_1, &pk, &mut prng)?;
        let (mut ct_2, _) = ahe.encrypt(&pt_2, &pk, &mut prng)?;
        let res = ahe.add_ciphertexts_in_place(&ct_1, &mut ct_2);
        verify_that!(res, status_is(StatusErrorCode::InvalidArgument))?;

        // Create new ciphertexts.
        let (ct_1, _) = ahe.encrypt(&pt_1, &pk, &mut prng)?;
        let (ct_2, _) = ahe.encrypt(&pt_2, &pk, &mut prng)?;

        // Partial decryption.
        let mut partial_decryptions_1 = Vec::new();
        for sk_share in secret_key_shares {
            partial_decryptions_1.push(ahe.partial_decrypt(
                &ct_1.component_a,
                &sk_share,
                &mut prng,
            )?);
        }
        verify_false!(partial_decryptions_1.is_empty())?;
        let mut partial_decryption_1 = partial_decryptions_1.pop().unwrap();
        for pd in partial_decryptions_1 {
            ahe.add_partial_decryptions_in_place(&pd, &mut partial_decryption_1)?;
        }

        // Recovery, check that we can't combine different lengths.
        let res = ahe.recover(&partial_decryption_1, &ct_2.component_b, None);
        verify_that!(res, status_is(StatusErrorCode::InvalidArgument))?;

        Ok(())
    }

    // Helper function to generate the matrix representing the left hand side
    // of a polynomial multiplication. See Section 2.2 in https://eprint.iacr.org/2022/1461.
    fn phi(a: &[u128], i: usize, j: usize) -> i128 {
        let n: usize = a.len();
        assert!(i < n);
        assert!(j < n);
        let element = a[(i + n - j) % n] as i128;
        if i < j {
            -element
        } else {
            element
        }
    }

    #[gtest]
    fn test_manual_encryption() -> googletest::Result<()> {
        let config = make_ahe_config();
        let q: i128 = config.qs.iter().map(|x| *x as i128).product();

        let ahe = ShellAhe::new(config, CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (_, pk_share, _) = ahe.key_gen(&mut prng)?;
        let pk = ahe.aggregate_public_key_shares(&[pk_share])?;
        let pt = vec![1, 2, 3, 4, 5, 6, 7, 8];

        // Encrypt directly, saving the encryption metadata.
        let (ciphertext, encryption_metadata) = ahe.encrypt(&pt, &pk, &mut prng)?;
        verify_that!(encryption_metadata.secret_r.len(), eq(1))?;
        verify_that!(encryption_metadata.error_e.len(), eq(1))?;

        // Export public parameters, ciphertext, and metadata.
        let pk_component_a = ahe.export_public_parameters()?;
        let ct_a = ahe.export_ciphertext(&ciphertext.component_a)?;
        let (secret_r, error_e) = ahe.export_encryption_metadata(&encryption_metadata)?;
        let num_coeffs = pk_component_a.len();
        verify_that!(ct_a.len(), eq(1))?;
        verify_that!(secret_r.len(), eq(1))?;
        verify_that!(error_e.len(), eq(1))?;
        verify_that!(ct_a[0].len(), eq(num_coeffs))?;
        verify_that!(secret_r[0].len(), eq(num_coeffs))?;
        verify_that!(error_e[0].len(), eq(num_coeffs))?;

        // Encrypt by hand using the exported r and e.
        let mut ct_a_manual = vec![0i128; num_coeffs];
        for i in 0..num_coeffs {
            for j in 0..num_coeffs {
                ct_a_manual[i] += phi(&pk_component_a, i, j) * secret_r[0][j] as i128;
            }
            ct_a_manual[i] += error_e[0][i] as i128;
            ct_a_manual[i] = ct_a_manual[i].rem_euclid(q);
        }
        let ct_a_manual = ct_a_manual.into_iter().map(|x| x as u128).collect::<Vec<u128>>();

        // Check manual encryption matches exported ciphertext.
        verify_that!(ct_a_manual, eq(&ct_a[0]))
    }

    #[gtest]
    fn test_export_ciphertext_has_right_order() -> googletest::Result<()> {
        let config = make_ahe_config();
        let ahe = ShellAhe::new(config, CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (_, pk_share, _) = ahe.key_gen(&mut prng)?;
        let pk = ahe.aggregate_public_key_shares(&[pk_share])?;
        let pt = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let (ciphertext, _) = ahe.encrypt(&pt, &pk, &mut prng)?;

        let ct_export = ahe.export_ciphertext(&ciphertext)?;
        expect_eq!(ct_export.0, ahe.export_ciphertext(&ciphertext.component_b)?);
        expect_eq!(ct_export.1, ahe.export_ciphertext(&ciphertext.component_a)?);
        Ok(())
    }
}
