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

use kahe::{KahePublicParametersWrapper, PackedVectorConfig};
use kahe_traits::{
    KaheBase, KaheDecrypt, KaheEncrypt, KaheKeygen, TrySecretKeyFrom, TrySecretKeyInto,
};
use shell_types::{
    add_in_place, add_in_place_vec, read_small_rns_polynomial_from_buffer,
    write_small_rns_polynomial_to_buffer, RnsPolynomial, RnsPolynomialVec,
};
use single_thread_hkdf::SingleThreadHkdfPrng;
use std::collections::HashMap;

/// Number of bits supported by the C++ big integer type used for KAHE
/// plaintext.
const BIG_INT_BITS: usize = 256;

#[derive(Debug, PartialEq, Clone)]
pub struct ShellKaheConfig {
    pub log_n: usize,
    pub moduli: Vec<u64>,
    pub log_t: usize,
    pub num_public_polynomials: usize,
    pub packed_vector_configs: HashMap<String, PackedVectorConfig>,
}

/// Base type holding public KAHE configuration and C++ parameters.
pub struct ShellKahe {
    /// Parameters used to initialize ShellKahe.
    config: ShellKaheConfig,

    /// Number of coefficients in a KAHE polynomial.
    num_coeffs: usize,

    /// The KAHE public parameters implemented in C++, including the public polynomials and
    /// the parameters to instantiate the KAHE scheme.
    public_kahe_parameters: KahePublicParametersWrapper,
}

impl ShellKahe {
    /// Validates KAHE parameters in ShellKaheConfig.
    fn validate_kahe_config(config: &ShellKaheConfig) -> Result<(), status::StatusError> {
        if config.log_t > BIG_INT_BITS {
            return Err(status::invalid_argument(format!(
                "log_t must be <= {} for plaintexts to fit in the C++ big integer type, got {}",
                BIG_INT_BITS, config.log_t
            )));
        }
        for (id, packed_vector_config) in config.packed_vector_configs.iter() {
            let base = packed_vector_config.base;
            let dimension = packed_vector_config.dimension;
            let num_packed_coeffs = packed_vector_config.num_packed_coeffs;
            if base <= 1 {
                return Err(status::invalid_argument(format!("base must be > 1, got {}", base)));
            }
            if dimension <= 0 {
                return Err(status::invalid_argument(format!(
                    "For packing id {}, dimension must be > 0, got {}",
                    id, dimension
                )));
            }
            if num_packed_coeffs <= 0 {
                return Err(status::invalid_argument(format!(
                    "For packing id {}, num_packed_coeffs must be > 0, got {}",
                    id, num_packed_coeffs
                )));
            }
            let log_base = (base as f64).log2().ceil() as u64;
            if log_base * dimension > config.log_t as u64 {
                return Err(status::invalid_argument(format!(
                    "For packing id {}, base^dimension must not be larger than the KAHE plaintext modulus 2^log_t+1: base = {}, dimension = {}, log_t = {}", id, base, dimension, config.log_t
                )));
            }
        }
        Ok(())
    }
}

impl KaheBase for ShellKahe {
    type SecretKey = RnsPolynomial;

    type Plaintext = HashMap<String, Vec<u64>>;

    type Ciphertext = RnsPolynomialVec;

    type Rng = SingleThreadHkdfPrng;

    type Config = ShellKaheConfig;

    fn new(
        shell_kahe_config: Self::Config,
        context_string: &[u8],
    ) -> Result<Self, status::StatusError> {
        Self::validate_kahe_config(&shell_kahe_config)?;
        let num_coeffs = 1 << shell_kahe_config.log_n;
        let public_seed = single_thread_hkdf::compute_hkdf(
            context_string,
            b"",
            b"ShellKahe.public_seed",
            single_thread_hkdf::seed_length(),
        )?;
        let public_kahe_parameters = kahe::create_public_parameters(
            shell_kahe_config.log_n as u64,
            shell_kahe_config.log_t as u64,
            &shell_kahe_config.moduli,
            shell_kahe_config.num_public_polynomials,
            &public_seed,
        )?;
        Ok(Self { config: shell_kahe_config, num_coeffs, public_kahe_parameters })
    }

    fn add_keys_in_place(
        &self,
        left: &Self::SecretKey,
        right: &mut Self::SecretKey,
    ) -> Result<(), status::StatusError> {
        // NOTE: This is just calling `MakeSpan` on an existing vector of raw pointers
        // that lives in `public_kahe_parameters`.
        let moduli = kahe::get_moduli(&self.public_kahe_parameters);
        add_in_place(&moduli, left, right)?;
        Ok(())
    }

    fn add_plaintexts_in_place(
        &self,
        left: &Self::Plaintext,
        right: &mut Self::Plaintext,
    ) -> Result<(), status::StatusError> {
        if left.len() != right.len() {
            return Err(status::invalid_argument(format!(
                "left and right must have the same length, got {} and {}",
                left.len(),
                right.len()
            )));
        }
        for (id, values) in left.iter() {
            if let Some(right_values) = right.get_mut(id) {
                if right_values.len() != values.len() {
                    return Err(status::invalid_argument(format!(
                        "right values for key {} must have the same length as left, got {} and {}",
                        id,
                        right_values.len(),
                        values.len()
                    )));
                }
                for (i, v) in values.iter().enumerate() {
                    right_values[i] += v;
                }
            } else {
                return Err(status::invalid_argument(format!("right must contain key {}", id)));
            }
        }
        Ok(())
    }

    fn add_ciphertexts_in_place(
        &self,
        left: &Self::Ciphertext,
        right: &mut Self::Ciphertext,
    ) -> Result<(), status::StatusError> {
        let moduli = kahe::get_moduli(&self.public_kahe_parameters);
        add_in_place_vec(&moduli, left, right)?;
        Ok(())
    }
}

impl KaheKeygen for ShellKahe {
    fn key_gen(&self, r: &mut Self::Rng) -> Result<Self::SecretKey, status::StatusError> {
        kahe::generate_secret_key(&self.public_kahe_parameters, &mut r.0)
    }
}

impl KaheEncrypt for ShellKahe {
    fn encrypt(
        &self,
        pt: &Self::Plaintext,
        sk: &Self::SecretKey,
        r: &mut Self::Rng,
    ) -> Result<Self::Ciphertext, status::StatusError> {
        // Check that inputs are valid to avoid packing and plaintext overflow errors.
        for (id, values) in pt.iter() {
            if let Some(packed_vector_config) = self.config.packed_vector_configs.get(id) {
                let max_length =
                    packed_vector_config.dimension * packed_vector_config.num_packed_coeffs;
                if values.len() > max_length as usize {
                    return Err(status::invalid_argument(format!(
                        "plaintext for id {} can have at most {} elements, got {}",
                        id,
                        max_length,
                        values.len()
                    )));
                }
                for v in values.iter() {
                    if *v >= packed_vector_config.base {
                        return Err(status::invalid_argument(format!(
                            "plaintext for id {} cannot contain values larger than the input bound {}, got {}",
                            id,
                            packed_vector_config.base,
                            *v,
                        )));
                    }
                }
            } else {
                return Err(status::invalid_argument(format!("unknown plaintext id {}", id)));
            }
        }

        kahe::encrypt(
            &pt,
            &self.config.packed_vector_configs,
            &sk,
            &self.public_kahe_parameters,
            &mut r.0,
        )
    }
}

impl KaheDecrypt for ShellKahe {
    fn decrypt(
        &self,
        ct: &Self::Ciphertext,
        sk: &Self::SecretKey,
    ) -> Result<Self::Plaintext, status::StatusError> {
        kahe::decrypt(&ct, &sk, &self.public_kahe_parameters, &self.config.packed_vector_configs)
    }
}

impl TrySecretKeyInto<Vec<i64>> for ShellKahe {
    fn try_secret_key_into(&self, sk: Self::SecretKey) -> Result<Vec<i64>, status::StatusError> {
        let mut signed_values: Vec<i64> = vec![0; self.num_coeffs];
        let moduli = kahe::get_moduli(&self.public_kahe_parameters);
        let n_written = write_small_rns_polynomial_to_buffer(&sk, &moduli, &mut signed_values[..])?;
        if n_written != self.num_coeffs {
            return Err(status::internal(format!(
                "Expected {} coefficients, but got {}.",
                self.num_coeffs, n_written
            )));
        }

        return Ok(signed_values);
    }
}

impl TrySecretKeyFrom<Vec<i64>> for ShellKahe {
    fn try_secret_key_from(
        &self,
        sk_buffer: Vec<i64>,
    ) -> Result<Self::SecretKey, status::StatusError> {
        if sk_buffer.len() < self.num_coeffs {
            return Err(status::invalid_argument(format!(
                "secret key buffer is too short: {} < {}",
                sk_buffer.len(),
                self.num_coeffs
            )));
        }

        let moduli = kahe::get_moduli(&self.public_kahe_parameters);
        let poly = read_small_rns_polynomial_from_buffer(
            &sk_buffer[..self.num_coeffs], // Remove potential padding from AHE decryption.
            self.num_coeffs as u64,
            &moduli,
        )?;
        Ok(poly)
    }
}

#[cfg(test)]
mod test {
    // Instead of `super::*` because we consume types from other testing crates.
    use googletest::{gtest, verify_eq, verify_le};
    use kahe::PackedVectorConfig;
    use kahe_shell::*;
    use kahe_traits::{
        KaheBase, KaheDecrypt, KaheEncrypt, KaheKeygen, TrySecretKeyFrom, TrySecretKeyInto,
    };
    use prng_traits::SecurePrng;
    use shell_testing_parameters::{make_kahe_config_for, set_kahe_num_public_polynomials};
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use std::collections::HashMap;
    use testing_utils::generate_random_unsigned_vector;

    /// Standard deviation of the discrete Gaussian distribution used for
    /// secret key generation. Hardcoded in shell_wrapper/kahe.h for now (if we ever
    /// need to change it then we can pass it from Rust like we do in shell/ahe.rs).
    const SECRET_KEY_STD: f64 = 4.5;

    /// The tail bound cut-off multiplier such that the probability of a sample
    /// of DG_s being outside of [+/- `kTailBoundMultiplier` * s] is
    /// negligible. See rlwe/sampler/discrete_gaussian.h.
    const TAIL_BOUND_MULTIPLIER: f64 = 8.0;

    /// Tail bound for the case of a single secret key.
    const TAIL_BOUND: i64 = (TAIL_BOUND_MULTIPLIER * SECRET_KEY_STD + 1.0) as i64;

    /// Default ID used in tests.
    const DEFAULT_ID: &str = "default";

    const CONTEXT_STRING: &[u8] = b"test_context_string";

    #[gtest]
    fn test_encrypt_decrypt_short() -> googletest::Result<()> {
        let plaintext_modulus_bits = 39;
        let packed_vector_configs = HashMap::from([(
            String::from(DEFAULT_ID),
            PackedVectorConfig { base: 10, dimension: 2, num_packed_coeffs: 5 },
        )]);
        let kahe_config = make_kahe_config_for(plaintext_modulus_bits, packed_vector_configs)?;
        let kahe = ShellKahe::new(kahe_config, CONTEXT_STRING)?;

        let pt = HashMap::from([(String::from(DEFAULT_ID), vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9])]);
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let sk = kahe.key_gen(&mut prng)?;
        let ct = kahe.encrypt(&pt, &sk, &mut prng)?;
        let decrypted = kahe.decrypt(&ct, &sk)?;
        verify_eq!(&pt, &decrypted)
    }

    #[gtest]
    fn test_encrypt_decrypt_with_serialized_key() -> googletest::Result<()> {
        let plaintext_modulus_bits = 39;
        let packed_vector_configs = HashMap::from([(
            String::from(DEFAULT_ID),
            PackedVectorConfig { base: 10, dimension: 2, num_packed_coeffs: 5 },
        )]);
        let kahe_config = make_kahe_config_for(plaintext_modulus_bits, packed_vector_configs)?;
        let kahe = ShellKahe::new(kahe_config, CONTEXT_STRING)?;

        let pt = HashMap::from([(String::from(DEFAULT_ID), vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9])]);
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let sk = kahe.key_gen(&mut prng)?;
        let ct = kahe.encrypt(&pt, &sk, &mut prng)?;

        // Serialize the key and deserialize it.
        let sk_buffer = kahe.try_secret_key_into(sk)?;
        let sk_recovered = kahe.try_secret_key_from(sk_buffer)?;

        // Check that the decrypted value is the same as the original plaintext.
        let decrypted = kahe.decrypt(&ct, &sk_recovered)?;
        verify_eq!(&pt, &decrypted)
    }

    #[gtest]
    fn test_encrypt_decrypt_long() -> googletest::Result<()> {
        let plaintext_modulus_bits = 17;
        let input_domain = 5;
        let packed_vector_configs = HashMap::from([(
            String::from(DEFAULT_ID),
            PackedVectorConfig {
                base: input_domain,
                dimension: 1,
                num_packed_coeffs: 0, // Dummy value until we compute it from kahe_config.
            },
        )]);
        let mut kahe_config = make_kahe_config_for(plaintext_modulus_bits, packed_vector_configs)?;
        // Set the number of packed coefficients to 2x the KAHE ring degree.
        let num_messages = (1 << kahe_config.log_n) * 2; // Needs two polynomials.
        let packed_vector_config = kahe_config.packed_vector_configs.get_mut(DEFAULT_ID).unwrap();
        packed_vector_config.num_packed_coeffs = num_messages;
        set_kahe_num_public_polynomials(&mut kahe_config);

        let kahe = ShellKahe::new(kahe_config, CONTEXT_STRING)?;

        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let sk = kahe.key_gen(&mut prng)?;

        // Generate a random vector, encrypt and decrypt it.
        let pt = HashMap::from([(
            String::from(DEFAULT_ID),
            generate_random_unsigned_vector(num_messages as usize, input_domain as u64),
        )]);
        let ct = kahe.encrypt(&pt, &sk, &mut prng)?;
        let decrypted = kahe.decrypt(&ct, &sk)?;
        verify_eq!(pt, decrypted) // Both vectors are padded to the same length.
    }

    /// Check homomorphic addition of two inputs.
    #[gtest]
    fn add_two_inputs() -> googletest::Result<()> {
        let plaintext_modulus_bits = 93;
        let input_domain = 10;
        let num_messages = 50;
        let packed_vector_configs = HashMap::from([(
            String::from(DEFAULT_ID),
            PackedVectorConfig {
                base: input_domain * 2,
                dimension: 1,
                num_packed_coeffs: num_messages,
            },
        )]);
        let kahe_config = make_kahe_config_for(plaintext_modulus_bits, packed_vector_configs)?;

        let kahe = ShellKahe::new(kahe_config, CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;

        // Client 1
        let sk1 = kahe.key_gen(&mut prng)?;
        let pt1 = HashMap::from([(
            String::from(DEFAULT_ID),
            generate_random_unsigned_vector(num_messages as usize, input_domain as u64),
        )]);
        let ct1 = kahe.encrypt(&pt1, &sk1, &mut prng)?;

        // Client 2
        let mut sk2 = kahe.key_gen(&mut prng)?;
        let mut pt2 = HashMap::from([(
            String::from(DEFAULT_ID),
            generate_random_unsigned_vector(num_messages as usize, input_domain as u64),
        )]);
        let mut ct2 = kahe.encrypt(&pt2, &sk2, &mut prng)?;

        // Decryptor adds up keys
        kahe.add_keys_in_place(&sk1, &mut sk2)?;

        // Server adds ciphertexts and uses aggregated key to decrypt.
        kahe.add_ciphertexts_in_place(&ct1, &mut ct2)?;
        let pt_sum = kahe.decrypt(&ct2, &sk2)?;
        kahe.add_plaintexts_in_place(&pt1, &mut pt2)?;
        verify_eq!(&pt2, &pt_sum)
    }

    #[gtest]
    fn read_write_secret_key() -> googletest::Result<()> {
        let plaintext_modulus_bits = 17;
        let packed_vector_configs = HashMap::from([]);
        let kahe_config = make_kahe_config_for(plaintext_modulus_bits, packed_vector_configs)?;

        let kahe = ShellKahe::new(kahe_config, CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;

        // Create a key and write it to a buffer.
        let sk = kahe.key_gen(&mut prng)?;
        let sk_buffer = kahe.try_secret_key_into(sk)?;

        // Check that read+write is identity.
        let sk_recovered = kahe.try_secret_key_from(sk_buffer.clone())?;
        let sk_recovered_buffer = kahe.try_secret_key_into(sk_recovered)?;
        assert_eq!(sk_recovered_buffer, sk_buffer);

        // Generating twice the same key gives the same buffer.
        let mut prng2 = SingleThreadHkdfPrng::create(&seed)?;
        let sk2 = kahe.key_gen(&mut prng2)?;
        let sk_buffer_2 = kahe.try_secret_key_into(sk2)?;
        assert_eq!(sk_buffer, sk_buffer_2);

        // Check that each discrete Gaussian sample is within the right tail bound
        for v in sk_buffer.iter() {
            assert!(*v <= TAIL_BOUND);
            assert!(*v >= -TAIL_BOUND);
        }

        // Check a Gaussian concentration bound too.
        let mut sum = 0;
        for v in sk_buffer.iter() {
            sum += *v;
        }
        let n = sk_buffer.len() as f64;
        let mean = (sum as f64) / n as f64;
        let mean_std = SECRET_KEY_STD / n.sqrt();
        verify_le!(mean.abs(), TAIL_BOUND_MULTIPLIER * mean_std)
    }

    #[gtest]
    fn test_key_serialization_is_homomorphic() -> googletest::Result<()> {
        // Set up a ShellKahe instance.
        let plaintext_modulus_bits = 39;
        let packed_vector_configs = HashMap::from([]);
        let kahe_config = make_kahe_config_for(plaintext_modulus_bits, packed_vector_configs)?;
        let kahe = ShellKahe::new(kahe_config, CONTEXT_STRING)?;

        // The seed used to sample the secret keys.
        let seed = SingleThreadHkdfPrng::generate_seed()?;

        // Generate two keys, write them to buffers then add the buffers together.
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let sk1 = kahe.key_gen(&mut prng)?;
        let sk2 = kahe.key_gen(&mut prng)?;
        let sk1_buffer = kahe.try_secret_key_into(sk1)?;
        let mut sk2_buffer = kahe.try_secret_key_into(sk2)?;
        for i in 0..sk1_buffer.len() {
            sk2_buffer[i] += sk1_buffer[i];
        }

        // Generate same two keys but add them together before writing to a buffer.
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let sk1 = kahe.key_gen(&mut prng)?;
        let mut sk2 = kahe.key_gen(&mut prng)?;
        kahe.add_keys_in_place(&sk1, &mut sk2)?;
        let sk_buffer = kahe.try_secret_key_into(sk2)?;

        // Check that the two buffers are the same.
        verify_eq!(sk_buffer[..], sk2_buffer[..])
    }
}
