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

use googletest::{
    expect_that, fail, gtest,
    matchers::{container_eq, eq, gt},
    verify_that, Result,
};
use kahe::{create_public_parameters, decrypt, encrypt, generate_secret_key, PackedVectorConfig};
use rand::Rng;
use status::StatusErrorCode;
use status_matchers_rs::status_is;
use std::collections::HashMap;

// RNS configuration. LOG_T is the bit length of the KAHE plaintext modulus.
const LOG_T: u64 = 11;
const LOG_N: u64 = 12;
const QS: [u64; 2] = [1125899906826241, 1125899906629633];

#[gtest]
fn encrypt_decrypt() -> Result<()> {
    const DEFAULT_ID: &str = "default";

    // Generate public parameters.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let num_public_polynomials = 1;
    let params = create_public_parameters(LOG_N, LOG_T, &QS, num_public_polynomials, &public_seed)?;

    // Generate secret key.
    let seed = single_thread_hkdf::generate_seed()?;
    let mut prng = single_thread_hkdf::create(&seed)?;
    let secret_key = generate_secret_key(&params, &mut prng)?;

    // Encrypt small vector. `ciphertext` is a wrapper around a C++ pointer.
    let input_values = vec![1, 2, 3];
    let plaintext = HashMap::from([(String::from(DEFAULT_ID), input_values.clone())]);
    let packed_vector_configs = HashMap::from([(
        String::from(DEFAULT_ID),
        PackedVectorConfig { base: 10, dimension: 2, num_packed_coeffs: 2 },
    )]);
    let ciphertext = encrypt(&plaintext, &packed_vector_configs, &secret_key, &params, &mut prng)?;

    let output_values = decrypt(&ciphertext, &secret_key, &params, &packed_vector_configs)?;
    expect_that!(output_values.contains_key(DEFAULT_ID), eq(true));
    expect_that!(output_values[DEFAULT_ID][..3], container_eq(input_values));
    Ok(())
}

#[gtest]
fn encrypt_decrypt_padding() -> Result<()> {
    const DEFAULT_ID: &str = "default";

    // Generate public parameters and secret key.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let num_public_polynomials = 1;
    let params = create_public_parameters(LOG_N, LOG_T, &QS, num_public_polynomials, &public_seed)?;
    let seed = single_thread_hkdf::generate_seed()?;
    let mut prng = single_thread_hkdf::create(&seed)?;
    let secret_key = generate_secret_key(&params, &mut prng)?;

    // Generate a short random vector.
    let num_input_values = 40;
    let input_domain = 10;
    let packing_dimension = 3;
    // Set num_packed_coeffs to be larger than the actual number of packed values. The packing
    // function should pad with zeros to fill in the packed vector.
    let num_packed_coeffs =
        (num_input_values + packing_dimension - 1) / packing_dimension + 1 as usize;
    let input_values: Vec<u64> =
        (0..num_input_values).map(|_| rand::thread_rng().gen_range(0..input_domain)).collect();

    // Encrypt the vector.
    let plaintext = HashMap::from([(String::from(DEFAULT_ID), input_values.clone())]);
    let packed_vector_configs = HashMap::from([(
        String::from(DEFAULT_ID),
        PackedVectorConfig {
            base: input_domain as u64,
            dimension: packing_dimension as u64,
            num_packed_coeffs: num_packed_coeffs as u64,
        },
    )]);
    let ciphertext = encrypt(&plaintext, &packed_vector_configs, &secret_key, &params, &mut prng)?;

    // Decrypt and unpack the ciphertexts.
    let decrypted = decrypt(&ciphertext, &secret_key, &params, &packed_vector_configs)?;
    let output_values = &decrypted[DEFAULT_ID];

    // Check that message is correctly decrypted with right padding.
    let padded_length = (num_packed_coeffs * packing_dimension) as usize;
    expect_that!(output_values.len(), eq(padded_length));
    expect_that!(output_values.len(), gt(num_input_values));
    expect_that!(output_values[..num_input_values], container_eq(input_values));
    expect_that!(
        output_values[num_input_values..],
        container_eq(vec![0; padded_length - num_input_values])
    );

    Ok(())
}

#[gtest]
fn encrypt_decrypt_long() -> Result<()> {
    const DEFAULT_ID: &str = "default";

    // Generate public parameters and secret key.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let num_public_polynomials = 10; // Generate enough a's to pass long messages.
    let params = create_public_parameters(LOG_N, LOG_T, &QS, num_public_polynomials, &public_seed)?;
    let seed = single_thread_hkdf::generate_seed()?;
    let mut prng = single_thread_hkdf::create(&seed)?;
    let secret_key = generate_secret_key(&params, &mut prng)?;
    let packing_dimension = 8 as usize;
    let num_coeffs_per_poly = (1 << LOG_N) as usize;
    // Number of values can be packed into one polynomial.
    let poly_capacity = num_coeffs_per_poly * packing_dimension;

    // Generate a long random vector, encrypt and decrypt it.
    let input_domain = 2;
    let num_input_values = 3 * poly_capacity + 1;
    let num_packed_coeffs = (num_input_values + packing_dimension - 1) / packing_dimension as usize;
    let input_values: Vec<u64> =
        (0..num_input_values).map(|_| rand::thread_rng().gen_range(0..input_domain)).collect();
    let plaintext = HashMap::from([(String::from(DEFAULT_ID), input_values.clone())]);
    let packed_vector_configs = HashMap::from([(
        String::from(DEFAULT_ID),
        PackedVectorConfig {
            base: input_domain as u64,
            dimension: packing_dimension as u64,
            num_packed_coeffs: num_packed_coeffs as u64,
        },
    )]);
    let ciphertext = encrypt(&plaintext, &packed_vector_configs, &secret_key, &params, &mut prng)?;

    let decrypted = decrypt(&ciphertext, &secret_key, &params, &packed_vector_configs)?;
    let output_values = &decrypted[DEFAULT_ID];

    // Check that message is correctly decrypted with right padding.
    let padded_length = num_packed_coeffs * packing_dimension;
    expect_that!(output_values.len(), eq(padded_length));
    expect_that!(output_values.len(), gt(num_input_values));
    expect_that!(output_values[..num_input_values], container_eq(input_values));
    expect_that!(
        output_values[num_input_values..],
        container_eq(vec![0; padded_length - num_input_values])
    );

    // If the input is too long, we should fail.
    let num_values_too_long = num_public_polynomials * poly_capacity + 1;
    let input_values_too_long: Vec<u64> =
        (0..num_values_too_long).map(|_| rand::thread_rng().gen_range(0..input_domain)).collect();
    let plaintext_too_long = HashMap::from([(String::from(DEFAULT_ID), input_values_too_long)]);
    match encrypt(&plaintext_too_long, &packed_vector_configs, &secret_key, &params, &mut prng) {
        Err(e) => expect_that!(e, status_is(StatusErrorCode::InvalidArgument)),
        Ok(_) => fail!("Expected call to fail")?,
    }

    Ok(())
}

#[gtest]
fn encrypt_decrypt_two_vectors() -> Result<()> {
    const ID0: &str = "fst";
    const ID1: &str = "snd";

    // Generate public parameters and secret key.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let num_public_polynomials = 1;
    let params = create_public_parameters(LOG_N, LOG_T, &QS, num_public_polynomials, &public_seed)?;
    let seed = single_thread_hkdf::generate_seed()?;
    let mut prng = single_thread_hkdf::create(&seed)?;
    let secret_key = generate_secret_key(&params, &mut prng)?;

    // Specifications for the two input vectors.
    let input_domains = [10, 8];
    let packing_dimensions = [2, 3];
    let num_input_values = [9, 13];
    // The number of packed coefficients for both vectors.
    let num_packed_coeffs = [5, 5];

    let packed_vector_configs = HashMap::from([
        (
            String::from(ID0),
            PackedVectorConfig {
                base: input_domains[0] as u64,
                dimension: packing_dimensions[0] as u64,
                num_packed_coeffs: num_packed_coeffs[0] as u64,
            },
        ),
        (
            String::from(ID1),
            PackedVectorConfig {
                base: input_domains[1] as u64,
                dimension: packing_dimensions[1] as u64,
                num_packed_coeffs: num_packed_coeffs[1] as u64,
            },
        ),
    ]);

    // The plaintext contains two vectors.
    let input_values0: Vec<u64> = (0..num_input_values[0])
        .map(|_| rand::thread_rng().gen_range(0..input_domains[0]))
        .collect();
    let input_values1: Vec<u64> = (0..num_input_values[1])
        .map(|_| rand::thread_rng().gen_range(0..input_domains[1]))
        .collect();
    let plaintext = HashMap::from([
        (String::from(ID0), input_values0.clone()),
        (String::from(ID1), input_values1.clone()),
    ]);
    let ciphertext = encrypt(&plaintext, &packed_vector_configs, &secret_key, &params, &mut prng)?;

    // Decrypt and check the output contains the two vectors that are padded correctly.
    let decrypted = decrypt(&ciphertext, &secret_key, &params, &packed_vector_configs)?;
    verify_that!(decrypted.contains_key(ID0), eq(true))?;
    verify_that!(decrypted.contains_key(ID1), eq(true))?;

    let output_values0 = &decrypted[ID0];
    let output_values1 = &decrypted[ID1];
    expect_that!(output_values0.len(), eq(num_packed_coeffs[0] * packing_dimensions[0]));
    expect_that!(output_values0.len(), gt(num_input_values[0]));
    expect_that!(output_values0[..num_input_values[0]], container_eq(input_values0));
    expect_that!(
        output_values0[num_input_values[0]..],
        container_eq(vec![0; num_packed_coeffs[0] * packing_dimensions[0] - num_input_values[0]])
    );
    expect_that!(output_values1.len(), eq(num_packed_coeffs[1] * packing_dimensions[1]));
    expect_that!(output_values1.len(), gt(num_input_values[1]));
    expect_that!(output_values1[..num_input_values[1]], container_eq(input_values1));
    expect_that!(
        output_values1[num_input_values[1]..],
        container_eq(vec![0; num_packed_coeffs[1] * packing_dimensions[1] - num_input_values[1]])
    );
    Ok(())
}
