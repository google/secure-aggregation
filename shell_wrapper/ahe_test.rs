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

use ahe::{
    ahe_encrypt, create_public_parameters, create_zero_rns_polynomial, generate_public_key_share,
    generate_secret_key, get_moduli, get_rns_context_ref, partial_decrypt, public_key_component_a,
    recover_messages,
};
use googletest::{
    expect_that, gtest,
    matchers::{contains, eq, not},
    Result,
};
use rand::Rng;
use shell_types::{add_in_place, create_empty_rns_polynomial, write_rns_polynomial_to_buffer_128};

const LOG_N: u64 = 11;
const T: u64 = 10001;
const QS: [u64; 2] = [1073692673, 1073668097];
const QS_LARGE: [u64; 2] = [1125899906826241, 1125899906629633];
const S_FLOOD: f64 = 1.0e+10;

const NUM_PARTIES: usize = 5;
const PUBLIC_KEY_VARIANCE: u64 = 8;
const MAX_VALUE: u64 = 72;
const S_BASE: f64 = 12.8;

#[gtest]
fn encrypt_add_recover() -> Result<()> {
    // Create the public parameters.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let params = create_public_parameters(
        LOG_N,
        T,
        &QS,
        PUBLIC_KEY_VARIANCE,
        S_BASE,
        S_FLOOD,
        &public_seed,
    )?;
    let moduli = get_moduli(&params);

    let private_seed = single_thread_hkdf::generate_seed()?;
    let mut prng = single_thread_hkdf::create(&private_seed)?;

    // Distributed key generation.
    let mut secret_key_shares = Vec::new();
    let mut public_key_shares = Vec::new();
    for _ in 0..NUM_PARTIES {
        let sk_share = generate_secret_key(&params, &mut prng)?;

        let mut public_key_share_b = create_empty_rns_polynomial();
        let mut public_key_share_error = create_empty_rns_polynomial();
        generate_public_key_share(
            &sk_share,
            &params,
            &mut prng,
            &mut public_key_share_b,
            &mut public_key_share_error,
            None,
        )?;

        secret_key_shares.push(sk_share);
        public_key_shares.push(public_key_share_b);
    }
    let mut public_key_b = create_zero_rns_polynomial(&params)?;
    for public_key_share in public_key_shares {
        add_in_place(&moduli, &public_key_share, &mut public_key_b)?;
    }

    // Generate two random vectors.
    let num_messages = 1 << LOG_N;
    let mut coeffs0: Vec<u64> = Vec::with_capacity(num_messages);
    let mut coeffs1: Vec<u64> = Vec::with_capacity(num_messages);
    for _ in 0..num_messages {
        coeffs0.push(rand::thread_rng().gen_range(0..MAX_VALUE));
        coeffs1.push(rand::thread_rng().gen_range(0..MAX_VALUE));
    }

    // Encrypt the two vectors.
    let mut c0_b = create_empty_rns_polynomial();
    let mut c0_a = create_empty_rns_polynomial();
    let mut c0_r = create_empty_rns_polynomial();
    let mut c0_e = create_empty_rns_polynomial();
    ahe_encrypt(
        &coeffs0,
        &public_key_b,
        &params,
        &mut prng,
        &mut c0_b,
        &mut c0_a,
        &mut c0_r,
        &mut c0_e,
        None,
    )?;

    let mut c1_b = create_empty_rns_polynomial();
    let mut c1_a = create_empty_rns_polynomial();
    let mut c1_r = create_empty_rns_polynomial();
    let mut c1_e = create_empty_rns_polynomial();
    ahe_encrypt(
        &coeffs1,
        &public_key_b,
        &params,
        &mut prng,
        &mut c1_b,
        &mut c1_a,
        &mut c1_r,
        &mut c1_e,
        None,
    )?;

    // Accumulate component a
    let mut ciphertext_a = create_zero_rns_polynomial(&params)?;
    add_in_place(&moduli, &c0_a, &mut ciphertext_a)?;
    add_in_place(&moduli, &c1_a, &mut ciphertext_a)?;

    // Let all secret key share holders do partial decryption.
    let mut sum_partial_decryptions = create_zero_rns_polynomial(&params)?;
    for sk_share in secret_key_shares {
        let partial_decryption =
            partial_decrypt(&ciphertext_a, &sk_share, &params, &mut prng, None, None)?;
        add_in_place(&moduli, &partial_decryption, &mut sum_partial_decryptions)?;
    }

    // Accumulate component b
    let mut ciphertext_b = create_zero_rns_polynomial(&params)?;
    add_in_place(&moduli, &c0_b, &mut ciphertext_b)?;
    add_in_place(&moduli, &c1_b, &mut ciphertext_b)?;

    // Recover from partial decryptions and component b
    let mut output_values = vec![0; 2 * num_messages];
    let n_written =
        recover_messages(&sum_partial_decryptions, &ciphertext_b, &params, &mut output_values)?;
    expect_that!(n_written, eq(num_messages as u64));

    // Check homomorphism.
    for i in 0..num_messages {
        expect_that!(output_values[i], eq((coeffs0[i] + coeffs1[i]) % T));
    }

    Ok(())
}

#[gtest]
fn export_public_key_component_a_not_trivially_broken() -> Result<()> {
    // Create the public parameters.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let params = create_public_parameters(
        LOG_N,
        T,
        &QS_LARGE,
        PUBLIC_KEY_VARIANCE,
        S_BASE,
        S_FLOOD,
        &public_seed,
    )?;
    let rns_context = get_rns_context_ref(&params);

    let pk_a = public_key_component_a(&params)?;
    let mut buf = vec![0u64; 1 << (LOG_N + 1)];
    write_rns_polynomial_to_buffer_128(&rns_context, &pk_a, &mut buf)?;

    // Check that none of the public key coefficients are zero or less than 64 bits.
    expect_that!(buf, not(contains(eq(&0u64))));
    Ok(())
}

#[gtest]
fn generate_public_key_share_writes_to_wraparound() -> Result<()> {
    // Create the public parameters.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let params = create_public_parameters(
        LOG_N,
        T,
        &QS_LARGE,
        PUBLIC_KEY_VARIANCE,
        S_BASE,
        S_FLOOD,
        &public_seed,
    )?;
    let private_seed = single_thread_hkdf::generate_seed()?;
    let mut prng = single_thread_hkdf::create(&private_seed)?;

    let sk_share = generate_secret_key(&params, &mut prng)?;

    let mut public_key_share_b = create_empty_rns_polynomial();
    let mut public_key_share_error = create_empty_rns_polynomial();
    let mut wraparound = create_empty_rns_polynomial();
    generate_public_key_share(
        &sk_share,
        &params,
        &mut prng,
        &mut public_key_share_b,
        &mut public_key_share_error,
        Some(&mut wraparound),
    )?;

    let rns_context = get_rns_context_ref(&params);

    let mut buf = vec![0u64; 1 << (LOG_N + 1)];
    // Check that the wraparound is not empty.
    write_rns_polynomial_to_buffer_128(&rns_context, &wraparound, &mut buf)?;
    let mut wraparound_is_empty = true;
    for i in 0..1 << (LOG_N + 1) {
        if buf[i] != 0 {
            wraparound_is_empty = false;
            break;
        }
    }
    expect_that!(wraparound_is_empty, eq(false));
    Ok(())
}

#[gtest]
fn generate_ahe_encrypt_writes_to_wraparound() -> Result<()> {
    // Create the public parameters.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let params = create_public_parameters(
        LOG_N,
        T,
        &QS_LARGE,
        PUBLIC_KEY_VARIANCE,
        S_BASE,
        S_FLOOD,
        &public_seed,
    )?;
    let private_seed = single_thread_hkdf::generate_seed()?;
    let mut prng = single_thread_hkdf::create(&private_seed)?;

    let sk_share = generate_secret_key(&params, &mut prng)?;

    let mut public_key_share_b = create_empty_rns_polynomial();
    let mut public_key_share_error = create_empty_rns_polynomial();
    generate_public_key_share(
        &sk_share,
        &params,
        &mut prng,
        &mut public_key_share_b,
        &mut public_key_share_error,
        None,
    )?;

    let mut coeffs = vec![0u64; 8];
    for _ in 0..8 {
        coeffs.push(rand::thread_rng().gen_range(0..MAX_VALUE));
    }
    let mut ct_b = create_empty_rns_polynomial();
    let mut ct_a = create_empty_rns_polynomial();
    let mut ct_r = create_empty_rns_polynomial();
    let mut ct_e = create_empty_rns_polynomial();
    let mut wraparound = create_empty_rns_polynomial();
    ahe_encrypt(
        &coeffs,
        &public_key_share_b,
        &params,
        &mut prng,
        &mut ct_b,
        &mut ct_a,
        &mut ct_r,
        &mut ct_e,
        Some(&mut wraparound),
    )?;

    let rns_context = get_rns_context_ref(&params);

    let mut buf = vec![0u64; 1 << (LOG_N + 1)];
    // Check that the wraparound is not empty.
    write_rns_polynomial_to_buffer_128(&rns_context, &wraparound, &mut buf)?;
    let mut wraparound_is_empty = true;
    for i in 0..1 << (LOG_N + 1) {
        if buf[i] != 0 {
            wraparound_is_empty = false;
            break;
        }
    }
    expect_that!(wraparound_is_empty, eq(false));
    Ok(())
}

#[gtest]
fn generate_partial_decrypt_writes_to_error_flood_and_wraparound() -> Result<()> {
    // Create the public parameters.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let params = create_public_parameters(
        LOG_N,
        T,
        &QS_LARGE,
        PUBLIC_KEY_VARIANCE,
        S_BASE,
        S_FLOOD,
        &public_seed,
    )?;
    let private_seed = single_thread_hkdf::generate_seed()?;
    let mut prng = single_thread_hkdf::create(&private_seed)?;

    let sk_share = generate_secret_key(&params, &mut prng)?;

    let mut public_key_share_b = create_empty_rns_polynomial();
    let mut public_key_share_error = create_empty_rns_polynomial();
    generate_public_key_share(
        &sk_share,
        &params,
        &mut prng,
        &mut public_key_share_b,
        &mut public_key_share_error,
        None,
    )?;

    let mut coeffs = vec![0u64; 8];
    for _ in 0..8 {
        coeffs.push(rand::thread_rng().gen_range(0..MAX_VALUE));
    }
    let mut ct_b = create_empty_rns_polynomial();
    let mut ct_a = create_empty_rns_polynomial();
    let mut ct_r = create_empty_rns_polynomial();
    let mut ct_e = create_empty_rns_polynomial();
    ahe_encrypt(
        &coeffs,
        &public_key_share_b,
        &params,
        &mut prng,
        &mut ct_b,
        &mut ct_a,
        &mut ct_r,
        &mut ct_e,
        None,
    )?;

    let mut error_flood = create_empty_rns_polynomial();
    let mut wraparound = create_empty_rns_polynomial();
    partial_decrypt(
        &ct_a,
        &sk_share,
        &params,
        &mut prng,
        Some(&mut error_flood),
        Some(&mut wraparound),
    )?;

    let rns_context = get_rns_context_ref(&params);

    let mut buf = vec![0u64; 1 << (LOG_N + 1)];
    // Check that the error flood is not empty.
    write_rns_polynomial_to_buffer_128(&rns_context, &error_flood, &mut buf)?;
    let mut error_flood_is_empty = true;
    for i in 0..1 << (LOG_N + 1) {
        if buf[i] != 0 {
            error_flood_is_empty = false;
            break;
        }
    }
    expect_that!(error_flood_is_empty, eq(false));

    // Check that the wraparound is not empty.
    write_rns_polynomial_to_buffer_128(&rns_context, &wraparound, &mut buf)?;
    let mut wraparound_is_empty = true;
    for i in 0..1 << (LOG_N + 1) {
        if buf[i] != 0 {
            wraparound_is_empty = false;
            break;
        }
    }
    expect_that!(wraparound_is_empty, eq(false));
    Ok(())
}
