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

use ahe_traits::{AheBase, PartialDec};
use kahe_shell::ShellKahe;
use kahe_traits::KaheBase;
use rand::Rng;
use std::collections::HashMap;
use vahe_shell::ShellVahe;
use vahe_traits::Recover;
use willow_api_common::AggregationConfig;

pub fn generate_random_unsigned_vector(num_values: usize, max_absolute_value: u64) -> Vec<u64> {
    let mut pt: Vec<u64> = Vec::with_capacity(num_values);
    for _ in 0..num_values {
        pt.push(rand::thread_rng().gen_range(0..max_absolute_value));
    }
    pt
}

pub fn generate_random_signed_vector(num_values: usize, max_absolute_value: i64) -> Vec<i64> {
    let mut pt: Vec<i64> = Vec::with_capacity(num_values);
    for _ in 0..num_values {
        let v: i64 = rand::thread_rng().gen_range(0..2 * max_absolute_value).try_into().unwrap();
        pt.push(v - max_absolute_value);
    }
    pt
}

pub fn ahe_decrypt_with_single_sk_share(
    ahe_ciphertext: &<ShellVahe as AheBase>::Ciphertext,
    sk_share: &<ShellVahe as AheBase>::SecretKeyShare,
    vahe: &ShellVahe,
    prng: &mut <ShellKahe as KaheBase>::Rng,
) -> Result<<ShellVahe as AheBase>::Plaintext, status::StatusError> {
    let decryption_request = vahe.get_partial_dec_ciphertext(&ahe_ciphertext).unwrap();
    let rest_of_ciphertext = vahe.get_recover_ciphertext(&ahe_ciphertext).unwrap();
    let partial_decryption = vahe.partial_decrypt(&decryption_request, &sk_share, prng).unwrap();
    vahe.recover(&partial_decryption, &rest_of_ciphertext, None)
}

/// Generates an AggregationConfig for test cases in this file.
pub fn generate_aggregation_config(
    vector_id: String,
    vector_length: isize,
    vector_bound: i64,
    max_number_of_decryptors: i64,
    max_number_of_clients: i64,
) -> AggregationConfig {
    AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([(vector_id, (vector_length, vector_bound))]),
        max_number_of_decryptors,
        max_number_of_clients,
        max_decryptor_dropouts: 0,
        session_id: String::from("test"),
        willow_version: (1, 0),
    }
}
