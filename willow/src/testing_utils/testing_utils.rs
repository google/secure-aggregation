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
use shell_testing_parameters::{make_ahe_config, make_kahe_config};
use single_thread_hkdf::Seed;
use vahe_shell::ShellVahe;
use vahe_traits::{Recover, VaheBase};
use willow_api_common::AggregationConfig;
use willow_v1_client::WillowV1Client;
use willow_v1_common::{WillowClientMessage, WillowCommon};

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

/// Creates a `WillowCommon` for SHELL with the default AHE/KAHE configurations
/// and the given public seeds.
pub fn create_willow_common(
    aggregation_config: &AggregationConfig,
    public_kahe_seed: &Seed,
    public_ahe_seed: &Seed,
) -> WillowCommon<ShellKahe, ShellVahe> {
    let kahe = ShellKahe::new(make_kahe_config(aggregation_config), public_kahe_seed).unwrap();
    let vahe = ShellVahe::new(make_ahe_config(), public_ahe_seed).unwrap();
    WillowCommon { kahe, vahe }
}

pub fn ahe_decrypt_with_single_sk_share(
    ahe_ciphertext: &<ShellVahe as AheBase>::Ciphertext,
    sk_share: &<ShellVahe as AheBase>::SecretKeyShare,
    common: &WillowCommon<ShellKahe, ShellVahe>,
    prng: &mut <ShellKahe as KaheBase>::Rng,
) -> Result<<ShellVahe as AheBase>::Plaintext, status::StatusError> {
    let decryption_request = common.vahe.get_partial_dec_ciphertext(&ahe_ciphertext).unwrap();
    let rest_of_ciphertext = common.vahe.get_recover_ciphertext(&ahe_ciphertext).unwrap();
    let partial_decryption =
        common.vahe.partial_decrypt(&decryption_request, &sk_share, prng).unwrap();
    common.vahe.recover(&partial_decryption, &rest_of_ciphertext, None)
}

/// Concrete implementation of the client using the Shell KAHE/VAHE
/// implementations.
pub type ShellClient = WillowV1Client<ShellKahe, ShellVahe>;

pub type ShellClientMessage = WillowClientMessage<ShellKahe, ShellVahe>;
