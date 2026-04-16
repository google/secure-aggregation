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

use aggregation_config::AggregationConfig;
use shell_ahe::ShellAheConfig;
use shell_kahe::ShellKaheConfig;

use shell_parameters_generation::{divide_and_roundup, generate_packing_config};

/// This file contains parameters for the KAHE and AHE schemes in Willow, which
/// are selected to have at least 128 bits of computational security and 40 bits
/// of statistical security, based on:
/// - the Homomorphic Encryption Standard https://homomorphicencryption.org/standard/
/// - the Lattice Estimator https://github.com/malb/lattice-estimator
/// - the noise flooding analysis in https://eprint.iacr.org/2022/816
///
/// The secret and error distributions of both KAHE and AHE are fixed, defined
/// in the respective implementation. Here we define their underlying rings and
/// encoding parameters. In addition we define the noise flooding parameter for
/// AHE, as it depends on the AHE's plaintext space.
///

/// ----------------------------------------------------------------------------
/// AHE parameters are fixed across all input settings.
/// ----------------------------------------------------------------------------
/// This set of AHE parameters are good for the following assumption:
/// - there are at most 10^7 clients, and at least 99.999% of them are honest;
/// - there are at most 100 decryptors, and all of them are honest;
/// - verifiable key gen, encryption, and partial decryption use approximate L_inf
///   range proofs.
const AHE_FIXED_LOG_N: u64 = 12;
const AHE_FIXED_T: u64 = 262145; // 2^18 + 1
const AHE_FIXED_QS: [u64; 2] = [281474976546817, 281474975662081]; // 96 bits total
const AHE_FIXED_S_FLOOD: f64 = 4.81659e+19;
const AHE_FIXED_MAX_NUM_DECRYPTORS: i64 = 1;

/// ----------------------------------------------------------------------------
/// KAHE parameters for some typical input settings.
/// ----------------------------------------------------------------------------
/// KAHE parameters for:
/// - input of length 1K with 32-bit domain
/// - max number of clients 10M
/// - max number of decryptors 100
const KAHE_FOR_FIXED_AHE_LOG_N_1K_10M: usize = 12;
const KAHE_FOR_FIXED_AHE_LOG_T_1K_10M: usize = 56;
const KAHE_FOR_FIXED_AHE_QS_1K_10M: [u64; 2] = [
    274877816833, // 38 bits
    274877718529, // 38 bits
];

/// KAHE parameters for:
/// - input of length 100K with 32-bit domain
/// - max number of clients 10M
/// - max number of decryptors 100
const KAHE_FOR_FIXED_AHE_LOG_N_100K_10M: usize = 13;
const KAHE_FOR_FIXED_AHE_LOG_T_100K_10M: usize = 168;
const KAHE_FOR_FIXED_AHE_QS_100K_10M: [u64; 4] = [
    140737488273409, // 47 bits
    140737488125953, // 47 bits
    140737487290369, // 47 bits
    140737487093761, // 47 bits
];

/// KAHE parameters for:
/// - input of length 10M with 32-bit domain
/// - max number of clients 10M
/// - max number of decryptors 100
const KAHE_FOR_FIXED_AHE_LOG_N_10M_10M: usize = KAHE_FOR_FIXED_AHE_LOG_N_100K_10M;
const KAHE_FOR_FIXED_AHE_LOG_T_10M_10M: usize = KAHE_FOR_FIXED_AHE_LOG_T_100K_10M;
const KAHE_FOR_FIXED_AHE_QS_10M_10M: [u64; 4] = KAHE_FOR_FIXED_AHE_QS_100K_10M;

pub fn create_shell_ahe_config(
    max_number_of_decryptors: i64,
) -> Result<ShellAheConfig, status::StatusError> {
    if max_number_of_decryptors > AHE_FIXED_MAX_NUM_DECRYPTORS {
        return Err(status::invalid_argument(&format!(
            "`max_number_of_decryptors` cannot be larger than {}",
            AHE_FIXED_MAX_NUM_DECRYPTORS
        )));
    }

    Ok(ShellAheConfig {
        log_n: AHE_FIXED_LOG_N,
        t: AHE_FIXED_T,
        qs: AHE_FIXED_QS.to_vec(),
        s_flood: AHE_FIXED_S_FLOOD,
    })
}

pub fn create_shell_kahe_config(
    aggregation_config: &AggregationConfig,
) -> Result<ShellKaheConfig, status::StatusError> {
    // Use heuristics to select parameters.
    let total_input_length: i64 = aggregation_config
        .vector_lengths_and_bounds
        .values()
        .map(|(length, _)| *length as i64)
        .sum();
    let max_input_bound =
        aggregation_config.vector_lengths_and_bounds.values().map(|(_, bound)| bound).max().ok_or(
            status::invalid_argument(&format!("empty vector configs in aggregation config")),
        )?;

    if total_input_length <= 1000
        && *max_input_bound <= (1i64 << 32)
        && aggregation_config.max_number_of_clients <= 10_000_000
        && aggregation_config.max_number_of_decryptors <= 100
    {
        let packed_vector_configs =
            generate_packing_config(KAHE_FOR_FIXED_AHE_LOG_T_1K_10M, aggregation_config)?;
        let kahe_total_num_coeffs: usize = packed_vector_configs
            .values()
            .map(|packed_vector_cfg| packed_vector_cfg.num_packed_coeffs as usize)
            .sum();
        let kahe_num_coeffs = 1 << KAHE_FOR_FIXED_AHE_LOG_N_1K_10M;
        return Ok(ShellKaheConfig {
            log_n: KAHE_FOR_FIXED_AHE_LOG_N_1K_10M,
            moduli: KAHE_FOR_FIXED_AHE_QS_1K_10M.to_vec(),
            log_t: KAHE_FOR_FIXED_AHE_LOG_T_1K_10M,
            num_public_polynomials: divide_and_roundup(kahe_total_num_coeffs, kahe_num_coeffs),
            packed_vector_configs,
        });
    }

    if total_input_length <= 100_000
        && *max_input_bound <= (1i64 << 32)
        && aggregation_config.max_number_of_clients <= 10_000_000
        && aggregation_config.max_number_of_decryptors <= 100
    {
        let packed_vector_configs =
            generate_packing_config(KAHE_FOR_FIXED_AHE_LOG_T_100K_10M, aggregation_config)?;
        let kahe_total_num_coeffs: usize = packed_vector_configs
            .values()
            .map(|packed_vector_cfg| packed_vector_cfg.num_packed_coeffs as usize)
            .sum();
        let kahe_num_coeffs = 1 << KAHE_FOR_FIXED_AHE_LOG_N_100K_10M;
        return Ok(ShellKaheConfig {
            log_n: KAHE_FOR_FIXED_AHE_LOG_N_100K_10M,
            moduli: KAHE_FOR_FIXED_AHE_QS_100K_10M.to_vec(),
            log_t: KAHE_FOR_FIXED_AHE_LOG_T_100K_10M,
            num_public_polynomials: divide_and_roundup(kahe_total_num_coeffs, kahe_num_coeffs),
            packed_vector_configs,
        });
    }

    if total_input_length <= 10_000_000
        && *max_input_bound <= (1i64 << 32)
        && aggregation_config.max_number_of_clients <= 10_000_000
        && aggregation_config.max_number_of_decryptors <= 100
    {
        let packed_vector_configs =
            generate_packing_config(KAHE_FOR_FIXED_AHE_LOG_T_10M_10M, aggregation_config)?;
        let kahe_total_num_coeffs: usize = packed_vector_configs
            .values()
            .map(|packed_vector_cfg| packed_vector_cfg.num_packed_coeffs as usize)
            .sum();
        let kahe_num_coeffs = 1 << KAHE_FOR_FIXED_AHE_LOG_N_10M_10M;
        return Ok(ShellKaheConfig {
            log_n: KAHE_FOR_FIXED_AHE_LOG_N_10M_10M,
            moduli: KAHE_FOR_FIXED_AHE_QS_10M_10M.to_vec(),
            log_t: KAHE_FOR_FIXED_AHE_LOG_T_10M_10M,
            num_public_polynomials: divide_and_roundup(kahe_total_num_coeffs, kahe_num_coeffs),
            packed_vector_configs,
        });
    }

    Err(status::invalid_argument(&format!(
        "input setting is not supported: aggregation_config = {:?}",
        aggregation_config
    )))
}

/// Creates a pair (ShellKaheConfig, ShellAheConfig) to be used to instantiate
/// KAHE and AHE schemes for the given protocol setting.
pub fn create_shell_configs(
    aggregation_config: &AggregationConfig,
) -> Result<(ShellKaheConfig, ShellAheConfig), status::StatusError> {
    let ahe_config = create_shell_ahe_config(aggregation_config.max_number_of_decryptors)?;
    let kahe_config = create_shell_kahe_config(&aggregation_config)?;
    Ok((kahe_config, ahe_config))
}
