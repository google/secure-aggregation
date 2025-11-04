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

use ahe_shell::ShellAheConfig;
use kahe_shell::ShellKaheConfig;
use shell_parameters_generation::{divide_and_roundup, generate_packing_config};
use willow_api_common::AggregationConfig;

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
/// To generate parameters for new settings, see go/willow-parameters.
/// In particular, AHE moduli must be NTT-friendly wrt 2^(AHE_LOG_N+1) for
/// efficiently computing the wrap around terms.

/// Parameter constants for:
/// - input of length 1K with 32-bit domain
/// - max number of clients 10M
/// - max number of decryptors 100
const KAHE_LOG_N_1K_10M: usize = 12;
const KAHE_LOG_T_1K_10M: usize = 56;
const KAHE_QS_1K_10M: [u64; 2] = [
    274877816833, // 38 bits
    274877718529, // 38 bits
];
const AHE_LOG_N_1K_10M: u64 = 12;
const AHE_T_1K_10M: u64 = 109965;
const AHE_QS_1K_10M: [u64; 2] = [1099510824961, 1099508760577]; // 80 bits total
const AHE_S_FLOOD_1K_10M: f64 = 3.0834e+16;

/// Parameter constants for:
/// - input of length 100K with 32-bit domain
/// - max number of clients 10M
/// - max number of decryptors 100
const KAHE_LOG_N_100K_10M: usize = 13;
const KAHE_LOG_T_100K_10M: usize = 168;
const KAHE_QS_100K_10M: [u64; 4] = [
    1125899906629633, // 50 bits
    1125899905744897, // 50 bits
    1125899905351681, // 50 bits
    1125899903827969, // 50 bits
];
const AHE_LOG_N_100K_10M: u64 = 12;
const AHE_T_100K_10M: u64 = 6582404323;
const AHE_QS_100K_10M: [u64; 2] = [281474976546817, 281474975662081]; // 96 bits total
const AHE_S_FLOOD_100K_10M: f64 = 3.0834e+16;

/// Parameter constants for:
/// - input of length 10M with 32-bit domain
/// - max number of clients 10M
/// - max number of decryptors 100
const KAHE_LOG_N_10M_10M: usize = 14;
const KAHE_LOG_T_10M_10M: usize = 224;
const KAHE_QS_10M_10M: [u64; 4] = [
    2305843009211596801, // 61 bits
    2305843009211400193, // 61 bits
    2305843009210515457, // 61 bits
    2305843009210023937, // 61 bits
];
const AHE_LOG_N_10M_10M: u64 = 12;
const AHE_T_10M_10M: u64 = 7121256483;
const AHE_QS_10M_10M: [u64; 2] = [281474976546817, 281474975662081]; // 96 bits total
const AHE_S_FLOOD_10M_10M: f64 = 3.0834e+16;

/// Creates a pair (ShellKaheConfig, ShellAheConfig) to be used to instantiate
/// KAHE and AHE schemes for the given protocol setting.
pub fn create_shell_configs(
    aggregation_config: &AggregationConfig,
) -> Result<(ShellKaheConfig, ShellAheConfig), status::StatusError> {
    // Use heuristics to select parameters.
    let total_input_length: i64 = aggregation_config
        .vector_lengths_and_bounds
        .values()
        .map(|(length, _)| *length as i64)
        .sum();
    let max_input_bound = aggregation_config
        .vector_lengths_and_bounds
        .values()
        .map(|(_, bound)| bound)
        .max()
        .unwrap();

    if total_input_length <= 1000
        && *max_input_bound <= (1i64 << 32)
        && aggregation_config.max_number_of_clients <= 10_000_000
        && aggregation_config.max_number_of_decryptors <= 100
    {
        let packed_vector_configs = generate_packing_config(KAHE_LOG_T_1K_10M, aggregation_config)?;
        let kahe_total_num_coeffs: usize = packed_vector_configs
            .values()
            .map(|packed_vector_cfg| packed_vector_cfg.num_packed_coeffs as usize)
            .sum();
        let kahe_num_coeffs = 1 << KAHE_LOG_N_1K_10M;
        return Ok((
            ShellKaheConfig {
                log_n: KAHE_LOG_N_1K_10M,
                moduli: KAHE_QS_1K_10M.to_vec(),
                log_t: KAHE_LOG_T_1K_10M,
                num_public_polynomials: divide_and_roundup(kahe_total_num_coeffs, kahe_num_coeffs),
                packed_vector_configs,
            },
            ShellAheConfig {
                log_n: AHE_LOG_N_1K_10M,
                t: AHE_T_1K_10M,
                qs: AHE_QS_1K_10M.to_vec(),
                s_flood: AHE_S_FLOOD_1K_10M,
            },
        ));
    }

    if total_input_length <= 100_000
        && *max_input_bound <= (1i64 << 32)
        && aggregation_config.max_number_of_clients <= 10_000_000
        && aggregation_config.max_number_of_decryptors <= 100
    {
        let packed_vector_configs =
            generate_packing_config(KAHE_LOG_T_100K_10M, aggregation_config)?;
        let kahe_total_num_coeffs: usize = packed_vector_configs
            .values()
            .map(|packed_vector_cfg| packed_vector_cfg.num_packed_coeffs as usize)
            .sum();
        let kahe_num_coeffs = 1 << KAHE_LOG_N_100K_10M;
        return Ok((
            ShellKaheConfig {
                log_n: KAHE_LOG_N_100K_10M,
                moduli: KAHE_QS_100K_10M.to_vec(),
                log_t: KAHE_LOG_T_100K_10M,
                num_public_polynomials: divide_and_roundup(kahe_total_num_coeffs, kahe_num_coeffs),
                packed_vector_configs,
            },
            ShellAheConfig {
                log_n: AHE_LOG_N_100K_10M,
                t: AHE_T_100K_10M,
                qs: AHE_QS_100K_10M.to_vec(),
                s_flood: AHE_S_FLOOD_100K_10M,
            },
        ));
    }

    if total_input_length <= 10_000_000
        && *max_input_bound <= (1i64 << 32)
        && aggregation_config.max_number_of_clients <= 10_000_000
        && aggregation_config.max_number_of_decryptors <= 100
    {
        let packed_vector_configs =
            generate_packing_config(KAHE_LOG_T_10M_10M, aggregation_config)?;
        let kahe_total_num_coeffs: usize = packed_vector_configs
            .values()
            .map(|packed_vector_cfg| packed_vector_cfg.num_packed_coeffs as usize)
            .sum();
        let kahe_num_coeffs = 1 << KAHE_LOG_N_10M_10M;
        return Ok((
            ShellKaheConfig {
                log_n: KAHE_LOG_N_10M_10M,
                moduli: KAHE_QS_10M_10M.to_vec(),
                log_t: KAHE_LOG_T_10M_10M,
                num_public_polynomials: divide_and_roundup(kahe_total_num_coeffs, kahe_num_coeffs),
                packed_vector_configs,
            },
            ShellAheConfig {
                log_n: AHE_LOG_N_10M_10M,
                t: AHE_T_10M_10M,
                qs: AHE_QS_10M_10M.to_vec(),
                s_flood: AHE_S_FLOOD_10M_10M,
            },
        ));
    }

    Err(status::invalid_argument(format!(
        "input setting is not supported: aggregation_config = {:?}",
        aggregation_config
    )))
}
