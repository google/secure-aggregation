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
use kahe::PackedVectorConfig;
use kahe_shell::ShellKaheConfig;
use shell_parameters_generation::{divide_and_roundup, generate_packing_config};
use std::collections::HashMap;
use willow_api_common::AggregationConfig;

/// Creates an KAHE configuration with the given plaintext modulus bits, by
/// looking up some pre-generated configurations.
pub fn make_kahe_config_for(
    plaintext_modulus_bits: usize,
    packed_vector_configs: HashMap<String, PackedVectorConfig>,
) -> Result<ShellKaheConfig, status::StatusError> {
    // Configurations below come from:
    // google3/experimental/users/baiyuli/async_rlwe_secagg/parameters.cc,
    // originally generated with:
    // google3/experimental/users/baiyuli/lattice/find_rns_moduli.sage
    // NOTE: For decoding we need  t * e in [-q/2, q/2).
    //       We take plaintext_modulus_bits < composite_modulus_bits - 1 -
    //       log2(kTailBoundMultiplier) - log2(kPrgErrorS)
    //       = composite_modulus_bits - 7
    match plaintext_modulus_bits {
        17 => {
            let total_num_coeffs =
                packed_vector_configs.values().map(|cfg| cfg.num_packed_coeffs as usize).sum();
            Ok(ShellKaheConfig {
                log_n: 10,
                moduli: vec![16760833u64],
                log_t: 17,
                packed_vector_configs,
                num_public_polynomials: divide_and_roundup(total_num_coeffs, 1 << 10),
            })
        }
        39 => {
            let total_num_coeffs =
                packed_vector_configs.values().map(|cfg| cfg.num_packed_coeffs as usize).sum();
            Ok(ShellKaheConfig {
                log_n: 11,
                moduli: vec![70368744067073u64],
                log_t: 39,
                packed_vector_configs,
                num_public_polynomials: divide_and_roundup(total_num_coeffs, 1 << 11),
            })
        }
        93 => {
            let total_num_coeffs =
                packed_vector_configs.values().map(|cfg| cfg.num_packed_coeffs as usize).sum();
            Ok(ShellKaheConfig {
                log_n: 12,
                moduli: vec![1125899906826241u64, 1125899906629633u64],
                log_t: 93,
                packed_vector_configs,
                num_public_polynomials: divide_and_roundup(total_num_coeffs, 1 << 12),
            })
        }
        _ => Err(status::invalid_argument(format!(
            "No KAHE configuration for plaintext_modulus_bits = {}",
            plaintext_modulus_bits
        ))),
    }
}

pub fn set_kahe_num_public_polynomials(kahe_config: &mut ShellKaheConfig) -> () {
    let num_coeffs_per_poly = 1 << kahe_config.log_n;
    let total_num_coeffs =
        kahe_config.packed_vector_configs.values().map(|cfg| cfg.num_packed_coeffs as usize).sum();
    kahe_config.num_public_polynomials = divide_and_roundup(total_num_coeffs, num_coeffs_per_poly);
}

/// Creates a sample KAHE configuration, for quick tests that need just any
/// valid configuration.
pub fn make_kahe_config(aggregation_config: &AggregationConfig) -> ShellKaheConfig {
    const PLAINTEXT_MODULUS_BITS: usize = 93;
    let packed_vector_configs =
        generate_packing_config(PLAINTEXT_MODULUS_BITS, aggregation_config).unwrap();
    make_kahe_config_for(PLAINTEXT_MODULUS_BITS, packed_vector_configs).unwrap()
}

/// Creates an AHE configuration with 69-bit main modulus and 64-bit RNS moduli.
/// Parameters from https://github.com/google/shell-encryption/blob/master/shell_encryption/testing/parameters.h
pub fn make_ahe_config() -> ShellAheConfig {
    // Defines RLWE parameters for the ring Z[X]/(Q, X^N+1) where N = 2^log_n,
    // and Q = prod(qs). This is the ciphertext space of the AHE scheme, i.e.
    // the public keys and ciphertexts are all polynomials in this ring.
    // The primes in `qs` must be NTT-friendly for X^{2N} + 1, i.e. each member
    // q of `qs` should be such that 4N factors q-1. This allows to compute the
    // "wrap around" polynomials of the public key shares.
    // The parameter `t` specifies the plaintext modulus, i.e. the plaintext of
    // the AHE scheme is Z[X]/(t, X^N+1).
    // The parameter `s_flood` specifies the Gaussian parameter of the flooding
    // noise polynomial e(X) used in partial decryptions, i.e. e(X) has i.i.d.
    // discrete Gaussian coefficients of parameter `s_flood`.
    //
    ShellAheConfig { log_n: 12, t: 54001, qs: vec![34359410689, 34359361537], s_flood: 4.25839e+13 }
}
