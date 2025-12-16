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
use kahe::PackedVectorConfig;
use std::collections::HashMap;

/// Generating KAHE and AHE parameters given the Willow protocol configuration.

// We set the packing base to be a power of 2 in the C++ Integer type (uint64_t).
const MAX_PACKING_BASE_BITS: usize = 63;
// Bit size of the C++ BigInteger type used to store packed plaintext coefficients.
const BIG_INT_BITS: usize = 256;

// Returns ceil(x / y).
pub fn divide_and_roundup(x: usize, y: usize) -> usize {
    (x + y - 1) / y
}

// Returns the packing configurations and the bit size of the largest packed coefficients.
// The packing config determines how to pack input vector coefficients into the plaintext modulus
// that allows summation of up to `agg_config.max_number_of_clients` many vectors.
pub fn generate_packing_config(
    plaintext_bits: usize,
    agg_config: &AggregationConfig,
) -> Result<HashMap<String, PackedVectorConfig>, status::StatusError> {
    if plaintext_bits == 0 {
        return Err(status::invalid_argument("`plaintext_bits` must be positive."));
    }
    if plaintext_bits >= BIG_INT_BITS {
        return Err(status::invalid_argument(format!(
            "`plaintext_bits` must be less than {}.",
            BIG_INT_BITS
        )));
    }
    if agg_config.max_number_of_clients <= 0 {
        return Err(status::invalid_argument("`max_number_of_clients` must be positive."));
    }
    let mut packing_configs = HashMap::<String, PackedVectorConfig>::new();
    for (id, (length, bound)) in agg_config.vector_lengths_and_bounds.iter() {
        if *length <= 0 {
            return Err(status::invalid_argument(format!(
                "For id = {}, input length must be positive.",
                id
            )));
        }
        if *bound <= 0 {
            return Err(status::invalid_argument(format!(
                "For id = {}, input bound must be positive.",
                id
            )));
        }
        // The input values are in [0, bound], so we set the packing base to
        // 2^ceil(log2(bound * max_number_of_clients + 1)).
        let agg_bound: i64 = agg_config.max_number_of_clients * bound;
        let base_bits: usize = (agg_bound as f64 + 1.0).log2().ceil() as usize;
        if base_bits > MAX_PACKING_BASE_BITS {
            return Err(status::invalid_argument(format!(
                "For id = {}, input bound * max_number_of_clients is too large.",
                id,
            )));
        }
        if base_bits == 0 {
            return Err(status::invalid_argument(format!("For id = {}, base bits is 0.", id,)));
        }
        let base = 1i64 << base_bits;
        let dimension = plaintext_bits / base_bits;
        if dimension == 0 {
            return Err(status::invalid_argument(format!(
                "For id = {}, plaintext_bits is too small; got {}, expected at least {}.",
                id, plaintext_bits, base_bits
            )));
        }
        let num_packed_coeffs = divide_and_roundup(*length as usize, dimension);
        packing_configs.insert(
            id.clone(),
            PackedVectorConfig {
                base: base as u64,
                dimension: dimension as u64,
                num_packed_coeffs: num_packed_coeffs as u64,
            },
        );
    }
    Ok(packing_configs)
}

#[cfg(test)]
mod test {
    use super::*;
    use googletest::prelude::*;
    use std::collections::HashMap;

    #[gtest]
    fn test_generate_packing_config_invalid_plaintext_bits() -> googletest::Result<()> {
        let agg_config = AggregationConfig {
            vector_lengths_and_bounds: HashMap::new(),
            max_number_of_decryptors: 1,
            max_decryptor_dropouts: 0,
            max_number_of_clients: 1,
            session_id: String::from("test"),
        };
        let invalid_plaintext_bits = 0;
        let result = generate_packing_config(invalid_plaintext_bits, &agg_config);
        expect_true!(result.is_err());

        let invalid_plaintext_bits = BIG_INT_BITS;
        let result = generate_packing_config(invalid_plaintext_bits, &agg_config);
        expect_true!(result.is_err());
        Ok(())
    }

    #[gtest]
    fn test_generate_packing_config_invalid_input_length_or_bound() -> googletest::Result<()> {
        let plaintext_bits = 100;
        let bad_agg_inputs = HashMap::from([(String::from("vec0"), (/*length=*/ 0, 1 << 16))]);
        let mut bad_agg_config = AggregationConfig {
            vector_lengths_and_bounds: bad_agg_inputs,
            max_number_of_decryptors: 1,
            max_decryptor_dropouts: 0,
            max_number_of_clients: 1,
            session_id: String::from("test"),
        };
        let result = generate_packing_config(plaintext_bits, &bad_agg_config);
        expect_true!(result.is_err());

        let bad_agg_inputs = HashMap::from([(String::from("vec0"), (32, /*bound=*/ 0))]);
        bad_agg_config.vector_lengths_and_bounds = bad_agg_inputs;
        let result = generate_packing_config(plaintext_bits, &bad_agg_config);
        expect_true!(result.is_err());
        Ok(())
    }

    #[gtest]
    fn test_generate_packing_config_invalid_aggregation_config() -> googletest::Result<()> {
        let plaintext_bits = 100;
        let agg_inputs = HashMap::from([(String::from("vec0"), (10, 1 << 8))]);
        let bad_agg_config = AggregationConfig {
            vector_lengths_and_bounds: agg_inputs,
            max_number_of_decryptors: 1,
            max_decryptor_dropouts: 0,
            max_number_of_clients: 0,
            session_id: String::from("test"),
        };
        let result = generate_packing_config(plaintext_bits, &bad_agg_config);
        expect_true!(result.is_err());
        Ok(())
    }

    #[gtest]
    fn test_generate_packing_config_plaintext_bits_too_small() -> googletest::Result<()> {
        // `plaintext_bits` is too small to fit in the sum of input vectors.
        let plaintext_bits = 8;
        let agg_inputs = HashMap::from([(String::from("vec0"), (10, 1 << plaintext_bits))]);
        let agg_config = AggregationConfig {
            vector_lengths_and_bounds: agg_inputs,
            max_number_of_decryptors: 1,
            max_decryptor_dropouts: 0,
            max_number_of_clients: 2,
            session_id: String::from("test"),
        };
        let result = generate_packing_config(plaintext_bits, &agg_config);
        expect_true!(result.is_err());
        Ok(())
    }

    #[gtest]
    fn test_generate_packing_config() -> googletest::Result<()> {
        let agg_inputs = HashMap::from([
            (String::from("small"), (1024, 7)),
            (String::from("large"), (32, (1 << 16) - 1)),
            (String::from("long"), (1 << 16, (1 << 16) - 1)),
        ]);
        let agg_config = AggregationConfig {
            vector_lengths_and_bounds: agg_inputs,
            max_number_of_decryptors: 1,
            max_decryptor_dropouts: 0,
            max_number_of_clients: 1 << 8,
            session_id: String::from("test"),
        };
        let plaintext_bits = 24;
        let packed_vector_configs = generate_packing_config(plaintext_bits, &agg_config)?;
        verify_that!(
            packed_vector_configs.keys().collect::<Vec<_>>(),
            unordered_elements_are![
                eq(&&String::from("small")),
                eq(&&String::from("large")),
                eq(&&String::from("long"))
            ]
        )?;
        expect_eq!(
            packed_vector_configs.get("small").unwrap(),
            &PackedVectorConfig { base: 1 << 11, dimension: 2, num_packed_coeffs: 512 }
        );
        expect_eq!(
            packed_vector_configs.get("large").unwrap(),
            &PackedVectorConfig { base: 1 << 24, dimension: 1, num_packed_coeffs: 32 }
        );
        expect_eq!(
            packed_vector_configs.get("long").unwrap(),
            &PackedVectorConfig { base: 1 << 24, dimension: 1, num_packed_coeffs: 65536 }
        );
        Ok(())
    }
}
