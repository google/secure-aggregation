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

//! This file contains some utility functions for working with Willow parameters:
//! - Conversions between Rust structs and their corresponding protos.
//! - FFI bridge to generate and print Shell parameters from C++.

use aggregation_config::AggregationConfig;
use aggregation_config_rust_proto::AggregationConfigProto;
use cxx::{CxxString, UniquePtr};
use kahe::PackedVectorConfig;
use kahe_shell::ShellKaheConfig;
use parameters_shell::create_shell_configs;
use proto_serialization_traits::FromProto;
use protobuf::{proto, Parse, ProtoStr};
use shell_parameters_rust_proto::{
    PackedVectorConfigProto, PackedVectorConfigProtoView, ShellKaheConfigProto,
    ShellKaheConfigProtoView,
};
use std::collections::BTreeMap;

#[cxx::bridge]
pub mod ffi {
    // Re-define FfiStatus since CXX requires shared structs to be defined in the same module
    // (https://github.com/dtolnay/cxx/issues/297#issuecomment-727042059)
    unsafe extern "C++" {
        include!("ffi_utils/status.rs.h");
        #[namespace = "secure_aggregation"]
        type FfiStatus = status::ffi::FfiStatus;
    }

    #[namespace = "secure_aggregation"]
    extern "Rust" {
        unsafe fn create_human_readable_shell_config(
            aggregation_config_proto: UniquePtr<CxxString>,
            out: *mut Vec<u8>,
        ) -> FfiStatus;
    }
}

fn create_human_readable_shell_config_impl(
    aggregation_config_proto: UniquePtr<CxxString>,
) -> Result<Vec<u8>, status::StatusError> {
    let config_proto =
        AggregationConfigProto::parse(aggregation_config_proto.as_bytes()).map_err(|e| {
            status::invalid_argument(format!("Failed to parse AggregationConfigProto: {}", e))
        })?;
    let config = AggregationConfig::from_proto(config_proto, ())?;
    let (kahe_config, ahe_config) = create_shell_configs(&config)?;
    let kahe_config_string = format!("{:#?}", kahe_config);
    let ahe_config_string = format!("{:#?}", ahe_config);
    let result =
        format!("ShellKaheConfig: {}\nShellAheConfig: {}", kahe_config_string, ahe_config_string);
    Ok(result.into_bytes())
}

/// SAFETY: `out` must not be null.
unsafe fn create_human_readable_shell_config(
    aggregation_config_proto: UniquePtr<CxxString>,
    out: *mut Vec<u8>,
) -> ffi::FfiStatus {
    create_human_readable_shell_config_impl(aggregation_config_proto)
        .map(|result| *out = result)
        .into()
}

/// Convert a rust struct `PackedVectorConfig` to the corresponding proto.
pub fn packed_vector_config_to_proto(config: &PackedVectorConfig) -> PackedVectorConfigProto {
    proto!(PackedVectorConfigProto {
        base: config.base as i64,
        dimension: config.dimension as i64,
        num_packed_coeffs: config.num_packed_coeffs as i64,
        length: config.length as i64,
    })
}

/// Convert a `PackedVectorConfigProto` to its corresponding rust struct.
pub fn packed_vector_config_from_proto(proto: PackedVectorConfigProtoView) -> PackedVectorConfig {
    PackedVectorConfig {
        base: proto.base() as u64,
        dimension: proto.dimension() as u64,
        num_packed_coeffs: proto.num_packed_coeffs() as u64,
        length: proto.length() as u64,
    }
}

/// Convert a rust struct `ShellKaheConfig` to the corresponding proto.
pub fn kahe_config_to_proto(config: &ShellKaheConfig) -> ShellKaheConfigProto {
    proto!(ShellKaheConfigProto {
        log_n: config.log_n as i64,
        moduli: config.moduli.clone().into_iter(),
        log_t: config.log_t as i64,
        num_public_polynomials: config.num_public_polynomials as i64,
        packed_vectors: config
            .packed_vector_configs
            .iter()
            .map(|(id, packed_vector_config)| {
                (ProtoStr::from_str(&id), packed_vector_config_to_proto(&packed_vector_config))
            })
            .collect::<Vec<_>>()
            .into_iter(),
    })
}

/// Convert a `ShellKaheConfigProto` to the corresponding rust struct.
pub fn kahe_config_from_proto(
    proto: ShellKaheConfigProtoView,
) -> Result<ShellKaheConfig, status::StatusError> {
    Ok(ShellKaheConfig {
        log_n: proto.log_n() as usize,
        moduli: proto.moduli().iter().collect(),
        log_t: proto.log_t() as usize,
        num_public_polynomials: proto.num_public_polynomials() as usize,
        packed_vector_configs: proto
            .packed_vectors()
            .iter()
            .map(|(id, packed_vector_config)| {
                if let Ok(id_str) = id.to_str() {
                    Ok((id_str.to_string(), packed_vector_config_from_proto(packed_vector_config)))
                } else {
                    Err(status::invalid_argument("invalid id in `packed_vectors`."))
                }
            })
            .collect::<Result<BTreeMap<String, PackedVectorConfig>, _>>()?,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use googletest::prelude::*;

    #[gtest]
    fn test_packed_vector_config_proto_roundtrip() -> googletest::Result<()> {
        let config = PackedVectorConfig {
            base: 8u64,
            dimension: 2u64,
            num_packed_coeffs: 1024u64,
            length: 2048u64,
        };
        let proto = packed_vector_config_to_proto(&config);
        let config_from_proto = packed_vector_config_from_proto(proto.as_view());
        verify_eq!(config_from_proto, config)
    }

    #[gtest]
    fn test_kahe_config_proto_roundtrip() -> googletest::Result<()> {
        let config = ShellKaheConfig {
            log_n: 10usize,
            moduli: vec![65537u64, 12289u64],
            log_t: 5usize,
            num_public_polynomials: 2usize,
            packed_vector_configs: BTreeMap::from([
                (
                    String::from("vector0"),
                    PackedVectorConfig {
                        base: 16u64,
                        dimension: 8u64,
                        num_packed_coeffs: 1024u64,
                        length: 8192u64,
                    },
                ),
                (
                    String::from("vector1"),
                    PackedVectorConfig {
                        base: 65536u64,
                        dimension: 1u64,
                        num_packed_coeffs: 16u64,
                        length: 16u64,
                    },
                ),
            ]),
        };
        let proto = kahe_config_to_proto(&config);
        let config_from_proto = kahe_config_from_proto(proto.as_view())?;
        verify_eq!(config_from_proto, config)
    }
}
