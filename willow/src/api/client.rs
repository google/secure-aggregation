/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use aggregation_config::AggregationConfig;
use aggregation_config_rust_proto::AggregationConfigProto;
use ahe_shell::PublicKey;
use ahe_traits::AheBase;
use client_traits::SecureAggregationClient;
use kahe_shell::ShellKahe;
use kahe_traits::KaheBase;
use parameters_shell::create_shell_configs;
use prng_traits::SecurePrng;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use shell_ciphertexts_rust_proto::ShellAhePublicKey;
use single_thread_hkdf::SingleThreadHkdfPrng;
use status::ffi::FfiStatus;
use status::StatusError;
use std::collections::HashMap;
use vahe_shell::ShellVahe;
use willow_v1_client::WillowV1Client;

/// CXX bridge to call Rust client code from C++.
///
/// SAFETY: all functions in this module are only called from the wrapping C++ library,
///   ensuring that output pointers are correctly wrapped by a rust::Box, and that pointer arguments
///   are not null.
#[cxx::bridge(namespace = "secure_aggregation")]
pub mod ffi {
    /// One entry in the plaintext map. Obtained by taking slices of the metric names and values
    /// owned by the C++ EncodedData object (hence the lifetime).
    struct DataEntryView<'a> {
        key: &'a [u8],
        values: &'a [u64],
    }

    extern "Rust" {
        // cxx: types used as extern Rust types are required to be defined by the same crate that
        // contains the bridge using them
        type WillowShellClient;

        pub unsafe fn initialize_client(
            config: UniquePtr<CxxString>,
            out: *mut *mut WillowShellClient,
            out_status_message: *mut UniquePtr<CxxString>,
        ) -> i32;

        unsafe fn client_into_box(ptr: *mut WillowShellClient) -> Box<WillowShellClient>;

        unsafe fn generate_contribution(
            client: &mut Box<WillowShellClient>,
            data: &[DataEntryView],
            key: UniquePtr<CxxString>,
            nonce: &[u8],
            out: *mut Vec<u8>,
            out_status_message: *mut UniquePtr<CxxString>,
        ) -> i32;
    }
}

pub struct WillowShellClient(WillowV1Client<ShellKahe, ShellVahe>);

impl WillowShellClient {
    fn new_from_serialized_config(
        config: cxx::UniquePtr<cxx::CxxString>,
    ) -> Result<Self, StatusError> {
        let aggregation_config_proto =
            AggregationConfigProto::parse(config.as_bytes()).map_err(|e| {
                status::internal(format!("Failed to parse AggregationConfigProto: {}", e))
            })?;
        let aggregation_config = AggregationConfig::from_proto(aggregation_config_proto, ())?;
        let (kahe_config, ahe_config) = create_shell_configs(&aggregation_config)?;
        let context_bytes = &aggregation_config.key_id;
        let kahe = ShellKahe::new(kahe_config, &context_bytes)?;
        let vahe = ShellVahe::new(ahe_config, &context_bytes)?;
        let client = WillowV1Client::new_with_randomly_generated_seed(kahe, vahe)?;
        Ok(WillowShellClient(client))
    }

    fn generate_contribution(
        &mut self,
        data: &[ffi::DataEntryView],
        public_key: cxx::UniquePtr<cxx::CxxString>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, StatusError> {
        let mut plaintext_slice: HashMap<&str, &[u64]> = HashMap::new();
        for entry in data {
            let key = std::str::from_utf8(entry.key)
                .map_err(|e| status::internal(format!("Failed to parse key as UTF-8: {}", e)))?;
            plaintext_slice.insert(key, entry.values);
        }
        let public_key_proto = ShellAhePublicKey::parse(public_key.as_bytes())
            .map_err(|e| status::internal(format!("Failed to parse ShellAhePublicKey: {}", e)))?;
        let public_key_rust = PublicKey::from_proto(public_key_proto, &self.0.vahe)?;
        let message = self.0.create_client_message(&plaintext_slice, &public_key_rust, nonce)?;
        Ok(message
            .to_proto(&self.0)?
            .serialize()
            .map_err(|e| status::internal(format!("Failed to serialize ClientMessage: {}", e)))?)
    }
}

/// SAFETY: `out` and `out_status_message` must not be null.
unsafe fn initialize_client(
    config: cxx::UniquePtr<cxx::CxxString>,
    out: *mut *mut WillowShellClient,
    out_status_message: *mut cxx::UniquePtr<cxx::CxxString>,
) -> i32 {
    match WillowShellClient::new_from_serialized_config(config) {
        Ok(client) => {
            *out = Box::into_raw(Box::new(client));
            0
        }
        Err(status_error) => {
            let ffi_status: FfiStatus = status_error.into();
            *out_status_message = ffi_status.message;
            ffi_status.code
        }
    }
}

/// Converts a raw pointer to a Box. Ideally we would use `rust::Box::from_raw`
/// (https://cxx.rs/binding/box.html) directly from C++, but that causes linker errors.
///
/// SAFETY: `ptr` must have been created by `Box::into_raw`, as in `initialize_client`.
unsafe fn client_into_box(ptr: *mut WillowShellClient) -> Box<WillowShellClient> {
    Box::from_raw(ptr)
}

/// SAFETY: `out` and `out_status_message` must not be null.
unsafe fn generate_contribution(
    client: &mut Box<WillowShellClient>,
    data: &[ffi::DataEntryView],
    public_key: cxx::UniquePtr<cxx::CxxString>,
    nonce: &[u8],
    out: *mut Vec<u8>,
    out_status_message: *mut cxx::UniquePtr<cxx::CxxString>,
) -> i32 {
    match client.generate_contribution(data, public_key, nonce) {
        Ok(contribution) => {
            *out = contribution;
            0
        }
        Err(status_error) => {
            let ffi_status: FfiStatus = status_error.into();
            *out_status_message = ffi_status.message;
            ffi_status.code
        }
    }
}
