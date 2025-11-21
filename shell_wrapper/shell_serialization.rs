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

//! Rust wrapper for serialization support of SHELL types.

use protobuf::prelude::*;
use rns_serialization_rust_proto::SerializedRnsPolynomial;
use shell_types::{create_empty_rns_polynomial, Moduli, RnsPolynomial};
use status::{StatusError, StatusErrorCode};

#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("shell_wrapper/shell_serialization.h");
        include!("shell_wrapper/shell_types.h");

        type FfiStatus = shell_types::ffi::FfiStatus;
        type ModuliWrapper = shell_types::ffi::ModuliWrapper;
        type RnsPolynomialWrapper = shell_types::ffi::RnsPolynomialWrapper;

        pub unsafe fn SerializeRnsPolynomialToBytes(
            poly: *const RnsPolynomialWrapper,
            moduli: ModuliWrapper,
            out: &mut UniquePtr<CxxString>,
        ) -> FfiStatus;

        pub unsafe fn DeserializeRnsPolynomialFromBytes(
            serialized_poly: &[u8],
            moduli: ModuliWrapper,
            out: *mut RnsPolynomialWrapper,
        ) -> FfiStatus;

    }
}

use status::rust_status_from_cpp;

// Serialize a RnsPolynomial to a SerializedRnsPolynomial proto.
pub fn rns_polynomial_to_proto(
    poly: &RnsPolynomial,
    moduli: &Moduli,
) -> Result<SerializedRnsPolynomial, status::StatusError> {
    let mut out = cxx::UniquePtr::null();
    // SAFETY: No lifetime constraints (no references are kept by the C++ function).
    // `SerializeRnsPolynomialToBytes` allocates a C++ string to write the proto bytes to, and assigns
    // the string to `out`.
    rust_status_from_cpp(unsafe {
        ffi::SerializeRnsPolynomialToBytes(poly, moduli.moduli, &mut out)
    })?;
    SerializedRnsPolynomial::parse(out.as_bytes()).map_err(|parse_error| {
        StatusError::new_with_current_location(
            StatusErrorCode::Internal,
            format!("{parse_error:?}"),
        )
    })
}

// Deserialize a SerializedRnsPolynomial proto to a RnsPolynomial.
pub fn rns_polynomial_from_proto(
    serialized: SerializedRnsPolynomial,
    moduli: &Moduli,
) -> Result<RnsPolynomial, status::StatusError> {
    let serialized_bytes = serialized.serialize().map_err(|serialize_error| {
        StatusError::new_with_current_location(
            StatusErrorCode::Internal,
            format!("{serialize_error:?}"),
        )
    })?;

    // SAFETY: No lifetime constraints (`create_empty_rns_polynomial` creates and returns an empty
    // C++ object).
    let mut poly = unsafe { create_empty_rns_polynomial() };

    // SAFETY: No lifetime constraints (no references are kept by the C++ function).
    // `DeserializeRnsPolynomialFromBytes` allocates a C++ RnsPolynomial object and assigns it to `poly`.
    rust_status_from_cpp(unsafe {
        ffi::DeserializeRnsPolynomialFromBytes(&serialized_bytes, moduli.moduli, &mut poly)
    })?;
    Ok(poly)
}
