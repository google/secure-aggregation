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

//! Rust wrapper around the simplified C++ API for Key Additive Homomorphic
//! Encryption.

use shell_types::{Moduli, RnsContextRef, RnsPolynomial, RnsPolynomialVec};
use single_thread_hkdf::{SeedWrapper, SingleThreadHkdfWrapper};
use status::rust_status_from_cpp;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::mem::MaybeUninit;

#[derive(Debug, PartialEq, Clone)]
pub struct PackedVectorConfig {
    pub base: u64,
    pub dimension: u64,
    pub num_packed_coeffs: u64,
}

#[cxx::bridge]
mod ffi {
    /// Owned KahePublicParameters behind a unique_ptr.
    pub struct KahePublicParametersWrapper {
        pub ptr: UniquePtr<KahePublicParameters>,
    }

    pub struct BigIntVectorWrapper {
        pub ptr: UniquePtr<CxxVector<BigInteger>>,
    }

    unsafe extern "C++" {
        include!("shell_wrapper/kahe.h");
        include!("shell_wrapper/shell_types.h");

        #[namespace = "secure_aggregation"]
        type KahePublicParameters;

        #[namespace = "secure_aggregation"]
        type BigInteger;

        type FfiStatus = shell_types::ffi::FfiStatus;
        type ModuliWrapper = shell_types::ffi::ModuliWrapper;
        #[namespace = "secure_aggregation"]
        type RnsContext = shell_types::ffi::RnsContext;
        type RnsPolynomialWrapper = shell_types::ffi::RnsPolynomialWrapper;
        type RnsPolynomialVecWrapper = shell_types::ffi::RnsPolynomialVecWrapper;
        type SingleThreadHkdfWrapper = single_thread_hkdf::SingleThreadHkdfWrapper;

        pub unsafe fn CreateKahePublicParametersWrapper(
            log_n: u64,
            log_t: u64,
            qs: &[u64],
            num_public_polynomials: u64,
            seed: &[u8],
            out: *mut KahePublicParametersWrapper,
        ) -> FfiStatus;

        pub unsafe fn CreateModuliWrapperFromKaheParams(
            params: &KahePublicParametersWrapper,
        ) -> ModuliWrapper;

        pub unsafe fn GetRnsContextFromKaheParams(
            params: &KahePublicParametersWrapper,
        ) -> *const RnsContext;

        pub unsafe fn GenerateSecretKeyWrapper(
            params: &KahePublicParametersWrapper,
            prng: *mut SingleThreadHkdfWrapper,
            out: *mut RnsPolynomialWrapper,
        ) -> FfiStatus;

        pub unsafe fn PackMessagesRaw(
            messages: &[u64],
            packing_base: u64,
            packing_dimension: u64,
            num_packed_values: u64,
            packed_values: *mut BigIntVectorWrapper,
        ) -> FfiStatus;

        pub unsafe fn UnpackMessagesRaw(
            packing_base: u64,
            packing_dimension: u64,
            num_packed_values: u64,
            packed_values: &mut BigIntVectorWrapper,
            out: &mut Vec<u64>,
        ) -> FfiStatus;

        pub unsafe fn Encrypt(
            packed_values: &BigIntVectorWrapper,
            secret_key: &RnsPolynomialWrapper,
            params: &KahePublicParametersWrapper,
            prng: *mut SingleThreadHkdfWrapper,
            out: *mut RnsPolynomialVecWrapper,
        ) -> FfiStatus;

        pub unsafe fn Decrypt(
            ciphertexts: &RnsPolynomialVecWrapper,
            secret_key: &RnsPolynomialWrapper,
            params: &KahePublicParametersWrapper,
            output_values: *mut BigIntVectorWrapper,
        ) -> FfiStatus;
    }
}
pub use ffi::KahePublicParametersWrapper;

/// Creates new public parameters for KAHE. `num_public_polynomials` is the
/// number of public "a" polynomials to generate from the public `seed`. Each
/// call to `encrypt` using the same secret key must use a different public
/// polynomial. `log_t` is the number of bits of the KAHE plaintext modulus (q1
/// from [Willow](https://eprint.iacr.org/2024/936.pdf)).
pub fn create_public_parameters(
    log_n: u64,
    log_t: u64,
    qs: &[u64],
    num_public_polynomials: usize,
    seed: &SeedWrapper,
) -> Result<KahePublicParametersWrapper, status::StatusError> {
    let mut out = MaybeUninit::<KahePublicParametersWrapper>::zeroed();
    // SAFETY: No lifetime constraints (the new `PublicParametersWrapper` does not
    // keep any reference to the seed). Only reads the `qs` buffer within a valid
    // range.
    rust_status_from_cpp(unsafe {
        ffi::CreateKahePublicParametersWrapper(
            log_n,
            log_t,
            qs,
            num_public_polynomials as u64,
            seed.as_bytes(),
            out.as_mut_ptr(),
        )
    })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

/// Returns RNS moduli, containing pointers to the moduli in the public
/// parameters.
pub fn get_moduli<'a>(params: &'a KahePublicParametersWrapper) -> Moduli<'a> {
    // SAFETY: `moduli` contains raw pointers to the moduli in `params`, but the bindings
    // don't know that, so we add a lifetime annotation with PhantomData. After
    // that, both `params` and `moduli` live for at least `'a`.
    let moduli = unsafe { ffi::CreateModuliWrapperFromKaheParams(params) };
    Moduli { moduli, phantom: PhantomData }
}

/// Returns an RnsContextRef, containing a pointer to the RNS context in the
/// public parameters.
pub fn get_rns_context_ref<'a>(params: &'a KahePublicParametersWrapper) -> RnsContextRef<'a> {
    // SAFETY: `rns_context` contains a raw pointer to the RNS context in
    // `params`, but the bindings don't know that, so we add a lifetime annotation
    // with PhantomData. After that, both `params` and `rns_context` live for at
    // least `
    let rns_context = unsafe { ffi::GetRnsContextFromKaheParams(params) };
    RnsContextRef { rns_context, phantom: PhantomData }
}

/// Generates a BGV secret key.
pub fn generate_secret_key(
    params: &KahePublicParametersWrapper,
    prng: &mut SingleThreadHkdfWrapper,
) -> Result<RnsPolynomial, status::StatusError> {
    let mut out = MaybeUninit::<RnsPolynomial>::zeroed();
    // SAFETY: `out` pointer is valid, no references to `params` or `prng` are kept.
    rust_status_from_cpp(unsafe { ffi::GenerateSecretKeyWrapper(params, prng, out.as_mut_ptr()) })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

pub use ffi::BigIntVectorWrapper;

/// Encrypts the vectors stored in `input_vectors` using `secret_key` and the public polynomials
/// stored in `params`. The input vectors are packed according to the given `packed_vector_configs`.
/// Returns the resulting ciphertexts.
pub fn encrypt(
    input_vectors: &HashMap<String, Vec<u64>>,
    packed_vector_configs: &HashMap<String, PackedVectorConfig>,
    secret_key: &RnsPolynomial,
    params: &KahePublicParametersWrapper,
    prng: &mut SingleThreadHkdfWrapper,
) -> Result<RnsPolynomialVec, status::StatusError> {
    let mut packed_values = MaybeUninit::<BigIntVectorWrapper>::zeroed();
    // SAFETY: No lifetime constraints (`PackMessagesRaw` may create a new vector of BigIntegers
    // wrapped by `packed_values` which does not keep any reference to the inputs).
    // `PackMessagesRaw` only appends to the C++ vector wrapped by `packed_values`,
    // allocating it in case it is NULL (in the first iteration).
    for (id, packed_vector_config) in packed_vector_configs.iter() {
        if !input_vectors.contains_key(id) {
            return Err(status::invalid_argument(format!("Input vector with id {} not found", id)));
        }
        rust_status_from_cpp(unsafe {
            ffi::PackMessagesRaw(
                &input_vectors[id],
                packed_vector_config.base,
                packed_vector_config.dimension,
                packed_vector_config.num_packed_coeffs,
                packed_values.as_mut_ptr(),
            )
        })?;
    }

    let mut out = MaybeUninit::<RnsPolynomialVec>::zeroed();
    // SAFETY: No lifetime constraints (`Encrypt` creates a new vector of polynomials wrapped by
    // `out` which does not keep any reference to the inputs). `Encrypt` reads the C++ vector
    // wrapped by `packed_values`, updates the states wrapped by `prng`, and writes into the C++
    // vector wrapped by `out`.
    rust_status_from_cpp(unsafe {
        ffi::Encrypt(&packed_values.assume_init(), secret_key, params, prng, out.as_mut_ptr())
    })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

/// Decrypts ciphertexts that were encrypted with `secret_key` and the public polynomials stored
/// in `params`. Returns the unpacked decrypted values.
/// The decrypted values are unpacked according to the given `packed_vector_configs`.
pub fn decrypt(
    ciphertext: &RnsPolynomialVec,
    secret_key: &RnsPolynomial,
    params: &KahePublicParametersWrapper,
    packed_vector_configs: &HashMap<String, PackedVectorConfig>,
) -> Result<HashMap<String, Vec<u64>>, status::StatusError> {
    let mut packed_values = MaybeUninit::<BigIntVectorWrapper>::zeroed();
    // SAFETY: No lifetime constraints (`packed_values` does not keep any reference to the inputs).
    // `Decrypt` creates a new C++ vector wrapped by `output_values` and only modifies this buffer.
    rust_status_from_cpp(unsafe {
        ffi::Decrypt(ciphertext, secret_key, params, packed_values.as_mut_ptr())
    })?;

    let mut output_vectors = HashMap::<String, Vec<u64>>::new();
    // Assume the packed values are stored in the same order as the configs.
    for (id, packed_vector_config) in packed_vector_configs.iter() {
        let unpacked_size =
            (packed_vector_config.num_packed_coeffs * packed_vector_config.dimension) as usize;
        let mut unpacked_values = Vec::with_capacity(unpacked_size);
        /// SAFETY: No lifetime constraints (output values of `UnpackMessagesRaw` do not keep any
        /// reference to its inputs). `UnpackMessagesRaw` reads and removes a prefix of the C++
        /// vector wrapped by `packed_values`, and writes into the buffer `out`.
        rust_status_from_cpp(unsafe {
            ffi::UnpackMessagesRaw(
                packed_vector_config.base,
                packed_vector_config.dimension,
                packed_vector_config.num_packed_coeffs,
                packed_values.assume_init_mut(),
                &mut unpacked_values,
            )
        })?;
        output_vectors.insert(id.clone(), unpacked_values);
    }

    Ok(output_vectors)
}
