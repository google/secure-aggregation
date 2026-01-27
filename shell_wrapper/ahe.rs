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

//! Rust wrapper around the simplified C++ API for multiparty asymmetric
//! Additive Homomorphic Encryption (AHE).

use shell_types::{
    to_cpp_pointer_len_pair, to_cpp_pointer_len_pair_mut, Moduli, RnsContextRef, RnsPolynomial,
};
use single_thread_hkdf::{SeedWrapper, SingleThreadHkdfWrapper};
use status::rust_status_from_cpp;
use std::marker::PhantomData;
use std::mem::MaybeUninit;

#[cxx::bridge(namespace = "secure_aggregation")]
mod ffi {
    // Struct containing AHE public parameters, accessible from Rust and C++.
    struct AhePublicParameters {
        rlwe_public_parameter: UniquePtr<ConstModularIntPublicParameter>,
        rns_context: UniquePtr<ConstRnsContext>,
        encoder: UniquePtr<ConstModularIntCoefficientEncoder>,
        error_params: UniquePtr<ConstModularIntRnsErrorParams>,
        dg_sampler_flood: UniquePtr<IntegerDiscreteGaussianSampler>,
        s_flood: f64,
    }

    unsafe extern "C++" {

        include!("shell_wrapper/shell_types.h");
        include!("shell_wrapper/single_thread_hkdf.h");
        include!("shell_wrapper/ahe_aliases.h");
        include!("shell_wrapper/shell_aliases.h");
        include!("shell_wrapper/ahe.h");

        type FfiStatus = status::ffi::FfiStatus;
        type ModuliWrapper = shell_types::ffi::ModuliWrapper;
        type RnsPolynomialWrapper = shell_types::ffi::RnsPolynomialWrapper;
        type SingleThreadHkdfWrapper = single_thread_hkdf::SingleThreadHkdfWrapper;
        type ConstModularIntPublicParameter;
        type ConstModularIntCoefficientEncoder;
        type ConstModularIntRnsErrorParams;
        type IntegerDiscreteGaussianSampler;
        type ConstRnsContext;
        type RnsContext = shell_types::ffi::RnsContext;
        type ModularInt;

        pub unsafe fn CreateAhePublicParameters(
            log_n: u64,
            t: u64,
            qs: *const u64,
            num_qs: usize,
            error_variance: u64,
            s_base_flood: f64,
            s_flood: f64,
            seed: &[u8],
            out: *mut AhePublicParameters,
        ) -> FfiStatus;

        pub unsafe fn CreateModuliWrapperFromAheParams(
            params: &AhePublicParameters,
        ) -> ModuliWrapper;

        pub unsafe fn GetPlaintextModulusFromAheParams(params: &AhePublicParameters) -> u64;

        pub unsafe fn GetRnsContextFromAheParams(params: &AhePublicParameters)
            -> *const RnsContext;

        pub unsafe fn GenerateSecretKeyShare(
            params: &AhePublicParameters,
            prng: *mut SingleThreadHkdfWrapper,
            out: *mut RnsPolynomialWrapper,
        ) -> FfiStatus;

        pub unsafe fn GeneratePublicKeyShareWrapper(
            secret_key_share: &RnsPolynomialWrapper,
            params: &AhePublicParameters,
            prng: *mut SingleThreadHkdfWrapper,
            public_key_share_b: *mut RnsPolynomialWrapper,
            public_key_share_error: *mut RnsPolynomialWrapper,
            wraparound: *mut RnsPolynomialWrapper,
        ) -> FfiStatus;

        pub unsafe fn AheEncrypt(
            input_values: *const u64,
            num_input_values: usize,
            public_key_b: &RnsPolynomialWrapper,
            params: &AhePublicParameters,
            prng: *mut SingleThreadHkdfWrapper,
            ciphertext_component_b: *mut RnsPolynomialWrapper,
            ciphertext_component_a: *mut RnsPolynomialWrapper,
            ciphertext_secret_r: *mut RnsPolynomialWrapper,
            ciphertext_error_e: *mut RnsPolynomialWrapper,
            wraparound: *mut RnsPolynomialWrapper,
        ) -> FfiStatus;

        pub unsafe fn PartialDecrypt(
            ciphertext_component_a: &RnsPolynomialWrapper,
            secret_key_share: &RnsPolynomialWrapper,
            params: &AhePublicParameters,
            prng: *mut SingleThreadHkdfWrapper,
            out: *mut RnsPolynomialWrapper,
            error_flood: *mut RnsPolynomialWrapper,
            wraparound: *mut RnsPolynomialWrapper,
        ) -> FfiStatus;

        pub unsafe fn RecoverMessages(
            sum_partial_decryptions: &RnsPolynomialWrapper,
            ciphertext_component_b: &RnsPolynomialWrapper,
            params: &AhePublicParameters,
            num_output_values: usize,
            output_values: *mut u64,
            n_written: *mut usize,
        ) -> FfiStatus;

        pub unsafe fn CreateZeroRnsPolynomialWrapper(
            params: &AhePublicParameters,
            out: *mut RnsPolynomialWrapper,
        ) -> FfiStatus;

        pub unsafe fn PublicKeyComponentA(
            params: &AhePublicParameters,
            out: *mut RnsPolynomialWrapper,
        ) -> FfiStatus;

        pub unsafe fn SFlood(params: &AhePublicParameters, out: *mut f64) -> FfiStatus;
    }
}

/// Re-export bindings. This wrapper holds a status code and
/// unique pointers to AHE parameters, defined in `ahe.h`.
pub use ffi::AhePublicParameters;

/// Creates new public parameters for AHE.
pub fn create_public_parameters(
    log_n: u64,
    t: u64,
    qs: &[u64],
    error_variance: u64,
    s_base_flood: f64,
    s_flood: f64,
    seed: &SeedWrapper,
) -> Result<AhePublicParameters, status::StatusError> {
    let mut out = MaybeUninit::<AhePublicParameters>::zeroed();
    let (in_ptr, in_len) = to_cpp_pointer_len_pair(qs);
    // SAFETY: No lifetime constraints (the new `AhePublicParameters` does
    // not keep any reference to the seed). Only reads the `qs` buffer within a
    // valid range.
    rust_status_from_cpp(unsafe {
        ffi::CreateAhePublicParameters(
            log_n,
            t,
            in_ptr,
            in_len,
            error_variance,
            s_base_flood,
            s_flood,
            seed.as_bytes().into(),
            out.as_mut_ptr(),
        )
    })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

/// Returns RNS moduli, containing pointers to the moduli in the public
/// parameters.
pub fn get_moduli<'a>(params: &'a AhePublicParameters) -> Moduli<'a> {
    // SAFETY: `moduli` contains raw pointers to the moduli in `params`, but the bindings
    // don't know that, so we add a lifetime annotation with PhantomData. After
    // that, both `params` and `moduli` live for at least `'a`.
    let moduli = unsafe { ffi::CreateModuliWrapperFromAheParams(params) };
    Moduli { moduli: moduli, phantom: PhantomData }
}

/// Returns the plaintext modulus.
pub fn get_plaintext_modulus(params: &AhePublicParameters) -> u64 {
    unsafe { ffi::GetPlaintextModulusFromAheParams(params) }
}

/// Returns an RnsContextRef, containing a pointer to the RNS context in the
/// public parameters.
pub fn get_rns_context_ref<'a>(params: &'a AhePublicParameters) -> RnsContextRef<'a> {
    // SAFETY: `rns_context` contains a raw pointer to the RNS context in
    // `params`, but the bindings don't know that, so we add a lifetime annotation
    // with PhantomData. After that, both `params` and `rns_context` live for at
    // least `'a`.
    let rns_context = unsafe { ffi::GetRnsContextFromAheParams(params) };
    RnsContextRef { rns_context: rns_context, phantom: PhantomData }
}

/// Generates a secret key share.
pub fn generate_secret_key(
    params: &AhePublicParameters,
    prng: &mut SingleThreadHkdfWrapper,
) -> Result<RnsPolynomial, status::StatusError> {
    let mut out = MaybeUninit::<RnsPolynomial>::zeroed();
    // SAFETY: No lifetime constraints (the new `RnsPolynomial` is obtained by
    // reading data from `params` and using fresh randomness generated by
    // `prng`).
    rust_status_from_cpp(unsafe { ffi::GenerateSecretKeyShare(params, prng, out.as_mut_ptr()) })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

/// Generates a public key share in `public_key_share_b`, and stores the error
/// in `public_key_share_error` (for ZK proofs). Returns an absl status code.
pub fn generate_public_key_share(
    secret_key_share: &RnsPolynomial,
    params: &AhePublicParameters,
    prng: &mut SingleThreadHkdfWrapper,
    public_key_share_b: &mut RnsPolynomial,
    public_key_share_error: &mut RnsPolynomial,
    wraparound_option: Option<&mut RnsPolynomial>,
) -> status::Status {
    let wraparound_ptr = match wraparound_option {
        Some(wraparound_ref) => wraparound_ref,
        None => std::ptr::null_mut(),
    };
    // SAFETY: `public_key_share_b` and `public_key_share_error` are non null, and
    // receive valid `RnsPolynomial`s. No lifetime constraints (the values
    // written in the raw pointers are obtained by reading data from `params` and
    // `secret_key_share`, and using fresh randomness generated by `prng`).
    // `wraparound_ptr` is null-checked on the C++ side and only used if available.
    rust_status_from_cpp(unsafe {
        ffi::GeneratePublicKeyShareWrapper(
            secret_key_share,
            params,
            prng,
            public_key_share_b,
            public_key_share_error,
            wraparound_ptr,
        )
    })
}

/// Encodes the input values and encrypts them using the public key
/// `public_key_b`, which is obtained by summing `public_key_shares_b` from all
/// parties. Stores the two components of the
/// ciphertext in `ciphertext_component_b` (a.k.a. ct0) and
/// `ciphertext_component_a` (a.k.a. ct1). Also stores the secret and error for
/// ZK proofs. Returns an absl status code.
pub fn ahe_encrypt(
    input_values: &[u64],
    public_key_b: &RnsPolynomial,
    params: &AhePublicParameters,
    prng: &mut SingleThreadHkdfWrapper,
    ciphertext_component_b: &mut RnsPolynomial,
    ciphertext_component_a: &mut RnsPolynomial,
    ciphertext_secret_r: &mut RnsPolynomial,
    ciphertext_error_e: &mut RnsPolynomial,
    wraparound_option: Option<&mut RnsPolynomial>,
) -> status::Status {
    let (in_ptr, in_len) = to_cpp_pointer_len_pair(input_values);
    let wraparound_ptr = match wraparound_option {
        Some(wraparound_ref) => wraparound_ref,
        None => std::ptr::null_mut(),
    };
    // SAFETY: the 4 ciphertext pointers are non null, and receive valid
    // `RnsPolynomial`s. `AheEncrypt` reads the `input_values` buffer within a valid
    // range. No lifetime constraints (the new `RnsPolynomial`s are obtained by
    // reading data from `params` and `input_Values`, and using fresh randomness
    // generated by `prng`).
    // `wraparound_ptr` is null-checked on the C++ side and only written to if available.
    rust_status_from_cpp(unsafe {
        ffi::AheEncrypt(
            in_ptr,
            in_len,
            public_key_b,
            params,
            prng,
            ciphertext_component_b,
            ciphertext_component_a,
            ciphertext_secret_r,
            ciphertext_error_e,
            wraparound_ptr,
        )
    })
}

/// Computes the partial decryption of a ciphertext component A.
pub fn partial_decrypt(
    ciphertext_component_a: &RnsPolynomial,
    secret_key_share: &RnsPolynomial,
    params: &AhePublicParameters,
    prng: &mut SingleThreadHkdfWrapper,
    error_flood_option: Option<&mut RnsPolynomial>,
    wraparound_option: Option<&mut RnsPolynomial>,
) -> Result<RnsPolynomial, status::StatusError> {
    let mut out = MaybeUninit::<RnsPolynomial>::zeroed();
    let error_flood_ptr = match error_flood_option {
        Some(error_flood_ref) => error_flood_ref,
        None => std::ptr::null_mut(),
    };
    let wraparound_ptr = match wraparound_option {
        Some(wraparound_ref) => wraparound_ref,
        None => std::ptr::null_mut(),
    };
    // SAFETY: No lifetime constraints (the new `RnsPolynomial` is obtained by
    // reading data from `params` and `ciphertext_component_a` and using fresh
    // randomness generated by `prng`).
    // `error_flood_ptr` and `wraparound_ptr` are null-checked on the C++ side and only written to
    // if available.
    rust_status_from_cpp(unsafe {
        ffi::PartialDecrypt(
            ciphertext_component_a,
            secret_key_share,
            params,
            prng,
            out.as_mut_ptr(),
            error_flood_ptr,
            wraparound_ptr,
        )
    })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

/// Recovers messages from a sum of partial decryptions.
pub fn recover_messages(
    sum_partial_decryptions: &RnsPolynomial,
    ciphertext_component_b: &RnsPolynomial,
    params: &AhePublicParameters,
    output_values: &mut [u64],
) -> Result<usize, status::StatusError> {
    let mut n_written = 0usize;
    let (out_ptr, out_len) = to_cpp_pointer_len_pair_mut(output_values);
    // SAFETY:  No lifetime constraints (`BufferResult` just holds two ints and
    // does not keep any reference to the inputs). `Decrypt` only modifies the
    // `output_values` buffer within a valid range.
    rust_status_from_cpp(unsafe {
        ffi::RecoverMessages(
            sum_partial_decryptions,
            ciphertext_component_b,
            params,
            out_len,
            out_ptr,
            &mut n_written,
        )
    })?;
    Ok(n_written)
}

/// Creates a zero polynomial with the same RNS parameters as `params`.
pub fn create_zero_rns_polynomial(
    params: &AhePublicParameters,
) -> Result<RnsPolynomial, status::StatusError> {
    let mut out = MaybeUninit::<RnsPolynomial>::zeroed();
    // SAFETY: No lifetime constraints (the new `RnsPolynomial` is obtained by
    // reading data from `params`).
    rust_status_from_cpp(unsafe { ffi::CreateZeroRnsPolynomialWrapper(params, out.as_mut_ptr()) })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

/// Returns the public key component A from the given parameters.
pub fn public_key_component_a(
    params: &AhePublicParameters,
) -> Result<RnsPolynomial, status::StatusError> {
    let mut out = MaybeUninit::<RnsPolynomial>::zeroed();
    // SAFETY: No lifetime constraints. The number of elements written is checked
    // inside the C++ function.
    rust_status_from_cpp(unsafe { ffi::PublicKeyComponentA(params, out.as_mut_ptr()) })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

pub fn s_flood(params: &AhePublicParameters) -> Result<f64, status::StatusError> {
    let mut out: f64 = 0.0;
    // SAFETY: No lifetime constraints. Only a member of type double of params is accessed on the
    // C++ side and written to `out`, and no pointers are retained on the C++ side.
    let status = unsafe { ffi::SFlood(params, &mut out) };
    rust_status_from_cpp(status)?;
    return Ok(out);
}
