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

use status::Status;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ops::Deref;

#[cxx::bridge]
pub mod ffi {
    /// Owned RnsPolynomial behind a unique_ptr.
    pub struct RnsPolynomialWrapper {
        ptr: UniquePtr<RnsPolynomial>,
    }

    pub struct RnsPolynomialVecWrapper {
        ptr: UniquePtr<CxxVector<RnsPolynomial>>,
    }

    /// Stores a span of pointers to the prime moduli, for polynomial operations. The
    /// pointers are backed by a AhePublicParameters or KahePublicParameters struct.
    #[derive(Copy, Clone)]
    struct ModuliWrapper {
        moduli: *const *const PrimeModulus,
        len: usize,
    }

    unsafe extern "C++" {
        type FfiStatus = status::ffi::FfiStatus;
        include!("shell_wrapper/shell_types.h");
        include!("shell_wrapper/shell_aliases.h");
        #[namespace = "secure_aggregation"]
        type RnsPolynomial;
        #[namespace = "secure_aggregation"]
        type RnsContext;

        #[namespace = "secure_aggregation"]
        type PrimeModulus;

        pub fn CreateEmptyRnsPolynomialWrapper() -> RnsPolynomialWrapper;

        pub unsafe fn WriteSmallRnsPolynomialToBuffer(
            poly: *const RnsPolynomialWrapper,
            moduli: ModuliWrapper,
            buffer_len: u64,
            buffer: *mut i64,
            n_written: *mut u64,
        ) -> FfiStatus;

        pub unsafe fn ReadSmallRnsPolynomialFromBuffer(
            buffer: *const i64,
            buffer_len: u64,
            log_n: u64,
            moduli: ModuliWrapper,
            out: *mut RnsPolynomialWrapper,
        ) -> FfiStatus;

        pub unsafe fn AddInPlace(
            moduli: ModuliWrapper,
            in_: *const RnsPolynomialWrapper,
            out: *mut RnsPolynomialWrapper,
        ) -> FfiStatus;

        pub unsafe fn AddInPlaceVec(
            moduli: ModuliWrapper,
            in_: *const RnsPolynomialVecWrapper,
            out: *mut RnsPolynomialVecWrapper,
        ) -> FfiStatus;

        pub unsafe fn WriteRnsPolynomialToBuffer128(
            rns_context: *const RnsContext,
            poly: *const RnsPolynomialWrapper,
            buffer_len: usize,
            buffer: *mut u64,
        ) -> FfiStatus;

        pub unsafe fn CloneRnsPolynomialWrapper(
            poly: *const RnsPolynomialWrapper,
        ) -> RnsPolynomialWrapper;

        pub unsafe fn CloneRnsPolynomialVecWrapper(
            poly: *const RnsPolynomialVecWrapper,
        ) -> RnsPolynomialVecWrapper;

        pub fn RustVecToRnsPolynomialVecWrapper(
            v: Vec<RnsPolynomialWrapper>,
        ) -> RnsPolynomialVecWrapper;

        pub fn CloneString(x: &CxxString) -> UniquePtr<CxxString>;
        pub fn EmptyString() -> &'static CxxString;

    }
}

pub use ffi::ModuliWrapper;
use status::rust_status_from_cpp;

/// Re-export CXX bindings, and implement Clone for them.
pub use ffi::RnsPolynomialVecWrapper as RnsPolynomialVec;

impl Deref for RnsPolynomialVec {
    type Target = cxx::Vector<ffi::RnsPolynomial>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: No lifetime constraints. self->ptr is guaranteed to be non-null.
        &self.ptr.deref()
    }
}

impl Clone for RnsPolynomialVec {
    fn clone(&self) -> Self {
        // SAFETY: No lifetime constraints. self->ptr is guaranteed to be non-null.
        unsafe { ffi::CloneRnsPolynomialVecWrapper(self) }
    }
}

pub use ffi::RnsPolynomialWrapper as RnsPolynomial;

impl Deref for RnsPolynomial {
    type Target = ffi::RnsPolynomial;

    fn deref(&self) -> &Self::Target {
        // SAFETY: self.ptr is guaranteed to be non-null in all safe Rust code.
        self.ptr.deref()
    }
}

impl Clone for RnsPolynomial {
    fn clone(&self) -> Self {
        // SAFETY: No lifetime constraints. self->ptr is guaranteed to be non-null.
        unsafe { ffi::CloneRnsPolynomialWrapper(self) }
    }
}

pub use ffi::CreateEmptyRnsPolynomialWrapper as create_empty_rns_polynomial;

/// Store some raw pointers to the prime moduli. The bindings don't know that
/// ModuliWrapper actually has a lifetime, so we add it manually with
/// PhantomData.
pub struct Moduli<'a> {
    pub moduli: ModuliWrapper, // Only valid for the lifetime of the Ahe or Kahe parameters.
    pub phantom: PhantomData<&'a ()>,
}

/// Represents a borrowed reference to an RnsContext. Used for polynomial
/// operations. The bindings don't know that RnsContext actually has a
/// lifetime, so we add it manually with PhantomData.
pub struct RnsContextRef<'a> {
    pub rns_context: *const ffi::RnsContext, /* Only valid for the lifetime of the Ahe or Kahe
                                              * parameters. */
    pub phantom: PhantomData<&'a ()>,
}

///  Converts slices into C++-safe pointer and length pairs.
pub fn to_cpp_pointer_len_pair<T>(s: &[T]) -> (*const T, usize) {
    if s.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (s.as_ptr(), s.len())
    }
}

/// Converts slices into C++-safe mutable pointer and length pairs.
pub fn to_cpp_pointer_len_pair_mut<T>(s: &mut [T]) -> (*mut T, usize) {
    if s.is_empty() {
        (std::ptr::null_mut(), 0)
    } else {
        (s.as_mut_ptr(), s.len())
    }
}

/// Takes prime moduli {q_i}, and the RNS representation `poly` of a "small"
/// polynomial in Z[X] where each coefficient c \in Z verifies |c| < q_i/2 for
/// all q_i. Fills in the buffer with the signed integer coefficients of `poly`.
/// Accepts `poly` in both coefficient form and NTT form (by internally
/// converting to coefficient form if needed). Returns the number of buffer
/// elements written if successful, and a StatusError otherwise.
pub fn write_small_rns_polynomial_to_buffer(
    poly: &RnsPolynomial,
    moduli: &Moduli,
    buffer: &mut [i64],
) -> Result<usize, status::StatusError> {
    let mut n_written: u64 = 0;
    // SAFETY: No lifetime constraints. Writes to `buffer` within a valid range.
    rust_status_from_cpp(unsafe {
        ffi::WriteSmallRnsPolynomialToBuffer(
            poly,
            moduli.moduli,
            buffer.len() as u64,
            buffer.as_mut_ptr(),
            &mut n_written,
        )
    })?;
    Ok(n_written as usize)
}

/// Takes prime moduli {q_i}, and a buffer of `buffer_len` signed integers,
/// representing the coefficients of a "small" polynomial in Z[X] where each
/// coefficient c \in Z verifies |c| < q_i/2 for all q_i. Returns a
/// RnsPolynomialWrapper containing the polynomial in RNS coefficient form if
/// successful, and a StatusError otherwise.
pub fn read_small_rns_polynomial_from_buffer(
    buffer: &[i64],
    log_n: u64,
    moduli: &Moduli,
) -> Result<RnsPolynomial, status::StatusError> {
    let mut out = MaybeUninit::<RnsPolynomial>::zeroed();
    // SAFETY: No lifetime constraints (the resulting `RnsPolynomial` does not keep
    // any references). Reads from `buffer` within a valid range. `out` is safely
    // initialized if `status` is OK.
    rust_status_from_cpp(unsafe {
        ffi::ReadSmallRnsPolynomialFromBuffer(
            buffer.as_ptr(),
            buffer.len() as u64,
            log_n,
            moduli.moduli,
            out.as_mut_ptr(),
        )
    })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

/// Adds the polynomial `in` to `out` in-place, using the RNS `moduli`. Returns
/// () if successful, and a StatusError otherwise.
pub fn add_in_place(
    moduli: &Moduli,
    in_polynomial: &RnsPolynomial,
    out_polynomial: &mut RnsPolynomial,
) -> Status {
    // SAFETY: No lifetime constraints (`AddInPlace` copies the contents of
    // `in_polynomial` and adds them into `out_polynomial`).
    rust_status_from_cpp(unsafe { ffi::AddInPlace(moduli.moduli, in_polynomial, out_polynomial) })
}

// Adds the vector of polynomials `in` to `out` in-place element-wise, using the
// RNS `moduli`. Does not failatomically: if the result is not Ok, the value of
// `out` is undefined.
pub fn add_in_place_vec(
    moduli: &Moduli,
    in_polynomial_vec: &RnsPolynomialVec,
    out_polynomial_vec: &mut RnsPolynomialVec,
) -> Status {
    // SAFETY: No lifetime constraints (`AddInPlaceVec` copies the contents of
    // `in_polynomial_vec` and adds them into `out_polynomial_vec`).
    rust_status_from_cpp(unsafe {
        ffi::AddInPlaceVec(moduli.moduli, in_polynomial_vec, out_polynomial_vec)
    })
}

/// Converts the given RnsPolynomial `poly` to coefficient form, interpolating
/// the coefficients to a single modulus using CRT interpolation. Writes the
/// resulting coefficient vector to `buffer`, using two consecutive uint64_t
/// words for every coefficient, with the lower half being written first.
/// Returns an error if any pointer arguments are null, if any coefficient
/// exceeds 128 bits, or if the buffer length is not equal to
/// `2*poly->ptr->NumCoeffs()`.
pub fn write_rns_polynomial_to_buffer_128(
    rns_context: &RnsContextRef,
    in_polynomial: &RnsPolynomial,
    output_buffer: &mut [u64],
) -> status::Status {
    let (out_ptr, out_len) = to_cpp_pointer_len_pair_mut(output_buffer);
    // SAFETY: No lifetime constraints. The number of elements written is checked
    // inside the C++ function.
    rust_status_from_cpp(unsafe {
        ffi::WriteRnsPolynomialToBuffer128(rns_context.rns_context, in_polynomial, out_len, out_ptr)
    })?;
    Ok(())
}
