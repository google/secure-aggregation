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

//! Rust wrapper around https://github.com/google/shell-encryption/blob/master/shell_encryption/prng/single_thread_hkdf_prng.h

use status::rust_status_from_cpp;

#[cxx::bridge(namespace = "secure_aggregation")]
mod ffi {
    struct SingleThreadHkdfWrapper {
        ptr: UniquePtr<SingleThreadHkdfPrng>,
    }

    unsafe extern "C++" {
        type FfiStatus = status::ffi::FfiStatus;

        include!("shell_encryption/prng/single_thread_hkdf_prng.h");
        #[namespace = "rlwe"]
        type SingleThreadHkdfPrng;

        include!("shell_wrapper/single_thread_hkdf.h");
        pub fn GenerateSingleThreadHkdfSeed(out: &mut UniquePtr<CxxString>) -> FfiStatus;
        pub fn CreateSingleThreadHkdf(seed: &[u8], out: &mut SingleThreadHkdfWrapper) -> FfiStatus;
        pub fn Rand8(prng: &mut SingleThreadHkdfWrapper, out: &mut u8) -> FfiStatus;

        pub fn SingleThreadHkdfSeedLength() -> usize;

        pub fn ComputeHkdfWrapper(
            input: &[u8],
            salt: &[u8],
            info: &[u8],
            out_len: usize,
            out: &mut UniquePtr<CxxString>,
        ) -> FfiStatus;

        include!("ffi_utils/cxx_utils.h");
        pub fn CloneString(x: &CxxString) -> UniquePtr<CxxString>;

        pub fn EmptyString() -> &'static CxxString;

    }
}

/// Contains a pointer to a PRNG. Re-exported from cxx.
pub use ffi::SingleThreadHkdfWrapper;

/// Contains a pointer to a C++ string.
pub struct SeedWrapper(cxx::UniquePtr<cxx::CxxString>);
impl Clone for SeedWrapper {
    fn clone(&self) -> Self {
        if self.0.is_null() {
            Self(cxx::UniquePtr::null())
        } else {
            Self(ffi::CloneString(&self.0))
        }
    }
}

impl std::ops::Deref for SeedWrapper {
    type Target = cxx::CxxString;
    fn deref(&self) -> &cxx::CxxString {
        if self.0.is_null() {
            ffi::EmptyString()
        } else {
            &self.0
        }
    }
}

pub use ffi::SingleThreadHkdfSeedLength as seed_length;

/// Generates a valid seed for the Prng.
///
/// Fails on internal cryptographic errors.
pub fn generate_seed() -> Result<SeedWrapper, status::StatusError> {
    let mut out = cxx::UniquePtr::null();
    rust_status_from_cpp(ffi::GenerateSingleThreadHkdfSeed(&mut out))?;
    Ok(SeedWrapper(out))
}

/// Constructs a new PRNG from a seed. See
/// https://github.com/google/shell-encryption/blob/master/shell_encryption/prng/single_thread_hkdf_prng.h
///
/// Fails if the key is not the expected size or on internal cryptographic
/// errors.
pub fn create(seed: &SeedWrapper) -> Result<SingleThreadHkdfWrapper, status::StatusError> {
    let mut out = ffi::SingleThreadHkdfWrapper { ptr: cxx::UniquePtr::null() };
    rust_status_from_cpp(ffi::CreateSingleThreadHkdf(seed.as_bytes(), &mut out))?;
    Ok(out)
}

/// Returns a random byte.
///
/// Fails on internal cryptographic errors.
pub fn rand8(prng: &mut SingleThreadHkdfWrapper) -> Result<u8, status::StatusError> {
    // SAFETY: Rand8 advances the state of the C++ PRNG contained in `prng`, and
    // returns one u8 that does not keep any references). No lifetime constraints.
    let mut out: u8 = 0;
    rust_status_from_cpp(ffi::Rand8(prng, &mut out))?;
    Ok(out)
}

pub fn compute_hkdf(
    input: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<SeedWrapper, status::StatusError> {
    let mut out = cxx::UniquePtr::null();
    let status = ffi::ComputeHkdfWrapper(input.into(), salt.into(), info.into(), out_len, &mut out);
    rust_status_from_cpp(status)?;
    Ok(SeedWrapper(out))
}

#[cfg(test)]
mod test {
    use googletest::prelude::*;

    #[gtest]
    fn test_empty_seed_deref() -> googletest::Result<()> {
        let seed = super::SeedWrapper(cxx::UniquePtr::null());
        assert_eq!(seed.as_bytes(), "".as_bytes());
        Ok(())
    }

    #[gtest]
    fn test_empty_seed_clone() -> googletest::Result<()> {
        let seed = super::SeedWrapper(cxx::UniquePtr::null());
        let cloned_seed = seed.clone();
        assert_eq!(cloned_seed.as_bytes(), "".as_bytes());
        Ok(())
    }

    #[gtest]
    fn test_non_empty_seed_clone() -> googletest::Result<()> {
        let seed = super::generate_seed()?;
        let cloned_seed = seed.clone();
        assert_eq!(seed.as_bytes(), cloned_seed.as_bytes());
        assert_ne!(seed.as_bytes().len(), 0);
        Ok(())
    }
}
