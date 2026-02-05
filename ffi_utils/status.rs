// Copyright 2024 The Abseil Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Tentative Rust API for absl::Status.
//!
//! absl::Status is (roughly) isomorphic to a type that permits
//! case distinction between an "ok" case and an error case.
//! In Rust, this is achieved through Result<(), E> type.
//! There is language-level support via the `?` operator.
//! corresponding to the widely used RETURN_IF_ERROR macro.

use std::borrow::Cow;
use std::fmt::Debug;

#[cxx::bridge(namespace = "secure_aggregation")]
pub mod ffi {
    unsafe extern "C++" {
        include!("absl/status/status.h");
        #[namespace = "absl"]
        type Status;
    }

    // A simple Status wrapper which is cxx-compatible (because it directly uses unique_ptr).
    pub struct FfiStatus {
        // Wrapped absl::Status. A nullptr is interpreted as an OK status.
        ptr: UniquePtr<Status>,
    }

    unsafe extern "C++" {
        include!("ffi_utils/status.h");
        #[rust_name = "make_ok_ffi_status"]
        pub fn MakeFfiStatus() -> FfiStatus;
        #[rust_name = "make_ffi_status"]
        pub fn MakeFfiStatus(code: i32, message: &[u8]) -> FfiStatus;
        #[rust_name = "ffi_status_code"]
        pub fn FfiStatusCode(status: &FfiStatus) -> i32;
        #[rust_name = "ffi_status_message"]
        pub fn FfiStatusMessage<'a>(status: &'a FfiStatus) -> &'a [u8];
        #[rust_name = "clone_ffi_status"]
        pub fn CloneFfiStatus(status: &FfiStatus) -> FfiStatus;
    }
}

pub type Status = Result<(), StatusError>;
pub type StatusOr<T> = Result<T, StatusError>;

impl Clone for ffi::FfiStatus {
    fn clone(&self) -> Self {
        ffi::clone_ffi_status(self)
    }
}

impl Debug for ffi::FfiStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "FfiStatus({}: {})",
            ffi::ffi_status_code(self),
            String::from_utf8_lossy(ffi::ffi_status_message(self))
        )
    }
}

/// All cases of C++ StatusErrorCode except `StatusErrorCode::kOk`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
#[repr(i32)]
pub enum StatusErrorCode {
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

/// Holds a wrapped non-OK absl::Status.
/// We optionally keep a source location, but note that it cannot be passed to
/// C++ yet.
#[derive(Debug, Clone)]
pub struct StatusError {
    ffi_status: ffi::FfiStatus,
    loc: Option<&'static core::panic::Location<'static>>,
}

impl StatusError {
    pub fn new(
        code: StatusErrorCode,
        message: &[u8],
        loc: &'static core::panic::Location<'static>,
    ) -> Self {
        StatusError { ffi_status: ffi::make_ffi_status(code as i32, message), loc: Some(loc) }
    }

    pub fn from_ffi_status(
        ffi_status: ffi::FfiStatus,
        loc: Option<&'static core::panic::Location<'static>>,
    ) -> Self {
        if ffi::ffi_status_code(&ffi_status) == 0 {
            panic!("Cannot create StatusError from OK status");
        }
        StatusError { ffi_status, loc }
    }

    /// Create a new StatusError with no source code location.
    pub fn new_untracked(code: StatusErrorCode, message: &[u8]) -> Self {
        StatusError { ffi_status: ffi::make_ffi_status(code as i32, message), loc: None }
    }

    /// Create a new StatusError pointing to the current source location.
    #[track_caller]
    pub fn new_with_current_location(code: StatusErrorCode, message: &[u8]) -> Self {
        StatusError::new_untracked(code, message).with_current_location()
    }

    /// Returns the canonical error code of this status.
    pub fn code(&self) -> StatusErrorCode {
        ffi::ffi_status_code(&self.ffi_status).try_into().unwrap_or(StatusErrorCode::Unknown)
    }

    /// Returns the error message associated with this error code.
    /// Note that this message rarely describes the error code.  It is not
    /// unusual for the error message to be the empty string. As a result,
    /// prefer `Display` for debug logging.
    pub fn message(&self) -> Cow<str> {
        String::from_utf8_lossy(self.message_bytes())
    }

    /// Returns the raw bytes of the error message.
    pub fn message_bytes(&self) -> &[u8] {
        ffi::ffi_status_message(&self.ffi_status)
    }

    /// Returns location of the error message.
    pub fn loc(&self) -> Option<&'static core::panic::Location<'static>> {
        self.loc
    }

    /// Returns a new `StatusError` with the same code and message but pointing
    /// to the provided source location.
    pub fn with_location(self, location: &'static core::panic::Location<'static>) -> Self {
        StatusError { ffi_status: self.ffi_status, loc: Some(location) }
    }

    /// Returns a new `StatusError` with the same code and message but pointing
    /// to the current source location.
    #[track_caller]
    pub fn with_current_location(self) -> Self {
        self.with_location(core::panic::Location::caller())
    }
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        if let Some(loc) = self.loc {
            write!(f, "{}:{}:{}: {}", self.code().as_str(), loc.file(), loc.line(), self.message())
        } else {
            write!(f, "{}: {}", self.code().as_str(), self.message())
        }
    }
}

impl std::error::Error for StatusError {}

impl StatusErrorCode {
    pub fn as_str(self) -> &'static str {
        // Same as `absl::StatusCodeToString`
        match self {
            StatusErrorCode::Cancelled => "CANCELLED",
            StatusErrorCode::Unknown => "UNKNOWN",
            StatusErrorCode::InvalidArgument => "INVALID_ARGUMENT",
            StatusErrorCode::DeadlineExceeded => "DEADLINE_EXCEEDED",
            StatusErrorCode::NotFound => "NOT_FOUND",
            StatusErrorCode::AlreadyExists => "ALREADY_EXISTS",
            StatusErrorCode::PermissionDenied => "PERMISSION_DENIED",
            StatusErrorCode::ResourceExhausted => "RESOURCE_EXHAUSTED",
            StatusErrorCode::FailedPrecondition => "FAILED_PRECONDITION",
            StatusErrorCode::Aborted => "ABORTED",
            StatusErrorCode::OutOfRange => "OUT_OF_RANGE",
            StatusErrorCode::Unimplemented => "UNIMPLEMENTED",
            StatusErrorCode::Internal => "INTERNAL",
            StatusErrorCode::Unavailable => "UNAVAILABLE",
            StatusErrorCode::DataLoss => "DATA_LOSS",
            StatusErrorCode::Unauthenticated => "UNAUTHENTICATED",
        }
    }
}

impl TryFrom<i32> for StatusErrorCode {
    type Error = StatusErrorCodeTryFromError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => StatusErrorCode::Cancelled,
            2 => StatusErrorCode::Unknown,
            3 => StatusErrorCode::InvalidArgument,
            4 => StatusErrorCode::DeadlineExceeded,
            5 => StatusErrorCode::NotFound,
            6 => StatusErrorCode::AlreadyExists,
            7 => StatusErrorCode::PermissionDenied,
            8 => StatusErrorCode::ResourceExhausted,
            9 => StatusErrorCode::FailedPrecondition,
            10 => StatusErrorCode::Aborted,
            11 => StatusErrorCode::OutOfRange,
            12 => StatusErrorCode::Unimplemented,
            13 => StatusErrorCode::Internal,
            14 => StatusErrorCode::Unavailable,
            15 => StatusErrorCode::DataLoss,
            16 => StatusErrorCode::Unauthenticated,
            _ => return Err(StatusErrorCodeTryFromError(())),
        })
    }
}

macro_rules! impl_try_from {
    ($(impl TryFrom<$From:ty> for $To:ty;)*) => {
        $(
            impl TryFrom<$From> for $To {
                type Error = StatusErrorCodeTryFromError;

                fn try_from(value: $From) -> Result<Self, Self::Error> {
                    match i32::try_from(value) {
                        Ok(i) => <$To>::try_from(i),
                        Err(_) => Err(StatusErrorCodeTryFromError(())),
                    }
                }
            }
        )*
    }
}

impl_try_from! {
    impl TryFrom<i8> for StatusErrorCode;
    impl TryFrom<u8> for StatusErrorCode;
    impl TryFrom<i16> for StatusErrorCode;
    impl TryFrom<u16> for StatusErrorCode;
    impl TryFrom<u32> for StatusErrorCode;
    impl TryFrom<i64> for StatusErrorCode;
    impl TryFrom<u64> for StatusErrorCode;
    impl TryFrom<i128> for StatusErrorCode;
    impl TryFrom<u128> for StatusErrorCode;
    impl TryFrom<isize> for StatusErrorCode;
    impl TryFrom<usize> for StatusErrorCode;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct StatusErrorCodeTryFromError(pub(crate) ());

impl std::fmt::Display for StatusErrorCodeTryFromError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "error status code out of range: must be between {} and {}",
            StatusErrorCode::Cancelled as i32,
            StatusErrorCode::Unauthenticated as i32
        )
    }
}

impl std::error::Error for StatusErrorCodeTryFromError {}

impl From<StatusError> for ffi::FfiStatus {
    fn from(error: StatusError) -> Self {
        error.ffi_status
    }
}

impl From<Status> for ffi::FfiStatus {
    fn from(status: Status) -> Self {
        match status {
            Ok(()) => ffi::make_ok_ffi_status(),
            Err(error) => error.into(),
        }
    }
}

pub fn rust_status_from_cpp(status: ffi::FfiStatus) -> Status {
    match ffi::ffi_status_code(&status) {
        0 => Ok(()),
        _code => Err(StatusError::from_ffi_status(status, Some(core::panic::Location::caller()))),
    }
}

#[track_caller]
pub fn cancelled(msg: &str) -> StatusError {
    StatusError::new(StatusErrorCode::Cancelled, msg.as_bytes(), core::panic::Location::caller())
}

#[track_caller]
pub fn unknown(msg: &str) -> StatusError {
    StatusError::new(StatusErrorCode::Unknown, msg.as_bytes(), core::panic::Location::caller())
}

#[track_caller]
pub fn invalid_argument(msg: &str) -> StatusError {
    StatusError::new(
        StatusErrorCode::InvalidArgument,
        msg.as_bytes(),
        core::panic::Location::caller(),
    )
}

#[track_caller]
pub fn deadline_exceeded(msg: &str) -> StatusError {
    StatusError::new(
        StatusErrorCode::DeadlineExceeded,
        msg.as_bytes(),
        core::panic::Location::caller(),
    )
}

#[track_caller]
pub fn not_found(msg: &str) -> StatusError {
    StatusError::new(StatusErrorCode::NotFound, msg.as_bytes(), core::panic::Location::caller())
}

#[track_caller]
pub fn already_exists(msg: &str) -> StatusError {
    StatusError::new(
        StatusErrorCode::AlreadyExists,
        msg.as_bytes(),
        core::panic::Location::caller(),
    )
}

#[track_caller]
pub fn permission_denied(msg: &str) -> StatusError {
    StatusError::new(
        StatusErrorCode::PermissionDenied,
        msg.as_bytes(),
        core::panic::Location::caller(),
    )
}

#[track_caller]
pub fn resource_exhausted(msg: &str) -> StatusError {
    StatusError::new(
        StatusErrorCode::ResourceExhausted,
        msg.as_bytes(),
        core::panic::Location::caller(),
    )
}

#[track_caller]
pub fn failed_precondition(msg: &str) -> StatusError {
    StatusError::new(
        StatusErrorCode::FailedPrecondition,
        msg.as_bytes(),
        core::panic::Location::caller(),
    )
}

#[track_caller]
pub fn aborted(msg: &str) -> StatusError {
    StatusError::new(StatusErrorCode::Aborted, msg.as_bytes(), core::panic::Location::caller())
}

#[track_caller]
pub fn out_of_range(msg: &str) -> StatusError {
    StatusError::new(StatusErrorCode::OutOfRange, msg.as_bytes(), core::panic::Location::caller())
}

#[track_caller]
pub fn unimplemented(msg: &str) -> StatusError {
    StatusError::new(
        StatusErrorCode::Unimplemented,
        msg.as_bytes(),
        core::panic::Location::caller(),
    )
}

#[track_caller]
pub fn internal(msg: &str) -> StatusError {
    StatusError::new(StatusErrorCode::Internal, msg.as_bytes(), core::panic::Location::caller())
}

#[track_caller]
pub fn unavailable(msg: &str) -> StatusError {
    StatusError::new(StatusErrorCode::Unavailable, msg.as_bytes(), core::panic::Location::caller())
}

#[track_caller]
pub fn data_loss(msg: &str) -> StatusError {
    StatusError::new(StatusErrorCode::DataLoss, msg.as_bytes(), core::panic::Location::caller())
}

#[track_caller]
pub fn unauthenticated(msg: &str) -> StatusError {
    StatusError::new(
        StatusErrorCode::Unauthenticated,
        msg.as_bytes(),
        core::panic::Location::caller(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi::ffi_status_code;
    use ffi::ffi_status_message;
    use googletest::prelude::*;

    #[allow(dead_code)]
    fn compile_test() -> Status {
        if 0 == 1 {
            return Err(cancelled(&format!("bad stuff: {}", 0)));
        }
        Ok(())
    }

    fn fail() -> Status {
        Err(cancelled("goodbye"))
    }

    fn fail_whale() -> Status {
        fail()?;
        Ok(()) // not reached.
    }

    #[gtest]
    fn test() -> Result<()> {
        let status = fail_whale();
        if status.is_err() && status.as_ref().err().unwrap().code() == StatusErrorCode::Cancelled {
            Ok(())
        } else {
            fail!("unexpected status: {:?}", status)
        }
    }

    #[gtest]
    fn test_clone_ok() {
        let status = ffi::make_ok_ffi_status();
        let status2 = status.clone();
        expect_eq!(ffi_status_code(&status2), 0);
    }

    #[gtest]
    fn test_clone_error() {
        let status = ffi::make_ffi_status(1, b"test");
        let status2 = status.clone();
        expect_eq!(ffi_status_code(&status2), 1);
        expect_eq!(ffi_status_message(&status2), b"test");
    }

    #[gtest]
    fn test_try_from() {
        for i in 1..=16 {
            expect_eq!(StatusErrorCode::try_from(i).unwrap() as i32, i);
        }
    }

    #[gtest]
    fn test_try_from_err() {
        expect_that!(
            StatusErrorCode::try_from(0),
            err(displays_as(eq("error status code out of range: must be between 1 and 16")))
        );
    }

    #[gtest]
    fn test_ffi_status_from_status_error() {
        let error = StatusError::new_untracked(StatusErrorCode::Cancelled, b"test");
        let ffi_status: ffi::FfiStatus = error.into();
        expect_eq!(ffi_status_code(&ffi_status), 1);
        expect_eq!(ffi_status_message(&ffi_status), b"test");
    }

    #[gtest]
    fn test_rust_status_from_cpp() {
        let ffi_status = ffi::make_ffi_status(1, b"test");
        let rust_status = rust_status_from_cpp(ffi_status);
        assert!(rust_status.is_err());
        expect_eq!(&rust_status.as_ref().err().unwrap().code(), &StatusErrorCode::Cancelled);
        expect_eq!(&rust_status.as_ref().err().unwrap().message_bytes(), &b"test");
    }

    #[gtest]
    fn test_ffi_status_from_ok_status() {
        let rust_status = Ok(());
        let ffi_status: ffi::FfiStatus = rust_status.into();
        expect_eq!(ffi_status_code(&ffi_status), 0);
        expect_eq!(ffi_status_message(&ffi_status).is_empty(), true);
    }

    #[gtest]
    fn test_ffi_status_from_non_ok_status() {
        let rust_status = Err(StatusError::new_untracked(StatusErrorCode::Cancelled, b"test"));
        let ffi_status: ffi::FfiStatus = rust_status.into();
        expect_eq!(ffi_status_code(&ffi_status), StatusErrorCode::Cancelled as i32);
        expect_eq!(ffi_status_message(&ffi_status), b"test");
    }
}
