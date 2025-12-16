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

#[cxx::bridge]
pub mod ffi {
    // A simple Status alternative which is cxx-compatible (because it directly uses unique_ptr).
    pub struct FfiStatus {
        pub code: i32,
        pub message: UniquePtr<CxxString>,
    }

    unsafe extern "C++" {
        include!("shell_wrapper/status.h");
        pub fn MakeFfiStatus(code: i32, message: &[u8]) -> FfiStatus;
    }
}

pub type Status = Result<(), StatusError>;
pub type StatusOr<T> = Result<T, StatusError>;

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

/// Holds components of absl::Status in the error case.
/// We optionally keep a source location, but note that it cannot be passed to
/// C++ yet.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StatusError {
    code: StatusErrorCode,
    message: MaybeString,
    loc: Option<&'static core::panic::Location<'static>>,
}

impl StatusError {
    pub fn new(
        code: StatusErrorCode,
        message: impl Into<Vec<u8>>,
        loc: &'static core::panic::Location<'static>,
    ) -> Self {
        StatusError { code, message: MaybeString(message.into()), loc: Some(loc) }
    }

    /// Create a new StatusError with no source code location.
    pub fn new_untracked(code: StatusErrorCode, message: impl Into<Vec<u8>>) -> Self {
        StatusError { code, message: MaybeString(message.into()), loc: None }
    }

    /// Create a new StatusError pointing to the current source location.
    #[track_caller]
    pub fn new_with_current_location(code: StatusErrorCode, message: impl Into<Vec<u8>>) -> Self {
        StatusError::new_untracked(code, message).with_current_location()
    }

    /// Returns the canonical error code of this status.
    pub fn code(&self) -> StatusErrorCode {
        self.code
    }

    /// Returns the error message associated with this error code.
    /// Note that this message rarely describes the error code.  It is not
    /// unusual for the error message to be the empty string. As a result,
    /// prefer `Display` for debug logging.
    pub fn message(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.message.0)
    }

    /// Returns the raw bytes of the error message.
    pub fn message_bytes(&self) -> &[u8] {
        &self.message.0
    }

    /// Returns location of the error message.
    pub fn loc(&self) -> Option<&'static core::panic::Location<'static>> {
        self.loc
    }

    /// Returns a new `StatusError` with the same code and message but pointing
    /// to the provided source location.
    pub fn with_location(self, location: &'static core::panic::Location<'static>) -> Self {
        StatusError { code: self.code, message: self.message, loc: Some(location) }
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
            write!(f, "{}:{}:{}: {}", self.code.as_str(), loc.file(), loc.line(), self.message())
        } else {
            write!(f, "{}: {}", self.code.as_str(), self.message())
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
        ffi::MakeFfiStatus(error.code as i32, error.message.0.as_slice())
    }
}

impl From<Status> for ffi::FfiStatus {
    fn from(status: Status) -> Self {
        match status {
            Ok(()) => ffi::FfiStatus { code: 0, message: cxx::UniquePtr::null() },
            Err(error) => error.into(),
        }
    }
}

pub fn rust_status_from_cpp(status: ffi::FfiStatus) -> Status {
    if status.code == 0 {
        Ok(())
    } else {
        let message = if status.message.is_null() { b"" } else { status.message.as_bytes() };
        Err(StatusError::new(
            status.code.try_into().unwrap_or(StatusErrorCode::Unknown),
            message,
            core::panic::Location::caller(),
        ))
    }
}

#[track_caller]
pub fn cancelled<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::Cancelled, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn unknown<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::Unknown, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn invalid_argument<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::InvalidArgument, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn deadline_exceeded<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::DeadlineExceeded, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn not_found<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::NotFound, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn already_exists<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::AlreadyExists, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn permission_denied<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::PermissionDenied, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn resource_exhausted<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(
        StatusErrorCode::ResourceExhausted,
        msg.into(),
        core::panic::Location::caller(),
    )
}

#[track_caller]
pub fn failed_precondition<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(
        StatusErrorCode::FailedPrecondition,
        msg.into(),
        core::panic::Location::caller(),
    )
}

#[track_caller]
pub fn aborted<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::Aborted, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn out_of_range<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::OutOfRange, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn unimplemented<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::Unimplemented, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn internal<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::Internal, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn unavailable<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::Unavailable, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn data_loss<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::DataLoss, msg.into(), core::panic::Location::caller())
}

#[track_caller]
pub fn unauthenticated<S: Into<String>>(msg: S) -> StatusError {
    StatusError::new(StatusErrorCode::Unauthenticated, msg.into(), core::panic::Location::caller())
}

/// Holds a sequence of bytes that may be UTF-8. This primarily exists to give
/// it a String-like Debug implementation.
#[derive(PartialEq, Eq, Clone)]
struct MaybeString(pub Vec<u8>);

impl std::fmt::Debug for MaybeString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let string = String::from_utf8_lossy(&self.0);
        write!(f, "{:?}", string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;

    #[allow(dead_code)]
    fn compile_test() -> Status {
        if 0 == 1 {
            return Err(cancelled(format!("bad stuff: {}", 0)));
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
        match fail_whale() {
            Err(StatusError { code: StatusErrorCode::Cancelled, .. }) => Ok(()),
            status => fail!("unexpected status: {:?}", status),
        }
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
        let error = StatusError::new_untracked(StatusErrorCode::Cancelled, "test");
        let ffi_status: ffi::FfiStatus = error.into();
        expect_eq!(ffi_status.code, 1);
        expect_eq!(ffi_status.message.as_bytes(), b"test");
    }

    #[gtest]
    fn test_rust_status_from_cpp() {
        let ffi_status = ffi::MakeFfiStatus(1, b"test");
        let rust_status = rust_status_from_cpp(ffi_status);
        assert!(rust_status.is_err());
        expect_eq!(&rust_status.as_ref().err().unwrap().code(), &StatusErrorCode::Cancelled);
        expect_eq!(&rust_status.as_ref().err().unwrap().message_bytes(), &b"test");
    }

    #[gtest]
    fn test_ffi_status_from_ok_status() {
        let rust_status = Ok(());
        let ffi_status: ffi::FfiStatus = rust_status.into();
        expect_eq!(ffi_status.code, 0);
        expect_eq!(ffi_status.message.is_null(), true);
    }

    #[gtest]
    fn test_ffi_status_from_non_ok_status() {
        let rust_status = Err(StatusError::new_untracked(StatusErrorCode::Cancelled, "test"));
        let ffi_status: ffi::FfiStatus = rust_status.into();
        expect_eq!(ffi_status.code, StatusErrorCode::Cancelled as i32);
        expect_eq!(ffi_status.message.as_bytes(), b"test");
    }
}
