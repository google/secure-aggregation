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

use googletest::description::Description;
use googletest::matcher::{Matcher, MatcherBase, MatcherResult};
use status::{StatusError, StatusErrorCode};
use std::fmt::Debug;
use std::result::Result;

/// Matches a `Result<_, StatusError>` or a `StatusError` with the expected
/// error code.
///
/// ```
/// verify_that!(cancelled("cancelled"),
///   status_is(StatusErrorCode::Cancelled))?;  // Passes
/// verify_that!(internal("out of bound"),
///   status_is(StatusErrorCode::InvalidArgument))?;   // Fails
/// verify_that!(Ok("Some value"),
///   status_is(StatusErrorCode::Cancelled))?;   // Fails
/// ```
///
/// If you are looking for the Rust correspondent to `testing::status::IsOk()`
/// and `testing::status::IsOkAndHolds`, see
/// [`googletest::ok(...)`](https://docs.rs/googletest/0.11.0/googletest/matchers/fn.ok.html).
pub fn status_is(expected_code: StatusErrorCode) -> StatusIsMatcher {
    StatusIsMatcher { expected_code, message_matcher: None }
}

#[derive(MatcherBase)]
pub struct StatusIsMatcher {
    expected_code: StatusErrorCode,
    message_matcher: Option<Box<dyn for<'a> Matcher<&'a str> + 'static>>,
}

impl StatusIsMatcher {
    /// Add a matcher for the error message of the `StatusError`.
    pub fn with_message<M: for<'a> Matcher<&'a str> + 'static>(self, message_matcher: M) -> Self {
        Self { expected_code: self.expected_code, message_matcher: Some(Box::new(message_matcher)) }
    }
}

impl<T: Debug> Matcher<&Result<T, StatusError>> for StatusIsMatcher {
    fn matches(&self, actual: &Result<T, StatusError>) -> MatcherResult {
        if let Err(error) = actual {
            self.matches(error)
        } else {
            MatcherResult::NoMatch
        }
    }

    fn explain_match(&self, actual: &Result<T, StatusError>) -> Description {
        let Err(status_error) = actual else {
            return Description::new().text("which is a success");
        };

        self.explain_match(status_error)
    }

    fn describe(&self, result: MatcherResult) -> Description {
        match (result, &self.message_matcher) {
            (MatcherResult::Match, Some(message_matcher)) => Description::new().text(format!(
                "is a StatusError with code {} and an error message, which {}",
                self.expected_code.as_str(),
                message_matcher.describe(result)
            )),
            (MatcherResult::Match, None) => Description::new()
                .text(format!("is a StatusError with code {}", self.expected_code.as_str())),
            (MatcherResult::NoMatch, Some(message_matcher)) => Description::new().text(format!(
            "is a success or a StatusError with any code except {} or an error message, which {}",
            self.expected_code.as_str(),
            message_matcher.describe(result)
        )),
            (MatcherResult::NoMatch, None) => Description::new().text(format!(
                "is a success or a StatusError with any code except {}",
                self.expected_code.as_str()
            )),
        }
    }
}

impl Matcher<&StatusError> for StatusIsMatcher {
    fn matches(&self, actual: &StatusError) -> MatcherResult {
        if actual.code() != self.expected_code {
            return MatcherResult::NoMatch;
        }

        if let Some(message_matcher) = &self.message_matcher {
            message_matcher.matches(&actual.message())
        } else {
            MatcherResult::Match
        }
    }

    fn explain_match(&self, actual: &StatusError) -> Description {
        let code = actual.code();
        let message = actual.message();
        let Some(message_matcher) = &self.message_matcher else {
            return Description::new()
                .text(format!("which is a StatusError with code {}", code.as_str()));
        };

        match (actual.code() == self.expected_code, message_matcher.matches(&message)) {
            (true, MatcherResult::NoMatch) => Description::new().text(format!(
                "which is a StatusError with error message: {}, {}",
                message,
                message_matcher.explain_match(&message)
            )),
            (false, MatcherResult::Match) => Description::new()
                .text(format!("which is a StatusError with code {}", code.as_str())),
            (_, _) => Description::new().text(format!(
                "which is a StatusError with code {} and error message: {}, {}",
                code.as_str(),
                message,
                message_matcher.explain_match(&message)
            )),
        }
    }

    fn describe(&self, result: MatcherResult) -> Description {
        match (result, &self.message_matcher) {
            (MatcherResult::Match, Some(message_matcher)) => Description::new().text(format!(
                "is a StatusError with code {} and an error message, which {}",
                self.expected_code.as_str(),
                message_matcher.describe(result)
            )),
            (MatcherResult::Match, None) => Description::new()
                .text(format!("is a StatusError with code {}", self.expected_code.as_str())),
            (MatcherResult::NoMatch, Some(message_matcher)) => Description::new().text(format!(
                "is a StatusError with any code except {} or an error message, which {}",
                self.expected_code.as_str(),
                message_matcher.describe(result)
            )),
            (MatcherResult::NoMatch, None) => Description::new().text(format!(
                "is a StatusError with any code except {}",
                self.expected_code.as_str()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::status_is;
    use googletest::prelude::*;
    use indoc::indoc;
    use status::{cancelled, StatusError, StatusErrorCode};

    #[gtest]
    fn matches_status() -> Result<()> {
        verify_that!(cancelled("cancelled"), status_is(StatusErrorCode::Cancelled))
    }

    #[gtest]
    fn matches_status_with_message() -> Result<()> {
        verify_that!(
            cancelled("cancelled"),
            status_is(StatusErrorCode::Cancelled).with_message(eq("cancelled"))
        )
    }

    #[gtest]
    fn matches_status_error() -> Result<()> {
        verify_that!(
            StatusError::new_with_current_location(StatusErrorCode::Cancelled, "cancelled",),
            status_is(StatusErrorCode::Cancelled)
        )
    }

    #[gtest]
    fn matches_status_error_with_message() -> Result<()> {
        verify_that!(
            StatusError::new_with_current_location(StatusErrorCode::Cancelled, "cancelled",),
            status_is(StatusErrorCode::Cancelled).with_message(eq("cancelled"))
        )
    }

    #[gtest]
    fn wrong_code_failure_message() -> Result<()> {
        let result = verify_that!(
            StatusError::new_untracked(StatusErrorCode::Cancelled, "cancelled"),
            status_is(StatusErrorCode::InvalidArgument)
        );

        verify_that!(
            result,
            err(displays_as(contains_substring(indoc!(
                r#"
                    Expected: is a StatusError with code INVALID_ARGUMENT
                    Actual: StatusError {
                        code: Cancelled,
                        message: "cancelled",
                        loc: None,
                    },
                      which is a StatusError with code CANCELLED
                "#
            ))))
        )
    }
}
