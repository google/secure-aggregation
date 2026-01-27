/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Testing utilities for working with absl::Status and absl::StatusOr.
//
// Defines the following utilities:
//
//   =================
//   SECAGG_EXPECT_OK(s)
//
//   SECAGG_ASSERT_OK(s)
//   =================
//   Convenience macros for `EXPECT_THAT(s, IsOk())`, where `s` is either
//   a `Status` or a `StatusOr<T>`.
//
//   There are no EXPECT_NOT_OK/ASSERT_NOT_OK macros since they would not
//   provide much value (when they fail, they would just print the OK status
//   which conveys no more information than `EXPECT_FALSE(s.ok())`. You can
//   of course use `EXPECT_THAT(s, Not(IsOk()))` if you prefer _THAT style.
//
//   If you want to check for particular errors, better alternatives are:
//   EXPECT_THAT(s, StatusIs(expected_error));
//   EXPECT_THAT(s, StatusIs(_, HasSubstr("expected error")));
//
//   ===============
//   IsOkAndHolds(m)
//   ===============
//
//   This gMock matcher matches a StatusOr<T> value whose status is OK
//   and whose inner value matches matcher m.  Example:
//
//     using ::testing::MatchesRegex;
//     using secure_aggregation::IsOkAndHolds;
//     ...
//     absl::StatusOr<string> maybe_name = ...;
//     EXPECT_THAT(maybe_name, IsOkAndHolds(MatchesRegex("John .*")));
//
//   ===============================
//   StatusIs(status_code_matcher,
//            error_message_matcher)
//   ===============================
//
//   This gMock matcher matches a Status or StatusOr<T> value if all of the
//   following are true:
//
//     - the status' error_code() matches status_code_matcher, and
//     - the status' error_message() matches error_message_matcher.
//
//   Example:
//
//     enum FooErrorCode {
//       ...
//       kServerError
//     };
//
//     using ::testing::HasSubstr;
//     using ::testing::MatchesRegex;
//     using ::testing::Ne;
//     using ::testing::_;
//     using secure_aggregation::StatusIs;
//     absl::StatusOr<string> GetName(int id);
//     ...
//
//     // The status code must be kServerError; the error message can be
//     // anything.
//     EXPECT_THAT(GetName(42),
//                 StatusIs(kServerError, _));
//     // The status code can be anything; the error message must match the
//     // regex.
//     EXPECT_THAT(GetName(43),
//                 StatusIs(_, MatchesRegex("server.*time-out")));
//
//     // The status code should not be kServerError; the error message can be
//     // anything with "client" in it.
//     EXPECT_CALL(mock_env, HandleStatus(
//         StatusIs(Ne(kServerError), HasSubstr("client"))));
//
//   ===============================
//   StatusIs(status_code_matcher)
//   ===============================
//
//   This is a shorthand for
//     StatusIs(status_code_matcher,
//              testing::_)
//   In other words, it's like the two-argument StatusIs(), except that it
//   ignores error message.
//
//   ===============
//   IsOk()
//   ===============
//
//   Matches an absl::Status or absl::StatusOr<T> value whose status value is
//   absl::StatusCode::kOk. Equivalent to 'StatusIs(absl::StatusCode::kOk)'.
//   Example:
//     using secure_aggregation::IsOk;
//     ...
//     absl::StatusOr<string> maybe_name = ...;
//     EXPECT_THAT(maybe_name, IsOk());
//     Status s = ...;
//     EXPECT_THAT(s, IsOk());
//

#ifndef SECURE_AGGREGATION_SHELL_WRAPPER_STATUS_MATCHERS_H_
#define SECURE_AGGREGATION_SHELL_WRAPPER_STATUS_MATCHERS_H_

#include <ostream>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "ffi_utils/status_macros.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace secure_aggregation {
namespace secagg_internal {

inline const absl::Status& GetStatus(const absl::Status& status) {
  return status;
}

template <typename T>
inline const absl::Status& GetStatus(const absl::StatusOr<T>& status) {
  return status.status();
}

////////////////////////////////////////////////////////////
// Implementation of IsOkAndHolds().

// Monomorphic implementation of matcher IsOkAndHolds(m).  StatusOrType is a
// reference to StatusOr<T>.
template <typename StatusOrType>
class IsOkAndHoldsMatcherImpl
    : public ::testing::MatcherInterface<StatusOrType> {
 public:
  typedef
      typename std::remove_reference<StatusOrType>::type::value_type value_type;

  template <typename InnerMatcher>
  explicit IsOkAndHoldsMatcherImpl(InnerMatcher&& inner_matcher)
      : inner_matcher_(::testing::SafeMatcherCast<const value_type&>(
            std::forward<InnerMatcher>(inner_matcher))) {}

  void DescribeTo(std::ostream* os) const override {
    *os << "is OK and has a value that ";
    inner_matcher_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "isn't OK or has a value that ";
    inner_matcher_.DescribeNegationTo(os);
  }

  bool MatchAndExplain(
      StatusOrType actual_value,
      ::testing::MatchResultListener* result_listener) const override {
    if (!actual_value.ok()) {
      *result_listener << "which has status " << actual_value.status();
      return false;
    }

    ::testing::StringMatchResultListener inner_listener;
    const bool matches =
        inner_matcher_.MatchAndExplain(*actual_value, &inner_listener);
    const std::string inner_explanation = inner_listener.str();
    if (!inner_explanation.empty()) {
      *result_listener << "which contains value "
                       << ::testing::PrintToString(*actual_value) << ", "
                       << inner_explanation;
    }
    return matches;
  }

 private:
  const ::testing::Matcher<const value_type&> inner_matcher_;
};

// Implements IsOkAndHolds(m) as a polymorphic matcher.
template <typename InnerMatcher>
class IsOkAndHoldsMatcher {
 public:
  explicit IsOkAndHoldsMatcher(InnerMatcher inner_matcher)
      : inner_matcher_(std::move(inner_matcher)) {}

  // Converts this polymorphic matcher to a monomorphic matcher of the
  // given type.  StatusOrType can be either StatusOr<T> or a
  // reference to StatusOr<T>.
  template <typename StatusOrType>
  operator ::testing::Matcher<StatusOrType>() const {  // NOLINT
    return ::testing::Matcher<StatusOrType>(
        new IsOkAndHoldsMatcherImpl<const StatusOrType&>(inner_matcher_));
  }

 private:
  const InnerMatcher inner_matcher_;
};

////////////////////////////////////////////////////////////
// Implementation of StatusIs().

// StatusIs() is a polymorphic matcher.  This class is the common
// implementation of it shared by all types T where StatusIs() can be
// used as a Matcher<T>.
class StatusIsMatcherCommonImpl {
 public:
  StatusIsMatcherCommonImpl(
      ::testing::Matcher<absl::StatusCode> code_matcher,
      ::testing::Matcher<const std::string&> message_matcher)
      : code_matcher_(std::move(code_matcher)),
        message_matcher_(std::move(message_matcher)) {}

  void DescribeTo(std::ostream* os) const;

  void DescribeNegationTo(std::ostream* os) const;

  bool MatchAndExplain(const absl::Status& status,
                       ::testing::MatchResultListener* result_listener) const;

 private:
  const ::testing::Matcher<absl::StatusCode> code_matcher_;
  const ::testing::Matcher<const std::string&> message_matcher_;
};

// Monomorphic implementation of matcher StatusIs() for a given type
// T.  T can be Status, StatusOr<>, or a reference to either of them.
template <typename T>
class MonoStatusIsMatcherImpl : public ::testing::MatcherInterface<T> {
 public:
  explicit MonoStatusIsMatcherImpl(StatusIsMatcherCommonImpl common_impl)
      : common_impl_(std::move(common_impl)) {}

  void DescribeTo(std::ostream* os) const override {
    common_impl_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    common_impl_.DescribeNegationTo(os);
  }

  bool MatchAndExplain(
      T actual_value,
      ::testing::MatchResultListener* result_listener) const override {
    return common_impl_.MatchAndExplain(GetStatus(actual_value),
                                        result_listener);
  }

 private:
  StatusIsMatcherCommonImpl common_impl_;
};

// Implements StatusIs() as a polymorphic matcher.
class StatusIsMatcher {
 public:
  template <typename StatusCodeMatcher, typename StatusMessageMatcher>
  StatusIsMatcher(StatusCodeMatcher&& code_matcher,
                  StatusMessageMatcher&& message_matcher)
      : common_impl_(::testing::MatcherCast<absl::StatusCode>(
                         std::forward<StatusCodeMatcher>(code_matcher)),
                     ::testing::MatcherCast<const std::string&>(
                         std::forward<StatusMessageMatcher>(message_matcher))) {
  }

  // Converts this polymorphic matcher to a monomorphic matcher of the
  // given type.  T can be StatusOr<>, Status, or a reference to
  // either of them.
  template <typename T>
  operator ::testing::Matcher<T>() const {  // NOLINT
    return ::testing::Matcher<T>(
        new MonoStatusIsMatcherImpl<const T&>(common_impl_));
  }

 private:
  const StatusIsMatcherCommonImpl common_impl_;
};

// Monomorphic implementation of matcher IsOk() for a given type T.
// T can be Status, StatusOr<>, or a reference to either of them.
template <typename T>
class MonoIsOkMatcherImpl : public ::testing::MatcherInterface<T> {
 public:
  void DescribeTo(std::ostream* os) const override { *os << "is OK"; }
  void DescribeNegationTo(std::ostream* os) const override {
    *os << "is not OK";
  }
  bool MatchAndExplain(
      T actual_value,
      ::testing::MatchResultListener* result_listener) const override {
    if (!actual_value.ok()) {
      *result_listener << "whose status is "
                       << GetStatus(actual_value).message();
      return false;
    }
    return true;
  }
};

// Implements IsOk() as a polymorphic matcher.
class IsOkMatcher {
 public:
  template <typename T>
  operator ::testing::Matcher<T>() const {  // NOLINT
    return ::testing::Matcher<T>(new MonoIsOkMatcherImpl<const T&>());
  }
};

// Macros for testing the results of functions that return absl::Status or
// absl::StatusOr<T> (for any type T).
#define SECAGG_EXPECT_OK(expression) \
  EXPECT_THAT(expression, secure_aggregation::secagg_internal::IsOk())
#define SECAGG_ASSERT_OK(expression) \
  ASSERT_THAT(expression, secure_aggregation::secagg_internal::IsOk())

// Executes an expression that returns an absl::StatusOr, and assigns the
// contained variable to lhs if the error code is OK.
// If the Status is non-OK, generates a test failure and returns from the
// current function, which must have a void return type.
//
// Example: Declaring and initializing a new value
//   SECAGG_ASSERT_OK_AND_ASSIGN(const ValueType& value, MaybeGetValue(arg));
//
// Example: Assigning to an existing value
//   ValueType value;
//   SECAGG_ASSERT_OK_AND_ASSIGN(value, MaybeGetValue(arg));
//
// The value assignment example would expand into something like:
//   auto status_or_value = MaybeGetValue(arg);
//   SECAGG_ASSERT_OK(status_or_value.status());
//   value = std::move(status_or_value).ValueOrDie();
//
// WARNING: Like SECAGG_ASSIGN_OR_RETURN, SECAGG_ASSERT_OK_AND_ASSIGN expands
// into multiple statements; it cannot be used in a single statement (e.g. as
// the body of an if statement without {})!
#define SECAGG_ASSERT_OK_AND_ASSIGN(lhs, rexpr)                           \
  SECAGG_ASSERT_OK_AND_ASSIGN_IMPL_(                                      \
      SECAGG_STATUS_MACROS_IMPL_CONCAT_(_status_or_value, __LINE__), lhs, \
      rexpr)

#define SECAGG_ASSERT_OK_AND_ASSIGN_IMPL_(statusor, lhs, rexpr) \
  auto statusor = (rexpr);                                      \
  SECAGG_ASSERT_OK(statusor);                                   \
  lhs = std::move(statusor).value();

// Returns a gMock matcher that matches a StatusOr<> whose status is
// OK and whose value matches the inner matcher.
template <typename InnerMatcher>
secagg_internal::IsOkAndHoldsMatcher<typename std::decay<InnerMatcher>::type>
IsOkAndHolds(InnerMatcher&& inner_matcher) {
  return secagg_internal::IsOkAndHoldsMatcher<
      typename std::decay<InnerMatcher>::type>(
      std::forward<InnerMatcher>(inner_matcher));
}

// Returns a gMock matcher that matches a Status or StatusOr<> whose status code
// matches code_matcher, and whose error message matches message_matcher.
template <typename StatusCodeMatcher, typename StatusMessageMatcher>
secagg_internal::StatusIsMatcher StatusIs(
    StatusCodeMatcher&& code_matcher, StatusMessageMatcher&& message_matcher) {
  return secagg_internal::StatusIsMatcher(
      std::forward<StatusCodeMatcher>(code_matcher),
      std::forward<StatusMessageMatcher>(message_matcher));
}

// Returns a gMock matcher that matches a Status or StatusOr<> whose status code
// matches code_matcher.
template <typename StatusCodeMatcher>
secagg_internal::StatusIsMatcher StatusIs(StatusCodeMatcher&& code_matcher) {
  return StatusIs(std::forward<StatusCodeMatcher>(code_matcher), ::testing::_);
}

// Returns a gMock matcher that matches a Status or StatusOr<> which is OK.
inline secagg_internal::IsOkMatcher IsOk() {
  return secagg_internal::IsOkMatcher();
}

}  // namespace secagg_internal
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_SHELL_WRAPPER_STATUS_MATCHERS_H_
