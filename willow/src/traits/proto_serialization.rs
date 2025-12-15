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

use status::StatusError;

/// Trait for converting a struct to a Protobuf message.
pub trait ToProto<Context = ()> {
    type Proto;

    fn to_proto(&self, ctx: Context) -> Result<Self::Proto, StatusError>;
}

/// Trait for converting a Protobuf message view to a struct.
pub trait FromProto<Context = ()>: Sized {
    type Proto;

    fn from_proto(
        proto: impl protobuf::AsView<Proxied = Self::Proto>,
        ctx: Context,
    ) -> Result<Self, StatusError>;
}
