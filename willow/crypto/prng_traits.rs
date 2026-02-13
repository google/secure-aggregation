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

/// Trait for a secure pseudorandom number generator.
/// Follows the same interface as the C++ interface from
/// https://github.com/google/shell-encryption/blob/master/shell_encryption/prng/prng.h
pub trait SecurePrng: Sized {
    type Seed;

    fn rand8(&mut self) -> Result<u8, StatusError>;

    // fn rand64(&mut self) -> Result<u64, StatusError>;

    fn create(seed: &Self::Seed) -> Result<Self, StatusError>;

    fn generate_seed() -> Result<Self::Seed, StatusError>;

    // fn seed_length() -> usize;
}
