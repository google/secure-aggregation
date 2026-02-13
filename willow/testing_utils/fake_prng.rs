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

use prng_traits::SecurePrng;

pub struct InsecureFakePrng {
    seed: u8,
    count: u8,
}

/// Implements a fake prng that returns n times seed for the nth byte.
/// When asked to generate a seed it returns 1.
impl SecurePrng for InsecureFakePrng {
    type Seed = u8;

    fn generate_seed() -> Result<Self::Seed, status::StatusError> {
        Ok(1)
    }

    fn create(seed: &Self::Seed) -> Result<Self, status::StatusError> {
        Ok(InsecureFakePrng { seed: *seed, count: 0 })
    }

    fn rand8(&mut self) -> Result<u8, status::StatusError> {
        self.count += 1;
        Ok(self.seed + self.count)
    }
}

#[cfg(test)]
mod test {

    use super::InsecureFakePrng;
    use googletest::{gtest, verify_false, verify_true};
    use prng_traits::SecurePrng;

    #[gtest]
    fn test_replay_same_seed() -> googletest::Result<()> {
        let mut equal = true;
        let seed = InsecureFakePrng::generate_seed()?;
        let mut prng1 = InsecureFakePrng::create(&seed)?;
        let mut prng2 = InsecureFakePrng::create(&seed)?;
        for _ in 0..8 {
            let a = prng1.rand8()?;
            let b = prng2.rand8()?;
            if a != b {
                equal = false;
            }
        }
        verify_true!(equal)
    }

    #[gtest]
    fn test_replay_different_seeds() -> googletest::Result<()> {
        let mut equal = true;
        let seed1: u8 = 1;
        let seed2: u8 = 3;
        let mut prng1 = InsecureFakePrng::create(&seed1)?;
        let mut prng2 = InsecureFakePrng::create(&seed2)?;
        for _ in 0..8 {
            let a = prng1.rand8()?;
            let b = prng2.rand8()?;
            if a != b {
                equal = false;
            }
        }
        verify_false!(equal)
    }
}
