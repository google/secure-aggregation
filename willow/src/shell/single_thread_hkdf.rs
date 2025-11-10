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
use single_thread_hkdf as wrapper;

pub use wrapper::SeedWrapper as Seed;
pub struct SingleThreadHkdfPrng(pub wrapper::SingleThreadHkdfWrapper);

pub use wrapper::compute_hkdf;
pub use wrapper::seed_length;

impl SecurePrng for SingleThreadHkdfPrng {
    type Seed = Seed;

    fn generate_seed() -> Result<Self::Seed, status::StatusError> {
        Ok(wrapper::generate_seed()?)
    }

    fn create(seed: &Self::Seed) -> Result<Self, status::StatusError> {
        Ok(SingleThreadHkdfPrng(wrapper::create(&seed)?))
    }

    fn rand8(&mut self) -> Result<u8, status::StatusError> {
        wrapper::rand8(&mut self.0)
    }
}

#[cfg(test)]
mod test {

    use super::SingleThreadHkdfPrng;
    use googletest::{gtest, verify_eq, verify_false, verify_that};
    use prng_traits::SecurePrng;

    #[gtest]
    /// Two sequences of 8 random bits should be different (w.h.p).
    fn test_rand8() -> googletest::Result<()> {
        let mut equal = true;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        for _ in 0..8 {
            let a = prng.rand8()?;
            let b = prng.rand8()?;
            if a != b {
                equal = false;
            }
        }
        verify_false!(equal)
    }

    #[gtest]
    fn test_replay_same_seed() -> googletest::Result<()> {
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng1 = SingleThreadHkdfPrng::create(&seed)?;
        let mut prng2 = SingleThreadHkdfPrng::create(&seed)?;
        let a = prng1.rand8()?;
        let b = prng2.rand8()?;
        verify_eq!(a, b)
    }

    #[gtest]
    fn test_replay_different_seeds() -> googletest::Result<()> {
        let mut equal = true;
        let seed1 = SingleThreadHkdfPrng::generate_seed()?;
        let seed2 = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng1 = SingleThreadHkdfPrng::create(&seed1)?;
        let mut prng2 = SingleThreadHkdfPrng::create(&seed2)?;
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
