/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SECURE_AGGREGATION_WILLOW_SRC_PRNG_SINGLE_THREAD_HKDF_WRAPPER_H_
#define SECURE_AGGREGATION_WILLOW_SRC_PRNG_SINGLE_THREAD_HKDF_WRAPPER_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "include/cxx.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_wrapper/shell_types.h"
#include "shell_wrapper/single_thread_hkdf.rs.h"
#include "shell_wrapper/status.rs.h"

FfiStatus GenerateSingleThreadHkdfSeed(std::unique_ptr<std::string>& out);
FfiStatus CreateSingleThreadHkdf(rust::Slice<const uint8_t> seed,
                                 SingleThreadHkdfWrapper& out);
FfiStatus Rand8(SingleThreadHkdfWrapper& prng, uint8_t& out);

// FFI-friendly wrapper around crypto::tink::subtle::ComputeHkdf, with fixed
// hash function SHA256.
FfiStatus ComputeHkdfWrapper(rust::Slice<const uint8_t> input,
                             rust::Slice<const uint8_t> salt,
                             rust::Slice<const uint8_t> info, size_t out_len,
                             std::unique_ptr<std::string>& out);

extern "C" {
size_t SingleThreadHkdfSeedLength();
}

#endif  // SECURE_AGGREGATION_WILLOW_SRC_PRNG_SINGLE_THREAD_HKDF_WRAPPER_H_
