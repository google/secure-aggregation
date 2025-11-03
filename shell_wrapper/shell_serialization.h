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

#ifndef SECURE_AGGREGATION_SHELL_WRAPPER_SHELL_SERIALIZATION_H_
#define SECURE_AGGREGATION_SHELL_WRAPPER_SHELL_SERIALIZATION_H_

#include <cstdint>
#include <memory>
#include <string>

#include "include/cxx.h"
#include "shell_wrapper/shell_serialization.rs.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/status.rs.h"

extern "C" {

FfiStatus SerializeRnsPolynomialToBytes(const RnsPolynomialWrapper* poly,
                                        ModuliWrapper moduli,
                                        std::unique_ptr<std::string>& out);

FfiStatus DeserializeRnsPolynomialFromBytes(
    rust::Slice<const uint8_t> serialized_poly, ModuliWrapper moduli,
    RnsPolynomialWrapper* out);

}  // extern "C"

#endif  // SECURE_AGGREGATION_SHELL_WRAPPER_SHELL_SERIALIZATION_H_
