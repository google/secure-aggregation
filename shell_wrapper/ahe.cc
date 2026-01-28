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

#include "shell_wrapper/ahe.h"

#include <sys/types.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "ffi_utils/cxx_utils.h"
#include "ffi_utils/status.h"
#include "include/cxx.h"
#include "shell_encryption/multi_party/public_key.h"
#include "shell_encryption/multi_party/public_key_share.h"
#include "shell_encryption/multi_party/public_parameter.h"
#include "shell_encryption/multi_party/recovery.h"
#include "shell_encryption/multi_party/secret_key_share.h"
#include "shell_encryption/rns/coefficient_encoder.h"
#include "shell_encryption/rns/rns_error_params.h"
#include "shell_encryption/rns/rns_modulus.h"
#include "shell_encryption/rns/rns_polynomial.h"
#include "shell_encryption/sampler/discrete_gaussian.h"
#include "shell_wrapper/ahe.rs.h"
#include "shell_wrapper/shell_types.h"

// Friend classes to call the private constructor of `PublicKey` and
// `SecretKeyShare` directly with a polynomial obtained from a
// `RnsPolynomialWrapper`, potentially obtained by adding polynomials on the
// Rust side.
namespace rlwe {
namespace multi_party {

class SecretKeyShareRawFactory {
 public:
  static SecretKeyShare<secure_aggregation::ModularInt> Create(
      RnsPolynomial<secure_aggregation::ModularInt> key_b,
      absl::Span<const PrimeModulus<secure_aggregation::ModularInt>* const>
          moduli) {
    // `SecretKeyShare` needs a vector instead of a span.
    std::vector<const PrimeModulus<secure_aggregation::ModularInt>*>
        moduli_vector;
    moduli_vector.insert(moduli_vector.begin(), moduli.begin(), moduli.end());
    return SecretKeyShare<secure_aggregation::ModularInt>(
        std::move(key_b), std::move(moduli_vector));
  };
};

class PublicKeyRawFactory {
 public:
  static PublicKey<secure_aggregation::ModularInt> Create(
      const PublicParameter<secure_aggregation::ModularInt>* public_parameter,
      RnsPolynomial<secure_aggregation::ModularInt> key_b) {
    return PublicKey<secure_aggregation::ModularInt>(public_parameter,
                                                     std::move(key_b));
  };
};

}  // namespace multi_party
}  // namespace rlwe

namespace secure_aggregation {

FfiStatus CreateAhePublicParameters(uint64_t log_n, uint64_t t,
                                    const uint64_t* qs, uint64_t num_qs,
                                    uint64_t error_variance,
                                    double s_base_flood, double s_flood,
                                    rust::Slice<const uint8_t> seed,
                                    AhePublicParameters* out) {
  if (qs == nullptr || out == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  };

  // Parse and create RNS context.
  auto rns_context_config =
      secure_aggregation::ParseRnsContextConfig(log_n, t, qs, num_qs);
  auto rns_context = secure_aggregation::RnsContext::CreateForBfv(
      rns_context_config.log_n, rns_context_config.qs,
      /*ps=*/{}, rns_context_config.t);
  if (!rns_context.ok()) {
    return MakeFfiStatus(rns_context.status());
  }
  auto rns_context_ptr = std::make_unique<const secure_aggregation::RnsContext>(
      std::move(rns_context.value()));

  // Sample public polynomial.
  auto rlwe_public_parameter = rlwe::multi_party::
      PublicParameter<secure_aggregation::ModularInt>::CreateFromSeed(
          rns_context_ptr.get(), error_variance,
          std::string(ToAbslStringView(seed)), rlwe::PrngType::PRNG_TYPE_HKDF);
  if (!rlwe_public_parameter.ok()) {
    return MakeFfiStatus(rlwe_public_parameter.status());
  }

  // Initialize encoder, error params, and DG sampler.
  auto encoder =
      rlwe::CoefficientEncoder<secure_aggregation::ModularInt>::Create(
          rns_context_ptr.get());
  if (!encoder.ok()) {
    return MakeFfiStatus(encoder.status());
  }
  int log_t = std::floor(std::log2(static_cast<double>(rns_context_config.t)));
  auto error_params =
      rlwe::RnsErrorParams<secure_aggregation::ModularInt>::Create(
          rns_context_config.log_n, rns_context_ptr->MainPrimeModuli(),
          /*aux_moduli=*/{}, log_t, sqrt(error_variance));
  if (!error_params.ok()) {
    return MakeFfiStatus(error_params.status());
  }
  auto dg_sampler_flood =
      rlwe::DiscreteGaussianSampler<secure_aggregation::Integer>::Create(
          s_base_flood);
  if (!dg_sampler_flood.ok()) {
    return MakeFfiStatus(dg_sampler_flood.status());
  }

  out->rlwe_public_parameter = std::move(rlwe_public_parameter.value());
  out->rns_context = std::move(rns_context_ptr);
  out->encoder = std::make_unique<
      const rlwe::CoefficientEncoder<secure_aggregation::ModularInt>>(
      std::move(encoder.value()));
  out->error_params = std::make_unique<
      const rlwe::RnsErrorParams<secure_aggregation::ModularInt>>(
      std::move(error_params.value()));
  out->dg_sampler_flood = std::move(dg_sampler_flood.value());
  out->s_flood = s_flood;

  // All the unique_ptrs are non-null now.
  return MakeFfiStatus();
}

FfiStatus GenerateSecretKeyShare(const AhePublicParameters& params,
                                 SingleThreadHkdfWrapper* prng,
                                 RnsPolynomialWrapper* out) {
  if (prng == nullptr || prng->ptr == nullptr || out == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  auto secret_key_share =
      rlwe::multi_party::SecretKeyShare<secure_aggregation::ModularInt>::Sample(
          params.rns_context.get(), prng->ptr.get());
  if (!secret_key_share.ok()) {
    return MakeFfiStatus(secret_key_share.status());
  }
  out->ptr = std::make_unique<secure_aggregation::RnsPolynomial>(
      std::move(secret_key_share->Key()));
  return MakeFfiStatus();
}

FfiStatus GeneratePublicKeyShareWrapper(
    const RnsPolynomialWrapper& secret_key_share,
    const AhePublicParameters& params, SingleThreadHkdfWrapper* prng,
    RnsPolynomialWrapper* public_key_share_b,
    RnsPolynomialWrapper* public_key_share_error,
    RnsPolynomialWrapper* wraparound) {
  if (prng == nullptr || public_key_share_b == nullptr ||
      public_key_share_error == nullptr || secret_key_share.ptr == nullptr ||
      prng->ptr == nullptr || public_key_share_b->ptr == nullptr ||
      public_key_share_error->ptr == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }
  secure_aggregation::RnsPolynomial* wraparound_ptr =
      wraparound ? wraparound->ptr.get() : nullptr;
  return MakeFfiStatus(
      rlwe::multi_party::PublicKeyShare<secure_aggregation::ModularInt>::
          CreateExplicit(*secret_key_share.ptr,
                         params.rlwe_public_parameter.get(), prng->ptr.get(),
                         public_key_share_b->ptr.get(),
                         public_key_share_error->ptr.get(), wraparound_ptr));
}

FfiStatus AheEncrypt(const uint64_t* input_values, uint64_t num_input_values,
                     const RnsPolynomialWrapper& public_key_b,
                     const AhePublicParameters& params,
                     SingleThreadHkdfWrapper* prng,
                     RnsPolynomialWrapper* ciphertext_component_b,
                     RnsPolynomialWrapper* ciphertext_component_a,
                     RnsPolynomialWrapper* ciphertext_secret_r,
                     RnsPolynomialWrapper* ciphertext_error_e,
                     RnsPolynomialWrapper* wraparound) {
  if (input_values == nullptr || prng == nullptr ||
      ciphertext_component_a == nullptr || ciphertext_component_b == nullptr ||
      ciphertext_secret_r == nullptr || ciphertext_error_e == nullptr ||
      public_key_b.ptr == nullptr || prng->ptr == nullptr ||
      ciphertext_component_a->ptr == nullptr ||
      ciphertext_component_b->ptr == nullptr ||
      ciphertext_secret_r->ptr == nullptr ||
      ciphertext_error_e->ptr == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  // Create a `PublicKey` to call `EncryptExplicit` on. This copies the
  // raw polynomial contained in `public_key_b`.
  auto public_key = rlwe::multi_party::PublicKeyRawFactory::Create(
      params.rlwe_public_parameter.get(), *public_key_b.ptr);

  absl::Span<const secure_aggregation::Integer> messages =
      absl::MakeSpan(input_values, num_input_values);
  secure_aggregation::RnsPolynomial* wraparound_ptr =
      wraparound ? wraparound->ptr.get() : nullptr;
  return MakeFfiStatus(public_key.EncryptExplicit(
      messages, params.encoder.get(), params.error_params.get(),
      prng->ptr.get(), ciphertext_component_b->ptr.get(),
      ciphertext_component_a->ptr.get(), ciphertext_secret_r->ptr.get(),
      ciphertext_error_e->ptr.get(), wraparound_ptr));
}

FfiStatus PartialDecrypt(const RnsPolynomialWrapper& ciphertext_component_a,
                         const RnsPolynomialWrapper& secret_key_share,
                         const AhePublicParameters& params,
                         SingleThreadHkdfWrapper* prng,
                         RnsPolynomialWrapper* out,
                         RnsPolynomialWrapper* error_flood,
                         RnsPolynomialWrapper* wraparound) {
  if (prng == nullptr || ciphertext_component_a.ptr == nullptr ||
      secret_key_share.ptr == nullptr || prng->ptr == nullptr ||
      out == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  // Create a `SecretKeyShare` to call `PartialDecrypt` on. This copies the
  // raw polynomial and the moduli.
  auto sk = rlwe::multi_party::SecretKeyShareRawFactory::Create(
      *secret_key_share.ptr, params.rlwe_public_parameter->Moduli());

  secure_aggregation::RnsPolynomial* error_flood_ptr =
      error_flood ? error_flood->ptr.get() : nullptr;
  secure_aggregation::RnsPolynomial* wraparound_ptr =
      wraparound ? wraparound->ptr.get() : nullptr;

  auto decryption =
      sk.PartialDecrypt(*ciphertext_component_a.ptr, params.s_flood,
                        params.dg_sampler_flood.get(), prng->ptr.get(),
                        error_flood_ptr, wraparound_ptr);
  if (!decryption.ok()) {
    return MakeFfiStatus(decryption.status());
  }

  out->ptr = std::make_unique<secure_aggregation::RnsPolynomial>(
      std::move(decryption.value()));
  return MakeFfiStatus();
}

FfiStatus RecoverMessages(const RnsPolynomialWrapper& sum_partial_decryptions,
                          const RnsPolynomialWrapper& ciphertext_component_b,
                          const AhePublicParameters& params,
                          uint64_t output_values_length,
                          uint64_t* output_values, uint64_t* n_written) {
  if (output_values == nullptr || sum_partial_decryptions.ptr == nullptr ||
      ciphertext_component_b.ptr == nullptr || n_written == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  absl::StatusOr<std::vector<secure_aggregation::Integer>> messages =
      rlwe::multi_party::RecoverMessagesFromSum<secure_aggregation::ModularInt>(
          *sum_partial_decryptions.ptr, *ciphertext_component_b.ptr,
          *params.rlwe_public_parameter, params.encoder.get());

  if (!messages.ok()) {
    return MakeFfiStatus(messages.status());
  }

  // Copy messages from vector to output buffer.
  *n_written =
      std::min(output_values_length, static_cast<uint64_t>(messages->size()));
  std::copy_n(messages->begin(), *n_written, output_values);
  return MakeFfiStatus();
}

FfiStatus AddInPlace(const AhePublicParameters& params,
                     const RnsPolynomialWrapper& in,
                     RnsPolynomialWrapper* out) {
  if (in.ptr == nullptr || out == nullptr || out->ptr == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }
  return MakeFfiStatus(
      out->ptr->AddInPlace(*in.ptr, params.rlwe_public_parameter->Moduli()));
}

FfiStatus CreateZeroRnsPolynomialWrapper(const AhePublicParameters& params,
                                         RnsPolynomialWrapper* out) {
  if (out == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  auto poly = secure_aggregation::RnsPolynomial::CreateZero(
      params.rlwe_public_parameter->LogN(),
      params.rlwe_public_parameter->Moduli(),
      /*is_ntt=*/true);

  if (!poly.ok()) {
    return MakeFfiStatus(poly.status());
  }
  out->ptr = std::make_unique<secure_aggregation::RnsPolynomial>(
      std::move(poly.value()));
  return MakeFfiStatus();
}

FfiStatus PublicKeyComponentA(const AhePublicParameters& params,
                              RnsPolynomialWrapper* out) {
  if (out == nullptr || params.rlwe_public_parameter == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  out->ptr = std::make_unique<secure_aggregation::RnsPolynomial>(
      params.rlwe_public_parameter->PublicKeyComponentA());
  return MakeFfiStatus();
}

FfiStatus SFlood(const AhePublicParameters& params, double* out) {
  if (out == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }
  *out = params.s_flood;
  return MakeFfiStatus();
}

}  // namespace secure_aggregation
