// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>
#include <memory>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "pybind11_abseil/status_casters.h"
#include "willow/input_encoding/codec.h"
#include "willow/input_encoding/codec_factory.h"
#include "willow/proto/willow/input_spec.pb.h"

namespace py = pybind11;

namespace secure_aggregation {
namespace willow {

PYBIND11_MODULE(codec_bindings, m) {
  pybind11::google::ImportStatusModule();

  py::class_<Codec>(m, "Codec")
      .def("ValidateExampleQuery",
           [](const Codec& self,
              const py::dict& query_output_specs) -> absl::Status {
             absl::flat_hash_map<std::string, std::string> cpp_map;
             for (const auto& item : query_output_specs) {
               cpp_map[item.first.cast<std::string>()] =
                   item.second.cast<std::string>();
             }
             return self.ValidateExampleQuery(cpp_map);
           });

  m.def(
      "CreateExplicitCodec",
      [](const std::string& serialized_input_spec)
          -> absl::StatusOr<std::unique_ptr<Codec>> {
        InputSpec input_spec;
        if (!input_spec.ParseFromString(serialized_input_spec)) {
          return absl::InvalidArgumentError("Failed to parse InputSpec");
        }
        return CodecFactory::CreateExplicitCodec(input_spec);
      },
      py::arg("serialized_input_spec"));

  m.def(
      "ValidateExplicitCodecInputSpec",
      [](const std::string& serialized_input_spec,
         size_t max_flattened_domain_size) -> absl::Status {
        InputSpec input_spec;
        if (!input_spec.ParseFromString(serialized_input_spec)) {
          return absl::InvalidArgumentError("Failed to parse InputSpec");
        }
        if (max_flattened_domain_size == 0) {
          return CodecFactory::ValidateExplicitCodecInputSpec(input_spec);
        } else {
          return CodecFactory::ValidateExplicitCodecInputSpec(
              input_spec, max_flattened_domain_size);
        }
      },
      py::arg("serialized_input_spec"),
      py::arg("max_flattened_domain_size") = 0);
}

}  // namespace willow
}  // namespace secure_aggregation
