# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for codec_bindings."""

import unittest

from pybind11_abseil import status as py_status
from willow.input_encoding import codec_bindings
from willow.proto.willow import input_spec_pb2


class CodecBindingsTest(unittest.TestCase):

  def test_validate_example_query_success(self):
    spec = input_spec_pb2.InputSpec()
    metric = spec.metric_vector_specs.add()
    metric.vector_name = "metric1"
    metric.data_type = input_spec_pb2.InputSpec.INT64

    group_by = spec.group_by_vector_specs.add()
    group_by.vector_name = "group1"
    group_by.data_type = input_spec_pb2.InputSpec.STRING

    codec = codec_bindings.CreateExplicitCodec(spec.SerializeToString())

    query_specs = {
        "metric1": "INT64",
        "group1": "STRING",
    }

    # Should not raise
    codec.ValidateExampleQuery(query_specs)

  def test_validate_example_query_type_mismatch(self):
    spec = input_spec_pb2.InputSpec()
    metric = spec.metric_vector_specs.add()
    metric.vector_name = "metric1"
    metric.data_type = input_spec_pb2.InputSpec.INT64

    codec = codec_bindings.CreateExplicitCodec(spec.SerializeToString())

    query_specs = {
        "metric1": "STRING",  # Wrong type
    }

    with self.assertRaisesRegex(
        py_status.StatusNotOk, "is metric but type is not INT64"
    ):
      codec.ValidateExampleQuery(query_specs)

  def test_validate_example_query_vector_not_found(self):
    spec = input_spec_pb2.InputSpec()
    metric = spec.metric_vector_specs.add()
    metric.vector_name = "metric1"
    metric.data_type = input_spec_pb2.InputSpec.INT64

    codec = codec_bindings.CreateExplicitCodec(spec.SerializeToString())

    query_specs = {
        "unknown_vector": "INT64",
    }

    with self.assertRaisesRegex(
        py_status.StatusNotOk, "not found in input spec"
    ):
      codec.ValidateExampleQuery(query_specs)


if __name__ == "__main__":
  unittest.main()
