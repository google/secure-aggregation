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

use aggregation_config_rust_proto::AggregationConfigProto;
use aggregation_config_rust_proto::VectorConfig;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use protobuf::AsView;
use status::StatusError;
use std::collections::HashMap;

/// The configuration of the aggregation.
/// vector_lengths_and_bounds: The length and upper bound of each vector to be aggregated,
///                            indexed by the name of the vector.
/// max_number_of_decryptors:  The maximum number of decryptors that will participate in the
///                            aggregation.
/// max_decryptor_dropouts:    The maximum number decryptors that can drop out without the
///                            aggregation failing.
/// max_number_of_clients:     The maximum number of clients that will participate in the
///                            aggregation.
/// session_id:                The session id of the aggregation.
/// willow_version:            The version of the willow protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregationConfig {
    pub vector_lengths_and_bounds: HashMap<String, (isize, i64)>,
    pub max_number_of_decryptors: i64,
    pub max_decryptor_dropouts: i64,
    pub max_number_of_clients: i64,
    pub session_id: String,
}

impl FromProto for AggregationConfig {
    type Proto = AggregationConfigProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        _context: (),
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        Ok(AggregationConfig {
            vector_lengths_and_bounds: proto
                .vector_configs()
                .iter()
                .map(|(key, value)| (key.to_string(), (value.length() as isize, value.bound())))
                .collect(),
            max_number_of_decryptors: proto.max_number_of_decryptors(),
            max_decryptor_dropouts: proto.max_decryptor_dropouts(),
            max_number_of_clients: proto.max_number_of_clients(),
            session_id: proto.session_id().to_string(),
        })
    }
}

impl ToProto for AggregationConfig {
    type Proto = AggregationConfigProto;

    fn to_proto(&self, _context: ()) -> Result<Self::Proto, StatusError> {
        let mut aggregation_config_proto = proto!(AggregationConfigProto {
            vector_configs: protobuf::Map::default(),
            max_number_of_decryptors: self.max_number_of_decryptors,
            max_decryptor_dropouts: self.max_decryptor_dropouts,
            max_number_of_clients: self.max_number_of_clients,
            session_id: self.session_id.clone(),
        });
        aggregation_config_proto.vector_configs_mut().copy_from(
            self.vector_lengths_and_bounds.iter().map(|(key, (length, bound))| {
                (key.as_str(), proto!(VectorConfig { length: *length as i64, bound: *bound }))
            }),
        );
        Ok(aggregation_config_proto)
    }
}

#[cfg(test)]
mod tests {
    use crate::AggregationConfig;
    use googletest::{gtest, matchers::eq, verify_that};
    use proto_serialization_traits::{FromProto, ToProto};
    use std::collections::HashMap;

    #[gtest]
    fn convert_to_and_from_proto() -> googletest::Result<()> {
        let aggregation_config = AggregationConfig {
            vector_lengths_and_bounds: HashMap::from([("default".to_string(), (16, 10))]),
            max_number_of_decryptors: 1,
            max_decryptor_dropouts: 0,
            max_number_of_clients: 1,
            session_id: String::from("test"),
        };

        verify_that!(
            AggregationConfig::from_proto(
                AggregationConfig::to_proto(&aggregation_config, ())?,
                ()
            )?,
            eq(&aggregation_config),
        )
    }
}
