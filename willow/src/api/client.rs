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

// This is the API for Willow clients.
//
// Each function should be called once (by each client) in the order they appear in the trait.
use aggregation_config::AggregationConfig;
use aggregation_config_rust_proto::{AggregationKey, Contribution};
use std::collections::HashMap;

pub struct Client {}

pub struct ClientState {
}

pub trait ClientAPI {
    /// Initializes a client at the beginning of an aggregation.
    /// Returns the client state to be used for subsequent calls to the client.
    /// config: The configuration of the aggregation.
    fn initialize_client(config: AggregationConfig) -> Result<ClientState, status::StatusError>;

    /// Run by the client to generate the contribution to be sent to the server.
    /// Returns the contribution to be sent to the server.
    /// aggregation_key: The aggregation key to use for the contribution.
    /// client_input: The input to be aggregated.
    fn generate_contribution(
        aggregation_key: AggregationKey,
        client_input: HashMap<String, Vec<i64>>,
    ) -> Result<Contribution, status::StatusError>;
}
