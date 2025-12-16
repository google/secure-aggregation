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

// This is the API for Willow decryptors.
//
// Each function should be called once by the decryptor in the order they appear in the trait.
//
// If a function returns an error, that error can be logged and the decryptor
// should be considered to have dropped out.

use aggregation_config::AggregationConfig;
use aggregation_config_rust_proto::{
    DecryptionRequest, DecryptionResponse, KeyGenRequest, KeyGenResponse,
};

pub struct Decryptor {}

pub struct DecryptorState {}

pub struct SigningKey {
    // This is a placeholder until the signing key type is defined.
}

impl DecryptorState {
    fn serialize() -> Vec<u8> {
        unimplemented!()
    }

    fn deserialize(serialized: &[u8]) -> Result<DecryptorState, status::StatusError> {
        unimplemented!()
    }
}

pub trait DecryptorAPI {
    /// Initializes a decryptor at the beginning of an aggregation.
    /// Returns the decryptor state to be used for subsequent calls to the decryptor.
    /// signing_key: The private signing key of the decryptor, this must correspond to the
    ///              verification key provided in the config.
    /// config: The configuration of the aggregation.
    fn initialize_decryptor(
        signing_key: SigningKey,
        config: AggregationConfig,
    ) -> Result<DecryptorState, status::StatusError>;

    /// Single-decryptor case only.
    /// Run by the decryptor to generate the aggregation key.
    /// Returns a request to be sent to the clients.
    /// decryptor_state: The state of the decryptor which will be updated.
    /// request: The KeyGenRequest from the server.
    fn handle_key_gen_request(
        decryptor_state: &mut DecryptorState,
        request: KeyGenRequest,
    ) -> Result<KeyGenResponse, status::StatusError>;

    /// Run by the decryptor to decrypt the output.
    /// decryptor_state: The state of the decryptor which will be updated.
    /// decryption_request: The decryption request from the server.
    fn decrypt(
        decryptor_state: &mut DecryptorState,
        decryption_request: DecryptionRequest,
    ) -> Result<DecryptionResponse, status::StatusError>;
}
