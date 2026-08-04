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

use ahe_traits::AheBase;
use client_traits::SecureAggregationClient;

use accumulator_traits::SecureAggregationCiphertextAccumulator;
use googletest::prelude::container_eq;
use googletest::{gtest, verify_eq, verify_that};
use kahe_traits::KaheBase;
use messages::{
    CiphertextContribution, ClientMessage, CoordinatorState, CoordinatorStatus,
    DecryptionRequestContribution, DecryptorPublicKeyShare, PartialDecryptionRequest,
    PartialDecryptionResponse,
};
use proto_serialization_traits::{FromProto, ToProto};
use shell_kahe::ShellKahe;
use shell_parameters::{create_shell_ahe_config, create_shell_kahe_config};
use shell_vahe::ShellVahe;
use status::StatusErrorCode;
use status_matchers_rs::status_is;
use std::collections::HashMap;
use std::rc::Rc;
use testing_utils::{
    generate_aggregation_config, generate_random_nonce, generate_random_unsigned_vector,
};
use verifier_traits::SecureAggregationVerifier;
use willow_v1_accumulator::{CiphertextAccumulatorState, WillowV1CiphertextAccumulator};
use willow_v1_client::WillowV1Client;
use willow_v1_coordinator::WillowV1Coordinator;
use willow_v1_decryptor::{DecryptorState, WillowV1Decryptor};
use willow_v1_verifier::{VerifierState, WillowV1Verifier};

const CONTEXT_STRING: &[u8] = b"testing_context_string";

/// Encrypt and decrypt with a single decryptor and single client.
#[gtest]
fn encrypt_decrypt_one() -> googletest::Result<()> {
    use decryptor_traits::SecureAggregationDecryptor;
    let default_id = String::from("default");
    let aggregation_config = generate_aggregation_config(default_id.clone(), 16, 10, 1, 1);
    let max_number_of_decryptors = aggregation_config.max_number_of_decryptors;

    // Create common KAHE/VAHE instances.
    let vahe = Rc::new(ShellVahe::new(
        create_shell_ahe_config(max_number_of_decryptors)?,
        CONTEXT_STRING,
    )?);
    let kahe =
        Rc::new(ShellKahe::new(create_shell_kahe_config(&aggregation_config)?, CONTEXT_STRING)?);

    // Create client.
    let client =
        WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))?;

    let mut decryptor_state = DecryptorState::default();
    let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe))?;

    // Create accumulator.
    let accumulator =
        WillowV1CiphertextAccumulator { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
    let mut accumulator_state = CiphertextAccumulatorState::default();

    // Create verifier.
    let verifier = WillowV1Verifier { vahe: Rc::clone(&vahe) };
    let mut verifier_state = VerifierState::default();

    // Decryptor generates public key share.
    let public_key_share = decryptor.create_public_key_share(&mut decryptor_state)?;

    // Aggregate public key share directly.
    let public_key = vahe.aggregate_public_key_shares(std::iter::once(&public_key_share))?;

    // Client encrypts.
    let input_values = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
    let client_plaintext = HashMap::from([(default_id.as_str(), input_values.as_slice())]);
    let nonce = generate_random_nonce();
    let client_message = client.create_client_message(&client_plaintext, &public_key, &nonce)?;

    // The client message is split and handled by the accumulator and verifier.
    let (ciphertext_contribution, decryption_request_contribution) =
        accumulator.split_client_message(client_message)?;
    verifier.verify_and_include(decryption_request_contribution, &mut verifier_state)?;
    accumulator
        .accumulate_ciphertext_contribution(ciphertext_contribution, &mut accumulator_state)?;

    // Verifier creates the partial decryption request.
    let pd_ct = verifier.create_partial_decryption_request(verifier_state)?;

    // Decryptor creates partial decryption.
    let pd = decryptor.handle_partial_decryption_request(pd_ct, &mut decryptor_state)?;

    // Accumulator recovers the aggregation result.
    let finalized_pd =
        messages::FinalizedPartialDecryption { partial_decryption_sum: pd.partial_decryption };
    let aggregation_result =
        accumulator.recover_aggregation_result(&accumulator_state, &finalized_pd)?;

    // Check that the (padded) result matches the client plaintext.
    verify_that!(aggregation_result.keys().collect::<Vec<_>>(), container_eq([&default_id]))?;
    let client_plaintext_length = client_plaintext.get(default_id.as_str()).unwrap().len();
    verify_eq!(
        aggregation_result.get(default_id.as_str()).unwrap()[..client_plaintext_length],
        client_plaintext.get(default_id.as_str()).unwrap()[..]
    )
}

/// Encrypt and decrypt with a single decryptor and single client, using serialization.
#[gtest]
fn encrypt_decrypt_one_serialized() -> googletest::Result<()> {
    use decryptor_traits::SecureAggregationDecryptor;
    let default_id = String::from("default");
    let aggregation_config = generate_aggregation_config(default_id.clone(), 16, 10, 1, 1);
    let max_number_of_decryptors = aggregation_config.max_number_of_decryptors;

    // Create common KAHE/VAHE instances.
    let kahe =
        Rc::new(ShellKahe::new(create_shell_kahe_config(&aggregation_config)?, CONTEXT_STRING)?);
    let vahe = Rc::new(ShellVahe::new(
        create_shell_ahe_config(max_number_of_decryptors)?,
        CONTEXT_STRING,
    )?);

    // Create client.
    let client =
        WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))?;

    // Create decryptor.
    let mut decryptor_state = DecryptorState::default();
    let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe))?;

    // Create accumulator.
    let accumulator =
        WillowV1CiphertextAccumulator { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
    let mut accumulator_state = CiphertextAccumulatorState::default();

    // Create verifier.
    let verifier = WillowV1Verifier { vahe: Rc::clone(&vahe) };
    let mut verifier_state = VerifierState::default();

    // Decryptor generates public key share.
    let public_key_share = decryptor.create_public_key_share(&mut decryptor_state)?;

    // Serialize and deserialize the public key share.
    let public_key_share_proto = public_key_share.to_proto(decryptor.vahe.as_ref())?;
    let public_key_share: DecryptorPublicKeyShare<ShellVahe> =
        DecryptorPublicKeyShare::<ShellVahe>::from_proto(
            public_key_share_proto,
            accumulator.vahe.as_ref(),
        )?;

    // Aggregate public key share directly.
    let public_key = vahe.aggregate_public_key_shares(std::iter::once(&public_key_share))?;

    // Serialize and deserialize the public key.
    let public_key_proto = public_key.to_proto(accumulator.vahe.as_ref())?;
    let public_key = messages::DecryptorPublicKey::<ShellVahe>::from_proto(
        public_key_proto,
        client.vahe.as_ref(),
    )?;

    // Client encrypts.
    let client_plaintext =
        HashMap::from([(default_id.clone(), vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1])]);
    let nonce = generate_random_nonce();
    let client_message = client.create_client_message(
        &ShellKahe::plaintext_as_slice(&client_plaintext),
        &public_key,
        &nonce,
    )?;

    // Serialize and deserialize the client message.
    let client_message_proto = client_message.to_proto(&client)?;
    let client_message: ClientMessage<ShellKahe, ShellVahe> =
        ClientMessage::from_proto(client_message_proto, &accumulator)?;

    // The client message is split and handled by the accumulator and verifier.
    let (ciphertext_contribution, decryption_request_contribution) =
        accumulator.split_client_message(client_message)?;

    // Serialize and deserialize the contributions.
    let ciphertext_contribution_proto = ciphertext_contribution.to_proto(&accumulator)?;
    let ciphertext_contribution: CiphertextContribution<ShellKahe, ShellVahe> =
        CiphertextContribution::from_proto(ciphertext_contribution_proto, &accumulator)?;

    let decryption_request_contribution_proto =
        decryption_request_contribution.to_proto(&accumulator)?;
    let decryption_request_contribution: DecryptionRequestContribution<ShellVahe> =
        DecryptionRequestContribution::from_proto(
            decryption_request_contribution_proto,
            &verifier,
        )?;

    verifier.verify_and_include(decryption_request_contribution, &mut verifier_state)?;
    accumulator
        .accumulate_ciphertext_contribution(ciphertext_contribution, &mut accumulator_state)?;

    // Verifier creates the partial decryption request.
    let pd_ct = verifier.create_partial_decryption_request(verifier_state)?;

    // Serialize and deserialize the partial decryption request.
    let pd_ct_proto = pd_ct.to_proto(&verifier)?;
    let pd_ct: PartialDecryptionRequest<ShellVahe> =
        PartialDecryptionRequest::from_proto(pd_ct_proto, &decryptor)?;

    // Decryptor creates partial decryption.
    let pd = decryptor.handle_partial_decryption_request(pd_ct, &mut decryptor_state)?;

    // Serialize and deserialize the partial decryption.
    let pd_proto = pd.to_proto((&decryptor, None))?;
    let pd: PartialDecryptionResponse<ShellKahe, ShellVahe> =
        PartialDecryptionResponse::from_proto(pd_proto, &accumulator)?;

    // Accumulator recovers the aggregation result.
    let finalized_pd =
        messages::FinalizedPartialDecryption { partial_decryption_sum: pd.partial_decryption };
    let aggregation_result =
        accumulator.recover_aggregation_result(&accumulator_state, &finalized_pd)?;

    // Check that the (padded) result matches the client plaintext.
    verify_that!(aggregation_result.keys().collect::<Vec<_>>(), container_eq([&default_id]))?;
    let client_plaintext_length = client_plaintext.get(&default_id).unwrap().len();
    verify_eq!(
        aggregation_result.get(&default_id).unwrap()[..client_plaintext_length],
        client_plaintext.get(&default_id).unwrap()[..]
    )
}

// Encrypt and decrypt with multiple clients and a single decryptor.
#[gtest]
fn encrypt_decrypt_multiple_clients() -> googletest::Result<()> {
    use decryptor_traits::SecureAggregationDecryptor;
    const NUM_CLIENTS: i64 = 10;
    let default_id = String::from("default");
    let aggregation_config =
        generate_aggregation_config(default_id.clone(), 16, 10, 1, NUM_CLIENTS);
    let max_number_of_decryptors = aggregation_config.max_number_of_decryptors;

    // Create common KAHE/VAHE instances.
    let vahe = Rc::new(ShellVahe::new(
        create_shell_ahe_config(max_number_of_decryptors)?,
        CONTEXT_STRING,
    )?);
    let kahe =
        Rc::new(ShellKahe::new(create_shell_kahe_config(&aggregation_config)?, CONTEXT_STRING)?);

    // Create clients.
    let mut clients = vec![];
    for _ in 0..NUM_CLIENTS {
        let client =
            WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))?;
        clients.push(client);
    }

    // Create decryptor.
    let mut decryptor_state = DecryptorState::default();
    let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe))?;

    // Create accumulator.
    let accumulator =
        WillowV1CiphertextAccumulator { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
    let mut accumulator_state = CiphertextAccumulatorState::default();

    // Create verifier.
    let verifier = WillowV1Verifier { vahe: Rc::clone(&vahe) };
    let mut verifier_state = VerifierState::default();

    // Decryptor generates public key share.
    let public_key_share = decryptor.create_public_key_share(&mut decryptor_state)?;

    // Aggregate public key share directly.
    let public_key = vahe.aggregate_public_key_shares(std::iter::once(&public_key_share))?;

    // Clients encrypt.
    let mut expected_output = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut client_messages = vec![];
    for client in &mut clients {
        let client_input_values = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
        for i in 0..expected_output.len() {
            expected_output[i] += client_input_values[i];
        }
        let client_plaintext =
            HashMap::from([(default_id.as_str(), client_input_values.as_slice())]);
        let nonce = generate_random_nonce();
        let client_message =
            client.create_client_message(&client_plaintext, &public_key, &nonce)?;
        client_messages.push(client_message);
    }

    // Sort client messages by nonce.
    client_messages.sort_by(|a, b| a.nonce.cmp(&b.nonce));

    // Handle client messages.
    for client_message in client_messages.clone() {
        // The client message is split and handled by the accumulator and verifier.
        let (ciphertext_contribution, decryption_request_contribution) =
            accumulator.split_client_message(client_message)?;
        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state)?;
        accumulator
            .accumulate_ciphertext_contribution(ciphertext_contribution, &mut accumulator_state)?;
    }

    // Verify again using two states and merge the states to check that merge works.
    let mut verifier_state_1 = VerifierState::default();
    let mut verifier_state_2 = VerifierState::default();
    let half = client_messages.len() / 2;
    for (i, client_message) in client_messages.into_iter().enumerate() {
        let (_, decryption_request_contribution) =
            accumulator.split_client_message(client_message)?;
        let mut verifier_state =
            if i < half { &mut verifier_state_1 } else { &mut verifier_state_2 };
        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state)?;
    }
    let verifier_state_merged = verifier.merge_states(verifier_state_1, verifier_state_2)?;

    // Run the rest of the protocol twice, once with each of the the two copies of the verifier state.
    for (accumulator_state, verifier_state) in
        [(accumulator_state.clone(), verifier_state), (accumulator_state, verifier_state_merged)]
    {
        // Verifier creates the partial decryption request.
        let pd_ct = verifier.create_partial_decryption_request(verifier_state)?;

        // Decryptor creates partial decryption.
        let pd = decryptor.handle_partial_decryption_request(pd_ct, &mut decryptor_state)?;

        // Accumulator recovers the aggregation result.
        let finalized_pd =
            messages::FinalizedPartialDecryption { partial_decryption_sum: pd.partial_decryption };
        let aggregation_result =
            accumulator.recover_aggregation_result(&accumulator_state, &finalized_pd)?;

        // Check that the (padded) result matches the client plaintext.
        verify_that!(aggregation_result.keys().collect::<Vec<_>>(), container_eq([&default_id]))?;
        verify_eq!(
            aggregation_result.get(default_id.as_str()).unwrap()[..expected_output.len()],
            expected_output
        )?;
    }
    Ok(())
}

// Encrypt and decrypt with multiple clients including invalid client proofs and a single decryptor.
#[gtest]
fn encrypt_decrypt_multiple_clients_including_invalid_proofs() -> googletest::Result<()> {
    use decryptor_traits::SecureAggregationDecryptor;
    const NUM_MAX_CLIENTS: i64 = 10;
    const NUM_GOOD_CLIENTS: i64 = 10;
    const NUM_BAD_CLIENTS: i64 = 5;
    let default_id = String::from("default");
    let aggregation_config =
        generate_aggregation_config(default_id.clone(), 16, 10, 1, NUM_MAX_CLIENTS);
    let max_number_of_decryptors = aggregation_config.max_number_of_decryptors;

    // Create common KAHE/VAHE instances.
    let vahe = Rc::new(ShellVahe::new(
        create_shell_ahe_config(max_number_of_decryptors)?,
        CONTEXT_STRING,
    )?);
    let kahe =
        Rc::new(ShellKahe::new(create_shell_kahe_config(&aggregation_config)?, CONTEXT_STRING)?);

    // Create clients.
    let mut good_clients = vec![];
    for _ in 0..NUM_GOOD_CLIENTS {
        let client =
            WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))?;
        good_clients.push(client);
    }

    // Create bad clients.
    let mut bad_clients = vec![];
    for _ in 0..NUM_BAD_CLIENTS {
        let client =
            WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))?;
        bad_clients.push(client);
    }

    // Create decryptor.
    let mut decryptor_state = DecryptorState::default();
    let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe))?;

    // Create accumulator.
    let accumulator =
        WillowV1CiphertextAccumulator { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
    let mut accumulator_state = CiphertextAccumulatorState::default();

    // Create verifier.
    let verifier = WillowV1Verifier { vahe: Rc::clone(&vahe) };
    let mut verifier_state = VerifierState::default();

    // Decryptor generates public key share.
    let public_key_share = decryptor.create_public_key_share(&mut decryptor_state)?;

    // Aggregate public key share directly.
    let public_key = vahe.aggregate_public_key_shares(std::iter::once(&public_key_share))?;

    // Good Clients encrypt and should be included in the aggregation.
    let mut expected_output = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut client_messages = vec![];
    for client in &mut good_clients {
        let client_input_values = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
        for i in 0..expected_output.len() {
            expected_output[i] += client_input_values[i];
        }
        let client_plaintext =
            HashMap::from([(default_id.as_str(), client_input_values.as_slice())]);
        let nonce = generate_random_nonce();
        let client_message =
            client.create_client_message(&client_plaintext, &public_key, &nonce)?;
        client_messages.push(client_message);
    }

    // Sort client messages by nonce.
    client_messages.sort_by(|a, b| a.nonce.cmp(&b.nonce));

    // Handle client messages.
    for client_message in client_messages {
        // The client message is split and handled by the accumulator and verifier.
        let (ciphertext_contribution, decryption_request_contribution) =
            accumulator.split_client_message(client_message)?;
        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state)?;
        accumulator
            .accumulate_ciphertext_contribution(ciphertext_contribution, &mut accumulator_state)?;
    }

    // Use first bad client to create a proof object that the others will use.
    let bad_proof;
    {
        let client = &mut bad_clients[0];
        let client_input_values = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
        let client_plaintext =
            HashMap::from([(default_id.as_str(), client_input_values.as_slice())]);
        let nonce = generate_random_nonce();
        let client_message =
            client.create_client_message(&client_plaintext, &public_key, &nonce)?;
        bad_proof = client_message.proof;
    }
    // Bad Clients encrypt and should not be included in the aggregation.
    let mut client_messages = vec![];
    for i in 1..bad_clients.len() {
        let client = &mut bad_clients[i];
        let client_input_values = vec![8, 7, 6, 5, 4, 3, 2, 1, 2, 3, 4, 5, 6, 7, 8];
        let client_plaintext =
            HashMap::from([(default_id.as_str(), client_input_values.as_slice())]);
        let nonce = generate_random_nonce();
        let mut client_message =
            client.create_client_message(&client_plaintext, &public_key, &nonce)?;
        client_message.proof = bad_proof.clone();
        client_messages.push(client_message);
    }
    client_messages.sort_by(|a, b| a.nonce.cmp(&b.nonce));
    for client_message in client_messages {
        // The client message is split and handled by the accumulator and verifier.
        let (_ciphertext_contribution, decryption_request_contribution) =
            accumulator.split_client_message(client_message)?;
        verify_that!(
            verifier.verify_and_include(decryption_request_contribution, &mut verifier_state),
            status_is(StatusErrorCode::PERMISSION_DENIED)
        )?;
    }

    // Verifier creates the partial decryption request.
    let pd_ct = verifier.create_partial_decryption_request(verifier_state)?;

    // Decryptor creates partial decryption.
    let pd = decryptor.handle_partial_decryption_request(pd_ct, &mut decryptor_state)?;

    // Accumulator recovers the aggregation result.
    let finalized_pd =
        messages::FinalizedPartialDecryption { partial_decryption_sum: pd.partial_decryption };
    let aggregation_result =
        accumulator.recover_aggregation_result(&accumulator_state, &finalized_pd)?;

    // Check that the (padded) result matches the client plaintext.
    verify_that!(aggregation_result.keys().collect::<Vec<_>>(), container_eq([&default_id]))?;
    verify_eq!(
        aggregation_result.get(default_id.as_str()).unwrap()[..expected_output.len()],
        expected_output
    )
}

/// Encrypt and decrypt with multiple clients and multiple decryptors.
/// Note: This test uses RLWE parameters for production use.
#[gtest]
fn encrypt_decrypt_many_clients_decryptors() -> googletest::Result<()> {
    use decryptor_traits::{
        SecureAggregationBaseMultiDecryptor, SecureAggregationReputableDecryptor,
    };
    const INPUT_LENGTH: isize = 100_000; // 100K
    const INPUT_DOMAIN: i64 = 1i64 << 32;
    const MAX_NUM_CLIENTS: i64 = 10_000_000; // used to generate parameters.
    const MAX_NUM_DECRYPTORS: i64 = 100; // used to generate parameters.
    const NUM_CLIENTS: usize = 3; // Actual number of clients to create.
    const NUM_DECRYPTORS: usize = 3; // Actual number of decryptors to create.

    let default_id = String::from("default");
    let aggregation_config = generate_aggregation_config(
        default_id.clone(),
        INPUT_LENGTH,
        INPUT_DOMAIN,
        MAX_NUM_DECRYPTORS,
        MAX_NUM_CLIENTS,
    );
    // The parameters used by `create_shell_ahe_config` below is secure for only a single
    // decryptor when assuming all clients are corrupted. As we are testing functionality
    // here anyway, we set `max_number_of_decryptors` to 1 just to obtain the AHE parameters.
    let max_number_of_decryptors = 1;

    // Create common KAHE/VAHE instances.
    let vahe = Rc::new(
        ShellVahe::new(create_shell_ahe_config(max_number_of_decryptors).unwrap(), CONTEXT_STRING)
            .unwrap(),
    );
    let kahe = Rc::new(
        ShellKahe::new(create_shell_kahe_config(&aggregation_config).unwrap(), CONTEXT_STRING)
            .unwrap(),
    );

    // Create accumulator.
    let accumulator =
        WillowV1CiphertextAccumulator { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
    let mut accumulator_state = CiphertextAccumulatorState::default();

    // Create verifier.
    let verifier = WillowV1Verifier { vahe: Rc::clone(&vahe) };
    let mut verifier_state = VerifierState::default();

    // Create coordinator.
    let coord = WillowV1Coordinator { vahe: Rc::clone(&vahe) };
    let mut coord_state = CoordinatorState::default();

    // Create decryptors.
    let mut decryptors = vec![];
    let mut decryptor_states = vec![];
    let mut setup_contributions = vec![];
    for _ in 0..NUM_DECRYPTORS {
        let mut decryptor_state = DecryptorState::default();
        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe))?;

        // Decryptor generates its setup contribution.
        let contribution = decryptor.create_setup_contribution(&mut decryptor_state)?;
        setup_contributions.push(contribution);

        decryptors.push(decryptor);
        decryptor_states.push(decryptor_state);
    }

    // Coordinator processes setup.
    let verify_request =
        coord.handle_setup_submissions(vec![], setup_contributions, &mut coord_state)?;

    // Reputable decryptor verifies and aggregates the public key.
    let public_key = decryptors[0].verify_and_aggregate_key_contributions(verify_request)?;

    // Create clients, and each client generates their messages.
    let mut expected_output = vec![0; INPUT_LENGTH as usize];
    let mut client_messages = vec![];
    for _ in 0..NUM_CLIENTS {
        let client =
            WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))?;

        let client_input_values =
            generate_random_unsigned_vector(INPUT_LENGTH as usize, INPUT_DOMAIN as u64);
        for i in 0..expected_output.len() {
            expected_output[i] += client_input_values[i];
        }
        let client_plaintext =
            HashMap::from([(default_id.as_str(), client_input_values.as_slice())]);
        let nonce = generate_random_nonce();
        let client_message =
            client.create_client_message(&client_plaintext, &public_key, &nonce)?;
        client_messages.push(client_message);
    }

    // Sort client messages by nonce.
    client_messages.sort_by(|a, b| a.nonce.cmp(&b.nonce));

    // Handle client messages.
    for client_message in client_messages {
        // The client message is split and handled by the accumulator and verifier.
        let (ciphertext_contribution, decryption_request_contribution) =
            accumulator.split_client_message(client_message)?;
        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state)?;
        accumulator
            .accumulate_ciphertext_contribution(ciphertext_contribution, &mut accumulator_state)?;
    }

    // Verifier creates the partial decryption request.
    let pd_ct = verifier.create_partial_decryption_request(verifier_state)?;

    // Coordinator prepares decryption request.
    let pd_request =
        coord.prepare_decryption_request(&pd_ct.partial_dec_ciphertext, &mut coord_state)?;

    // Decryptors perform partial decryption.
    let mut partial_responses = vec![];
    for i in 0..NUM_DECRYPTORS {
        // Each decryptor creates partial decryption.
        let pd = decryptors[i].handle_partial_decryption_request(
            pd_request.clone(),
            Some(kahe.as_ref()),
            &mut decryptor_states[i],
        )?;
        partial_responses.push(pd);
    }

    coord.aggregate_partial_decryptions(
        partial_responses,
        Some(kahe.as_ref()),
        &mut coord_state,
    )?;
    let finalized_pd = coord.finalize_partial_decryption(&mut coord_state)?;

    // Accumulator recovers the aggregation result.
    let aggregation_result =
        accumulator.recover_aggregation_result(&accumulator_state, &finalized_pd)?;

    // Check that the (padded) result matches the client plaintext.
    verify_that!(aggregation_result.keys().collect::<Vec<_>>(), container_eq([&default_id]))?;
    verify_eq!(
        aggregation_result.get(default_id.as_str()).unwrap()[..expected_output.len()],
        expected_output
    )
}

// Encrypt and decrypt with multiple clients and multiple decryptors, but no dropout.
#[gtest]
fn encrypt_decrypt_no_dropout() -> googletest::Result<()> {
    use decryptor_traits::{
        SecureAggregationBaseMultiDecryptor, SecureAggregationReputableDecryptor,
    };
    const NUM_CLIENTS: i64 = 10;
    const NUM_DECRYPTORS: i64 = 10;
    let default_id = String::from("default");
    let aggregation_config =
        generate_aggregation_config(default_id.clone(), 16, 10, NUM_DECRYPTORS, NUM_CLIENTS);
    // The parameters used by `create_shell_ahe_config` below is secure for only a single
    // decryptor when assuming all clients are corrupted. As we are testing functionality
    // here anyway, we set `max_number_of_decryptors` to 1 just to obtain the AHE parameters.
    let max_number_of_decryptors = 1;

    // Create common KAHE/VAHE instances.
    let vahe = Rc::new(ShellVahe::new(
        create_shell_ahe_config(max_number_of_decryptors)?,
        CONTEXT_STRING,
    )?);
    let kahe =
        Rc::new(ShellKahe::new(create_shell_kahe_config(&aggregation_config)?, CONTEXT_STRING)?);

    // Create clients.
    let mut clients = vec![];
    for _ in 0..NUM_CLIENTS {
        let client =
            WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))?;
        clients.push(client);
    }

    // Create decryptors.
    let mut decryptor_states = vec![];
    let mut decryptors = vec![];
    for _ in 0..NUM_DECRYPTORS {
        let decryptor_state = DecryptorState::default();
        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe))?;
        decryptor_states.push(decryptor_state);
        decryptors.push(decryptor);
    }

    // Create accumulator.
    let accumulator =
        WillowV1CiphertextAccumulator { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
    let mut accumulator_state = CiphertextAccumulatorState::default();

    // Create verifier.
    let verifier = WillowV1Verifier { vahe: Rc::clone(&vahe) };
    let mut verifier_state = VerifierState::default();

    // Create coordinator.
    let coord = WillowV1Coordinator { vahe: Rc::clone(&vahe) };
    let mut coord_state = CoordinatorState::default();

    // Decryptors generate setup contributions.
    let mut setup_contributions = vec![];
    for i in 0..decryptors.len() {
        let contribution = decryptors[i].create_setup_contribution(&mut decryptor_states[i])?;
        setup_contributions.push(contribution);
    }

    // Coordinator processes setup.
    let verify_request =
        coord.handle_setup_submissions(vec![], setup_contributions, &mut coord_state)?;

    // Reputable decryptor verifies and aggregates the public key.
    let public_key = decryptors[0].verify_and_aggregate_key_contributions(verify_request)?;

    // Clients encrypt.
    let mut expected_output = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut client_messages = vec![];
    for client in &mut clients {
        let client_input_values = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
        for i in 0..expected_output.len() {
            expected_output[i] += client_input_values[i];
        }
        let client_plaintext =
            HashMap::from([(default_id.as_str(), client_input_values.as_slice())]);
        let nonce = generate_random_nonce();
        let client_message =
            client.create_client_message(&client_plaintext, &public_key, &nonce)?;
        client_messages.push(client_message);
    }

    // Sort client messages by nonce.
    client_messages.sort_by(|a, b| a.nonce.cmp(&b.nonce));

    // Handle client messages.
    for client_message in client_messages {
        // The client message is split and handled by the accumulator and verifier.
        let (ciphertext_contribution, decryption_request_contribution) =
            accumulator.split_client_message(client_message)?;
        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state)?;
        accumulator
            .accumulate_ciphertext_contribution(ciphertext_contribution, &mut accumulator_state)?;
    }

    // Verifier creates the partial decryption request.
    let pd_ct = verifier.create_partial_decryption_request(verifier_state)?;

    // Coordinator prepares decryption request.
    let pd_request =
        coord.prepare_decryption_request(&pd_ct.partial_dec_ciphertext, &mut coord_state)?;

    // Decryptors perform partial decryption.
    let mut partial_responses = vec![];
    for i in 0..decryptors.len() {
        let pd = decryptors[i].handle_partial_decryption_request(
            pd_request.clone(),
            Some(kahe.as_ref()),
            &mut decryptor_states[i],
        )?;
        partial_responses.push(pd);
    }

    coord.aggregate_partial_decryptions(
        partial_responses,
        Some(kahe.as_ref()),
        &mut coord_state,
    )?;
    let finalized_pd = coord.finalize_partial_decryption(&mut coord_state)?;

    // Accumulator recovers the aggregation result.
    let aggregation_result =
        accumulator.recover_aggregation_result(&accumulator_state, &finalized_pd)?;

    // Check that the (padded) result matches the client plaintext.
    verify_that!(aggregation_result.keys().collect::<Vec<_>>(), container_eq([&default_id]))?;
    verify_eq!(
        aggregation_result.get(default_id.as_str()).unwrap()[..expected_output.len()],
        expected_output
    )
}
