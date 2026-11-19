// Copyright 2026 Google LLC
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

use ahe_traits::{AheBase, AheKeygen, PartialDec};
use feldman_vss::{self, derive_keygen_seed, Share};
use kahe_traits::KaheBase;
use messages::{
    compute_setup_transcript_hash, CommitteeConfig, CoordinatorState, CoordinatorStatus,
    DealerSetupInfo, FinalizedPartialDecryption, KeyContribution, PartialDecryptionRequest,
    PartialDecryptionResponse, RecoveryRequest, RecoveryResponse, SetupContribution,
    VerifyKeyContributionsRequest,
};
use prng_traits::SecurePrng;
use proto_serialization_traits::ToProto;
use protobuf::Serialize;
use shell_ciphertexts_rust_proto::ShellAhePublicKeyShare;
use status::StatusError;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::rc::Rc;
use vahe_traits::{HasVahe, VaheBase};

pub use messages::MAX_ENCRYPTED_SHARE_BYTES;

/// Coordinator implementation for the multi-decryptor Willow protocol.
///
/// The coordinator manages protocol flow and aggregates messages from all
/// decryptors. The coordinator itself does not contribute to the public key.
///
/// The coordinator is not trusted for security at all, it does not hold any secrets and the
/// protocol is secure even if it behaves arbitrarily.
/// As such it need not be run on secure hardware, however it does need access to the
/// cryptographic library for most of these functions.
pub struct Coordinator<Vahe: VaheBase> {
    pub vahe: Rc<Vahe>,
}

impl<Vahe: VaheBase> HasVahe for Coordinator<Vahe> {
    type Vahe = Vahe;
    fn vahe(&self) -> &Self::Vahe {
        &self.vahe
    }
}

impl<Vahe: VaheBase + PartialDec> Coordinator<Vahe> {
    /// Configures `coordinator_state` for a recoverable multi-decryptor committee session.
    /// Must be called while `coordinator_state.status == CoordinatorStatus::PreSetup`.
    pub fn configure_committee(
        &self,
        committee_config: CommitteeConfig,
        coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<(), StatusError> {
        if coordinator_state.status != CoordinatorStatus::PreSetup {
            return Err(status::failed_precondition(
                "configure_committee requires Coordinator in PreSetup state",
            ));
        }
        committee_config.validate()?;
        coordinator_state.committee_config = Some(committee_config);
        Ok(())
    }

    /// Stores setup contributions from all decryptors and creates a request to verify the
    /// contributions.
    ///
    /// In recoverable committee mode (`coordinator_state.committee_config.is_some()`, or when
    /// any contribution carries recoverable fields):
    /// 1. Validates pairwise-distinct `decryptor_index` in `1..=num_decryptors` across all
    ///    `non_reputable_contributions` (`len == num_decryptors`).
    /// 2. Validates `feldman_commitment.threshold() == committee_config.threshold`.
    /// 3. Validates that each dealer's `indexed_encrypted_shares` contains exact keys
    ///    `{1..=num_decryptors} \ {dealer_index}` with non-empty ciphertexts bounded by
    ///    `MAX_ENCRYPTED_SHARE_BYTES`.
    /// 4. Computes `setup_transcript_hash = compute_setup_transcript_hash(...)` and stores
    ///    `dealer_setup_info` in `coordinator_state`.
    pub fn handle_setup_submissions(
        &self,
        non_reputable_contributions: Vec<SetupContribution<Vahe>>,
        reputable_contributions: Vec<SetupContribution<Vahe>>,
        coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<VerifyKeyContributionsRequest<Vahe>, StatusError> {
        if coordinator_state.status != CoordinatorStatus::PreSetup {
            return Err(status::failed_precondition("Coordinator is not in PreSetup state"));
        }

        let has_recoverable_fields =
            non_reputable_contributions.iter().chain(reputable_contributions.iter()).any(|c| {
                c.decryptor_index.is_some()
                    || c.feldman_commitment.is_some()
                    || !c.indexed_encrypted_shares.is_empty()
            });

        if coordinator_state.committee_config.is_some() || has_recoverable_fields {
            let cfg = coordinator_state
                .committee_config
                .as_ref()
                .ok_or_else(|| {
                    status::failed_precondition(
                        "CoordinatorState is missing committee_config for recoverable setup contributions",
                    )
                })?
                .clone();
            cfg.validate()?;

            if non_reputable_contributions.len() != cfg.num_decryptors as usize {
                return Err(status::invalid_argument(
                    "non_reputable_contributions count must equal committee_config.num_decryptors",
                ));
            }
            for rep in &reputable_contributions {
                if rep.decryptor_index.is_some()
                    || rep.feldman_commitment.is_some()
                    || !rep.indexed_encrypted_shares.is_empty()
                    || rep.encrypted_randomness_shares.is_some()
                {
                    return Err(status::invalid_argument(
                        "reputable_contributions must not carry recoverable share fields",
                    ));
                }
            }

            let mut dealer_setup_info = BTreeMap::new();
            let mut dealer_commitments = BTreeMap::new();
            let mut key_contributions_by_index = BTreeMap::new();

            for contribution in non_reputable_contributions {
                if contribution.encrypted_randomness_shares.is_some() {
                    return Err(status::invalid_argument(
                        "recoverable SetupContribution must not populate legacy encrypted_randomness_shares",
                    ));
                }
                let dealer_index = contribution.decryptor_index.ok_or_else(|| {
                    status::invalid_argument(
                        "recoverable SetupContribution is missing decryptor_index",
                    )
                })?;
                if dealer_index.get() > cfg.num_decryptors {
                    return Err(status::invalid_argument(
                        "SetupContribution decryptor_index exceeds committee_config.num_decryptors",
                    ));
                }
                if dealer_setup_info.contains_key(&dealer_index) {
                    return Err(status::invalid_argument(
                        "Duplicate decryptor_index in non_reputable_contributions",
                    ));
                }
                let feldman_commitment = contribution.feldman_commitment.ok_or_else(|| {
                    status::invalid_argument(
                        "recoverable SetupContribution is missing feldman_commitment",
                    )
                })?;
                if feldman_commitment.threshold() != cfg.threshold as usize {
                    return Err(status::invalid_argument(
                        "SetupContribution feldman_commitment threshold does not match committee_config.threshold",
                    ));
                }
                if contribution.indexed_encrypted_shares.len() != (cfg.num_decryptors - 1) as usize
                {
                    return Err(status::invalid_argument(
                        "SetupContribution indexed_encrypted_shares count must equal num_decryptors - 1",
                    ));
                }
                for peer_raw in 1..=cfg.num_decryptors {
                    let peer_idx = NonZeroU32::new(peer_raw).ok_or_else(|| {
                        status::internal("peer index in 1..=num_decryptors must be non-zero")
                    })?;
                    if peer_idx == dealer_index {
                        if contribution.indexed_encrypted_shares.contains_key(&peer_idx) {
                            return Err(status::invalid_argument(
                                "SetupContribution indexed_encrypted_shares must not contain self-share",
                            ));
                        }
                        continue;
                    }
                    let ct = contribution.indexed_encrypted_shares.get(&peer_idx).ok_or_else(
                        || {
                            status::invalid_argument(
                                "SetupContribution indexed_encrypted_shares is missing peer recipient_index",
                            )
                        },
                    )?;
                    if ct.is_empty() || ct.len() > MAX_ENCRYPTED_SHARE_BYTES {
                        return Err(status::invalid_argument(
                            "SetupContribution encrypted share size out of bounds (1..=MAX_ENCRYPTED_SHARE_BYTES)",
                        ));
                    }
                }

                let public_key_share = contribution.key_contribution.public_key_share.clone();
                dealer_commitments.insert(dealer_index, feldman_commitment.clone());
                dealer_setup_info.insert(
                    dealer_index,
                    DealerSetupInfo {
                        dealer_index,
                        feldman_commitment,
                        public_key_share,
                        encrypted_shares: contribution.indexed_encrypted_shares,
                    },
                );
                key_contributions_by_index.insert(dealer_index, contribution.key_contribution);
            }

            let transcript_hash = compute_setup_transcript_hash(
                &cfg.roster_hash,
                &cfg.session_context,
                cfg.threshold,
                cfg.num_decryptors,
                &dealer_commitments,
            )?;

            let mut all_key_contributions: Vec<_> =
                key_contributions_by_index.into_values().collect();
            let mut saved_reputable_contributions =
                Vec::with_capacity(reputable_contributions.len());
            for rep in reputable_contributions {
                saved_reputable_contributions.push(SetupContribution {
                    key_contribution: KeyContribution {
                        public_key_share: rep.key_contribution.public_key_share.clone(),
                        proof: None,
                    },
                    dp_setup: None,
                    encrypted_randomness_shares: None,
                    decryptor_index: None,
                    feldman_commitment: None,
                    indexed_encrypted_shares: BTreeMap::new(),
                });
                all_key_contributions.push(rep.key_contribution);
            }

            for (i, kc_i) in all_key_contributions.iter().enumerate() {
                for kc_j in &all_key_contributions[i + 1..] {
                    if kc_i.public_key_share == kc_j.public_key_share {
                        return Err(status::invalid_argument(
                            "Duplicate public_key_share in setup submissions",
                        ));
                    }
                }
            }

            coordinator_state.setup_contributions = if saved_reputable_contributions.is_empty() {
                None
            } else {
                Some(saved_reputable_contributions)
            };
            coordinator_state.dealer_setup_info = dealer_setup_info;
            coordinator_state.setup_transcript_hash = Some(transcript_hash);
            coordinator_state.status = CoordinatorStatus::KeySharesReceived;

            return Ok(VerifyKeyContributionsRequest { key_contributions: all_key_contributions });
        }

        let mut all_key_contributions = Vec::new();
        let mut pending_randomness_shares = Vec::new();

        // Collect contributions. The coordinator does not verify proofs — that is the
        // reputable decryptor's responsibility (the coordinator is untrusted).
        for contribution in non_reputable_contributions.into_iter().chain(reputable_contributions) {
            // Store encrypted randomness shares from non-reputable decryptors.
            if let Some(shares) = contribution.encrypted_randomness_shares {
                pending_randomness_shares.push(shares);
            }

            all_key_contributions.push(contribution.key_contribution);
        }

        for (i, kc_i) in all_key_contributions.iter().enumerate() {
            for kc_j in &all_key_contributions[i + 1..] {
                if kc_i.public_key_share == kc_j.public_key_share {
                    return Err(status::invalid_argument(
                        "Duplicate public_key_share in setup submissions",
                    ));
                }
            }
        }

        coordinator_state.encrypted_randomness_shares.extend(pending_randomness_shares);
        coordinator_state.status = CoordinatorStatus::KeySharesReceived;

        Ok(VerifyKeyContributionsRequest { key_contributions: all_key_contributions })
    }

    /// Combines the verifier's ciphertext half with the accumulated AHE components.
    ///
    /// The result should be forwarded to decryptors for partial decryption.
    pub fn prepare_decryption_request(
        &self,
        verifier_ciphertext: &<Vahe as AheBase>::PartialDecCiphertext,
        coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<PartialDecryptionRequest<Vahe>, StatusError> {
        if coordinator_state.status != CoordinatorStatus::KeySharesReceived {
            return Err(status::failed_precondition(
                "Coordinator is not in KeySharesReceived state. \
                 Call handle_setup_submissions first.",
            ));
        }

        let partial_dec_ciphertext = verifier_ciphertext.clone();

        coordinator_state.partial_dec_ciphertext = Some(partial_dec_ciphertext.clone());
        coordinator_state.responded_decryptor_indices.clear();
        coordinator_state.status = CoordinatorStatus::AwaitingPartialDecryptions;

        Ok(PartialDecryptionRequest { partial_dec_ciphertext, aggregation_config: None })
    }

    /// Accumulates partial decryptions from responding decryptors.
    ///
    /// In recoverable committee mode (`coordinator_state.committee_config.is_some()`):
    /// - Validates that each committee `PartialDecryptionResponse` has a pairwise-distinct
    ///   `decryptor_index` in `1..=num_decryptors`.
    /// - Requires at least `threshold` committee responses (`d <= num_decryptors - threshold`);
    ///   aborts if fewer than `threshold` decryptors responded.
    /// - Transitions `coordinator_state.status` to `CoordinatorStatus::OutputReady` when all
    ///   `num_decryptors` responded (`d == 0`), or to `CoordinatorStatus::AwaitingRecovery` when `0
    ///   < d <= num_decryptors - threshold`.
    pub fn aggregate_partial_decryptions<Kahe: KaheBase>(
        &self,
        partial_responses: Vec<PartialDecryptionResponse<Kahe, Vahe>>,
        _kahe: Option<&Kahe>,
        coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<(), StatusError> {
        if coordinator_state.status != CoordinatorStatus::AwaitingPartialDecryptions {
            return Err(status::failed_precondition(
                "Coordinator is not in AwaitingPartialDecryptions state",
            ));
        }
        if partial_responses.is_empty() {
            return Err(status::invalid_argument("No partial decryptions provided"));
        }

        if let Some(cfg) = &coordinator_state.committee_config {
            let expected_reputable_count =
                coordinator_state.setup_contributions.as_ref().map_or(0, |v| v.len());
            let mut unindexed_count = 0usize;
            let mut responded_indices = coordinator_state.responded_decryptor_indices.clone();
            let mut partial_responses_iter = partial_responses.into_iter();
            let first = partial_responses_iter
                .next()
                .ok_or_else(|| status::invalid_argument("No partial decryptions provided"))?;
            if let Some(idx) = first.decryptor_index {
                if idx.get() > cfg.num_decryptors
                    || !coordinator_state.dealer_setup_info.contains_key(&idx)
                {
                    return Err(status::invalid_argument(
                        "PartialDecryptionResponse decryptor_index is not in committee",
                    ));
                }
                if !responded_indices.insert(idx) {
                    return Err(status::invalid_argument(
                        "Duplicate decryptor_index in partial_responses",
                    ));
                }
            } else if expected_reputable_count == 0 {
                return Err(status::invalid_argument(
                    "PartialDecryptionResponse is missing decryptor_index in committee mode",
                ));
            } else {
                unindexed_count += 1;
            }
            let mut sum = first.partial_decryption;

            for response in partial_responses_iter {
                if let Some(idx) = response.decryptor_index {
                    if idx.get() > cfg.num_decryptors
                        || !coordinator_state.dealer_setup_info.contains_key(&idx)
                    {
                        return Err(status::invalid_argument(
                            "PartialDecryptionResponse decryptor_index is not in committee",
                        ));
                    }
                    if !responded_indices.insert(idx) {
                        return Err(status::invalid_argument(
                            "Duplicate decryptor_index in partial_responses",
                        ));
                    }
                } else if expected_reputable_count == 0 {
                    return Err(status::invalid_argument(
                        "PartialDecryptionResponse is missing decryptor_index in committee mode",
                    ));
                } else {
                    unindexed_count += 1;
                }
                self.vahe
                    .add_partial_decryptions_in_place(&response.partial_decryption, &mut sum)?;
            }

            if unindexed_count != expected_reputable_count {
                return Err(status::invalid_argument(
                    "Count of unindexed reputable PartialDecryptionResponses does not match setup reputable_contributions count",
                ));
            }
            if responded_indices.len() < cfg.threshold as usize {
                return Err(status::failed_precondition(
                    "Insufficient partial decryption responses: fewer than threshold decryptors responded",
                ));
            }

            let num_decryptors = cfg.num_decryptors as usize;
            let num_responded = responded_indices.len();
            coordinator_state.responded_decryptor_indices = responded_indices;
            coordinator_state.partial_decryption_sum = Some(sum);
            if num_responded == num_decryptors {
                coordinator_state.status = CoordinatorStatus::OutputReady;
            } else {
                coordinator_state.status = CoordinatorStatus::AwaitingRecovery;
            }
            return Ok(());
        }

        // Legacy / non-recoverable mode (`committee_config.is_none()`):
        let mut partial_responses_iter = partial_responses.into_iter();
        let mut sum = partial_responses_iter
            .next()
            .ok_or_else(|| status::invalid_argument("No partial decryptions provided"))?
            .partial_decryption;
        for response in partial_responses_iter {
            self.vahe.add_partial_decryptions_in_place(&response.partial_decryption, &mut sum)?;
        }

        coordinator_state.partial_decryption_sum = Some(sum);
        coordinator_state.status = CoordinatorStatus::OutputReady;

        Ok(())
    }

    /// Creates recovery requests keyed by 1-based surviving `decryptor_index`
    /// (`responded_decryptor_indices`) to decrypt shares of dropped decryptors.
    ///
    /// If `coordinator_state.status == CoordinatorStatus::OutputReady` (0 dropouts), returns an
    /// empty map.
    pub fn create_indexed_recovery_requests(
        &self,
        coordinator_state: &CoordinatorState<Vahe>,
    ) -> Result<BTreeMap<NonZeroU32, RecoveryRequest>, StatusError> {
        if coordinator_state.status == CoordinatorStatus::OutputReady {
            return Ok(BTreeMap::new());
        }
        if coordinator_state.status != CoordinatorStatus::AwaitingRecovery {
            return Err(status::failed_precondition(
                "create_recovery_requests requires Coordinator in AwaitingRecovery or OutputReady state",
            ));
        }
        let cfg = coordinator_state.committee_config.as_ref().ok_or_else(|| {
            status::failed_precondition(
                "create_recovery_requests requires committee_config in CoordinatorState",
            )
        })?;
        if coordinator_state.dealer_setup_info.len() != cfg.num_decryptors as usize {
            return Err(status::failed_precondition(
                "CoordinatorState dealer_setup_info is incomplete",
            ));
        }

        let mut dropped_indices = Vec::new();
        let mut dealer_commitments = BTreeMap::new();
        for i in 1..=cfg.num_decryptors {
            let idx = NonZeroU32::new(i).ok_or_else(|| {
                status::internal("committee index in 1..=num_decryptors must be non-zero")
            })?;
            let info = coordinator_state.dealer_setup_info.get(&idx).ok_or_else(|| {
                status::failed_precondition("dealer_setup_info missing committee member")
            })?;
            dealer_commitments.insert(idx, info.feldman_commitment.clone());
            if !coordinator_state.responded_decryptor_indices.contains(&idx) {
                dropped_indices.push(idx);
            }
        }

        let max_dropouts = (cfg.num_decryptors - cfg.threshold) as usize;
        if dropped_indices.is_empty() || dropped_indices.len() > max_dropouts {
            return Err(status::failed_precondition(
                "Number of dropped decryptors is outside valid recovery range 1..=(num_decryptors - threshold)",
            ));
        }

        let mut requests = BTreeMap::new();
        for &survivor_idx in &coordinator_state.responded_decryptor_indices {
            let mut indexed_encrypted_shares = BTreeMap::new();
            for &dropped_idx in &dropped_indices {
                let dealer_info = &coordinator_state.dealer_setup_info[&dropped_idx];
                let ct = dealer_info.encrypted_shares.get(&survivor_idx).ok_or_else(|| {
                    status::failed_precondition(
                        "dealer_setup_info missing encrypted share for survivor",
                    )
                })?;
                indexed_encrypted_shares.insert(dropped_idx, ct.clone());
            }
            requests.insert(
                survivor_idx,
                RecoveryRequest {
                    encrypted_shares: Vec::new(),
                    indexed_encrypted_shares,
                    dealer_commitments: dealer_commitments.clone(),
                },
            );
        }

        Ok(requests)
    }

    /// Creates recovery requests for surviving decryptors (ordered by ascending
    /// `responded_decryptor_indices`) to decrypt shares of dropped decryptors.
    ///
    /// If the vector is empty, there are no dropped decryptors to recover and
    /// `recover_dropped_decryptors` can be called immediately with an empty vector.
    pub fn create_recovery_requests(
        &self,
        coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<Vec<RecoveryRequest>, StatusError> {
        let indexed = self.create_indexed_recovery_requests(coordinator_state)?;
        Ok(indexed.into_values().collect())
    }

    /// Recovers secret key shares of dropped decryptors from survivor `RecoveryResponse`s
    /// and accumulates their simulated partial decryptions into `coordinator_state`:
    /// 1. Deduplicates `RecoveryResponse`s by `survivor_index` (must belong to
    ///    `coordinator_state.responded_decryptor_indices` and never spoof another member's
    ///    `Share.index`).
    /// 2. Filters shares through `feldman_vss::verify_share` against each dropped dealer's setup
    ///    `FeldmanCommitment` (skipping invalid shares from corrupt survivors so recovery succeeds
    ///    whenever at least `threshold` valid shares are available).
    /// 3. Reconstructs `vss_secret` via `feldman_vss::reconstruct(&commitment_k,
    ///    &valid_shares[..t])`, re-derives `keygen_seed = derive_keygen_seed(...)`, and regenerates
    ///    `(recovered_sk_k, recovered_pk_k)` via fast non-ZK `vahe.key_gen(&mut keygen_prng)`.
    /// 4. Enforces **Willow Paper Fig. 10 Step 14 (`recovered_pk_k == setup_pk_k`)**, aborting with
    ///    `PERMISSION_DENIED` if a malicious dealer shared a seed inconsistent with its setup
    ///    `public_key_share`. Note: because Feldman VSS commits to the Ristretto255 seed scalar
    ///    `s_k` whereas `public_key_share` is a lattice RLWE public key generated from `HKDF(s_k)`,
    ///    a malicious dealer can share a valid VSS polynomial for a scalar `s'_k` unrelated to its
    ///    setup `public_key_share` and then drop out, causing recovery to abort at Step 14. This is
    ///    a bounded denial-of-service lever (identical to submitting an invalid setup proof in
    ///    `verify_and_aggregate_key_contributions`) and preserves input privacy under Willow's
    ///    non-guaranteed-output-delivery threat model.
    /// 5. Computes `vahe.partial_decrypt(&ct_1, &recovered_sk_k, &mut fresh_flooding_prng)` using a
    ///    **fresh** PRNG seed (never reusing `keygen_prng`) and transitions to
    ///    `CoordinatorStatus::OutputReady`. Ephemeral recovery secrets (`vss_secret`,
    ///    `keygen_seed`, `flooding_seed`, and `recovered_sk`) are dropped at the end of each
    ///    dropped-dealer iteration immediately after computing `simulated_pd`.
    pub fn recover_dropped_decryptors(
        &self,
        recovery_responses: Vec<RecoveryResponse>,
        coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<(), StatusError>
    where
        Vahe: AheKeygen,
        Vahe::Rng: SecurePrng<Seed = single_thread_hkdf::Seed>,
        for<'a> Vahe::PublicKeyShare: ToProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
    {
        if coordinator_state.status == CoordinatorStatus::OutputReady
            && recovery_responses.is_empty()
        {
            return Ok(());
        }
        if coordinator_state.status != CoordinatorStatus::AwaitingRecovery {
            return Err(status::failed_precondition(
                "recover_dropped_decryptors requires Coordinator in AwaitingRecovery state",
            ));
        }

        let cfg = coordinator_state
            .committee_config
            .as_ref()
            .ok_or_else(|| {
                status::failed_precondition(
                    "recover_dropped_decryptors requires committee_config in CoordinatorState",
                )
            })?
            .clone();
        let ct_1 = coordinator_state.partial_dec_ciphertext.as_ref().ok_or_else(|| {
            status::failed_precondition(
                "CoordinatorState is missing partial_dec_ciphertext for recovery",
            )
        })?;
        let mut pd_sum = coordinator_state
            .partial_decryption_sum
            .as_ref()
            .ok_or_else(|| {
                status::failed_precondition(
                    "CoordinatorState is missing partial_decryption_sum for recovery",
                )
            })?
            .clone();

        let mut dropped_indices = BTreeSet::new();
        for i in 1..=cfg.num_decryptors {
            let idx = NonZeroU32::new(i).ok_or_else(|| {
                status::internal("committee index in 1..=num_decryptors must be non-zero")
            })?;
            if !coordinator_state.responded_decryptor_indices.contains(&idx) {
                dropped_indices.insert(idx);
            }
        }
        if dropped_indices.is_empty()
            || dropped_indices.len() > (cfg.num_decryptors - cfg.threshold) as usize
        {
            return Err(status::failed_precondition(
                "Number of dropped decryptors is outside valid recovery range",
            ));
        }

        let mut seen_survivors = BTreeSet::new();
        let mut valid_shares_by_dealer: BTreeMap<NonZeroU32, Vec<Share>> = BTreeMap::new();

        for response in recovery_responses {
            if !response.decrypted_shares.is_empty() {
                return Err(status::invalid_argument(
                    "RecoveryResponse must not populate legacy unindexed decrypted_shares",
                ));
            }
            let survivor_idx = response.survivor_index.ok_or_else(|| {
                status::invalid_argument("RecoveryResponse is missing survivor_index")
            })?;
            if !coordinator_state.responded_decryptor_indices.contains(&survivor_idx) {
                return Err(status::invalid_argument(
                    "RecoveryResponse survivor_index is not in responded_decryptor_indices",
                ));
            }
            if !seen_survivors.insert(survivor_idx) {
                return Err(status::invalid_argument(
                    "Duplicate survivor_index in recovery_responses",
                ));
            }

            for (&dealer_idx, share) in &response.indexed_decrypted_shares {
                if !dropped_indices.contains(&dealer_idx) || share.index != survivor_idx {
                    continue;
                }
                let dealer_info =
                    coordinator_state.dealer_setup_info.get(&dealer_idx).ok_or_else(|| {
                        status::failed_precondition(
                            "dealer_setup_info missing dropped dealer_index",
                        )
                    })?;
                // Filter decrypted shares through `feldman_vss::verify_share`: skip bad shares
                // from corrupt survivors rather than aborting when >= threshold valid shares exist.
                if feldman_vss::verify_share(&dealer_info.feldman_commitment, share).is_ok() {
                    valid_shares_by_dealer.entry(dealer_idx).or_default().push(share.clone());
                }
            }
        }

        let threshold = cfg.threshold as usize;
        for &dealer_idx in &dropped_indices {
            let dealer_info =
                coordinator_state.dealer_setup_info.get(&dealer_idx).ok_or_else(|| {
                    status::failed_precondition("dealer_setup_info missing dropped dealer_index")
                })?;
            let valid_shares = valid_shares_by_dealer.get(&dealer_idx).ok_or_else(|| {
                status::failed_precondition(
                    "No valid recovery shares received for dropped decryptor",
                )
            })?;
            if valid_shares.len() < threshold {
                return Err(status::failed_precondition(
                    "Insufficient valid recovery shares (< threshold) for dropped decryptor",
                ));
            }

            let vss_secret = feldman_vss::reconstruct(
                &dealer_info.feldman_commitment,
                &valid_shares[..threshold],
            )?;
            let keygen_seed = derive_keygen_seed(
                &vss_secret,
                &cfg.session_context,
                &cfg.roster_hash,
                dealer_idx,
            )?;
            let mut keygen_prng = Vahe::Rng::create(&keygen_seed)?;
            let (recovered_sk, recovered_pk, _metadata) = self.vahe.key_gen(&mut keygen_prng)?;

            // Willow Paper Fig. 10 Step 14: verify `recovered_pk == setup_pk`.
            let recovered_pk_bytes = recovered_pk
                .to_proto(self.vahe.as_ref())?
                .serialize()
                .map_err(|_| status::internal("Failed to serialize recovered PublicKeyShare"))?;
            let expected_pk_bytes = dealer_info
                .public_key_share
                .to_proto(self.vahe.as_ref())?
                .serialize()
                .map_err(|_| status::internal("Failed to serialize expected PublicKeyShare"))?;
            if recovered_pk_bytes != expected_pk_bytes {
                return Err(status::permission_denied(
                    "Regenerated public key share does not match dealer's setup public key share (Willow Fig. 10 Step 14)",
                ));
            }

            // Compute simulated partial decryption using a FRESH flooding PRNG seed
            // (never reusing `keygen_prng`).
            let flooding_seed = Vahe::Rng::generate_seed()?;
            let mut fresh_flooding_prng = Vahe::Rng::create(&flooding_seed)?;
            let simulated_pd =
                self.vahe.partial_decrypt(ct_1, &recovered_sk, &mut fresh_flooding_prng)?;
            self.vahe.add_partial_decryptions_in_place(&simulated_pd, &mut pd_sum)?;
        }

        coordinator_state.partial_decryption_sum = Some(pd_sum);
        coordinator_state.status = CoordinatorStatus::OutputReady;
        Ok(())
    }

    /// Returns the finalized partial decryption.
    ///
    /// This can be combined with the aggregated client
    /// CiphertextContributions (KAHE ciphertext and AHE recover_plaintext ct_0) to
    /// obtain the final noisy KAHE plaintext.
    pub fn finalize_partial_decryption(
        &self,
        coordinator_state: &mut CoordinatorState<Vahe>,
    ) -> Result<FinalizedPartialDecryption<Vahe>, StatusError> {
        if coordinator_state.status != CoordinatorStatus::OutputReady {
            return Err(status::failed_precondition("Coordinator is not in OutputReady state"));
        }
        let partial_decryption_sum = coordinator_state
            .partial_decryption_sum
            .clone()
            .ok_or_else(|| status::failed_precondition("partial_decryption_sum is not set"))?;
        coordinator_state.status = CoordinatorStatus::Finished;
        Ok(FinalizedPartialDecryption { partial_decryption_sum })
    }
}

#[cfg(test)]
mod tests {
    use crate::{Coordinator, MAX_ENCRYPTED_SHARE_BYTES};
    use ahe_traits::AheBase;

    use decryptor::{Decryptor, DecryptorState};
    use feldman_vss::{SecretScalar, Share};
    use googletest::gtest;
    use googletest::prelude::*;
    use messages::{
        compute_roster_hash, CommitteeConfig, CoordinatorState, CoordinatorStatus, DecryptorStatus,
        RecoveryResponse, SecretSharingContribution,
    };
    use messages_rust_proto::CoordinatorStatus as CoordinatorStatusProto;
    use prng_traits::SecurePrng;
    use proto_serialization_traits::{FromProto, ToProto};
    use protobuf::prelude::*;
    use share_cipher::{ShareCipher, TinkHpkePrivateKey, TinkHpkePublicKey, TinkHpkeShareCipher};
    use shell_kahe::ShellKahe;
    use shell_parameters::create_shell_ahe_config;
    use shell_vahe::ShellVahe;
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use std::collections::BTreeMap;
    use std::num::NonZeroU32;
    use std::rc::Rc;
    use vahe_traits::{Recover, VerifiableEncrypt};

    const CONTEXT_STRING: &[u8] = b"testing_context_string";

    #[gtest]
    fn coordinator_handles_setup_and_creates_verification_request() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);

        // Create two decryptors.
        let decryptor1 = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let decryptor2 = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;

        let mut state1 = DecryptorState::default();
        let mut state2 = DecryptorState::default();
        let contribution1 = decryptor1.create_setup_contribution(&mut state1)?;
        let contribution2 = decryptor2.create_setup_contribution(&mut state2)?;

        // Create coordinator.
        let coordinator = Coordinator { vahe: vahe.clone() };
        let mut coord_state = CoordinatorState::default();

        // Handle setup submissions.
        let verify_request = coordinator.handle_setup_submissions(
            vec![],
            vec![contribution1, contribution2],
            &mut coord_state,
        )?;

        verify_true!(verify_request.key_contributions.len() == 2)?;
        verify_true!(coord_state.status == CoordinatorStatus::KeySharesReceived)?;

        Ok(())
    }

    #[gtest]
    fn coordinator_setup_fails_when_not_pre_setup() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);

        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let mut state = DecryptorState::default();
        let contribution = decryptor.create_setup_contribution(&mut state)?;

        let coordinator = Coordinator { vahe: vahe.clone() };
        let mut coord_state = CoordinatorState::default();

        // First call succeeds.
        coordinator.handle_setup_submissions(vec![], vec![contribution], &mut coord_state)?;

        // Second call should fail.
        let decryptor2 = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let mut state2 = DecryptorState::default();
        let contribution2 = decryptor2.create_setup_contribution(&mut state2)?;
        let result =
            coordinator.handle_setup_submissions(vec![], vec![contribution2], &mut coord_state);
        verify_true!(result.is_err())?;

        Ok(())
    }

    #[gtest]
    fn coordinator_setup_rejects_duplicate_public_key_shares() -> googletest::Result<()> {
        use messages::SetupContribution;

        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(2)?, CONTEXT_STRING)?);
        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let mut state = DecryptorState::default();
        let contribution = decryptor.create_setup_contribution(&mut state)?;

        let coordinator = Coordinator { vahe };
        let mut coord_state = CoordinatorState::default();

        // Duplicate public_key_share across non-reputable and reputable contributions must fail
        // without advancing CoordinatorState out of PreSetup.
        let dup = SetupContribution {
            key_contribution: contribution.key_contribution.clone(),
            dp_setup: None,
            encrypted_randomness_shares: None,
            decryptor_index: None,
            feldman_commitment: None,
            indexed_encrypted_shares: BTreeMap::new(),
        };
        let result =
            coordinator.handle_setup_submissions(vec![dup], vec![contribution], &mut coord_state);
        verify_true!(matches!(
            result.map_err(|e| e.code()),
            Err(status::StatusErrorCode::INVALID_ARGUMENT)
        ))?;
        verify_that!(coord_state.status, eq(CoordinatorStatus::PreSetup))?;

        Ok(())
    }

    #[gtest]
    fn aggregate_partial_decryptions_fails_with_no_responses() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let coordinator = Coordinator { vahe };
        let mut coord_state = CoordinatorState::default();
        coord_state.status = CoordinatorStatus::AwaitingPartialDecryptions;

        let result =
            coordinator.aggregate_partial_decryptions::<ShellKahe>(vec![], None, &mut coord_state);
        verify_true!(matches!(
            result.map_err(|e| e.code()),
            Err(status::StatusErrorCode::INVALID_ARGUMENT)
        ))?;
        verify_that!(coord_state.status, eq(CoordinatorStatus::AwaitingPartialDecryptions))?;
        verify_true!(coord_state.partial_decryption_sum.is_none())?;

        Ok(())
    }

    /// End-to-end test: setup -> encryption -> partial decryption -> recovery
    /// using the multi-decryptor protocol with a coordinator, one non-reputable decryptor and
    /// one reputable decryptor,
    /// serializing and deserializing CoordinatorState at every protocol transition.
    #[gtest]
    fn end_to_end_multi_decryptor_protocol() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);

        // Create two multi-decryptors (same struct, using multi-decryptor traits).
        let decryptor1 = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let decryptor2 = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;

        let mut dec_state1 = DecryptorState::default();
        let mut dec_state2 = DecryptorState::default();

        // --- Setup phase ---

        // Each decryptor generates its setup contribution.
        let contribution1 = decryptor1.create_setup_contribution(&mut dec_state1)?;
        let contribution2 = decryptor2.create_setup_contribution(&mut dec_state2)?;

        // Attach encrypted randomness shares to non-reputable decryptor1's contribution.
        let mut contribution1 = contribution1;
        contribution1.encrypted_randomness_shares = Some(vec![SecretSharingContribution {
            encrypted_share: b"test_encrypted_share".to_vec(),
            recipient_index: None,
        }]);

        // Coordinator processes setup (round-trip default PreSetup state first).
        let coordinator = Coordinator { vahe: vahe.clone() };
        let coord_state = CoordinatorState::default();
        let coord_state_proto = coord_state.to_proto(&coordinator)?;
        let mut coord_state = CoordinatorState::from_proto(coord_state_proto, &coordinator)?;
        verify_that!(coord_state.status, eq(CoordinatorStatus::PreSetup))?;

        let verify_request = coordinator.handle_setup_submissions(
            vec![contribution1],
            vec![contribution2],
            &mut coord_state,
        )?;

        // Round-trip CoordinatorState after setup submissions.
        let coord_state_proto = coord_state.to_proto(&coordinator)?;
        let mut coord_state = CoordinatorState::from_proto(coord_state_proto, &coordinator)?;
        verify_that!(coord_state.status, eq(CoordinatorStatus::KeySharesReceived))?;
        verify_that!(coord_state.encrypted_randomness_shares.len(), eq(1))?;
        verify_that!(
            coord_state.encrypted_randomness_shares[0][0].encrypted_share,
            eq(b"test_encrypted_share")
        )?;

        // Reputable decryptor verifies and aggregates the public key.
        let public_key = decryptor1.verify_and_aggregate_key_contributions(verify_request)?;

        // --- Encryption phase ---
        // Create a fake ciphertext by encrypting a known plaintext.
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let plaintext = vec![42i64; 8];
        let nonce = b"0123456789ABCDEF";
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&plaintext, &public_key, nonce, &mut prng)?;
        let partial_dec_ciphertext = vahe.get_partial_dec_ciphertext(&ciphertext)?;
        let recover_ciphertext = vahe.get_recover_ciphertext(&ciphertext)?;

        // --- Decryption phase ---

        // Coordinator prepares decryption request.
        let pd_request =
            coordinator.prepare_decryption_request(&partial_dec_ciphertext, &mut coord_state)?;

        // Round-trip CoordinatorState after preparing decryption request.
        let coord_state_proto = coord_state.to_proto(&coordinator)?;
        let mut coord_state = CoordinatorState::from_proto(coord_state_proto, &coordinator)?;
        verify_that!(coord_state.status, eq(CoordinatorStatus::AwaitingPartialDecryptions))?;

        // Each decryptor computes a partial decryption.
        let pd_response1: messages::PartialDecryptionResponse<ShellKahe, ShellVahe> = decryptor1
            .handle_partial_decryption_request(pd_request.clone(), None, &mut dec_state1)?;
        let pd_response2: messages::PartialDecryptionResponse<ShellKahe, ShellVahe> =
            decryptor2.handle_partial_decryption_request(pd_request, None, &mut dec_state2)?;

        // Coordinator aggregates partial decryptions.
        coordinator.aggregate_partial_decryptions::<ShellKahe>(
            vec![pd_response1, pd_response2],
            None,
            &mut coord_state,
        )?;

        // Round-trip CoordinatorState after aggregating partial decryptions.
        let coord_state_proto = coord_state.to_proto(&coordinator)?;
        let mut coord_state = CoordinatorState::from_proto(coord_state_proto, &coordinator)?;
        verify_that!(coord_state.status, eq(CoordinatorStatus::OutputReady))?;

        // Recover the plaintext using the finalized state.
        let finalized_state = coordinator.finalize_partial_decryption(&mut coord_state)?;
        let recovered = vahe.recover(
            &finalized_state.partial_decryption_sum,
            &recover_ciphertext,
            Some(plaintext.len()),
        )?;

        verify_that!(&recovered[..], eq(&plaintext[..]))?;

        Ok(())
    }

    #[gtest]
    fn coordinator_state_statuses_roundtrip() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let coordinator = Coordinator { vahe };

        for status in [
            CoordinatorStatus::PreSetup,
            CoordinatorStatus::KeySharesReceived,
            CoordinatorStatus::AwaitingContributions,
            CoordinatorStatus::AwaitingPartialDecryptions,
            CoordinatorStatus::AwaitingRecovery,
            CoordinatorStatus::Finished,
        ] {
            let state = CoordinatorState { status, ..CoordinatorState::default() };
            let proto = state.to_proto(&coordinator)?;
            let roundtrip = CoordinatorState::from_proto(proto.as_view(), &coordinator)?;
            verify_that!(roundtrip.status, eq(status))?;
            verify_that!(roundtrip.to_proto(&coordinator)?.serialize()?, eq(&proto.serialize()?))?;
        }

        Ok(())
    }

    #[gtest]
    fn coordinator_state_rejects_invalid_statuses_and_invariants() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let coordinator = Coordinator { vahe };

        // Unspecified CoordinatorStatusProto must fail deserialization with InvalidArgument.
        let err = CoordinatorStatus::from_proto(CoordinatorStatusProto::Unspecified, ())
            .expect_err("expected error for Unspecified CoordinatorStatus");
        verify_that!(err.message(), contains_substring("CoordinatorStatus"))?;

        // OutputReady without partial_decryption_sum must fail deserialization.
        let invalid_output_ready = CoordinatorState {
            status: CoordinatorStatus::OutputReady,
            ..CoordinatorState::default()
        };
        let invalid_proto = invalid_output_ready.to_proto(&coordinator)?;
        let err = CoordinatorState::from_proto(invalid_proto, &coordinator)
            .err()
            .expect("expected error for OutputReady without partial_decryption_sum");
        verify_that!(err.message(), contains_substring("partial_decryption_sum"))?;

        // PreSetup with populated encrypted_randomness_shares must fail deserialization.
        let invalid_pre_setup = CoordinatorState {
            status: CoordinatorStatus::PreSetup,
            encrypted_randomness_shares: vec![vec![SecretSharingContribution {
                encrypted_share: b"unexpected_share".to_vec(),
                recipient_index: None,
            }]],
            ..CoordinatorState::default()
        };
        let invalid_pre_setup_proto = invalid_pre_setup.to_proto(&coordinator)?;
        let err = CoordinatorState::from_proto(invalid_pre_setup_proto, &coordinator)
            .err()
            .expect("expected error for PreSetup with populated fields");
        verify_that!(err.message(), contains_substring("PreSetup"))?;

        Ok(())
    }

    #[gtest]
    fn coordinator_state_optional_fields_roundtrip() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let mut dec_state = DecryptorState::default();
        let contribution = decryptor.create_setup_contribution(&mut dec_state)?;
        let coordinator = Coordinator { vahe: vahe.clone() };

        let public_key = vahe.aggregate_public_key_shares(std::iter::once(
            &contribution.key_contribution.public_key_share,
        ))?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&vec![1i64; 8], &public_key, b"0123456789ABCDEF", &mut prng)?;
        let dp_noise_ct = vahe.get_partial_dec_ciphertext(&ciphertext)?;

        let state = CoordinatorState {
            status: CoordinatorStatus::KeySharesReceived,
            encrypted_randomness_shares: vec![vec![SecretSharingContribution {
                encrypted_share: b"share_bytes".to_vec(),
                recipient_index: None,
            }]],
            dp_noise_component_sum: Some(dp_noise_ct),
            setup_contributions: Some(vec![contribution]),
            partial_decryption_sum: None,
            ..CoordinatorState::default()
        };
        let proto = state.to_proto(&coordinator)?;
        let roundtrip = CoordinatorState::from_proto(proto.as_view(), &coordinator)?;
        verify_true!(roundtrip.dp_noise_component_sum.is_some())?;
        verify_that!(roundtrip.setup_contributions.as_ref().map(|v| v.len()), eq(Some(1)))?;
        verify_that!(roundtrip.to_proto(&coordinator)?.serialize()?, eq(&proto.serialize()?))?;

        Ok(())
    }

    fn build_committee_fixture(
        vahe: &Rc<ShellVahe>,
        n: u32,
        t: u32,
    ) -> Result<
        (
            CommitteeConfig,
            BTreeMap<NonZeroU32, TinkHpkePublicKey>,
            Vec<Decryptor<ShellVahe>>,
            Vec<DecryptorState<ShellVahe>>,
            BTreeMap<NonZeroU32, TinkHpkePrivateKey>,
            Vec<messages::SetupContribution<ShellVahe>>,
        ),
        status::StatusError,
    > {
        let mut hpke_sks = BTreeMap::new();
        let mut roster_pks = BTreeMap::new();
        let mut raw_roster = BTreeMap::new();
        for i in 1..=n {
            let idx = NonZeroU32::new(i).unwrap();
            let (sk, pk) = TinkHpkeShareCipher::generate_keypair()?;
            raw_roster.insert(idx, pk.as_bytes().to_vec());
            hpke_sks.insert(idx, sk);
            roster_pks.insert(idx, pk);
        }
        let roster_hash = compute_roster_hash(n, t, &raw_roster)?;
        let session_context = CONTEXT_STRING.to_vec();
        let coord_cfg = CommitteeConfig::new(
            NonZeroU32::new(1).unwrap(),
            n,
            t,
            roster_hash,
            session_context.clone(),
        )?;
        let mut decryptors = Vec::with_capacity(n as usize);
        let mut states = Vec::with_capacity(n as usize);
        let mut contributions = Vec::with_capacity(n as usize);
        for i in 1..=n {
            let idx = NonZeroU32::new(i).unwrap();
            let dec = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
            let mut state = DecryptorState::default();
            let cfg = CommitteeConfig::new(idx, n, t, roster_hash, session_context.clone())?;
            let contrib = dec.create_recoverable_setup_contribution(
                cfg,
                &roster_pks,
                &hpke_sks[&idx],
                &mut state,
            )?;
            decryptors.push(dec);
            states.push(state);
            contributions.push(contrib);
        }
        Ok((coord_cfg, roster_pks, decryptors, states, hpke_sks, contributions))
    }

    #[gtest]
    fn recoverable_committee_zero_dropouts_reaches_output_ready() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let (cfg, _roster_pks, decryptors, mut states, _hpke_sks, contributions) =
            build_committee_fixture(&vahe, 3, 2)?;

        let coordinator = Coordinator { vahe: vahe.clone() };
        let mut coord_state = CoordinatorState::default();
        coordinator.configure_committee(cfg, &mut coord_state)?;

        // Round-trip PreSetup with committee_config.
        let proto = coord_state.to_proto(&coordinator)?;
        let mut coord_state = CoordinatorState::from_proto(proto.as_view(), &coordinator)?;

        let verify_request =
            coordinator.handle_setup_submissions(contributions, vec![], &mut coord_state)?;
        verify_that!(verify_request.key_contributions.len(), eq(3))?;
        verify_that!(coord_state.status, eq(CoordinatorStatus::KeySharesReceived))?;
        verify_true!(coord_state.setup_transcript_hash.is_some())?;

        // Round-trip KeySharesReceived.
        let proto = coord_state.to_proto(&coordinator)?;
        let mut coord_state = CoordinatorState::from_proto(proto.as_view(), &coordinator)?;

        let public_key = decryptors[0].verify_and_aggregate_key_contributions(verify_request)?;

        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let plaintext = vec![17i64; 8];
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&plaintext, &public_key, b"0123456789ABCDEF", &mut prng)?;
        let partial_dec_ct = vahe.get_partial_dec_ciphertext(&ciphertext)?;
        let recover_ct = vahe.get_recover_ciphertext(&ciphertext)?;

        let pd_request =
            coordinator.prepare_decryption_request(&partial_dec_ct, &mut coord_state)?;
        let proto = coord_state.to_proto(&coordinator)?;
        let mut coord_state = CoordinatorState::from_proto(proto.as_view(), &coordinator)?;

        let mut pd_responses = Vec::new();
        for i in 0..3 {
            let mut pd: messages::PartialDecryptionResponse<ShellKahe, ShellVahe> = decryptors[i]
                .handle_partial_decryption_request(
                pd_request.clone(),
                None,
                &mut states[i],
            )?;
            pd.decryptor_index = Some(NonZeroU32::new((i + 1) as u32).unwrap());
            verify_that!(states[i].status, eq(DecryptorStatus::AwaitingRecoveryRequest))?;
            pd_responses.push(pd);
        }

        coordinator.aggregate_partial_decryptions::<ShellKahe>(
            pd_responses,
            None,
            &mut coord_state,
        )?;
        verify_that!(coord_state.status, eq(CoordinatorStatus::OutputReady))?;
        verify_true!(coordinator.create_indexed_recovery_requests(&coord_state)?.is_empty())?;
        verify_true!(coordinator.create_recovery_requests(&mut coord_state)?.is_empty())?;

        // Round-trip OutputReady.
        let proto = coord_state.to_proto(&coordinator)?;
        let mut coord_state = CoordinatorState::from_proto(proto.as_view(), &coordinator)?;

        let finalized = coordinator.finalize_partial_decryption(&mut coord_state)?;
        let recovered =
            vahe.recover(&finalized.partial_decryption_sum, &recover_ct, Some(plaintext.len()))?;
        verify_that!(&recovered[..], eq(&plaintext[..]))?;

        Ok(())
    }

    #[gtest]
    fn recoverable_committee_dropout_recovery_succeeds_for_up_to_n_minus_t_dropouts(
    ) -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let (cfg, _roster_pks, decryptors, mut states, _hpke_sks, contributions) =
            build_committee_fixture(&vahe, 5, 3)?;

        let coordinator = Coordinator { vahe: vahe.clone() };
        let mut coord_state = CoordinatorState::default();
        coordinator.configure_committee(cfg, &mut coord_state)?;
        let verify_request =
            coordinator.handle_setup_submissions(contributions, vec![], &mut coord_state)?;
        let public_key = decryptors[0].verify_and_aggregate_key_contributions(verify_request)?;

        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let plaintext = vec![99i64; 8];
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&plaintext, &public_key, b"0123456789ABCDEF", &mut prng)?;
        let partial_dec_ct = vahe.get_partial_dec_ciphertext(&ciphertext)?;
        let recover_ct = vahe.get_recover_ciphertext(&ciphertext)?;

        let pd_request =
            coordinator.prepare_decryption_request(&partial_dec_ct, &mut coord_state)?;

        // Decryptors 2 and 5 drop out (d = 2 <= n - t = 2); survivors are 1, 3, 4.
        let survivors = [1u32, 3, 4];
        let mut pd_responses = Vec::new();
        for &idx_raw in &survivors {
            let idx = NonZeroU32::new(idx_raw).unwrap();
            let i = (idx_raw - 1) as usize;
            let mut pd: messages::PartialDecryptionResponse<ShellKahe, ShellVahe> = decryptors[i]
                .handle_partial_decryption_request(
                pd_request.clone(),
                None,
                &mut states[i],
            )?;
            pd.decryptor_index = Some(idx);
            pd_responses.push(pd);
        }

        coordinator.aggregate_partial_decryptions::<ShellKahe>(
            pd_responses,
            None,
            &mut coord_state,
        )?;
        verify_that!(coord_state.status, eq(CoordinatorStatus::AwaitingRecovery))?;

        // Round-trip CoordinatorState in AwaitingRecovery.
        let proto = coord_state.to_proto(&coordinator)?;
        let mut coord_state = CoordinatorState::from_proto(proto.as_view(), &coordinator)?;
        verify_that!(coord_state.status, eq(CoordinatorStatus::AwaitingRecovery))?;

        let indexed_requests = coordinator.create_indexed_recovery_requests(&coord_state)?;
        verify_that!(indexed_requests.len(), eq(3))?;

        let mut recovery_responses = Vec::new();
        for (survivor_idx, req) in indexed_requests {
            let i = (survivor_idx.get() - 1) as usize;
            let resp = decryptors[i].handle_recovery_request(req, &mut states[i])?;
            verify_that!(states[i].status, eq(DecryptorStatus::Finished))?;
            recovery_responses.push(resp);
        }

        coordinator.recover_dropped_decryptors(recovery_responses, &mut coord_state)?;
        verify_that!(coord_state.status, eq(CoordinatorStatus::OutputReady))?;

        let finalized = coordinator.finalize_partial_decryption(&mut coord_state)?;
        let recovered =
            vahe.recover(&finalized.partial_decryption_sum, &recover_ct, Some(plaintext.len()))?;
        verify_that!(&recovered[..], eq(&plaintext[..]))?;

        Ok(())
    }

    #[gtest]
    fn recoverable_committee_aborts_when_more_than_n_minus_t_drop_out() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let (cfg, _roster_pks, decryptors, mut states, _hpke_sks, contributions) =
            build_committee_fixture(&vahe, 5, 3)?;

        let coordinator = Coordinator { vahe: vahe.clone() };
        let mut coord_state = CoordinatorState::default();
        coordinator.configure_committee(cfg, &mut coord_state)?;
        let verify_request =
            coordinator.handle_setup_submissions(contributions, vec![], &mut coord_state)?;
        let public_key = decryptors[0].verify_and_aggregate_key_contributions(verify_request)?;

        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&vec![7i64; 8], &public_key, b"0123456789ABCDEF", &mut prng)?;
        let partial_dec_ct = vahe.get_partial_dec_ciphertext(&ciphertext)?;
        let pd_request =
            coordinator.prepare_decryption_request(&partial_dec_ct, &mut coord_state)?;

        // Only 2 decryptors respond (< t = 3).
        let mut pd_responses = Vec::new();
        for idx_raw in [1u32, 2] {
            let i = (idx_raw - 1) as usize;
            let mut pd: messages::PartialDecryptionResponse<ShellKahe, ShellVahe> = decryptors[i]
                .handle_partial_decryption_request(
                pd_request.clone(),
                None,
                &mut states[i],
            )?;
            pd.decryptor_index = Some(NonZeroU32::new(idx_raw).unwrap());
            pd_responses.push(pd);
        }

        let err = coordinator
            .aggregate_partial_decryptions::<ShellKahe>(pd_responses, None, &mut coord_state)
            .expect_err("expected failure when < t decryptors respond");
        verify_that!(err.code(), eq(status::StatusErrorCode::FAILED_PRECONDITION))?;
        verify_that!(err.message(), contains_substring("fewer than threshold"))?;

        Ok(())
    }

    #[gtest]
    fn recoverable_committee_tolerates_corrupt_survivor_share_when_t_honest_shares_exist(
    ) -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let (cfg, _roster_pks, decryptors, mut states, _hpke_sks, contributions) =
            build_committee_fixture(&vahe, 5, 3)?;

        let coordinator = Coordinator { vahe: vahe.clone() };
        let mut coord_state = CoordinatorState::default();
        coordinator.configure_committee(cfg, &mut coord_state)?;
        let verify_request =
            coordinator.handle_setup_submissions(contributions, vec![], &mut coord_state)?;
        let public_key = decryptors[0].verify_and_aggregate_key_contributions(verify_request)?;

        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let plaintext = vec![123i64; 8];
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&plaintext, &public_key, b"0123456789ABCDEF", &mut prng)?;
        let partial_dec_ct = vahe.get_partial_dec_ciphertext(&ciphertext)?;
        let recover_ct = vahe.get_recover_ciphertext(&ciphertext)?;

        let pd_request =
            coordinator.prepare_decryption_request(&partial_dec_ct, &mut coord_state)?;

        // Decryptor 5 drops out; survivors 1, 2, 3, 4 respond (4 >= t = 3).
        let mut pd_responses = Vec::new();
        for idx_raw in [1u32, 2, 3, 4] {
            let i = (idx_raw - 1) as usize;
            let mut pd: messages::PartialDecryptionResponse<ShellKahe, ShellVahe> = decryptors[i]
                .handle_partial_decryption_request(
                pd_request.clone(),
                None,
                &mut states[i],
            )?;
            pd.decryptor_index = Some(NonZeroU32::new(idx_raw).unwrap());
            pd_responses.push(pd);
        }
        coordinator.aggregate_partial_decryptions::<ShellKahe>(
            pd_responses,
            None,
            &mut coord_state,
        )?;

        let indexed_requests = coordinator.create_indexed_recovery_requests(&coord_state)?;
        let mut recovery_responses = Vec::new();
        for (survivor_idx, req) in indexed_requests {
            let i = (survivor_idx.get() - 1) as usize;
            let resp = decryptors[i].handle_recovery_request(req, &mut states[i])?;
            recovery_responses.push(resp);
        }

        let idx3 = NonZeroU32::new(3).unwrap();
        let idx4 = NonZeroU32::new(4).unwrap();
        let idx5 = NonZeroU32::new(5).unwrap();

        // Corrupt survivor 4's share for dealer 5 (replace scalar with 1).
        let bad_share =
            Share { index: idx4, value: SecretScalar::from_canonical_bytes(&[1u8; 32])? };
        recovery_responses[3].indexed_decrypted_shares.insert(idx5, bad_share);

        // Also test that if a second survivor (survivor 3) is corrupted leaving only 2 < t = 3
        // valid shares, recovery fails with FAILED_PRECONDITION.
        let mut two_corrupt = recovery_responses.clone();
        let bad_share_3 =
            Share { index: idx3, value: SecretScalar::from_canonical_bytes(&[2u8; 32])? };
        two_corrupt[2].indexed_decrypted_shares.insert(idx5, bad_share_3);
        let mut failed_coord_state =
            CoordinatorState::from_proto(coord_state.to_proto(&coordinator)?, &coordinator)?;
        let err = coordinator
            .recover_dropped_decryptors(two_corrupt, &mut failed_coord_state)
            .expect_err("expected failure when < t valid shares remain after verify_share");
        verify_that!(err.code(), eq(status::StatusErrorCode::FAILED_PRECONDITION))?;

        // With 1 corrupt survivor and 3 honest survivors (3 >= t), recovery succeeds!
        coordinator.recover_dropped_decryptors(recovery_responses, &mut coord_state)?;
        let finalized = coordinator.finalize_partial_decryption(&mut coord_state)?;
        let recovered =
            vahe.recover(&finalized.partial_decryption_sum, &recover_ct, Some(plaintext.len()))?;
        verify_that!(&recovered[..], eq(&plaintext[..]))?;

        Ok(())
    }

    #[gtest]
    fn recoverable_committee_detects_malicious_dealer_wrong_pk_share_at_step_14(
    ) -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let (cfg, roster_pks, decryptors, mut states, hpke_sks, mut contributions) =
            build_committee_fixture(&vahe, 3, 2)?;
        let idx3 = NonZeroU32::new(3).unwrap();

        // Malicious dealer 3 generates a second recoverable setup contribution from a different
        // Decryptor instance (different VSS secret s'_3), and transplants its consistent
        // Feldman commitment + encrypted shares onto contribution[2] while keeping the original
        // key_contribution (pk_3). Thus verify_share and reconstruct succeed, but Step 14
        // (recovered_pk_3 == setup_pk_3) must catch the mismatch!
        let alt_decryptor = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let mut alt_state = DecryptorState::default();
        let alt_cfg =
            CommitteeConfig::new(idx3, 3, 2, cfg.roster_hash, cfg.session_context.clone())?;
        let alt_contrib = alt_decryptor.create_recoverable_setup_contribution(
            alt_cfg,
            &roster_pks,
            &hpke_sks[&idx3],
            &mut alt_state,
        )?;
        contributions[2].feldman_commitment = alt_contrib.feldman_commitment;
        contributions[2].indexed_encrypted_shares = alt_contrib.indexed_encrypted_shares;

        let coordinator = Coordinator { vahe: vahe.clone() };
        let mut coord_state = CoordinatorState::default();
        coordinator.configure_committee(cfg, &mut coord_state)?;
        let verify_request =
            coordinator.handle_setup_submissions(contributions, vec![], &mut coord_state)?;
        let public_key = decryptors[0].verify_and_aggregate_key_contributions(verify_request)?;

        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&vec![5i64; 8], &public_key, b"0123456789ABCDEF", &mut prng)?;
        let partial_dec_ct = vahe.get_partial_dec_ciphertext(&ciphertext)?;
        let pd_request =
            coordinator.prepare_decryption_request(&partial_dec_ct, &mut coord_state)?;

        // Dealer 3 drops out; survivors 1 and 2 respond.
        let mut pd_responses = Vec::new();
        for idx_raw in [1u32, 2] {
            let i = (idx_raw - 1) as usize;
            let mut pd: messages::PartialDecryptionResponse<ShellKahe, ShellVahe> = decryptors[i]
                .handle_partial_decryption_request(
                pd_request.clone(),
                None,
                &mut states[i],
            )?;
            pd.decryptor_index = Some(NonZeroU32::new(idx_raw).unwrap());
            pd_responses.push(pd);
        }
        coordinator.aggregate_partial_decryptions::<ShellKahe>(
            pd_responses,
            None,
            &mut coord_state,
        )?;

        let indexed_requests = coordinator.create_indexed_recovery_requests(&coord_state)?;
        let mut recovery_responses = Vec::new();
        for (survivor_idx, req) in indexed_requests {
            let i = (survivor_idx.get() - 1) as usize;
            let resp = decryptors[i].handle_recovery_request(req, &mut states[i])?;
            recovery_responses.push(resp);
        }

        let err = coordinator
            .recover_dropped_decryptors(recovery_responses, &mut coord_state)
            .expect_err("expected Step 14 public-key mismatch error for malicious dealer 3");
        verify_that!(err.code(), eq(status::StatusErrorCode::PERMISSION_DENIED))?;
        verify_that!(err.message(), contains_substring("Step 14"))?;

        Ok(())
    }

    #[gtest]
    fn recoverable_committee_rejects_invalid_setup_and_duplicate_or_spoofed_responses(
    ) -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let (cfg, _roster_pks, decryptors, mut states, _hpke_sks, contributions) =
            build_committee_fixture(&vahe, 3, 2)?;
        let coordinator = Coordinator { vahe: vahe.clone() };
        let idx1 = NonZeroU32::new(1).unwrap();
        let idx2 = NonZeroU32::new(2).unwrap();
        let idx3 = NonZeroU32::new(3).unwrap();

        let clone_contribs = |src: &[messages::SetupContribution<ShellVahe>]| -> Result<
            Vec<messages::SetupContribution<ShellVahe>>,
            status::StatusError,
        > {
            src.iter()
                .map(|c| {
                    let proto = c.to_proto(&coordinator)?;
                    messages::SetupContribution::from_proto(proto, &coordinator)
                })
                .collect()
        };
        let clone_pd = |pd: &messages::PartialDecryptionResponse<ShellKahe, ShellVahe>| {
            messages::PartialDecryptionResponse::<ShellKahe, ShellVahe> {
                partial_decryption: pd.partial_decryption.clone(),
                dp_ciphertext_contribution: pd.dp_ciphertext_contribution.clone(),
                decryptor_index: pd.decryptor_index,
            }
        };

        // 1. Wrong number of setup submissions.
        let mut state_wrong_count = CoordinatorState::default();
        coordinator.configure_committee(cfg.clone(), &mut state_wrong_count)?;
        verify_true!(coordinator
            .handle_setup_submissions(
                clone_contribs(&contributions[..2])?,
                vec![],
                &mut state_wrong_count,
            )
            .is_err())?;

        // 2. Duplicate decryptor_index in setup.
        let mut state_dup_idx = CoordinatorState::default();
        coordinator.configure_committee(cfg.clone(), &mut state_dup_idx)?;
        let mut dup_contribs = clone_contribs(&contributions)?;
        dup_contribs[1].decryptor_index = Some(idx1);
        verify_true!(coordinator
            .handle_setup_submissions(dup_contribs, vec![], &mut state_dup_idx)
            .is_err())?;

        // 3. Self-addressed encrypted share in setup.
        let mut state_self_share = CoordinatorState::default();
        coordinator.configure_committee(cfg.clone(), &mut state_self_share)?;
        let mut self_share_contribs = clone_contribs(&contributions)?;
        let ct_removed = self_share_contribs[0].indexed_encrypted_shares.remove(&idx2).unwrap();
        self_share_contribs[0].indexed_encrypted_shares.insert(idx1, ct_removed);
        verify_true!(coordinator
            .handle_setup_submissions(self_share_contribs, vec![], &mut state_self_share)
            .is_err())?;

        // 4. Oversized encrypted share (> MAX_ENCRYPTED_SHARE_BYTES).
        let mut state_oversized = CoordinatorState::default();
        coordinator.configure_committee(cfg.clone(), &mut state_oversized)?;
        let mut oversized_contribs = clone_contribs(&contributions)?;
        oversized_contribs[0]
            .indexed_encrypted_shares
            .insert(idx2, vec![0u8; MAX_ENCRYPTED_SHARE_BYTES + 1]);
        verify_true!(coordinator
            .handle_setup_submissions(oversized_contribs, vec![], &mut state_oversized)
            .is_err())?;

        // 5. Valid setup, then test duplicate / missing decryptor_index in partial decryption.
        let mut coord_state = CoordinatorState::default();
        coordinator.configure_committee(cfg, &mut coord_state)?;
        let verify_request =
            coordinator.handle_setup_submissions(contributions, vec![], &mut coord_state)?;
        let public_key = decryptors[0].verify_and_aggregate_key_contributions(verify_request)?;

        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&vec![3i64; 8], &public_key, b"0123456789ABCDEF", &mut prng)?;
        let partial_dec_ct = vahe.get_partial_dec_ciphertext(&ciphertext)?;
        let pd_request =
            coordinator.prepare_decryption_request(&partial_dec_ct, &mut coord_state)?;

        let mut pd1: messages::PartialDecryptionResponse<ShellKahe, ShellVahe> = decryptors[0]
            .handle_partial_decryption_request(pd_request.clone(), None, &mut states[0])?;
        let mut pd2: messages::PartialDecryptionResponse<ShellKahe, ShellVahe> = decryptors[1]
            .handle_partial_decryption_request(pd_request.clone(), None, &mut states[1])?;

        // Missing decryptor_index rejected.
        let mut pd1_missing_idx = clone_pd(&pd1);
        pd1_missing_idx.decryptor_index = None;
        let mut state_missing_idx =
            CoordinatorState::from_proto(coord_state.to_proto(&coordinator)?, &coordinator)?;
        verify_true!(coordinator
            .aggregate_partial_decryptions::<ShellKahe>(
                vec![pd1_missing_idx, clone_pd(&pd2)],
                None,
                &mut state_missing_idx,
            )
            .is_err())?;

        // Duplicate decryptor_index rejected.
        pd1.decryptor_index = Some(idx1);
        pd2.decryptor_index = Some(idx1);
        let mut state_dup_pd =
            CoordinatorState::from_proto(coord_state.to_proto(&coordinator)?, &coordinator)?;
        verify_true!(coordinator
            .aggregate_partial_decryptions::<ShellKahe>(
                vec![clone_pd(&pd1), clone_pd(&pd2)],
                None,
                &mut state_dup_pd,
            )
            .is_err())?;

        // Valid partial decryption with decryptors 1 and 2 (decryptor 3 dropped).
        pd2.decryptor_index = Some(idx2);
        coordinator.aggregate_partial_decryptions::<ShellKahe>(
            vec![pd1, pd2],
            None,
            &mut coord_state,
        )?;

        let indexed_requests = coordinator.create_indexed_recovery_requests(&coord_state)?;
        let resp1 = decryptors[0]
            .handle_recovery_request(indexed_requests[&idx1].clone(), &mut states[0])?;

        // Spoofed RecoveryResponse from dropped decryptor 3 is rejected.
        let mut state_spoofed =
            CoordinatorState::from_proto(coord_state.to_proto(&coordinator)?, &coordinator)?;
        let spoofed_resp = RecoveryResponse {
            decrypted_shares: Vec::new(),
            survivor_index: Some(idx3),
            indexed_decrypted_shares: resp1.indexed_decrypted_shares.clone(),
        };
        verify_true!(coordinator
            .recover_dropped_decryptors(vec![resp1.clone(), spoofed_resp], &mut state_spoofed)
            .is_err())?;

        // Duplicate RecoveryResponse from survivor 1 is rejected.
        let mut state_dup_rec =
            CoordinatorState::from_proto(coord_state.to_proto(&coordinator)?, &coordinator)?;
        verify_true!(coordinator
            .recover_dropped_decryptors(vec![resp1.clone(), resp1], &mut state_dup_rec)
            .is_err())?;

        Ok(())
    }
}
