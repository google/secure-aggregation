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

use aggregation_config::AggregationConfig;
use ahe_traits::{AheKeygen, PartialDec};
use feldman_vss::{
    self, derive_keygen_seed, FeldmanCommitment, SecretScalar, ROSTER_HASH_BYTE_LEN,
};
use kahe_traits::KaheBase;
use messages::{
    compute_roster_hash, compute_setup_transcript_hash, CommitteeConfig, DecryptorPublicKey,
    DecryptorStatus, KeyContribution, PartialDecryptionRequest, PartialDecryptionResponse,
    RecoveryRequest, RecoveryResponse, SetupContribution, VerifyKeyContributionsRequest,
};
use messages_rust_proto::DecryptorState as DecryptorStateProto;
use prng_traits::SecurePrng;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::AsView;
use share_cipher::{
    ShareCipher, TinkHpkeKeysetWrappingKey, TinkHpkePrivateKey, TinkHpkePublicKey,
    TinkHpkeShareCipher,
};
use shell_ciphertexts_rust_proto::ShellAheSecretKeyShare;
use shell_kahe::ShellKahe;
use status::StatusError;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::rc::Rc;
use vahe_traits::{HasVahe, KeyGenVerify, VaheBase, VerifiableKeyGen};

/// Implementation of Decryptor directly exposing VAHE types.
///
/// This struct supports multi-decryptor committee mode via inherent methods
/// (`create_setup_contribution`, `create_recoverable_setup_contribution`,
/// `handle_partial_decryption_request`, `verify_and_aggregate_key_contributions`,
/// `handle_recovery_request`).
pub struct Decryptor<Vahe: VaheBase> {
    pub vahe: Rc<Vahe>,
    pub prng: RefCell<Vahe::Rng>,
}

impl<Vahe: VaheBase> HasVahe for Decryptor<Vahe> {
    type Vahe = Vahe;
    fn vahe(&self) -> &Self::Vahe {
        &self.vahe
    }
}

impl<Vahe: VaheBase> Decryptor<Vahe> {
    pub fn new_with_randomly_generated_seed(vahe: Rc<Vahe>) -> Result<Self, status::StatusError> {
        let seed = Vahe::Rng::generate_seed()?;
        let prng = RefCell::new(Vahe::Rng::create(&seed)?);
        Ok(Self { vahe, prng })
    }
}

pub struct DecryptorState<Vahe: VaheBase> {
    pub sk_share: Option<Vahe::SecretKeyShare>,
    pub kahe: Option<Rc<ShellKahe>>,
    pub aggregation_config: Option<AggregationConfig>,
    pub status: DecryptorStatus,
    pub committee_config: Option<CommitteeConfig>,
    /// In-memory Tink HPKE private key handle for decrypting peer shares during recovery.
    /// Cleared immediately when `handle_recovery_request` is invoked.
    pub hpke_private_key: Option<TinkHpkePrivateKey>,
    /// Serialized Tink `EncryptedKeyset` bytes produced exclusively via
    /// `TinkHpkePrivateKey::to_encrypted_keyset` (or restored via `FromProto`).
    /// Kept private to prevent accidental storage of unencrypted keysets.
    hpke_private_keyset: Option<Vec<u8>>,
    /// Broadcast `FeldmanCommitment`s indexed by 1-based `dealer_index`, bound to
    /// `setup_transcript_hash`.
    pub dealer_commitments: BTreeMap<NonZeroU32, FeldmanCommitment>,
    /// 32-byte SHA-256 setup transcript hash binding `(session_context, roster_hash,
    /// dealer_commitments)`.
    pub setup_transcript_hash: Option<[u8; ROSTER_HASH_BYTE_LEN]>,
}

impl<Vahe: VaheBase> DecryptorState<Vahe> {
    /// Encrypts `private_key` under `wrapping_key` and `associated_data` using Tink
    /// `EncryptedKeysetFormat` (`TinkHpkePrivateKey::to_encrypted_keyset`), stores the
    /// resulting ciphertext in `self.hpke_private_keyset`, and caches the in-memory
    /// handle in `self.hpke_private_key`.
    pub fn set_encrypted_hpke_private_key(
        &mut self,
        private_key: &TinkHpkePrivateKey,
        wrapping_key: &TinkHpkeKeysetWrappingKey,
        associated_data: &[u8],
    ) -> status::Status {
        let encrypted = private_key.to_encrypted_keyset(wrapping_key, associated_data)?;
        self.hpke_private_keyset = Some(encrypted);
        self.hpke_private_key = Some(private_key.clone());
        Ok(())
    }

    /// Decrypts `self.hpke_private_keyset` under `wrapping_key` and `associated_data`
    /// (`TinkHpkePrivateKey::from_encrypted_keyset`) and caches the resulting handle in
    /// `self.hpke_private_key`.
    pub fn restore_encrypted_hpke_private_key(
        &mut self,
        wrapping_key: &TinkHpkeKeysetWrappingKey,
        associated_data: &[u8],
    ) -> Result<&TinkHpkePrivateKey, StatusError> {
        let encrypted = self.hpke_private_keyset.as_deref().ok_or_else(|| {
            status::failed_precondition("DecryptorState does not contain an encrypted HPKE keyset")
        })?;
        let key =
            TinkHpkePrivateKey::from_encrypted_keyset(encrypted, wrapping_key, associated_data)?;
        self.hpke_private_key = Some(key);
        self.hpke_private_key.as_ref().ok_or_else(|| {
            status::internal("hpke_private_key missing after successful restoration")
        })
    }

    /// Returns a read-only slice of the Tink `EncryptedKeyset` bytes, if present.
    pub fn encrypted_hpke_private_keyset(&self) -> Option<&[u8]> {
        self.hpke_private_keyset.as_deref()
    }

    /// Clears the in-memory `hpke_private_key` handle and drops `hpke_private_keyset`.
    pub fn clear_hpke_private_key(&mut self) {
        self.hpke_private_key = None;
        self.hpke_private_keyset = None;
    }
}

impl<Vahe: VaheBase> Default for DecryptorState<Vahe> {
    fn default() -> Self {
        Self {
            sk_share: None,
            kahe: None,
            aggregation_config: None,
            status: DecryptorStatus::PreSetup,
            committee_config: None,
            hpke_private_key: None,
            hpke_private_keyset: None,
            dealer_commitments: BTreeMap::new(),
            setup_transcript_hash: None,
        }
    }
}

impl<'a, C, Vahe> ToProto<&'a C> for DecryptorState<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::SecretKeyShare: ToProto<&'a Vahe, Proto = ShellAheSecretKeyShare>,
{
    type Proto = DecryptorStateProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = DecryptorStateProto::new();
        proto.set_status(self.status.to_proto(())?);
        if let Some(sk) = &self.sk_share {
            proto.set_sk_share(sk.to_proto(context.vahe())?);
        }
        if let Some(config) = &self.aggregation_config {
            proto.set_aggregation_config(config.to_proto(())?);
        }
        if let Some(committee_config) = &self.committee_config {
            proto.set_committee_config(committee_config.to_proto(())?);
        }
        if let Some(hpke_sk) = &self.hpke_private_keyset {
            proto.set_hpke_private_keyset(hpke_sk.as_slice());
        }
        for (&dealer_idx, commitment) in &self.dealer_commitments {
            proto.dealer_commitments_mut().insert(dealer_idx.get(), commitment.to_proto(())?);
        }
        if let Some(transcript_hash) = &self.setup_transcript_hash {
            proto.set_setup_transcript_hash(transcript_hash.as_slice());
        }
        Ok(proto)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for DecryptorState<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::SecretKeyShare: FromProto<&'a Vahe, Proto = ShellAheSecretKeyShare>,
{
    type Proto = DecryptorStateProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let sk_share = if proto.has_sk_share() {
            Some(Vahe::SecretKeyShare::from_proto(proto.sk_share(), context.vahe())?)
        } else {
            None
        };
        let committee_config = if proto.has_committee_config() {
            Some(CommitteeConfig::from_proto(proto.committee_config(), ())?)
        } else {
            None
        };
        let hpke_private_keyset = if proto.hpke_private_keyset().is_empty() {
            None
        } else {
            Some(proto.hpke_private_keyset().to_vec())
        };
        let mut dealer_commitments = BTreeMap::new();
        for (raw_idx, comm_view) in proto.dealer_commitments().iter() {
            let dealer_idx = NonZeroU32::new(raw_idx).ok_or_else(|| {
                status::invalid_argument("DecryptorState dealer_commitments key must be non-zero")
            })?;
            if let Some(cfg) = &committee_config {
                if dealer_idx.get() > cfg.num_decryptors {
                    return Err(status::invalid_argument(
                        "DecryptorState dealer_commitments index exceeds num_decryptors",
                    ));
                }
            }
            let commitment = FeldmanCommitment::from_proto(comm_view, ())?;
            if let Some(cfg) = &committee_config {
                if commitment.threshold() != cfg.threshold as usize {
                    return Err(status::invalid_argument(
                        "DecryptorState dealer commitment threshold does not match CommitteeConfig",
                    ));
                }
            }
            dealer_commitments.insert(dealer_idx, commitment);
        }
        let setup_transcript_hash = if proto.setup_transcript_hash().is_empty() {
            None
        } else {
            let hash: [u8; ROSTER_HASH_BYTE_LEN] =
                proto.setup_transcript_hash().try_into().map_err(|_| {
                    status::invalid_argument(
                        "DecryptorState setup_transcript_hash must be 32 bytes",
                    )
                })?;
            if let Some(cfg) = &committee_config {
                if dealer_commitments.len() == cfg.num_decryptors as usize {
                    let expected = compute_setup_transcript_hash(
                        &cfg.roster_hash,
                        &cfg.session_context,
                        cfg.threshold,
                        cfg.num_decryptors,
                        &dealer_commitments,
                    )?;
                    if expected != hash {
                        return Err(status::invalid_argument(
                            "DecryptorState setup_transcript_hash does not match dealer_commitments",
                        ));
                    }
                } else {
                    return Err(status::invalid_argument(
                        "DecryptorState with setup_transcript_hash must have all num_decryptors dealer_commitments",
                    ));
                }
            }
            Some(hash)
        };
        // Backward compatibility for legacy single-decryptor `DecryptorStateProto`
        // messages (`committee_config.is_none() && hpke_private_keyset.is_none()`)
        // where proto3 `status` defaults to `DECRYPTOR_STATUS_UNSPECIFIED` (0):
        // infer `AwaitingDecryptionRequest` when `sk_share` is present and `PreSetup`
        // when `sk_share` is absent. Recoverable committee states (`committee_config`
        // or `hpke_private_keyset` present) strictly reject `Unspecified` (`B7`).
        let status = match proto.status() {
            messages_rust_proto::DecryptorStatus::Unspecified => {
                if committee_config.is_some()
                    || hpke_private_keyset.is_some()
                    || !dealer_commitments.is_empty()
                    || setup_transcript_hash.is_some()
                {
                    return Err(status::invalid_argument(
                        "DecryptorStatus is unspecified for recoverable committee state",
                    ));
                }
                if sk_share.is_some() {
                    DecryptorStatus::AwaitingDecryptionRequest
                } else {
                    DecryptorStatus::PreSetup
                }
            }
            raw_status => DecryptorStatus::from_proto(raw_status, ())?,
        };
        if status == DecryptorStatus::PreSetup && sk_share.is_some() {
            return Err(status::invalid_argument(
                "DecryptorState in PreSetup status must not have sk_share",
            ));
        }
        if (status == DecryptorStatus::AwaitingDecryptionRequest
            || status == DecryptorStatus::AwaitingRecoveryRequest)
            && sk_share.is_none()
        {
            return Err(status::invalid_argument(
                "DecryptorState in active status is missing sk_share",
            ));
        }
        let aggregation_config = if proto.has_aggregation_config() {
            Some(AggregationConfig::from_proto(proto.aggregation_config(), ())?)
        } else {
            None
        };
        let kahe = if let Some(config) = &aggregation_config {
            use shell_parameters::create_shell_configs;
            let (kahe_config, _) = create_shell_configs(config)?;
            Some(Rc::new(ShellKahe::new(kahe_config, &config.key_id)?))
        } else {
            None
        };
        Ok(DecryptorState {
            sk_share,
            kahe,
            aggregation_config,
            status,
            committee_config,
            hpke_private_key: None,
            hpke_private_keyset,
            dealer_commitments,
            setup_transcript_hash,
        })
    }
}

impl<Vahe> Decryptor<Vahe>
where
    Vahe: VaheBase + VerifiableKeyGen + KeyGenVerify + PartialDec + AheKeygen,
{
    /// Creates a public key share and a ZK proof of knowledge of the secret key
    /// without secret-sharing the key generation seed.
    ///
    /// Preserved with its exact signature and PRNG draw sequence for single-decryptor
    /// and reputable-decryptor callers.
    pub fn create_setup_contribution(
        &self,
        decryptor_state: &mut DecryptorState<Vahe>,
    ) -> Result<SetupContribution<Vahe>, StatusError> {
        let (sk_share, pk_share, key_gen_proof) =
            self.vahe.verifiable_key_gen(&mut self.prng.borrow_mut())?;

        decryptor_state.sk_share = Some(sk_share);
        decryptor_state.status = DecryptorStatus::AwaitingDecryptionRequest;

        Ok(SetupContribution {
            key_contribution: KeyContribution {
                public_key_share: pk_share,
                proof: Some(key_gen_proof),
            },
            dp_setup: None,
            encrypted_randomness_shares: None,
            decryptor_index: decryptor_state.committee_config.as_ref().map(|c| c.my_index),
            feldman_commitment: None,
            indexed_encrypted_shares: BTreeMap::new(),
        })
    }

    /// Creates a recoverable multi-decryptor setup contribution for a committee member:
    /// 1. Validates `committee_config` and verifies that `roster_public_keys` forms a complete
    ///    1-based roster `1..=num_decryptors` whose `compute_roster_hash` matches
    ///    `committee_config.roster_hash`, and whose entry at `committee_config.my_index` matches
    ///    `hpke_private_key.public_key()`.
    /// 2. Samples a uniform non-zero Ristretto255 `vss_secret` from `self.prng`.
    /// 3. Derives a 64-byte `keygen_seed = derive_keygen_seed(&vss_secret, &session_context,
    ///    &roster_hash, my_index)` and runs `self.vahe.verifiable_key_gen` on an isolated
    ///    `Vahe::Rng::create(&keygen_seed)` instance (so `self.prng` is completely decoupled from
    ///    `verifiable_key_gen` draw counts).
    /// 4. Splits `vss_secret` into `(feldman_commitment, shares)` via `feldman_vss::split` and
    ///    HPKE-encrypts each peer share (`share.index != my_index`) under that peer's
    ///    `TinkHpkePublicKey` with context-bound `(session_context, roster_hash, my_index,
    ///    recipient_index)`.
    pub fn create_recoverable_setup_contribution(
        &self,
        committee_config: CommitteeConfig,
        roster_public_keys: &BTreeMap<NonZeroU32, TinkHpkePublicKey>,
        hpke_private_key: &TinkHpkePrivateKey,
        decryptor_state: &mut DecryptorState<Vahe>,
    ) -> Result<SetupContribution<Vahe>, StatusError>
    where
        Vahe::Rng: SecurePrng<Seed = single_thread_hkdf::Seed>,
    {
        if decryptor_state.status != DecryptorStatus::PreSetup || decryptor_state.sk_share.is_some()
        {
            return Err(status::failed_precondition(
                "create_recoverable_setup_contribution requires DecryptorState in PreSetup status",
            ));
        }
        if let Some(existing_cfg) = &decryptor_state.committee_config {
            if existing_cfg != &committee_config {
                return Err(status::failed_precondition(
                    "DecryptorState already has a different immutable CommitteeConfig",
                ));
            }
        }
        committee_config.validate()?;

        if roster_public_keys.len() != committee_config.num_decryptors as usize {
            return Err(status::invalid_argument(
                "roster_public_keys length must equal committee_config.num_decryptors",
            ));
        }
        let mut raw_roster = BTreeMap::new();
        for i in 1..=committee_config.num_decryptors {
            let idx = NonZeroU32::new(i).ok_or_else(|| {
                status::internal("committee index in 1..=num_decryptors must be non-zero")
            })?;
            let pk = roster_public_keys.get(&idx).ok_or_else(|| {
                status::invalid_argument(
                    "roster_public_keys must contain every index in 1..=num_decryptors",
                )
            })?;
            TinkHpkeShareCipher::validate_public_key(pk)?;
            raw_roster.insert(idx, pk.as_bytes().to_vec());
        }

        let own_expected_pk = hpke_private_key.public_key()?;
        let own_roster_pk =
            roster_public_keys.get(&committee_config.my_index).ok_or_else(|| {
                status::invalid_argument("roster_public_keys is missing committee_config.my_index")
            })?;
        if &own_expected_pk != own_roster_pk {
            return Err(status::invalid_argument(
                "hpke_private_key public key does not match roster_public_keys[my_index]",
            ));
        }

        let computed_roster_hash = compute_roster_hash(
            committee_config.num_decryptors,
            committee_config.threshold,
            &raw_roster,
        )?;
        if computed_roster_hash != committee_config.roster_hash {
            return Err(status::invalid_argument(
                "computed roster hash does not match committee_config.roster_hash",
            ));
        }

        // Sample `vss_secret` and split polynomial using `self.prng`, while running
        // `verifiable_key_gen` on an isolated PRNG seeded from `derive_keygen_seed`.
        let vss_secret = SecretScalar::random(&mut *self.prng.borrow_mut())?;
        let keygen_seed = derive_keygen_seed(
            &vss_secret,
            &committee_config.session_context,
            &committee_config.roster_hash,
            committee_config.my_index,
        )?;
        let mut keygen_prng = Vahe::Rng::create(&keygen_seed)?;
        let (sk_share, pk_share, key_gen_proof) = self.vahe.verifiable_key_gen(&mut keygen_prng)?;

        let (feldman_commitment, shares) = feldman_vss::split(
            &vss_secret,
            committee_config.threshold,
            committee_config.num_decryptors,
            &mut *self.prng.borrow_mut(),
        )?;

        let mut indexed_encrypted_shares = BTreeMap::new();
        for share in &shares {
            if share.index == committee_config.my_index {
                continue;
            }
            let peer_pk = roster_public_keys.get(&share.index).ok_or_else(|| {
                status::internal("peer public key missing for validated share index")
            })?;
            let ciphertext = TinkHpkeShareCipher::encrypt_share(
                peer_pk,
                share,
                &committee_config.session_context,
                &committee_config.roster_hash,
                committee_config.my_index,
            )?;
            indexed_encrypted_shares.insert(share.index, ciphertext);
        }

        let my_index = committee_config.my_index;
        decryptor_state.sk_share = Some(sk_share);
        decryptor_state.committee_config = Some(committee_config);
        decryptor_state.hpke_private_key = Some(hpke_private_key.clone());
        decryptor_state.dealer_commitments.insert(my_index, feldman_commitment.clone());
        decryptor_state.status = DecryptorStatus::AwaitingDecryptionRequest;

        Ok(SetupContribution {
            key_contribution: KeyContribution {
                public_key_share: pk_share,
                proof: Some(key_gen_proof),
            },
            dp_setup: None,
            encrypted_randomness_shares: None,
            decryptor_index: Some(my_index),
            feldman_commitment: Some(feldman_commitment),
            indexed_encrypted_shares,
        })
    }

    /// Validates and binds all committee members' broadcast `FeldmanCommitment`s into
    /// `decryptor_state`, verifying that:
    /// 1. Every `dealer_index` is in `1..=committee_config.num_decryptors` (`num_decryptors`
    ///    entries total) and every commitment has `threshold() == committee_config.threshold`.
    /// 2. If this decryptor generated its own `FeldmanCommitment` during setup, the entry at
    ///    `committee_config.my_index` is present and identical to the commitment it broadcast
    ///    (preventing Coordinator equivocation on this decryptor's commitment).
    /// 3. Computes and locks `setup_transcript_hash = compute_setup_transcript_hash(...)`
    ///    (rejecting any attempt to rebind a different commitment transcript).
    pub fn bind_setup_commitments(
        &self,
        dealer_commitments: BTreeMap<NonZeroU32, FeldmanCommitment>,
        decryptor_state: &mut DecryptorState<Vahe>,
    ) -> Result<[u8; ROSTER_HASH_BYTE_LEN], StatusError> {
        let cfg = decryptor_state.committee_config.as_ref().ok_or_else(|| {
            status::failed_precondition(
                "bind_setup_commitments requires committee_config in DecryptorState",
            )
        })?;
        if dealer_commitments.len() != cfg.num_decryptors as usize {
            return Err(status::invalid_argument(
                "dealer_commitments must contain exactly num_decryptors entries (1..=num_decryptors)",
            ));
        }
        for (&dealer_idx, commitment) in &dealer_commitments {
            if dealer_idx.get() > cfg.num_decryptors {
                return Err(status::invalid_argument(
                    "dealer_commitments index exceeds committee_config.num_decryptors",
                ));
            }
            if commitment.threshold() != cfg.threshold as usize {
                return Err(status::invalid_argument(
                    "dealer commitment threshold does not match committee_config.threshold",
                ));
            }
        }
        // If this decryptor already recorded its own commitment at `my_index` (or a previous
        // full commitment map), verify that our own commitment at `my_index` is unchanged.
        if let Some(own_commitment) = decryptor_state.dealer_commitments.get(&cfg.my_index) {
            let provided_own = dealer_commitments.get(&cfg.my_index).ok_or_else(|| {
                status::invalid_argument(
                    "dealer_commitments is missing this decryptor's own commitment at my_index",
                )
            })?;
            if provided_own != own_commitment {
                return Err(status::invalid_argument(
                    "dealer_commitments entry at my_index does not match own setup commitment",
                ));
            }
        }

        let transcript_hash = compute_setup_transcript_hash(
            &cfg.roster_hash,
            &cfg.session_context,
            cfg.threshold,
            cfg.num_decryptors,
            &dealer_commitments,
        )?;
        if let Some(existing_hash) = &decryptor_state.setup_transcript_hash {
            if existing_hash != &transcript_hash {
                return Err(status::failed_precondition(
                    "DecryptorState already bound a different setup_transcript_hash",
                ));
            }
        }
        decryptor_state.dealer_commitments = dealer_commitments;
        decryptor_state.setup_transcript_hash = Some(transcript_hash);
        Ok(transcript_hash)
    }

    /// Verifies the ZK proofs of knowledge of the secret key for all public key
    /// shares, and returns the aggregated public key. Calling code should sign
    /// the aggregated public key for the aggregation.
    ///
    /// Note: This method fails if any single contribution has an invalid proof,
    /// aborting the entire key generation. This is acceptable because the
    /// protocol does not guarantee output delivery against malicious decryptors
    /// or a malicious coordinator — a malicious participant could equally cause
    /// failure by refusing to provide partial decryptions and secret-sharing an
    /// invalid state in the setup contribution.
    pub fn verify_and_aggregate_key_contributions(
        &self,
        request: VerifyKeyContributionsRequest<Vahe>,
    ) -> Result<DecryptorPublicKey<Vahe>, StatusError> {
        if request.key_contributions.is_empty() {
            return Err(status::invalid_argument("key_contributions list is empty"));
        }

        // Verify all proofs.
        for key_contribution in &request.key_contributions {
            let proof = key_contribution.proof.as_ref().ok_or_else(|| {
                status::invalid_argument(
                    "Missing key generation proof in VerifyKeyContributionsRequest",
                )
            })?;
            self.vahe.verify_key_gen(proof, &key_contribution.public_key_share)?;
        }

        // Aggregate all public key shares into the final public key.
        let public_key_shares: Vec<_> =
            request.key_contributions.iter().map(|kc| &kc.public_key_share).collect();

        self.vahe.aggregate_public_key_shares(public_key_shares.into_iter())
    }

    /// Handles a partial decryption request received from the Server. Returns a
    /// partial decryption to the Server and transitions `decryptor_state.status`
    /// from `AwaitingDecryptionRequest` to `AwaitingRecoveryRequest` (enforcing
    /// one-shot partial decryption per committee session).
    pub fn handle_partial_decryption_request<Kahe: KaheBase>(
        &self,
        partial_decryption_request: PartialDecryptionRequest<Vahe>,
        _kahe: Option<&Kahe>,
        decryptor_state: &mut DecryptorState<Vahe>,
    ) -> Result<PartialDecryptionResponse<Kahe, Vahe>, StatusError> {
        if decryptor_state.status != DecryptorStatus::AwaitingDecryptionRequest {
            return Err(status::failed_precondition(
                "handle_partial_decryption_request requires DecryptorStatus::AwaitingDecryptionRequest",
            ));
        }
        if let Some(config) = &partial_decryption_request.aggregation_config {
            if decryptor_state.kahe.is_none() {
                use shell_parameters::create_shell_configs;
                let (kahe_config, _) = create_shell_configs(config)?;
                decryptor_state.kahe = Some(Rc::new(ShellKahe::new(kahe_config, &config.key_id)?));
                decryptor_state.aggregation_config = Some(config.clone());
            }
        }
        let sk_share = decryptor_state.sk_share.as_ref().ok_or_else(|| {
            status::failed_precondition("decryptor_state does not contain a secret key share")
        })?;
        // `borrow_mut()` will not panic here because `self.prng` is not
        // borrowed anywhere else in this call.
        let pd = self.vahe.partial_decrypt(
            &partial_decryption_request.partial_dec_ciphertext,
            sk_share,
            &mut self.prng.borrow_mut(),
        )?;
        decryptor_state.status = DecryptorStatus::AwaitingRecoveryRequest;
        Ok(PartialDecryptionResponse {
            partial_decryption: pd,
            dp_ciphertext_contribution: None,
            decryptor_index: decryptor_state.committee_config.as_ref().map(|c| c.my_index),
        })
    }

    /// Handles a one-shot request to decrypt Feldman VSS shares of dropped decryptors.
    ///
    /// Enforces:
    /// 1. `decryptor_state.status` is `AwaitingDecryptionRequest` or `AwaitingRecoveryRequest`, and
    ///    **immediately** burns the state to `DecryptorStatus::Finished` and clears the HPKE
    ///    private key before any fallible check (`C1` / `A2` one-shot guarantee).
    /// 2. At least 1 and at most `num_decryptors - threshold` (`n - t`) shares are requested.
    /// 3. The broadcast `FeldmanCommitment`s are bound to `setup_transcript_hash` (including
    ///    verifying that this decryptor's own commitment at `my_index` matches setup).
    /// 4. Each requested share is for a distinct `dealer_index != my_index` in
    ///    `1..=num_decryptors`, addressed to `recipient_index == my_index`, decrypts under HPKE
    ///    with context-bound `(session_context, roster_hash, dealer_index, my_index)`, and passes
    ///    `feldman_vss::verify_share(&dealer_commitment, &share)` before release (`#75`).
    pub fn handle_recovery_request(
        &self,
        recovery_request: RecoveryRequest,
        decryptor_state: &mut DecryptorState<Vahe>,
    ) -> Result<RecoveryResponse, StatusError> {
        if decryptor_state.status != DecryptorStatus::AwaitingDecryptionRequest
            && decryptor_state.status != DecryptorStatus::AwaitingRecoveryRequest
        {
            return Err(status::failed_precondition(
                "handle_recovery_request requires AwaitingDecryptionRequest or AwaitingRecoveryRequest status",
            ));
        }

        // Immediately transition to `Finished` and take and clear the HPKE private key so that
        // even a failed recovery call burns the one-shot recovery capability.
        decryptor_state.status = DecryptorStatus::Finished;
        let hpke_private_key = decryptor_state.hpke_private_key.take();
        decryptor_state.clear_hpke_private_key();

        let hpke_private_key = hpke_private_key.ok_or_else(|| {
            status::failed_precondition(
                "DecryptorState does not have an active hpke_private_key (call restore_encrypted_hpke_private_key first)",
            )
        })?;

        if !recovery_request.encrypted_shares.is_empty() {
            return Err(status::invalid_argument(
                "RecoveryRequest must not populate legacy unindexed encrypted_shares",
            ));
        }
        if !recovery_request.dealer_commitments.is_empty() {
            self.bind_setup_commitments(recovery_request.dealer_commitments, decryptor_state)?;
        }
        if decryptor_state.setup_transcript_hash.is_none() {
            return Err(status::failed_precondition(
                "handle_recovery_request requires bound dealer_commitments / setup_transcript_hash",
            ));
        }

        let cfg = decryptor_state.committee_config.as_ref().ok_or_else(|| {
            status::failed_precondition(
                "handle_recovery_request requires committee_config in DecryptorState",
            )
        })?;

        let max_dropouts = (cfg.num_decryptors - cfg.threshold) as usize;
        let requested_count = recovery_request.indexed_encrypted_shares.len();
        if requested_count == 0 {
            return Err(status::invalid_argument(
                "RecoveryRequest must contain at least one encrypted share",
            ));
        }
        if requested_count > max_dropouts {
            return Err(status::invalid_argument(
                "RecoveryRequest exceeds maximum allowed dropouts (num_decryptors - threshold)",
            ));
        }

        let mut indexed_decrypted_shares = BTreeMap::new();
        for (&dealer_index, ciphertext) in &recovery_request.indexed_encrypted_shares {
            if dealer_index.get() > cfg.num_decryptors {
                return Err(status::invalid_argument(
                    "RecoveryRequest dealer_index exceeds committee_config.num_decryptors",
                ));
            }
            if dealer_index == cfg.my_index {
                return Err(status::invalid_argument(
                    "RecoveryRequest must not request a decryptor's own dealer share",
                ));
            }
            if ciphertext.is_empty() {
                return Err(status::invalid_argument(
                    "RecoveryRequest encrypted share ciphertext must be non-empty",
                ));
            }
            let dealer_commitment =
                decryptor_state.dealer_commitments.get(&dealer_index).ok_or_else(|| {
                    status::invalid_argument(
                        "RecoveryRequest dealer_index is missing from bound dealer_commitments",
                    )
                })?;
            if dealer_commitment.threshold() != cfg.threshold as usize {
                return Err(status::invalid_argument(
                    "Bound dealer commitment threshold does not match committee_config.threshold",
                ));
            }

            let share = TinkHpkeShareCipher::decrypt_share(
                &hpke_private_key,
                ciphertext,
                &cfg.session_context,
                &cfg.roster_hash,
                dealer_index,
                cfg.my_index,
            )?;
            feldman_vss::verify_share(dealer_commitment, &share)?;

            indexed_decrypted_shares.insert(dealer_index, share);
        }

        Ok(RecoveryResponse {
            decrypted_shares: Vec::new(),
            survivor_index: Some(cfg.my_index),
            indexed_decrypted_shares,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{Decryptor, DecryptorState};
    use ahe_traits::AheBase;
    use googletest::{gtest, verify_true};
    use proto_serialization_traits::{FromProto, ToProto};
    use shell_parameters::create_shell_ahe_config;
    use shell_vahe::ShellVahe;
    use std::rc::Rc;

    const CONTEXT_STRING: &[u8] = b"testing_context_string";

    #[gtest]
    fn decryptor_state_serialization_roundtrip() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe)?;
        let mut decryptor_state = DecryptorState::default();

        // Check empty state serialization.
        let decryptor_state_proto = decryptor_state.to_proto(&decryptor)?;
        let decryptor_state_roundtrip =
            DecryptorState::from_proto(decryptor_state_proto, &decryptor)?;
        verify_true!(decryptor_state_roundtrip.sk_share.is_none())?;

        // Check populated state serialization.
        decryptor.create_setup_contribution(&mut decryptor_state)?;
        verify_true!(decryptor_state.sk_share.is_some())?;
        let decryptor_state_proto = decryptor_state.to_proto(&decryptor)?;
        let decryptor_state_roundtrip =
            DecryptorState::from_proto(decryptor_state_proto, &decryptor)?;
        verify_true!(decryptor_state_roundtrip.sk_share.is_some())?;

        Ok(())
    }

    #[gtest]
    fn decryptor_state_with_config_roundtrip() -> googletest::Result<()> {
        use kahe_traits::KaheBase;
        use shell_kahe::ShellKahe;
        use shell_parameters::create_shell_kahe_config;
        use testing_utils::generate_aggregation_config;

        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe)?;

        let config = generate_aggregation_config("default".to_string(), 16, 10, 1, 1);
        let kahe_config = create_shell_kahe_config(&config)?;
        let kahe = Rc::new(ShellKahe::new(kahe_config, &config.key_id)?);

        let mut decryptor_state = DecryptorState::default();
        decryptor.create_setup_contribution(&mut decryptor_state)?;
        decryptor_state.kahe = Some(kahe);
        decryptor_state.aggregation_config = Some(config);

        verify_true!(decryptor_state.kahe.is_some())?;
        verify_true!(decryptor_state.aggregation_config.is_some())?;

        let decryptor_state_proto = decryptor_state.to_proto(&decryptor)?;
        let decryptor_state_roundtrip =
            DecryptorState::from_proto(decryptor_state_proto, &decryptor)?;

        verify_true!(decryptor_state_roundtrip.sk_share.is_some())?;
        verify_true!(decryptor_state_roundtrip.kahe.is_some())?;
        verify_true!(decryptor_state_roundtrip.aggregation_config.is_some())?;

        Ok(())
    }

    // --- Multi-decryptor tests ---

    #[gtest]
    fn create_setup_contribution_generates_key_share_and_proof() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe)?;
        let mut state = DecryptorState::default();

        let contribution = decryptor.create_setup_contribution(&mut state)?;

        verify_true!(contribution.key_contribution.proof.is_some())?;
        verify_true!(state.sk_share.is_some())?;
        verify_true!(contribution.encrypted_randomness_shares.is_none())?;
        verify_true!(contribution.dp_setup.is_none())?;

        Ok(())
    }

    #[gtest]
    fn verify_and_aggregate_key_contributions_succeeds() -> googletest::Result<()> {
        use messages::VerifyKeyContributionsRequest;

        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let decryptor1 = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let decryptor2 = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;

        let mut state1 = DecryptorState::default();
        let mut state2 = DecryptorState::default();
        let contribution1 = decryptor1.create_setup_contribution(&mut state1)?;
        let contribution2 = decryptor2.create_setup_contribution(&mut state2)?;

        let request = VerifyKeyContributionsRequest {
            key_contributions: vec![contribution1.key_contribution, contribution2.key_contribution],
        };
        let result = decryptor1.verify_and_aggregate_key_contributions(request);
        verify_true!(result.is_ok())?;

        Ok(())
    }

    #[gtest]
    fn verify_key_contributions_fails_with_missing_proof() -> googletest::Result<()> {
        use messages::VerifyKeyContributionsRequest;

        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;

        let mut state = DecryptorState::default();
        let mut contribution = decryptor.create_setup_contribution(&mut state)?;
        contribution.key_contribution.proof = None;

        let request = VerifyKeyContributionsRequest {
            key_contributions: vec![contribution.key_contribution],
        };
        let result = decryptor.verify_and_aggregate_key_contributions(request);
        verify_true!(result.is_err())?;

        Ok(())
    }

    #[gtest]
    fn verify_key_contributions_fails_with_empty_list() -> googletest::Result<()> {
        use messages::VerifyKeyContributionsRequest;

        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe)?;

        let request = VerifyKeyContributionsRequest { key_contributions: vec![] };
        let result = decryptor.verify_and_aggregate_key_contributions(request);
        verify_true!(result.is_err())?;

        Ok(())
    }

    #[gtest]
    fn multi_decryptor_partial_decryption_works() -> googletest::Result<()> {
        use messages::PartialDecryptionResponse;
        use prng_traits::SecurePrng;
        use shell_kahe::ShellKahe;
        use single_thread_hkdf::SingleThreadHkdfPrng;
        use vahe_traits::{Recover, VerifiableEncrypt};

        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);

        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
        let mut state = DecryptorState::default();
        let contribution = decryptor.create_setup_contribution(&mut state)?;

        // Create a public key from the contribution.
        let public_key = vahe.aggregate_public_key_shares(std::iter::once(
            &contribution.key_contribution.public_key_share,
        ))?;

        // Create a ciphertext.
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let plaintext = vec![42i64; 8];
        let nonce = b"0123456789ABCDEF";
        let (ciphertext, _proof) =
            vahe.verifiable_encrypt(&plaintext, &public_key, nonce, &mut prng)?;
        let partial_dec_ciphertext = vahe.get_partial_dec_ciphertext(&ciphertext)?;

        let pd_request =
            messages::PartialDecryptionRequest { partial_dec_ciphertext, aggregation_config: None };

        let pd_response: PartialDecryptionResponse<ShellKahe, ShellVahe> =
            decryptor.handle_partial_decryption_request(pd_request, None, &mut state)?;

        // Verify we can recover from the partial decryption.
        let recover_ciphertext = vahe.get_recover_ciphertext(&ciphertext)?;
        let recovered = vahe.recover(
            &pd_response.partial_decryption,
            &recover_ciphertext,
            Some(plaintext.len()),
        )?;
        verify_true!(recovered == plaintext)?;

        Ok(())
    }

    #[gtest]
    fn decryptor_state_with_committee_config_and_status_roundtrip() -> googletest::Result<()> {
        use messages::{CommitteeConfig, DecryptorStatus};
        use share_cipher::{ShareCipher, TinkHpkeKeysetWrappingKey, TinkHpkeShareCipher};
        use std::num::NonZeroU32;

        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let decryptor = Decryptor::new_with_randomly_generated_seed(vahe)?;

        let cfg = CommitteeConfig::new(
            NonZeroU32::new(2).unwrap(),
            3,
            2,
            [0x33u8; 32],
            b"sess_ctx".to_vec(),
        )?;
        let (hpke_sk, hpke_pk) = TinkHpkeShareCipher::generate_keypair()?;
        let wrapping_key = TinkHpkeKeysetWrappingKey::generate()?;
        let aad = b"decryptor_state_aad";

        let mut state = DecryptorState::default();
        state.committee_config = Some(cfg.clone());
        state.set_encrypted_hpke_private_key(&hpke_sk, &wrapping_key, aad)?;
        verify_true!(state.status == DecryptorStatus::PreSetup)?;
        verify_true!(state.encrypted_hpke_private_keyset().is_some())?;

        // PreSetup roundtrip with committee_config and encrypted hpke_private_keyset.
        let proto = state.to_proto(&decryptor)?;
        let mut roundtrip = DecryptorState::from_proto(proto, &decryptor)?;
        verify_true!(roundtrip.status == DecryptorStatus::PreSetup)?;
        verify_true!(roundtrip.committee_config.as_ref() == Some(&cfg))?;
        verify_true!(
            roundtrip.encrypted_hpke_private_keyset() == state.encrypted_hpke_private_keyset()
        )?;
        // Restoring with wrong AAD fails; restoring with matching AAD recovers the HPKE keypair.
        verify_true!(roundtrip
            .restore_encrypted_hpke_private_key(&wrapping_key, b"wrong_aad")
            .is_err())?;
        let restored_sk = roundtrip.restore_encrypted_hpke_private_key(&wrapping_key, aad)?;
        verify_true!(restored_sk.public_key()? == hpke_pk)?;

        // Setup transitions status to AwaitingDecryptionRequest and sets decryptor_index on
        // contribution.
        let contrib = decryptor.create_setup_contribution(&mut state)?;
        verify_true!(state.status == DecryptorStatus::AwaitingDecryptionRequest)?;
        verify_true!(contrib.decryptor_index == Some(NonZeroU32::new(2).unwrap()))?;

        let proto = state.to_proto(&decryptor)?;
        let roundtrip = DecryptorState::from_proto(proto, &decryptor)?;
        verify_true!(roundtrip.status == DecryptorStatus::AwaitingDecryptionRequest)?;
        verify_true!(roundtrip.sk_share.is_some())?;
        verify_true!(roundtrip.committee_config.as_ref() == Some(&cfg))?;

        // Rejects PreSetup when sk_share is present.
        let mut invalid_proto = state.to_proto(&decryptor)?;
        invalid_proto.set_status(messages_rust_proto::DecryptorStatus::PreSetup);
        verify_true!(DecryptorState::from_proto(invalid_proto, &decryptor).is_err())?;

        // Rejects AwaitingDecryptionRequest when sk_share is missing.
        let mut missing_sk_proto = DecryptorState::default().to_proto(&decryptor)?;
        missing_sk_proto
            .set_status(messages_rust_proto::DecryptorStatus::AwaitingDecryptionRequest);
        verify_true!(DecryptorState::from_proto(missing_sk_proto, &decryptor).is_err())?;

        // Legacy backward compatibility: Unspecified status (proto3 default 0) on a
        // single-decryptor state (`committee_config == None && hpke_private_keyset == None`)
        // infers PreSetup when sk_share is absent and AwaitingDecryptionRequest when sk_share is
        // present.
        let mut legacy_empty_proto = DecryptorState::default().to_proto(&decryptor)?;
        legacy_empty_proto.set_status(messages_rust_proto::DecryptorStatus::Unspecified);
        let legacy_empty = DecryptorState::from_proto(legacy_empty_proto, &decryptor)?;
        verify_true!(legacy_empty.status == DecryptorStatus::PreSetup)?;

        let mut single_dec_state = DecryptorState::default();
        decryptor.create_setup_contribution(&mut single_dec_state)?;
        let mut legacy_sk_proto = single_dec_state.to_proto(&decryptor)?;
        legacy_sk_proto.set_status(messages_rust_proto::DecryptorStatus::Unspecified);
        let legacy_sk = DecryptorState::from_proto(legacy_sk_proto, &decryptor)?;
        verify_true!(legacy_sk.status == DecryptorStatus::AwaitingDecryptionRequest)?;
        verify_true!(legacy_sk.sk_share.is_some())?;

        // Recoverable committee state (`committee_config` or `hpke_private_keyset` present)
        // strictly rejects Unspecified status (`B7`).
        let mut committee_unspec_proto = state.to_proto(&decryptor)?;
        committee_unspec_proto.set_status(messages_rust_proto::DecryptorStatus::Unspecified);
        verify_true!(DecryptorState::from_proto(committee_unspec_proto, &decryptor).is_err())?;

        Ok(())
    }

    #[gtest]
    fn recoverable_setup_and_one_shot_recovery_end_to_end() -> googletest::Result<()> {
        use feldman_vss::derive_keygen_seed;
        use messages::{
            compute_roster_hash, CommitteeConfig, DecryptorStatus, PartialDecryptionRequest,
            PartialDecryptionResponse, RecoveryRequest,
        };
        use prng_traits::SecurePrng;
        use share_cipher::{ShareCipher, TinkHpkeShareCipher};
        use shell_kahe::ShellKahe;
        use single_thread_hkdf::SingleThreadHkdfPrng;
        use std::collections::BTreeMap;
        use std::num::NonZeroU32;
        use vahe_traits::{VerifiableEncrypt, VerifiableKeyGen};

        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let num_decryptors = 4u32;
        let threshold = 3u32;
        let session_context = b"session_recoverable_e2e".to_vec();

        // Generate HPKE keypairs for all 4 committee members.
        let mut hpke_sks = BTreeMap::new();
        let mut roster_pks = BTreeMap::new();
        let mut raw_roster = BTreeMap::new();
        for i in 1..=num_decryptors {
            let idx = NonZeroU32::new(i).unwrap();
            let (sk, pk) = TinkHpkeShareCipher::generate_keypair()?;
            raw_roster.insert(idx, pk.as_bytes().to_vec());
            hpke_sks.insert(idx, sk);
            roster_pks.insert(idx, pk);
        }
        let roster_hash = compute_roster_hash(num_decryptors, threshold, &raw_roster)?;

        // Each decryptor runs `create_recoverable_setup_contribution`.
        let mut decryptors = BTreeMap::new();
        let mut states = BTreeMap::new();
        let mut contributions = BTreeMap::new();
        let mut dealer_commitments = BTreeMap::new();
        for i in 1..=num_decryptors {
            let idx = NonZeroU32::new(i).unwrap();
            let dec = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
            let mut state = DecryptorState::default();
            let cfg = CommitteeConfig::new(
                idx,
                num_decryptors,
                threshold,
                roster_hash,
                session_context.clone(),
            )?;
            let contrib = dec.create_recoverable_setup_contribution(
                cfg,
                &roster_pks,
                &hpke_sks[&idx],
                &mut state,
            )?;
            verify_true!(state.status == DecryptorStatus::AwaitingDecryptionRequest)?;
            verify_true!(contrib.decryptor_index == Some(idx))?;
            verify_true!(contrib.indexed_encrypted_shares.len() == (num_decryptors - 1) as usize)?;
            dealer_commitments.insert(idx, contrib.feldman_commitment.clone().unwrap());
            decryptors.insert(idx, dec);
            states.insert(idx, state);
            contributions.insert(idx, contrib);
        }

        // Suppose decryptor 4 drops out after setup; survivors {1, 2, 3} perform partial decryption
        // and then decrypt their shares for dealer 4.
        let idx1 = NonZeroU32::new(1).unwrap();
        let idx2 = NonZeroU32::new(2).unwrap();
        let idx3 = NonZeroU32::new(3).unwrap();
        let idx4 = NonZeroU32::new(4).unwrap();

        let pk_shares: Vec<_> =
            contributions.values().map(|c| &c.key_contribution.public_key_share).collect();
        let joint_pk = vahe.aggregate_public_key_shares(pk_shares.into_iter())?;

        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let plaintext = vec![7i64; 8];
        let (ct, _) = vahe.verifiable_encrypt(&plaintext, &joint_pk, b"nonce_e2e", &mut prng)?;
        let pd_ct = vahe.get_partial_dec_ciphertext(&ct)?;

        // Survivor 1 handles partial decryption -> transitions to AwaitingRecoveryRequest;
        // a second partial decryption call on Survivor 1 is strictly rejected (`B7`).
        let pd_req = PartialDecryptionRequest {
            partial_dec_ciphertext: pd_ct.clone(),
            aggregation_config: None,
        };
        let _pd_resp1: PartialDecryptionResponse<ShellKahe, ShellVahe> = decryptors[&idx1]
            .handle_partial_decryption_request(
                pd_req.clone(),
                None,
                states.get_mut(&idx1).unwrap(),
            )?;
        verify_true!(states[&idx1].status == DecryptorStatus::AwaitingRecoveryRequest)?;
        let second_pd: Result<PartialDecryptionResponse<ShellKahe, ShellVahe>, _> = decryptors
            [&idx1]
            .handle_partial_decryption_request(pd_req, None, states.get_mut(&idx1).unwrap());
        verify_true!(second_pd.is_err())?;

        // Survivors {1, 2, 3} each handle a one-shot RecoveryRequest for dropped dealer 4.
        let mut recovered_shares_for_dealer4 = Vec::new();
        for &survivor_idx in &[idx1, idx2, idx3] {
            let enc_share = contributions[&idx4].indexed_encrypted_shares[&survivor_idx].clone();
            let mut indexed_encrypted_shares = BTreeMap::new();
            indexed_encrypted_shares.insert(idx4, enc_share);
            let req = RecoveryRequest {
                encrypted_shares: Vec::new(),
                indexed_encrypted_shares,
                dealer_commitments: dealer_commitments.clone(),
            };
            let resp = decryptors[&survivor_idx]
                .handle_recovery_request(req, states.get_mut(&survivor_idx).unwrap())?;
            verify_true!(states[&survivor_idx].status == DecryptorStatus::Finished)?;
            verify_true!(states[&survivor_idx].hpke_private_key.is_none())?;
            verify_true!(states[&survivor_idx].encrypted_hpke_private_keyset().is_none())?;
            verify_true!(resp.survivor_index == Some(survivor_idx))?;
            recovered_shares_for_dealer4.push(resp.indexed_decrypted_shares[&idx4].clone());
        }

        // Reconstruct dealer 4's `vss_secret` from the 3 verified shares, re-derive `keygen_seed`,
        // and verify that `verifiable_key_gen` Deterministically reproduces dealer 4's exact
        // `public_key_share`!
        let reconstructed_secret =
            feldman_vss::reconstruct(&dealer_commitments[&idx4], &recovered_shares_for_dealer4)?;
        let regenerated_seed =
            derive_keygen_seed(&reconstructed_secret, &session_context, &roster_hash, idx4)?;
        let mut regen_prng = SingleThreadHkdfPrng::create(&regenerated_seed)?;
        let (_regen_sk4, regen_pk4, _regen_proof4) = vahe.verifiable_key_gen(&mut regen_prng)?;
        let expected_pk4_proto =
            contributions[&idx4].key_contribution.public_key_share.to_proto(vahe.as_ref())?;
        let regen_pk4_proto = regen_pk4.to_proto(vahe.as_ref())?;
        verify_true!(
            protobuf::Serialize::serialize(&regen_pk4_proto).unwrap()
                == protobuf::Serialize::serialize(&expected_pk4_proto).unwrap()
        )?;

        Ok(())
    }

    #[gtest]
    fn recovery_rejects_excess_dropouts_forged_shares_equivocation_and_burns_state(
    ) -> googletest::Result<()> {
        use feldman_vss::{SecretScalar, Share};
        use messages::{compute_roster_hash, CommitteeConfig, DecryptorStatus, RecoveryRequest};
        use share_cipher::{ShareCipher, TinkHpkeShareCipher};
        use std::collections::BTreeMap;
        use std::num::NonZeroU32;

        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, CONTEXT_STRING)?);
        let num_decryptors = 3u32;
        let threshold = 2u32; // max_dropouts = n - t = 1
        let session_context = b"session_adversarial_recovery".to_vec();

        let mut hpke_sks = BTreeMap::new();
        let mut roster_pks = BTreeMap::new();
        let mut raw_roster = BTreeMap::new();
        for i in 1..=num_decryptors {
            let idx = NonZeroU32::new(i).unwrap();
            let (sk, pk) = TinkHpkeShareCipher::generate_keypair()?;
            raw_roster.insert(idx, pk.as_bytes().to_vec());
            hpke_sks.insert(idx, sk);
            roster_pks.insert(idx, pk);
        }
        let roster_hash = compute_roster_hash(num_decryptors, threshold, &raw_roster)?;

        let idx1 = NonZeroU32::new(1).unwrap();
        let idx2 = NonZeroU32::new(2).unwrap();
        let idx3 = NonZeroU32::new(3).unwrap();

        let mut decryptors = BTreeMap::new();
        let mut states = BTreeMap::new();
        let mut contributions = BTreeMap::new();
        let mut dealer_commitments = BTreeMap::new();
        for &idx in &[idx1, idx2, idx3] {
            let dec = Decryptor::new_with_randomly_generated_seed(vahe.clone())?;
            let mut state = DecryptorState::default();
            let cfg = CommitteeConfig::new(
                idx,
                num_decryptors,
                threshold,
                roster_hash,
                session_context.clone(),
            )?;
            let contrib = dec.create_recoverable_setup_contribution(
                cfg,
                &roster_pks,
                &hpke_sks[&idx],
                &mut state,
            )?;
            dealer_commitments.insert(idx, contrib.feldman_commitment.clone().unwrap());
            decryptors.insert(idx, dec);
            states.insert(idx, state);
            contributions.insert(idx, contrib);
        }

        // 1. Requesting > n - t shares (2 shares when n - t = 1) is rejected AND immediately
        // burns state1 to `DecryptorStatus::Finished` so a subsequent valid 1-share request
        // is also rejected (`C1` / `A2` one-shot guarantee).
        let mut two_shares = BTreeMap::new();
        two_shares.insert(idx2, contributions[&idx2].indexed_encrypted_shares[&idx1].clone());
        two_shares.insert(idx3, contributions[&idx3].indexed_encrypted_shares[&idx1].clone());
        let over_threshold_req = RecoveryRequest {
            encrypted_shares: Vec::new(),
            indexed_encrypted_shares: two_shares,
            dealer_commitments: dealer_commitments.clone(),
        };
        verify_true!(decryptors[&idx1]
            .handle_recovery_request(over_threshold_req, states.get_mut(&idx1).unwrap())
            .is_err())?;
        verify_true!(states[&idx1].status == DecryptorStatus::Finished)?;
        verify_true!(states[&idx1].hpke_private_key.is_none())?;

        // Retry with a valid 1-share request on burned `state1` must fail with FailedPrecondition.
        let mut valid_one_share = BTreeMap::new();
        valid_one_share.insert(idx2, contributions[&idx2].indexed_encrypted_shares[&idx1].clone());
        let retry_req = RecoveryRequest {
            encrypted_shares: Vec::new(),
            indexed_encrypted_shares: valid_one_share,
            dealer_commitments: dealer_commitments.clone(),
        };
        verify_true!(decryptors[&idx1]
            .handle_recovery_request(retry_req, states.get_mut(&idx1).unwrap())
            .is_err())?;

        // 2. Coordinator equivocation on survivor 2's own commitment at `my_index = 2`:
        // replacing `dealer_commitments[2]` with `dealer_commitments[3]` is rejected!
        let mut equivocated_commitments = dealer_commitments.clone();
        equivocated_commitments.insert(idx2, dealer_commitments[&idx3].clone());
        verify_true!(decryptors[&idx2]
            .bind_setup_commitments(equivocated_commitments, states.get_mut(&idx2).unwrap())
            .is_err())?;

        // 3. Forged share attack (`#75`): an untrusted Coordinator encrypts an arbitrary non-zero
        // scalar under survivor 2's public key with valid HPKE `context_info` for `(dealer=3,
        // recipient=2)`. HPKE decryption succeeds, but `feldman_vss::verify_share` against
        // `dealer_commitments[3]` catches the forged share and rejects!
        let forged_share =
            Share { index: idx2, value: SecretScalar::from_canonical_bytes(&[7u8; 32])? };
        let forged_ct = TinkHpkeShareCipher::encrypt_share(
            &roster_pks[&idx2],
            &forged_share,
            &session_context,
            &roster_hash,
            idx3,
        )?;
        let mut forged_map = BTreeMap::new();
        forged_map.insert(idx3, forged_ct);
        let forged_req = RecoveryRequest {
            encrypted_shares: Vec::new(),
            indexed_encrypted_shares: forged_map,
            dealer_commitments: dealer_commitments.clone(),
        };
        verify_true!(decryptors[&idx2]
            .handle_recovery_request(forged_req, states.get_mut(&idx2).unwrap())
            .is_err())?;
        verify_true!(states[&idx2].status == DecryptorStatus::Finished)?;

        // 4. Self-dealer request (`dealer_index == my_index = 3`) on survivor 3 is rejected
        // and burns state3.
        let mut self_dealer_map = BTreeMap::new();
        self_dealer_map.insert(idx3, vec![0x11; 64]);
        let self_dealer_req = RecoveryRequest {
            encrypted_shares: Vec::new(),
            indexed_encrypted_shares: self_dealer_map,
            dealer_commitments,
        };
        verify_true!(decryptors[&idx3]
            .handle_recovery_request(self_dealer_req, states.get_mut(&idx3).unwrap())
            .is_err())?;
        verify_true!(states[&idx3].status == DecryptorStatus::Finished)?;

        Ok(())
    }
}
