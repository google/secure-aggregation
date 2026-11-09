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

use aggregation_config::AggregationConfig;
use ahe_traits::AheBase;
use feldman_vss::{FeldmanCommitment, Share, MAX_SHARES, ROSTER_HASH_BYTE_LEN};
use kahe_traits::{HasKahe, KaheBase};
use messages_rust_proto::{
    CiphertextContribution as CiphertextContributionProto, ClientMessage as ClientMessageProto,
    CommitteeConfigProto, CoordinatorState as CoordinatorStateProto,
    CoordinatorStatus as CoordinatorStatusProto, DPSetupContribution as DPSetupContributionProto,
    DealerSetupInfoProto, DecryptionRequestContribution as DecryptionRequestContributionProto,
    DecryptorStatus as DecryptorStatusProto,
    EncryptedRandomnessShares as EncryptedRandomnessSharesProto,
    FinalizedPartialDecryption as FinalizedPartialDecryptionProto,
    KeyContribution as KeyContributionProto,
    PartialDecryptionRequest as PartialDecryptionRequestProto,
    PartialDecryptionResponse as PartialDecryptionResponseProto,
    RecoveryRequest as RecoveryRequestProto, RecoveryResponse as RecoveryResponseProto,
    SecretSharingContribution as SecretSharingContributionProto,
    SetupContribution as SetupContributionProto,
    VerifyKeyContributionsRequest as VerifyKeyContributionsRequestProto,
};
use proofs_rust_proto::{RlweRelationProofListProto, RlweRelationProofProto};
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::{proto, AsView};
use shell_ciphertexts_rust_proto::{
    ShellAheCiphertext, ShellAhePartialDecCiphertext, ShellAhePartialDecryption,
    ShellAhePublicKeyShare, ShellAheRecoverCiphertext, ShellKaheCiphertext,
};
use status::StatusError;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::num::NonZeroU32;
use vahe_traits::{HasVahe, VaheBase};

pub type DecryptorPublicKeyShare<Vahe> = <Vahe as AheBase>::PublicKeyShare;

pub type DecryptorPublicKey<Vahe> = <Vahe as AheBase>::PublicKey;

/// Domain separator for computing the 32-byte pre-setup committee `roster_hash`.
pub const COMMITTEE_ROSTER_HASH_INFO: &[u8] = b"Committee.roster";

/// Domain separator for computing the 32-byte Phase-1 setup commitment transcript hash.
pub const SETUP_TRANSCRIPT_HASH_INFO: &[u8] = b"Committee.commitments";

/// Maximum byte length of a single HPKE-encrypted 32-byte Feldman VSS share
/// (Tink HPKE X25519-HKDF-SHA256-AES128-GCM ciphertexts are ~92–97 bytes).
pub const MAX_ENCRYPTED_SHARE_BYTES: usize = 1024;

/// Configuration for a non-reputable decryptor committee member participating in
/// Feldman VSS + HPKE dropout recovery.
///
/// # Threat Model & Threshold Bounds
/// - **Active Hybrid Threat Model (with >= 1 honest Reputable Decryptor TEE)**: Enforces `2 <=
///   num_decryptors <= MAX_SHARES` (`100`), `1 <= threshold <= num_decryptors - 1` (since a dropped
///   dealer is offline and cannot return its own self-share, at most `num_decryptors - 1` peer
///   shares exist), and `1 <= my_index <= num_decryptors`.
///   `Coordinator::handle_recoverable_setup_submissions` does not verify ZK `KeyGenProof`s
///   itself—it returns `VerifyKeyContributionsRequest` for a Reputable Decryptor TEE to verify—and
///   therefore requires non-empty `NonEmptyReputableContributions` in recoverable committee mode
///   (matching `WillowProtocolImpl::ValidateRuntimeDependencies`).
/// - **Pure No-TEE Threat Model (not instantiated by `Coordinator`)**: Without a Reputable
///   Decryptor TEE privacy anchor or a signed survivor-set agreement round among committee members,
///   resisting Coordinator split-request equivocation would additionally require `2 * threshold >
///   num_decryptors + max_corrupt` (i.e., `2 * max_recoverable_dropouts < num_decryptors -
///   max_corrupt`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeConfig {
    pub my_index: NonZeroU32,
    pub num_decryptors: u32,
    pub threshold: u32,
    pub roster_hash: [u8; ROSTER_HASH_BYTE_LEN],
    pub session_context: Vec<u8>,
}

impl CommitteeConfig {
    /// Constructs and validates a `CommitteeConfig`.
    pub fn new(
        my_index: NonZeroU32,
        num_decryptors: u32,
        threshold: u32,
        roster_hash: [u8; ROSTER_HASH_BYTE_LEN],
        session_context: Vec<u8>,
    ) -> Result<Self, StatusError> {
        let config = Self { my_index, num_decryptors, threshold, roster_hash, session_context };
        config.validate()?;
        Ok(config)
    }

    /// Validates all committee parameter invariants:
    /// - `2 <= num_decryptors <= MAX_SHARES` (`100`)
    /// - `1 <= threshold <= num_decryptors - 1`
    /// - `1 <= my_index <= num_decryptors`
    /// - `!session_context.is_empty()`
    pub fn validate(&self) -> Result<(), StatusError> {
        if self.num_decryptors < 2 || self.num_decryptors > MAX_SHARES {
            return Err(status::invalid_argument(
                "CommitteeConfig: num_decryptors must be in 2..=MAX_SHARES",
            ));
        }
        if self.threshold < 1 || self.threshold >= self.num_decryptors {
            return Err(status::invalid_argument(
                "CommitteeConfig: threshold must be in 1..=(num_decryptors - 1)",
            ));
        }
        if self.my_index.get() > self.num_decryptors {
            return Err(status::invalid_argument(
                "CommitteeConfig: my_index exceeds num_decryptors",
            ));
        }
        if self.session_context.is_empty() {
            return Err(status::invalid_argument(
                "CommitteeConfig: session_context must not be empty",
            ));
        }
        Ok(())
    }

    /// Maximum number of dropped committee members (`n - t`) whose shares an honest
    /// survivor is permitted to decrypt in a single one-shot `RecoveryRequest`.
    pub fn max_recoverable_dropouts(&self) -> u32 {
        self.num_decryptors - self.threshold
    }
}

impl ToProto for CommitteeConfig {
    type Proto = CommitteeConfigProto;

    fn to_proto(&self, _ctx: ()) -> Result<Self::Proto, StatusError> {
        self.validate()?;
        Ok(proto!(CommitteeConfigProto {
            my_index: self.my_index.get(),
            num_decryptors: self.num_decryptors,
            threshold: self.threshold,
            roster_hash: self.roster_hash.as_slice(),
            session_context: self.session_context.as_slice(),
        }))
    }
}

impl FromProto for CommitteeConfig {
    type Proto = CommitteeConfigProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        _ctx: (),
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let my_index = NonZeroU32::new(proto.my_index()).ok_or_else(|| {
            status::invalid_argument("CommitteeConfigProto: my_index must be non-zero")
        })?;
        let roster_hash_bytes = proto.roster_hash();
        let roster_hash: [u8; ROSTER_HASH_BYTE_LEN] =
            roster_hash_bytes.try_into().map_err(|_| {
                status::invalid_argument("CommitteeConfigProto: roster_hash must be 32 bytes")
            })?;
        CommitteeConfig::new(
            my_index,
            proto.num_decryptors(),
            proto.threshold(),
            roster_hash,
            proto.session_context().to_vec(),
        )
    }
}

/// Computes the canonical 32-byte `roster_hash` over the pre-setup committee roster:
/// `(threshold, num_decryptors, sorted [(decryptor_index, u32_le(pk_len), hpke_public_key)])`.
///
/// Because `roster_hash` is an input to `derive_keygen_seed` in Phase 1 and
/// `build_share_hpke_context_info` in Phase 2, it is defined strictly over the pre-setup
/// committee roster before any `FeldmanCommitment`s are broadcast.
///
/// # Security Contract (Roster Attestation Trust Boundary — Audit A3 item 4)
///
/// `compute_roster_hash` binds the pre-setup mapping `1..=num_decryptors -> hpke_public_key`,
/// preventing any post-setup equivocation on the roster. However, the protocol library
/// itself does not authenticate how `roster_public_keys` was assembled. Callers (e.g.,
/// committee devices / executors) **MUST** obtain `roster_public_keys` from an authenticated
/// or attested roster source (or verify hardware/identity attestations on peer HPKE public
/// keys) so an untrusted Coordinator cannot populate the roster with Sybil HPKE public keys
/// it controls before `compute_roster_hash` is computed.
pub fn compute_roster_hash(
    num_decryptors: u32,
    threshold: u32,
    roster_public_keys: &BTreeMap<NonZeroU32, Vec<u8>>,
) -> Result<[u8; ROSTER_HASH_BYTE_LEN], StatusError> {
    if num_decryptors < 2 || num_decryptors > MAX_SHARES {
        return Err(status::invalid_argument(
            "compute_roster_hash: num_decryptors must be in 2..=MAX_SHARES",
        ));
    }
    if threshold < 1 || threshold >= num_decryptors {
        return Err(status::invalid_argument(
            "compute_roster_hash: threshold must be in 1..=(num_decryptors - 1)",
        ));
    }
    if roster_public_keys.len() != num_decryptors as usize {
        return Err(status::invalid_argument(
            "compute_roster_hash: roster_public_keys count must equal num_decryptors",
        ));
    }

    let mut ikm = Vec::new();
    ikm.extend_from_slice(&threshold.to_le_bytes());
    ikm.extend_from_slice(&num_decryptors.to_le_bytes());
    for (expected_idx, (&idx, pk_bytes)) in (1..=num_decryptors).zip(roster_public_keys.iter()) {
        if idx.get() != expected_idx {
            return Err(status::invalid_argument(
                "compute_roster_hash: roster indices must be 1..=num_decryptors",
            ));
        }
        if pk_bytes.is_empty() {
            return Err(status::invalid_argument(
                "compute_roster_hash: empty public key in roster",
            ));
        }
        let pk_len = u32::try_from(pk_bytes.len()).map_err(|_| {
            status::invalid_argument("compute_roster_hash: public key length exceeds u32::MAX")
        })?;
        ikm.extend_from_slice(&idx.get().to_le_bytes());
        ikm.extend_from_slice(&pk_len.to_le_bytes());
        ikm.extend_from_slice(pk_bytes);
    }

    let seed = single_thread_hkdf::compute_hkdf(
        &ikm,
        b"",
        COMMITTEE_ROSTER_HASH_INFO,
        ROSTER_HASH_BYTE_LEN as u64,
    )?;
    let bytes = seed.as_bytes();
    bytes
        .try_into()
        .map_err(|_| status::internal("compute_roster_hash: unexpected HKDF output length"))
}

/// Computes the canonical 32-byte `setup_transcript_hash` binding `roster_hash`,
/// `session_context`, `(threshold, num_decryptors)`, and all broadcast
/// `(dealer_index, FeldmanCommitment)` pairs in ascending `dealer_index` order
/// (`1..=num_decryptors`).
pub fn compute_setup_transcript_hash(
    roster_hash: &[u8; ROSTER_HASH_BYTE_LEN],
    session_context: &[u8],
    threshold: u32,
    num_decryptors: u32,
    commitments: &BTreeMap<NonZeroU32, FeldmanCommitment>,
) -> Result<[u8; ROSTER_HASH_BYTE_LEN], StatusError> {
    if session_context.is_empty() {
        return Err(status::invalid_argument(
            "compute_setup_transcript_hash: session_context must not be empty",
        ));
    }
    if num_decryptors < 2 || num_decryptors > MAX_SHARES {
        return Err(status::invalid_argument(
            "compute_setup_transcript_hash: num_decryptors must be in 2..=MAX_SHARES",
        ));
    }
    if threshold < 1 || threshold >= num_decryptors {
        return Err(status::invalid_argument(
            "compute_setup_transcript_hash: threshold must be in 1..=(num_decryptors - 1)",
        ));
    }
    if commitments.len() != num_decryptors as usize {
        return Err(status::invalid_argument(
            "compute_setup_transcript_hash: commitments count must equal num_decryptors",
        ));
    }

    let mut ikm = Vec::new();
    ikm.extend_from_slice(roster_hash);
    let ctx_len = u32::try_from(session_context.len()).map_err(|_| {
        status::invalid_argument(
            "compute_setup_transcript_hash: session_context length exceeds u32::MAX",
        )
    })?;
    ikm.extend_from_slice(&ctx_len.to_le_bytes());
    ikm.extend_from_slice(session_context);
    ikm.extend_from_slice(&threshold.to_le_bytes());
    ikm.extend_from_slice(&num_decryptors.to_le_bytes());
    for (expected_idx, (&dealer_idx, commitment)) in (1..=num_decryptors).zip(commitments.iter()) {
        if dealer_idx.get() != expected_idx {
            return Err(status::invalid_argument(
                "compute_setup_transcript_hash: dealer indices must be 1..=num_decryptors",
            ));
        }
        if commitment.threshold() != threshold as usize {
            return Err(status::invalid_argument(
                "compute_setup_transcript_hash: commitment threshold does not match committee threshold",
            ));
        }
        ikm.extend_from_slice(&dealer_idx.get().to_le_bytes());
        let deg_count = commitment.threshold() as u32;
        ikm.extend_from_slice(&deg_count.to_le_bytes());
        for pt in commitment.commitments() {
            ikm.extend_from_slice(pt.as_bytes());
        }
    }

    let seed = single_thread_hkdf::compute_hkdf(
        &ikm,
        roster_hash,
        SETUP_TRANSCRIPT_HASH_INFO,
        ROSTER_HASH_BYTE_LEN as u64,
    )?;
    let bytes = seed.as_bytes();
    bytes.try_into().map_err(|_| {
        status::internal("compute_setup_transcript_hash: unexpected HKDF output length")
    })
}

/// Message sent by a generic KAHE/AHE Willow client to the server.
#[derive(Debug)]
pub struct ClientMessage<Kahe: KaheBase, Vahe: VaheBase> {
    pub kahe_ciphertext: Kahe::Ciphertext,
    pub ahe_ciphertext: Vahe::Ciphertext,
    pub proof: Vahe::EncryptionProof,
    pub nonce: Vec<u8>,
}

impl<'a, C, Kahe, Vahe> ToProto<&'a C> for ClientMessage<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Kahe::Ciphertext: ToProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::Ciphertext: ToProto<&'a Vahe, Proto = ShellAheCiphertext>,
    Vahe::EncryptionProof: ToProto<Proto = RlweRelationProofListProto>,
{
    type Proto = ClientMessageProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        Ok(proto!(ClientMessageProto {
            kahe_ciphertext: self.kahe_ciphertext.to_proto(context.kahe())?,
            ahe_ciphertext: self.ahe_ciphertext.to_proto(context.vahe())?,
            proof: self.proof.to_proto(())?,
            nonce: self.nonce.clone(),
        }))
    }
}

impl<'a, C, Kahe, Vahe> FromProto<&'a C> for ClientMessage<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Kahe::Ciphertext: FromProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::Ciphertext: FromProto<&'a Vahe, Proto = ShellAheCiphertext>,
    Vahe::EncryptionProof: FromProto<Proto = RlweRelationProofListProto>,
{
    type Proto = ClientMessageProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        Ok(ClientMessage {
            kahe_ciphertext: Kahe::Ciphertext::from_proto(proto.kahe_ciphertext(), context.kahe())?,
            ahe_ciphertext: Vahe::Ciphertext::from_proto(proto.ahe_ciphertext(), context.vahe())?,
            proof: Vahe::EncryptionProof::from_proto(proto.proof(), ())?,
            nonce: proto.nonce().to_vec(),
        })
    }
}

impl<Kahe: KaheBase, Vahe: VaheBase> Clone for ClientMessage<Kahe, Vahe> {
    fn clone(self: &ClientMessage<Kahe, Vahe>) -> ClientMessage<Kahe, Vahe> {
        ClientMessage {
            kahe_ciphertext: self.kahe_ciphertext.clone(),
            ahe_ciphertext: self.ahe_ciphertext.clone(),
            proof: self.proof.clone(),
            nonce: self.nonce.clone(),
        }
    }
}

// Partial decryption request is an aggregated AHE partial decryption ciphertext (ct_1).
pub struct PartialDecryptionRequest<Vahe: VaheBase> {
    pub partial_dec_ciphertext: Vahe::PartialDecCiphertext,
    // Only set if the decryptor is adding DP noise.
    pub aggregation_config: Option<AggregationConfig>,
}

impl<'a, C, Vahe> ToProto<&'a C> for PartialDecryptionRequest<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: ToProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
{
    type Proto = PartialDecryptionRequestProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = proto!(PartialDecryptionRequestProto {
            partial_dec_ciphertext: self.partial_dec_ciphertext.to_proto(context.vahe())?,
        });
        if let Some(config) = &self.aggregation_config {
            proto.set_aggregation_config(config.to_proto(())?);
        }
        Ok(proto)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for PartialDecryptionRequest<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: FromProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
{
    type Proto = PartialDecryptionRequestProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let aggregation_config = if proto.has_aggregation_config() {
            Some(AggregationConfig::from_proto(proto.aggregation_config(), ())?)
        } else {
            None
        };
        Ok(PartialDecryptionRequest {
            partial_dec_ciphertext: Vahe::PartialDecCiphertext::from_proto(
                proto.partial_dec_ciphertext(),
                context.vahe(),
            )?,
            aggregation_config,
        })
    }
}

/// We manually implement clone for PartialDecryptionRequest because Vahe is not cloneable.
impl<Vahe: VaheBase> Clone for PartialDecryptionRequest<Vahe> {
    fn clone(&self) -> PartialDecryptionRequest<Vahe> {
        PartialDecryptionRequest {
            partial_dec_ciphertext: self.partial_dec_ciphertext.clone(),
            aggregation_config: self.aggregation_config.clone(),
        }
    }
}

impl<Vahe: VaheBase> Debug for PartialDecryptionRequest<Vahe> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("PartialDecryptionRequest")
            .field("partial_dec_ciphertext", &"(OMITTED)")
            .field("aggregation_config", &self.aggregation_config)
            .finish()
    }
}

pub struct PartialDecryptionResponse<Kahe: KaheBase, Vahe: VaheBase> {
    pub partial_decryption: Vahe::PartialDecryption,
    // This contribution just contains encrypted DP noise. The server will be forced to include
    // this contribution in the result because the randomness of the AHE encryption was included in
    // the partial decryption request.
    pub dp_ciphertext_contribution: Option<CiphertextContribution<Kahe, Vahe>>,
    /// 1-based committee index of the responding decryptor (`1..=MAX_SHARES`) in
    /// recoverable multi-decryptor mode (`None` in single/reputable/unindexed mode).
    pub decryptor_index: Option<NonZeroU32>,
}

impl<'a, C, Kahe, Vahe> ToProto<(&'a C, Option<&'a Kahe>)> for PartialDecryptionResponse<Kahe, Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecryption: ToProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
    Kahe::Ciphertext: ToProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::RecoverCiphertext: ToProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
{
    type Proto = PartialDecryptionResponseProto;

    fn to_proto(
        &self,
        (context, kahe): (&'a C, Option<&'a Kahe>),
    ) -> Result<Self::Proto, StatusError> {
        let vahe = context.vahe();
        let mut proto = proto!(PartialDecryptionResponseProto {
            partial_decryption: self.partial_decryption.to_proto(vahe)?,
        });
        if let Some(dp_ct) = &self.dp_ciphertext_contribution {
            let kahe = kahe.ok_or_else(|| {
                status::failed_precondition("Missing Kahe context for DP ciphertext contribution")
            })?;
            proto.set_dp_ciphertext_contribution(proto!(
                messages_rust_proto::CiphertextContribution {
                    kahe_ciphertext: dp_ct.kahe_ciphertext.to_proto(kahe)?,
                    ahe_recover_ciphertext: dp_ct.ahe_recover_ciphertext.to_proto(vahe)?,
                }
            ));
        }
        if let Some(idx) = self.decryptor_index {
            if idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "PartialDecryptionResponse: decryptor_index exceeds MAX_SHARES",
                ));
            }
            proto.set_decryptor_index(idx.get());
        }
        Ok(proto)
    }
}

impl<'a, C, Kahe, Vahe> FromProto<&'a C> for PartialDecryptionResponse<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecryption: FromProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
    Kahe::Ciphertext: FromProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::RecoverCiphertext: FromProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
{
    type Proto = PartialDecryptionResponseProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let dp_ciphertext_contribution = if proto.has_dp_ciphertext_contribution() {
            Some(CiphertextContribution::from_proto(proto.dp_ciphertext_contribution(), context)?)
        } else {
            None
        };
        let decryptor_index = if proto.decryptor_index() == 0 {
            None
        } else {
            let idx = NonZeroU32::new(proto.decryptor_index()).unwrap();
            if idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "PartialDecryptionResponseProto: decryptor_index exceeds MAX_SHARES",
                ));
            }
            Some(idx)
        };
        Ok(PartialDecryptionResponse {
            partial_decryption: Vahe::PartialDecryption::from_proto(
                proto.partial_decryption(),
                context.vahe(),
            )?,
            dp_ciphertext_contribution,
            decryptor_index,
        })
    }
}

/// The part of the client message that the verifier needn't check
pub struct CiphertextContribution<Kahe: KaheBase, Vahe: VaheBase> {
    pub kahe_ciphertext: Kahe::Ciphertext,
    pub ahe_recover_ciphertext: Vahe::RecoverCiphertext,
}

impl<'a, C, Kahe, Vahe> ToProto<&'a C> for CiphertextContribution<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Kahe::Ciphertext: ToProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::RecoverCiphertext: ToProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
{
    type Proto = CiphertextContributionProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        Ok(proto!(CiphertextContributionProto {
            kahe_ciphertext: self.kahe_ciphertext.to_proto(context.kahe())?,
            ahe_recover_ciphertext: self.ahe_recover_ciphertext.to_proto(context.vahe())?,
        }))
    }
}

impl<'a, C, Kahe, Vahe> FromProto<&'a C> for CiphertextContribution<Kahe, Vahe>
where
    C: HasKahe<Kahe = Kahe> + HasVahe<Vahe = Vahe>,
    Kahe: KaheBase + 'a,
    Vahe: VaheBase + 'a,
    Kahe::Ciphertext: FromProto<&'a Kahe, Proto = ShellKaheCiphertext>,
    Vahe::RecoverCiphertext: FromProto<&'a Vahe, Proto = ShellAheRecoverCiphertext>,
{
    type Proto = CiphertextContributionProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        Ok(CiphertextContribution {
            kahe_ciphertext: Kahe::Ciphertext::from_proto(proto.kahe_ciphertext(), context.kahe())?,
            ahe_recover_ciphertext: Vahe::RecoverCiphertext::from_proto(
                proto.ahe_recover_ciphertext(),
                context.vahe(),
            )?,
        })
    }
}

impl<Kahe: KaheBase, Vahe: VaheBase> Clone for CiphertextContribution<Kahe, Vahe> {
    fn clone(&self) -> CiphertextContribution<Kahe, Vahe> {
        CiphertextContribution {
            kahe_ciphertext: self.kahe_ciphertext.clone(),
            ahe_recover_ciphertext: self.ahe_recover_ciphertext.clone(),
        }
    }
}

/// The material from the client that the verifier must check.
#[derive(Debug)]
pub struct DecryptionRequestContribution<Vahe: VaheBase> {
    pub partial_dec_ciphertext: Vahe::PartialDecCiphertext,
    pub proof: Vahe::EncryptionProof,
    pub nonce: Vec<u8>,
}

impl<'a, C, Vahe> ToProto<&'a C> for DecryptionRequestContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: ToProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::EncryptionProof: ToProto<Proto = RlweRelationProofListProto>,
{
    type Proto = DecryptionRequestContributionProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        Ok(proto!(DecryptionRequestContributionProto {
            partial_dec_ciphertext: self.partial_dec_ciphertext.to_proto(context.vahe())?,
            proof: self.proof.to_proto(())?,
            nonce: self.nonce.clone(),
        }))
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for DecryptionRequestContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: FromProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::EncryptionProof: FromProto<Proto = RlweRelationProofListProto>,
{
    type Proto = DecryptionRequestContributionProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        Ok(DecryptionRequestContribution {
            partial_dec_ciphertext: Vahe::PartialDecCiphertext::from_proto(
                proto.partial_dec_ciphertext(),
                context.vahe(),
            )?,
            proof: Vahe::EncryptionProof::from_proto(proto.proof(), ())?,
            nonce: proto.nonce().to_vec(),
        })
    }
}

impl<Vahe: VaheBase> Clone for DecryptionRequestContribution<Vahe> {
    fn clone(&self) -> DecryptionRequestContribution<Vahe> {
        DecryptionRequestContribution {
            partial_dec_ciphertext: self.partial_dec_ciphertext.clone(),
            proof: self.proof.clone(),
            nonce: self.nonce.clone(),
        }
    }
}

/// A public key share and proof of knowledge of the secret key from a decryptor.
pub struct KeyContribution<Vahe: VaheBase> {
    pub public_key_share: DecryptorPublicKeyShare<Vahe>,
    /// This is required unless this is the only reputable decryptor.
    pub proof: Option<Vahe::KeyGenProof>,
}

impl<Vahe: VaheBase> Clone for KeyContribution<Vahe>
where
    Vahe::KeyGenProof: Clone,
{
    fn clone(&self) -> Self {
        Self { public_key_share: self.public_key_share.clone(), proof: self.proof.clone() }
    }
}

/// The initial contribution to the decryption key from a decryptor.
pub struct SetupContribution<Vahe: VaheBase> {
    pub key_contribution: KeyContribution<Vahe>,
    /// Only needed if we are adding DP noise.
    pub dp_setup: Option<DPSetupContribution<Vahe>>,
    /// Shares of the randomness (PRNG state) used for key generation, encrypted for other
    /// decryptors to enable recovery. Only used by non-reputable decryptors.
    pub encrypted_randomness_shares: Option<Vec<SecretSharingContribution>>,
    /// 1-based committee index of this decryptor (`1..=MAX_SHARES`), present in
    /// recoverable multi-decryptor committee mode.
    pub decryptor_index: Option<NonZeroU32>,
    /// Public Feldman VSS polynomial commitment (`C_0, ..., C_{t-1}`) to the
    /// dealer's secret scalar and polynomial coefficients.
    pub feldman_commitment: Option<FeldmanCommitment>,
    /// Encrypted randomness shares keyed by 1-based `recipient_index` (`1..=MAX_SHARES`).
    pub indexed_encrypted_shares: BTreeMap<NonZeroU32, Vec<u8>>,
}

/// Typed setup contribution from a non-reputable decryptor committee member participating in
/// Feldman VSS + HPKE dropout recovery, with non-optional recovery fields and no legacy
/// unindexed `encrypted_randomness_shares`.
pub struct RecoverableSetupContribution<Vahe: VaheBase> {
    pub key_contribution: KeyContribution<Vahe>,
    pub dp_setup: Option<DPSetupContribution<Vahe>>,
    pub decryptor_index: NonZeroU32,
    pub feldman_commitment: FeldmanCommitment,
    pub indexed_encrypted_shares: BTreeMap<NonZeroU32, Vec<u8>>,
}

/// Typed setup contribution from a Reputable Decryptor TEE, guaranteed by its Rust type not to
/// carry any non-reputable secret-sharing or Feldman VSS recovery fields.
pub struct ReputableSetupContribution<Vahe: VaheBase> {
    pub key_contribution: KeyContribution<Vahe>,
    pub dp_setup: Option<DPSetupContribution<Vahe>>,
}

/// Non-empty collection of [`ReputableSetupContribution`]s, guaranteeing at the Rust type level
/// that at least one Reputable Decryptor TEE participates in recoverable committee setup and
/// ZK proof verification.
pub struct NonEmptyReputableContributions<Vahe: VaheBase> {
    pub first: ReputableSetupContribution<Vahe>,
    pub rest: Vec<ReputableSetupContribution<Vahe>>,
}

impl<Vahe: VaheBase> NonEmptyReputableContributions<Vahe> {
    /// Constructs a `NonEmptyReputableContributions` with a single reputable contribution.
    pub fn single(first: ReputableSetupContribution<Vahe>) -> Self {
        Self { first, rest: Vec::new() }
    }

    /// Constructs a `NonEmptyReputableContributions` from a first contribution and any additional
    /// reputable contributions.
    pub fn new(
        first: ReputableSetupContribution<Vahe>,
        rest: Vec<ReputableSetupContribution<Vahe>>,
    ) -> Self {
        Self { first, rest }
    }

    /// Returns the total number of reputable contributions (`>= 1`).
    pub fn len(&self) -> usize {
        1 + self.rest.len()
    }

    /// Returns `false` (a `NonEmptyReputableContributions` is never empty).
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Consumes `self` and yields all reputable contributions (`first` followed by `rest`).
    pub fn into_vec(self) -> Vec<ReputableSetupContribution<Vahe>> {
        let mut out = Vec::with_capacity(1 + self.rest.len());
        out.push(self.first);
        out.extend(self.rest);
        out
    }
}

impl<Vahe: VaheBase> From<ReputableSetupContribution<Vahe>>
    for NonEmptyReputableContributions<Vahe>
{
    fn from(first: ReputableSetupContribution<Vahe>) -> Self {
        Self::single(first)
    }
}

impl<Vahe: VaheBase> TryFrom<Vec<ReputableSetupContribution<Vahe>>>
    for NonEmptyReputableContributions<Vahe>
{
    type Error = StatusError;

    fn try_from(mut contribs: Vec<ReputableSetupContribution<Vahe>>) -> Result<Self, Self::Error> {
        if contribs.is_empty() {
            return Err(status::invalid_argument(
                "At least one reputable_contribution is required in recoverable committee mode",
            ));
        }
        let first = contribs.remove(0);
        Ok(Self { first, rest: contribs })
    }
}

impl<Vahe: VaheBase> TryFrom<Vec<SetupContribution<Vahe>>>
    for NonEmptyReputableContributions<Vahe>
{
    type Error = StatusError;

    fn try_from(contribs: Vec<SetupContribution<Vahe>>) -> Result<Self, Self::Error> {
        if contribs.is_empty() {
            return Err(status::invalid_argument(
                "At least one reputable_contribution is required in recoverable committee mode",
            ));
        }
        let typed: Result<Vec<_>, _> =
            contribs.into_iter().map(ReputableSetupContribution::try_from).collect();
        Self::try_from(typed?)
    }
}

impl<Vahe: VaheBase> From<RecoverableSetupContribution<Vahe>> for SetupContribution<Vahe> {
    fn from(c: RecoverableSetupContribution<Vahe>) -> Self {
        SetupContribution {
            key_contribution: c.key_contribution,
            dp_setup: c.dp_setup,
            encrypted_randomness_shares: None,
            decryptor_index: Some(c.decryptor_index),
            feldman_commitment: Some(c.feldman_commitment),
            indexed_encrypted_shares: c.indexed_encrypted_shares,
        }
    }
}

impl<Vahe: VaheBase> TryFrom<SetupContribution<Vahe>> for RecoverableSetupContribution<Vahe> {
    type Error = StatusError;

    fn try_from(c: SetupContribution<Vahe>) -> Result<Self, Self::Error> {
        if c.encrypted_randomness_shares.is_some() {
            return Err(status::invalid_argument(
                "recoverable SetupContribution must not populate legacy encrypted_randomness_shares",
            ));
        }
        let decryptor_index = c.decryptor_index.ok_or_else(|| {
            status::invalid_argument("recoverable SetupContribution is missing decryptor_index")
        })?;
        let feldman_commitment = c.feldman_commitment.ok_or_else(|| {
            status::invalid_argument("recoverable SetupContribution is missing feldman_commitment")
        })?;
        Ok(RecoverableSetupContribution {
            key_contribution: c.key_contribution,
            dp_setup: c.dp_setup,
            decryptor_index,
            feldman_commitment,
            indexed_encrypted_shares: c.indexed_encrypted_shares,
        })
    }
}

impl<Vahe: VaheBase> From<ReputableSetupContribution<Vahe>> for SetupContribution<Vahe> {
    fn from(c: ReputableSetupContribution<Vahe>) -> Self {
        SetupContribution {
            key_contribution: c.key_contribution,
            dp_setup: c.dp_setup,
            encrypted_randomness_shares: None,
            decryptor_index: None,
            feldman_commitment: None,
            indexed_encrypted_shares: BTreeMap::new(),
        }
    }
}

impl<Vahe: VaheBase> TryFrom<SetupContribution<Vahe>> for ReputableSetupContribution<Vahe> {
    type Error = StatusError;

    fn try_from(c: SetupContribution<Vahe>) -> Result<Self, Self::Error> {
        if c.decryptor_index.is_some()
            || c.feldman_commitment.is_some()
            || !c.indexed_encrypted_shares.is_empty()
            || c.encrypted_randomness_shares.is_some()
        {
            return Err(status::invalid_argument(
                "reputable_contributions must not carry recoverable share fields",
            ));
        }
        Ok(ReputableSetupContribution {
            key_contribution: c.key_contribution,
            dp_setup: c.dp_setup,
        })
    }
}

/// An encrypted share of the randomness seed for secret sharing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecretSharingContribution {
    pub encrypted_share: Vec<u8>,
    /// Optional 1-based recipient decryptor index (`1..=MAX_SHARES`).
    pub recipient_index: Option<NonZeroU32>,
}

/// Public key independent half of ciphertext for noise, only present for adding DP.
pub struct DPSetupContribution<Vahe: VaheBase> {
    /// The public-key-independent half of the DP noise ciphertext (component_a).
    /// This is also the half that must be sent to the verifier.
    pub dp_partial_dec_ciphertext: Vahe::PartialDecCiphertext,
    /// Proof of knowledge of the randomness used to create the ciphertext.
    pub dp_partial_dec_ciphertext_proof: Option<Vahe::EncryptionProof>,
}

/// A request to a surviving decryptor to decrypt shares of dropped decryptors.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryRequest {
    /// Legacy unindexed encrypted shares.
    pub encrypted_shares: Vec<SecretSharingContribution>,
    /// Encrypted shares keyed by 1-based dropped `dealer_index` (`1..=MAX_SHARES`).
    pub indexed_encrypted_shares: BTreeMap<NonZeroU32, Vec<u8>>,
    /// Broadcast Feldman VSS polynomial commitments keyed by 1-based `dealer_index`
    /// (`1..=MAX_SHARES`), used by the surviving decryptor to verify the setup
    /// commitment transcript and each decrypted share (`feldman_vss::verify_share`).
    pub dealer_commitments: BTreeMap<NonZeroU32, FeldmanCommitment>,
}

/// A response containing the decrypted shares of dropped decryptors.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryResponse {
    /// Legacy unindexed decrypted shares.
    pub decrypted_shares: Vec<Vec<u8>>,
    /// 1-based committee index of the surviving decryptor (`1..=MAX_SHARES`)
    /// sending this response.
    pub survivor_index: Option<NonZeroU32>,
    /// Decrypted Feldman VSS shares keyed by 1-based dropped `dealer_index` (`1..=MAX_SHARES`).
    /// Each `Share` has `share.index == survivor_index`.
    pub indexed_decrypted_shares: BTreeMap<NonZeroU32, Share>,
}

/// A request from the coordinator to a reputable decryptor to verify setup contributions
/// and construct the aggregated public key.
pub struct VerifyKeyContributionsRequest<Vahe: VaheBase> {
    pub key_contributions: Vec<KeyContribution<Vahe>>,
}

/// Finalized partial decryption. Without DP, this is just the partial decryption sum.
pub struct FinalizedPartialDecryption<Vahe: VaheBase> {
    pub partial_decryption_sum: Vahe::PartialDecryption,
}

// --- ToProto / FromProto implementations for wire messages ---

impl ToProto for SecretSharingContribution {
    type Proto = SecretSharingContributionProto;

    fn to_proto(&self, _ctx: ()) -> Result<Self::Proto, StatusError> {
        let mut proto = proto!(SecretSharingContributionProto {
            encrypted_share: self.encrypted_share.clone(),
        });
        if let Some(idx) = self.recipient_index {
            if idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "SecretSharingContribution: recipient_index exceeds MAX_SHARES",
                ));
            }
            proto.set_recipient_index(idx.get());
        }
        Ok(proto)
    }
}

impl FromProto for SecretSharingContribution {
    type Proto = SecretSharingContributionProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        _ctx: (),
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let recipient_index = if proto.recipient_index() == 0 {
            None
        } else {
            let idx = NonZeroU32::new(proto.recipient_index()).unwrap();
            if idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "SecretSharingContributionProto: recipient_index exceeds MAX_SHARES",
                ));
            }
            Some(idx)
        };
        Ok(SecretSharingContribution {
            encrypted_share: proto.encrypted_share().to_vec(),
            recipient_index,
        })
    }
}

impl<'a, C, Vahe> ToProto<&'a C> for DPSetupContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: ToProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::EncryptionProof: ToProto<Proto = RlweRelationProofListProto>,
{
    type Proto = DPSetupContributionProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = proto!(DPSetupContributionProto {
            dp_partial_dec_ciphertext: self.dp_partial_dec_ciphertext.to_proto(context.vahe())?,
        });
        if let Some(proof) = &self.dp_partial_dec_ciphertext_proof {
            proto.set_dp_partial_dec_ciphertext_proof(proof.to_proto(())?);
        }
        Ok(proto)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for DPSetupContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecCiphertext: FromProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::EncryptionProof: FromProto<Proto = RlweRelationProofListProto>,
{
    type Proto = DPSetupContributionProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let dp_partial_dec_ciphertext_proof = if proto.has_dp_partial_dec_ciphertext_proof() {
            Some(Vahe::EncryptionProof::from_proto(proto.dp_partial_dec_ciphertext_proof(), ())?)
        } else {
            None
        };
        Ok(DPSetupContribution {
            dp_partial_dec_ciphertext: Vahe::PartialDecCiphertext::from_proto(
                proto.dp_partial_dec_ciphertext(),
                context.vahe(),
            )?,
            dp_partial_dec_ciphertext_proof,
        })
    }
}

impl<'a, C, Vahe> ToProto<&'a C> for KeyContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: ToProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
    Vahe::KeyGenProof: ToProto<Proto = RlweRelationProofProto>,
{
    type Proto = KeyContributionProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = proto!(KeyContributionProto {
            public_key_share: self.public_key_share.to_proto(context.vahe())?,
        });
        if let Some(proof) = &self.proof {
            proto.set_proof(proof.to_proto(())?);
        }
        Ok(proto)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for KeyContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: FromProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
    Vahe::KeyGenProof: FromProto<Proto = RlweRelationProofProto>,
{
    type Proto = KeyContributionProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let proof = if proto.has_proof() {
            Some(Vahe::KeyGenProof::from_proto(proto.proof(), ())?)
        } else {
            None
        };
        Ok(KeyContribution {
            public_key_share: Vahe::PublicKeyShare::from_proto(
                proto.public_key_share(),
                context.vahe(),
            )?,
            proof,
        })
    }
}

impl<'a, C, Vahe> ToProto<&'a C> for SetupContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: ToProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
    Vahe::PartialDecCiphertext: ToProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::KeyGenProof: ToProto<Proto = RlweRelationProofProto>,
    Vahe::EncryptionProof: ToProto<Proto = RlweRelationProofListProto>,
{
    type Proto = SetupContributionProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = proto!(SetupContributionProto {
            key_contribution: self.key_contribution.to_proto(context)?,
        });
        if let Some(dp_setup) = &self.dp_setup {
            proto.set_dp_setup(dp_setup.to_proto(context)?);
        }
        if let Some(shares) = &self.encrypted_randomness_shares {
            for share in shares {
                proto.encrypted_randomness_shares_mut().push(share.to_proto(())?);
            }
        }
        if let Some(dealer_idx) = self.decryptor_index {
            if dealer_idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "SetupContribution: decryptor_index exceeds MAX_SHARES",
                ));
            }
            proto.set_decryptor_index(dealer_idx.get());
        }
        if let Some(commitment) = &self.feldman_commitment {
            proto.set_feldman_commitment(commitment.to_proto(())?);
        }
        if !self.indexed_encrypted_shares.is_empty() {
            let dealer_idx = self.decryptor_index.ok_or_else(|| {
                status::invalid_argument(
                    "SetupContribution: decryptor_index is required when indexed_encrypted_shares is non-empty",
                )
            })?;
            for (&recipient_idx, ciphertext) in &self.indexed_encrypted_shares {
                if recipient_idx.get() > MAX_SHARES {
                    return Err(status::invalid_argument(
                        "SetupContribution: recipient_index exceeds MAX_SHARES",
                    ));
                }
                if recipient_idx == dealer_idx {
                    return Err(status::invalid_argument(
                        "SetupContribution: dealer must not include self-share in indexed_encrypted_shares",
                    ));
                }
                if ciphertext.is_empty() {
                    return Err(status::invalid_argument(
                        "SetupContribution: encrypted share must not be empty",
                    ));
                }
                proto
                    .indexed_encrypted_shares_mut()
                    .insert(recipient_idx.get(), ciphertext.as_slice());
            }
        }
        Ok(proto)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for SetupContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: FromProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
    Vahe::PartialDecCiphertext: FromProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::KeyGenProof: FromProto<Proto = RlweRelationProofProto>,
    Vahe::EncryptionProof: FromProto<Proto = RlweRelationProofListProto>,
{
    type Proto = SetupContributionProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let dp_setup = if proto.has_dp_setup() {
            Some(DPSetupContribution::from_proto(proto.dp_setup(), context)?)
        } else {
            None
        };
        let encrypted_randomness_shares = {
            let shares: Result<Vec<_>, _> = proto
                .encrypted_randomness_shares()
                .iter()
                .map(|s| SecretSharingContribution::from_proto(s, ()))
                .collect();
            let shares = shares?;
            if shares.is_empty() {
                None
            } else {
                Some(shares)
            }
        };
        let decryptor_index = if proto.decryptor_index() == 0 {
            None
        } else {
            let idx = NonZeroU32::new(proto.decryptor_index()).unwrap();
            if idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "SetupContributionProto: decryptor_index exceeds MAX_SHARES",
                ));
            }
            Some(idx)
        };
        let feldman_commitment = if proto.has_feldman_commitment() {
            Some(FeldmanCommitment::from_proto(proto.feldman_commitment(), ())?)
        } else {
            None
        };
        let mut indexed_encrypted_shares = BTreeMap::new();
        for (raw_recipient_idx, ciphertext) in proto.indexed_encrypted_shares().iter() {
            let dealer_idx = decryptor_index.ok_or_else(|| {
                status::invalid_argument(
                    "SetupContributionProto: decryptor_index is required when indexed_encrypted_shares is non-empty",
                )
            })?;
            let recipient_idx = NonZeroU32::new(raw_recipient_idx).ok_or_else(|| {
                status::invalid_argument(
                    "SetupContributionProto: recipient_index in indexed_encrypted_shares must be non-zero",
                )
            })?;
            if recipient_idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "SetupContributionProto: recipient_index exceeds MAX_SHARES",
                ));
            }
            if recipient_idx == dealer_idx {
                return Err(status::invalid_argument(
                    "SetupContributionProto: dealer must not include self-share in indexed_encrypted_shares",
                ));
            }
            if ciphertext.is_empty() {
                return Err(status::invalid_argument(
                    "SetupContributionProto: encrypted share must not be empty",
                ));
            }
            indexed_encrypted_shares.insert(recipient_idx, ciphertext.to_vec());
        }
        Ok(SetupContribution {
            key_contribution: KeyContribution::from_proto(proto.key_contribution(), context)?,
            dp_setup,
            encrypted_randomness_shares,
            decryptor_index,
            feldman_commitment,
            indexed_encrypted_shares,
        })
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for RecoverableSetupContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: FromProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
    Vahe::PartialDecCiphertext: FromProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::KeyGenProof: FromProto<Proto = RlweRelationProofProto>,
    Vahe::EncryptionProof: FromProto<Proto = RlweRelationProofListProto>,
{
    type Proto = SetupContributionProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let untyped = SetupContribution::from_proto(proto, context)?;
        RecoverableSetupContribution::try_from(untyped)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for ReputableSetupContribution<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: FromProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
    Vahe::PartialDecCiphertext: FromProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::KeyGenProof: FromProto<Proto = RlweRelationProofProto>,
    Vahe::EncryptionProof: FromProto<Proto = RlweRelationProofListProto>,
{
    type Proto = SetupContributionProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let untyped = SetupContribution::from_proto(proto, context)?;
        ReputableSetupContribution::try_from(untyped)
    }
}

impl ToProto for RecoveryRequest {
    type Proto = RecoveryRequestProto;

    fn to_proto(&self, _ctx: ()) -> Result<Self::Proto, StatusError> {
        let mut proto = proto!(RecoveryRequestProto {});
        for share in &self.encrypted_shares {
            proto.encrypted_shares_mut().push(share.to_proto(())?);
        }
        for (&dealer_idx, ciphertext) in &self.indexed_encrypted_shares {
            if dealer_idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "RecoveryRequest: dealer_index exceeds MAX_SHARES",
                ));
            }
            if ciphertext.is_empty() {
                return Err(status::invalid_argument(
                    "RecoveryRequest: encrypted_share must not be empty",
                ));
            }
            proto.indexed_encrypted_shares_mut().insert(dealer_idx.get(), ciphertext.as_slice());
        }
        for (&dealer_idx, commitment) in &self.dealer_commitments {
            if dealer_idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "RecoveryRequest: dealer_commitments dealer_index exceeds MAX_SHARES",
                ));
            }
            proto.dealer_commitments_mut().insert(dealer_idx.get(), commitment.to_proto(())?);
        }
        Ok(proto)
    }
}

impl FromProto for RecoveryRequest {
    type Proto = RecoveryRequestProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        _ctx: (),
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let encrypted_shares: Result<Vec<_>, _> = proto
            .encrypted_shares()
            .iter()
            .map(|s| SecretSharingContribution::from_proto(s, ()))
            .collect();
        let mut indexed_encrypted_shares = BTreeMap::new();
        for (raw_dealer_idx, ciphertext) in proto.indexed_encrypted_shares().iter() {
            let dealer_idx = NonZeroU32::new(raw_dealer_idx).ok_or_else(|| {
                status::invalid_argument("RecoveryRequestProto: dealer_index must be non-zero")
            })?;
            if dealer_idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "RecoveryRequestProto: dealer_index exceeds MAX_SHARES",
                ));
            }
            if ciphertext.is_empty() {
                return Err(status::invalid_argument(
                    "RecoveryRequestProto: encrypted_share must not be empty",
                ));
            }
            indexed_encrypted_shares.insert(dealer_idx, ciphertext.to_vec());
        }
        let mut dealer_commitments = BTreeMap::new();
        for (raw_dealer_idx, commitment_proto) in proto.dealer_commitments().iter() {
            let dealer_idx = NonZeroU32::new(raw_dealer_idx).ok_or_else(|| {
                status::invalid_argument(
                    "RecoveryRequestProto: dealer_commitments dealer_index must be non-zero",
                )
            })?;
            if dealer_idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "RecoveryRequestProto: dealer_commitments dealer_index exceeds MAX_SHARES",
                ));
            }
            let commitment = FeldmanCommitment::from_proto(commitment_proto, ())?;
            dealer_commitments.insert(dealer_idx, commitment);
        }
        Ok(RecoveryRequest {
            encrypted_shares: encrypted_shares?,
            indexed_encrypted_shares,
            dealer_commitments,
        })
    }
}

impl ToProto for RecoveryResponse {
    type Proto = RecoveryResponseProto;

    fn to_proto(&self, _ctx: ()) -> Result<Self::Proto, StatusError> {
        let mut proto = proto!(RecoveryResponseProto {
            decrypted_shares: self.decrypted_shares.iter().map(|s| s.as_slice()),
        });
        if let Some(survivor_idx) = self.survivor_index {
            if survivor_idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "RecoveryResponse: survivor_index exceeds MAX_SHARES",
                ));
            }
            proto.set_survivor_index(survivor_idx.get());
        }
        if !self.indexed_decrypted_shares.is_empty() {
            let survivor_idx = self.survivor_index.ok_or_else(|| {
                status::invalid_argument(
                    "RecoveryResponse: survivor_index is required when indexed_decrypted_shares is non-empty",
                )
            })?;
            for (&dealer_idx, share) in &self.indexed_decrypted_shares {
                if dealer_idx.get() > MAX_SHARES {
                    return Err(status::invalid_argument(
                        "RecoveryResponse: dealer_index exceeds MAX_SHARES",
                    ));
                }
                if dealer_idx == survivor_idx {
                    return Err(status::invalid_argument(
                        "RecoveryResponse: dealer_index must not equal survivor_index",
                    ));
                }
                if share.index != survivor_idx {
                    return Err(status::invalid_argument(
                        "RecoveryResponse: share.index must match survivor_index",
                    ));
                }
                proto.indexed_decrypted_shares_mut().insert(dealer_idx.get(), share.to_proto(())?);
            }
        }
        Ok(proto)
    }
}

impl FromProto for RecoveryResponse {
    type Proto = RecoveryResponseProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        _ctx: (),
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let decrypted_shares: Vec<Vec<u8>> =
            proto.decrypted_shares().iter().map(|s| s.to_vec()).collect();
        let survivor_index = if proto.survivor_index() == 0 {
            None
        } else {
            let idx = NonZeroU32::new(proto.survivor_index()).unwrap();
            if idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "RecoveryResponseProto: survivor_index exceeds MAX_SHARES",
                ));
            }
            Some(idx)
        };
        let mut indexed_decrypted_shares = BTreeMap::new();
        for (raw_dealer_idx, share_proto) in proto.indexed_decrypted_shares().iter() {
            let survivor_idx = survivor_index.ok_or_else(|| {
                status::invalid_argument(
                    "RecoveryResponseProto: survivor_index is required when indexed_decrypted_shares is non-empty",
                )
            })?;
            let dealer_idx = NonZeroU32::new(raw_dealer_idx).ok_or_else(|| {
                status::invalid_argument("RecoveryResponseProto: dealer_index must be non-zero")
            })?;
            if dealer_idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "RecoveryResponseProto: dealer_index exceeds MAX_SHARES",
                ));
            }
            if dealer_idx == survivor_idx {
                return Err(status::invalid_argument(
                    "RecoveryResponseProto: dealer_index must not equal survivor_index",
                ));
            }
            let share = Share::from_proto(share_proto, ())?;
            if share.index != survivor_idx {
                return Err(status::invalid_argument(
                    "RecoveryResponseProto: share.index must match survivor_index",
                ));
            }
            indexed_decrypted_shares.insert(dealer_idx, share);
        }
        Ok(RecoveryResponse { decrypted_shares, survivor_index, indexed_decrypted_shares })
    }
}

impl<'a, C, Vahe> ToProto<&'a C> for VerifyKeyContributionsRequest<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: ToProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
    Vahe::KeyGenProof: ToProto<Proto = RlweRelationProofProto>,
{
    type Proto = VerifyKeyContributionsRequestProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = proto!(VerifyKeyContributionsRequestProto {});
        for kc in &self.key_contributions {
            proto.key_contributions_mut().push(kc.to_proto(context)?);
        }
        Ok(proto)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for VerifyKeyContributionsRequest<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: FromProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
    Vahe::KeyGenProof: FromProto<Proto = RlweRelationProofProto>,
{
    type Proto = VerifyKeyContributionsRequestProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let key_contributions: Result<Vec<_>, _> = proto
            .key_contributions()
            .iter()
            .map(|kc| KeyContribution::from_proto(kc, context))
            .collect();
        Ok(VerifyKeyContributionsRequest { key_contributions: key_contributions? })
    }
}

impl<'a, C, Vahe> ToProto<&'a C> for FinalizedPartialDecryption<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecryption: ToProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
{
    type Proto = FinalizedPartialDecryptionProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let vahe = context.vahe();
        Ok(proto!(FinalizedPartialDecryptionProto {
            partial_decryption_sum: self.partial_decryption_sum.to_proto(vahe)?,
        }))
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for FinalizedPartialDecryption<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PartialDecryption: FromProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
{
    type Proto = FinalizedPartialDecryptionProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        Ok(FinalizedPartialDecryption {
            partial_decryption_sum: Vahe::PartialDecryption::from_proto(
                proto.partial_decryption_sum(),
                context.vahe(),
            )?,
        })
    }
}

/// Tracks a decryptor's progress through the protocol for strict one-shot enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecryptorStatus {
    #[default]
    PreSetup,
    AwaitingDecryptionRequest,
    AwaitingRecoveryRequest,
    Finished,
}

impl ToProto for DecryptorStatus {
    type Proto = DecryptorStatusProto;

    fn to_proto(&self, _ctx: ()) -> Result<Self::Proto, StatusError> {
        Ok(match self {
            DecryptorStatus::PreSetup => DecryptorStatusProto::PreSetup,
            DecryptorStatus::AwaitingDecryptionRequest => {
                DecryptorStatusProto::AwaitingDecryptionRequest
            }
            DecryptorStatus::AwaitingRecoveryRequest => {
                DecryptorStatusProto::AwaitingRecoveryRequest
            }
            DecryptorStatus::Finished => DecryptorStatusProto::Finished,
        })
    }
}

impl FromProto for DecryptorStatus {
    type Proto = DecryptorStatusProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        _ctx: (),
    ) -> Result<Self, StatusError> {
        match proto.as_view() {
            DecryptorStatusProto::PreSetup => Ok(DecryptorStatus::PreSetup),
            DecryptorStatusProto::AwaitingDecryptionRequest => {
                Ok(DecryptorStatus::AwaitingDecryptionRequest)
            }
            DecryptorStatusProto::AwaitingRecoveryRequest => {
                Ok(DecryptorStatus::AwaitingRecoveryRequest)
            }
            DecryptorStatusProto::Finished => Ok(DecryptorStatus::Finished),
            DecryptorStatusProto::Unspecified => {
                Err(status::invalid_argument("DecryptorStatus is unspecified"))
            }
            _ => Err(status::invalid_argument("Unknown DecryptorStatus")),
        }
    }
}

/// State stored by a multi-decryptor between protocol rounds.
pub struct MultiDecryptorState<Vahe: VaheBase> {
    /// The current status of the decryptor in the protocol.
    pub status: DecryptorStatus,
    /// The secret key share generated by the decryptor. None before setup.
    pub sk_share: Option<Vahe::SecretKeyShare>,
    /// The PRNG state / randomness used during the DP setup phase, if applicable.
    pub dp_randomness: Option<Vec<u8>>,
}

impl<Vahe: VaheBase> Default for MultiDecryptorState<Vahe> {
    fn default() -> Self {
        Self { status: DecryptorStatus::default(), sk_share: None, dp_randomness: None }
    }
}

/// Per-dealer recoverable setup metadata stored by the coordinator for
/// Feldman VSS dropout recovery.
pub struct DealerSetupInfo<Vahe: VaheBase> {
    /// 1-based committee index of the dealer (`1..=MAX_SHARES`).
    pub dealer_index: NonZeroU32,
    /// Broadcast Feldman VSS polynomial commitment (`C_0, ..., C_{t-1}`).
    pub feldman_commitment: FeldmanCommitment,
    /// Public key share submitted by this dealer during setup (used to verify
    /// regenerated `pk_share == expected_pk_share` during recovery).
    pub public_key_share: DecryptorPublicKeyShare<Vahe>,
    /// Encrypted randomness shares dealt by this dealer, keyed by 1-based
    /// `recipient_index` (`1..=MAX_SHARES`).
    pub encrypted_shares: BTreeMap<NonZeroU32, Vec<u8>>,
}

impl<Vahe: VaheBase> Clone for DealerSetupInfo<Vahe> {
    fn clone(&self) -> Self {
        Self {
            dealer_index: self.dealer_index,
            feldman_commitment: self.feldman_commitment.clone(),
            public_key_share: self.public_key_share.clone(),
            encrypted_shares: self.encrypted_shares.clone(),
        }
    }
}

impl<'a, C, Vahe> ToProto<&'a C> for DealerSetupInfo<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: ToProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
{
    type Proto = DealerSetupInfoProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        if self.dealer_index.get() > MAX_SHARES {
            return Err(status::invalid_argument(
                "DealerSetupInfo: dealer_index exceeds MAX_SHARES",
            ));
        }
        let mut proto = proto!(DealerSetupInfoProto {
            dealer_index: self.dealer_index.get(),
            feldman_commitment: self.feldman_commitment.to_proto(())?,
            public_key_share: self.public_key_share.to_proto(context.vahe())?,
        });
        for (&recipient_idx, ciphertext) in &self.encrypted_shares {
            if recipient_idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "DealerSetupInfo: recipient_index exceeds MAX_SHARES",
                ));
            }
            if recipient_idx == self.dealer_index {
                return Err(status::invalid_argument(
                    "DealerSetupInfo: dealer must not include self-share",
                ));
            }
            if ciphertext.is_empty() {
                return Err(status::invalid_argument(
                    "DealerSetupInfo: encrypted share must not be empty",
                ));
            }
            proto.encrypted_shares_mut().insert(recipient_idx.get(), ciphertext.as_slice());
        }
        Ok(proto)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for DealerSetupInfo<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: FromProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
{
    type Proto = DealerSetupInfoProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let dealer_index = NonZeroU32::new(proto.dealer_index()).ok_or_else(|| {
            status::invalid_argument("DealerSetupInfoProto: dealer_index must be non-zero")
        })?;
        if dealer_index.get() > MAX_SHARES {
            return Err(status::invalid_argument(
                "DealerSetupInfoProto: dealer_index exceeds MAX_SHARES",
            ));
        }
        if !proto.has_feldman_commitment() {
            return Err(status::invalid_argument(
                "DealerSetupInfoProto: missing feldman_commitment",
            ));
        }
        let feldman_commitment = FeldmanCommitment::from_proto(proto.feldman_commitment(), ())?;
        if !proto.has_public_key_share() {
            return Err(status::invalid_argument("DealerSetupInfoProto: missing public_key_share"));
        }
        let public_key_share =
            Vahe::PublicKeyShare::from_proto(proto.public_key_share(), context.vahe())?;

        let mut encrypted_shares = BTreeMap::new();
        for (raw_recipient_idx, ciphertext) in proto.encrypted_shares().iter() {
            let recipient_idx = NonZeroU32::new(raw_recipient_idx).ok_or_else(|| {
                status::invalid_argument("DealerSetupInfoProto: recipient_index must be non-zero")
            })?;
            if recipient_idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "DealerSetupInfoProto: recipient_index exceeds MAX_SHARES",
                ));
            }
            if recipient_idx == dealer_index {
                return Err(status::invalid_argument(
                    "DealerSetupInfoProto: dealer must not include self-share",
                ));
            }
            if ciphertext.is_empty() {
                return Err(status::invalid_argument(
                    "DealerSetupInfoProto: encrypted share must not be empty",
                ));
            }
            encrypted_shares.insert(recipient_idx, ciphertext.to_vec());
        }
        Ok(DealerSetupInfo { dealer_index, feldman_commitment, public_key_share, encrypted_shares })
    }
}

/// Tracks the coordinator's progress through the multi-decryptor protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoordinatorStatus {
    #[default]
    PreSetup,
    KeySharesReceived,
    AwaitingContributions,
    AwaitingPartialDecryptions,
    AwaitingRecovery,
    OutputReady,
    Finished,
}

/// State stored by the coordinator between protocol rounds.
pub struct CoordinatorState<Vahe: VaheBase> {
    /// The current status of the coordinator in the protocol.
    pub status: CoordinatorStatus,
    /// The encrypted secret shares received from non-reputable decryptors during setup. Each inner
    /// `Vec` contains shares from one non-reputable decryptor, encrypted for each *other*
    /// decryptor. The outer index corresponds to the sender (the non-reputable decryptor), and
    /// the inner index corresponds to the recipient decryptor.
    pub encrypted_randomness_shares: Vec<Vec<SecretSharingContribution>>,
    /// The accumulated public key independent components (sum of A*r+e) for DP noise, if
    /// applicable.
    pub dp_noise_component_sum: Option<Vahe::PartialDecCiphertext>,
    /// The public key shares and proofs from all contributions, for sending back to decryptors for
    /// signing requests. In legacy multi-reputable-decryptor mode this holds all setup
    /// contributions until consumed; in recoverable committee mode this records the reputable
    /// decryptors' setup contributions (`public_key_share` with `proof: None`, as the ZK proofs
    /// were already forwarded in `VerifyKeyContributionsRequest` during setup) so
    /// `aggregate_partial_decryptions` enforces `unindexed_count == expected_reputable_count`.
    /// Note: if multiple reputable decryptors are supported alongside a recoverable committee in
    /// the future, reputable `PartialDecryptionResponse`s should carry an authenticated reputable
    /// decryptor identifier to prevent duplicate submissions from a single reputable decryptor.
    pub setup_contributions: Option<Vec<SetupContribution<Vahe>>>,
    /// Sum of partial decryptions received from decryptors, set by
    /// `aggregate_partial_decryptions`.
    pub partial_decryption_sum: Option<Vahe::PartialDecryption>,
    /// 1-based committee indices of non-reputable decryptors that have responded with a
    /// `PartialDecryptionResponse`.
    pub responded_decryptor_indices: BTreeSet<NonZeroU32>,
    /// Saved partial decryption request ciphertext (`ct_1`) from `prepare_decryption_request`,
    /// needed to compute simulated partial decryptions for dropped decryptors during recovery.
    pub partial_dec_ciphertext: Option<Vahe::PartialDecCiphertext>,
    /// Per-dealer Feldman VSS commitment, setup `PublicKeyShare`, and encrypted shares
    /// keyed by 1-based `dealer_index` (`1..=MAX_SHARES`).
    pub dealer_setup_info: BTreeMap<NonZeroU32, DealerSetupInfo<Vahe>>,
    /// Optional committee configuration (`num_decryptors`, `threshold`, `roster_hash`,
    /// `session_context`) when running with a recoverable committee.
    pub committee_config: Option<CommitteeConfig>,
    /// Optional 32-byte setup transcript hash binding all broadcast
    /// `(dealer_index, FeldmanCommitment)` pairs.
    pub setup_transcript_hash: Option<[u8; ROSTER_HASH_BYTE_LEN]>,
}

impl<Vahe: VaheBase> Default for CoordinatorState<Vahe> {
    fn default() -> Self {
        Self {
            status: CoordinatorStatus::default(),
            encrypted_randomness_shares: Vec::new(),
            dp_noise_component_sum: None,
            setup_contributions: None,
            partial_decryption_sum: None,
            responded_decryptor_indices: BTreeSet::new(),
            partial_dec_ciphertext: None,
            dealer_setup_info: BTreeMap::new(),
            committee_config: None,
            setup_transcript_hash: None,
        }
    }
}

impl ToProto for CoordinatorStatus {
    type Proto = CoordinatorStatusProto;

    fn to_proto(&self, _ctx: ()) -> Result<Self::Proto, StatusError> {
        Ok(match self {
            CoordinatorStatus::PreSetup => CoordinatorStatusProto::PreSetup,
            CoordinatorStatus::KeySharesReceived => CoordinatorStatusProto::KeySharesReceived,
            CoordinatorStatus::AwaitingContributions => {
                CoordinatorStatusProto::AwaitingContributions
            }
            CoordinatorStatus::AwaitingPartialDecryptions => {
                CoordinatorStatusProto::AwaitingPartialDecryptions
            }
            CoordinatorStatus::AwaitingRecovery => CoordinatorStatusProto::AwaitingRecovery,
            CoordinatorStatus::OutputReady => CoordinatorStatusProto::OutputReady,
            CoordinatorStatus::Finished => CoordinatorStatusProto::Finished,
        })
    }
}

impl FromProto for CoordinatorStatus {
    type Proto = CoordinatorStatusProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        _ctx: (),
    ) -> Result<Self, StatusError> {
        match proto.as_view() {
            CoordinatorStatusProto::PreSetup => Ok(CoordinatorStatus::PreSetup),
            CoordinatorStatusProto::KeySharesReceived => Ok(CoordinatorStatus::KeySharesReceived),
            CoordinatorStatusProto::AwaitingContributions => {
                Ok(CoordinatorStatus::AwaitingContributions)
            }
            CoordinatorStatusProto::AwaitingPartialDecryptions => {
                Ok(CoordinatorStatus::AwaitingPartialDecryptions)
            }
            CoordinatorStatusProto::AwaitingRecovery => Ok(CoordinatorStatus::AwaitingRecovery),
            CoordinatorStatusProto::OutputReady => Ok(CoordinatorStatus::OutputReady),
            CoordinatorStatusProto::Finished => Ok(CoordinatorStatus::Finished),
            CoordinatorStatusProto::Unspecified => {
                Err(status::invalid_argument("CoordinatorStatus is unspecified"))
            }
            _ => Err(status::invalid_argument("Unknown CoordinatorStatus")),
        }
    }
}

impl<'a, C, Vahe> ToProto<&'a C> for CoordinatorState<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: ToProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
    Vahe::PartialDecCiphertext: ToProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::KeyGenProof: ToProto<Proto = RlweRelationProofProto>,
    Vahe::EncryptionProof: ToProto<Proto = RlweRelationProofListProto>,
    Vahe::PartialDecryption: ToProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
{
    type Proto = CoordinatorStateProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = proto!(CoordinatorStateProto { status: self.status.to_proto(())? });
        for shares in &self.encrypted_randomness_shares {
            let mut shares_proto = proto!(EncryptedRandomnessSharesProto {});
            for share in shares {
                shares_proto.shares_mut().push(share.to_proto(())?);
            }
            proto.encrypted_randomness_shares_mut().push(shares_proto);
        }
        if let Some(dp_sum) = &self.dp_noise_component_sum {
            proto.set_dp_noise_component_sum(dp_sum.to_proto(context.vahe())?);
        }
        if let Some(contributions) = &self.setup_contributions {
            for contribution in contributions {
                proto.setup_contributions_mut().push(contribution.to_proto(context)?);
            }
        }
        if let Some(pd_sum) = &self.partial_decryption_sum {
            proto.set_partial_decryption_sum(pd_sum.to_proto(context.vahe())?);
        }
        if let Some(cfg) = &self.committee_config {
            proto.set_committee_config(cfg.to_proto(())?);
        }
        for &idx in &self.responded_decryptor_indices {
            if idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "CoordinatorState: responded_decryptor_index exceeds MAX_SHARES",
                ));
            }
            if let Some(cfg) = &self.committee_config {
                if idx.get() > cfg.num_decryptors {
                    return Err(status::invalid_argument(
                        "CoordinatorState: responded_decryptor_index exceeds committee num_decryptors",
                    ));
                }
            }
            proto.responded_decryptor_indices_mut().push(idx.get());
        }
        if let Some(pd_ct) = &self.partial_dec_ciphertext {
            proto.set_partial_dec_ciphertext(pd_ct.to_proto(context.vahe())?);
        }
        for (&dealer_idx, info) in &self.dealer_setup_info {
            if dealer_idx != info.dealer_index {
                return Err(status::invalid_argument(
                    "CoordinatorState: dealer_setup_info map key does not match info.dealer_index",
                ));
            }
            if let Some(cfg) = &self.committee_config {
                if dealer_idx.get() > cfg.num_decryptors {
                    return Err(status::invalid_argument(
                        "CoordinatorState: dealer_index exceeds committee num_decryptors",
                    ));
                }
                if info.feldman_commitment.threshold() != cfg.threshold as usize {
                    return Err(status::invalid_argument(
                        "CoordinatorState: dealer FeldmanCommitment threshold does not match committee threshold",
                    ));
                }
            }
            proto.dealer_setup_info_mut().insert(dealer_idx.get(), info.to_proto(context)?);
        }
        if let Some(transcript_hash) = &self.setup_transcript_hash {
            proto.set_setup_transcript_hash(transcript_hash.as_slice());
        }
        Ok(proto)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for CoordinatorState<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::PublicKeyShare: FromProto<&'a Vahe, Proto = ShellAhePublicKeyShare>,
    Vahe::PartialDecCiphertext: FromProto<&'a Vahe, Proto = ShellAhePartialDecCiphertext>,
    Vahe::KeyGenProof: FromProto<Proto = RlweRelationProofProto>,
    Vahe::EncryptionProof: FromProto<Proto = RlweRelationProofListProto>,
    Vahe::PartialDecryption: FromProto<&'a Vahe, Proto = ShellAhePartialDecryption>,
{
    type Proto = CoordinatorStateProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let status = CoordinatorStatus::from_proto(proto.status(), ())?;
        let encrypted_randomness_shares: Result<Vec<Vec<_>>, StatusError> = proto
            .encrypted_randomness_shares()
            .iter()
            .map(|shares_proto| {
                shares_proto
                    .shares()
                    .iter()
                    .map(|s| SecretSharingContribution::from_proto(s, ()))
                    .collect()
            })
            .collect();
        let encrypted_randomness_shares = encrypted_randomness_shares?;
        let dp_noise_component_sum = if proto.has_dp_noise_component_sum() {
            Some(Vahe::PartialDecCiphertext::from_proto(
                proto.dp_noise_component_sum(),
                context.vahe(),
            )?)
        } else {
            None
        };
        let setup_contributions = {
            let contributions: Result<Vec<_>, _> = proto
                .setup_contributions()
                .iter()
                .map(|c| SetupContribution::from_proto(c, context))
                .collect();
            let contributions = contributions?;
            if contributions.is_empty() {
                None
            } else {
                Some(contributions)
            }
        };
        let partial_decryption_sum = if proto.has_partial_decryption_sum() {
            Some(Vahe::PartialDecryption::from_proto(
                proto.partial_decryption_sum(),
                context.vahe(),
            )?)
        } else {
            None
        };
        let committee_config = if proto.has_committee_config() {
            Some(CommitteeConfig::from_proto(proto.committee_config(), ())?)
        } else {
            None
        };
        let mut responded_decryptor_indices = BTreeSet::new();
        for raw_idx in proto.responded_decryptor_indices().iter() {
            let idx = NonZeroU32::new(raw_idx).ok_or_else(|| {
                status::invalid_argument(
                    "CoordinatorStateProto: responded_decryptor_index must be non-zero",
                )
            })?;
            if idx.get() > MAX_SHARES {
                return Err(status::invalid_argument(
                    "CoordinatorStateProto: responded_decryptor_index exceeds MAX_SHARES",
                ));
            }
            if let Some(cfg) = &committee_config {
                if idx.get() > cfg.num_decryptors {
                    return Err(status::invalid_argument(
                        "CoordinatorStateProto: responded_decryptor_index exceeds committee num_decryptors",
                    ));
                }
            }
            if !responded_decryptor_indices.insert(idx) {
                return Err(status::invalid_argument(
                    "CoordinatorStateProto: duplicate responded_decryptor_index",
                ));
            }
        }
        let partial_dec_ciphertext = if proto.has_partial_dec_ciphertext() {
            Some(Vahe::PartialDecCiphertext::from_proto(
                proto.partial_dec_ciphertext(),
                context.vahe(),
            )?)
        } else {
            None
        };
        let mut dealer_setup_info = BTreeMap::new();
        for (raw_dealer_idx, info_proto) in proto.dealer_setup_info().iter() {
            let dealer_idx = NonZeroU32::new(raw_dealer_idx).ok_or_else(|| {
                status::invalid_argument("CoordinatorStateProto: dealer_index must be non-zero")
            })?;
            let info = DealerSetupInfo::from_proto(info_proto, context)?;
            if info.dealer_index != dealer_idx {
                return Err(status::invalid_argument(
                    "CoordinatorStateProto: dealer_setup_info key does not match info.dealer_index",
                ));
            }
            if let Some(cfg) = &committee_config {
                if dealer_idx.get() > cfg.num_decryptors {
                    return Err(status::invalid_argument(
                        "CoordinatorStateProto: dealer_index exceeds committee num_decryptors",
                    ));
                }
                if info.feldman_commitment.threshold() != cfg.threshold as usize {
                    return Err(status::invalid_argument(
                        "CoordinatorStateProto: dealer FeldmanCommitment threshold does not match committee threshold",
                    ));
                }
                for &recipient_idx in info.encrypted_shares.keys() {
                    if recipient_idx.get() > cfg.num_decryptors {
                        return Err(status::invalid_argument(
                            "CoordinatorStateProto: recipient_index exceeds committee num_decryptors",
                        ));
                    }
                }
            }
            dealer_setup_info.insert(dealer_idx, info);
        }
        let setup_transcript_hash = if proto.setup_transcript_hash().is_empty() {
            None
        } else {
            let hash: [u8; ROSTER_HASH_BYTE_LEN] =
                proto.setup_transcript_hash().try_into().map_err(|_| {
                    status::invalid_argument(
                        "CoordinatorStateProto: setup_transcript_hash must be 32 bytes",
                    )
                })?;
            Some(hash)
        };
        if status == CoordinatorStatus::PreSetup
            && (!encrypted_randomness_shares.is_empty()
                || dp_noise_component_sum.is_some()
                || setup_contributions.is_some()
                || partial_decryption_sum.is_some()
                || !responded_decryptor_indices.is_empty()
                || partial_dec_ciphertext.is_some()
                || !dealer_setup_info.is_empty()
                || setup_transcript_hash.is_some())
        {
            return Err(status::invalid_argument(
                "CoordinatorState in PreSetup status must not have populated protocol fields",
            ));
        }
        if status == CoordinatorStatus::OutputReady && partial_decryption_sum.is_none() {
            return Err(status::invalid_argument(
                "CoordinatorState in OutputReady status is missing partial_decryption_sum",
            ));
        }
        Ok(CoordinatorState {
            status,
            encrypted_randomness_shares,
            dp_noise_component_sum,
            setup_contributions,
            partial_decryption_sum,
            responded_decryptor_indices,
            partial_dec_ciphertext,
            dealer_setup_info,
            committee_config,
            setup_transcript_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahe_traits::{AheBase, PartialDec};
    use feldman_vss::{split, SecretScalar};
    use googletest::prelude::*;
    use prng_traits::SecurePrng;
    use protobuf::prelude::*;
    use shell_kahe::ShellKahe;
    use shell_parameters::create_shell_ahe_config;
    use shell_vahe::ShellVahe;
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use std::rc::Rc;
    use vahe_traits::{VerifiableEncrypt, VerifiableKeyGen};

    const TEST_CONTEXT: &[u8] = b"messages_test_context";

    fn sample_split(
        threshold: u32,
        num_shares: u32,
    ) -> Result<(FeldmanCommitment, Vec<Share>), StatusError> {
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let secret = SecretScalar::random(&mut prng)?;
        split(&secret, threshold, num_shares, &mut prng)
    }

    struct TestVaheContext {
        vahe: Rc<ShellVahe>,
    }

    impl HasVahe for TestVaheContext {
        type Vahe = ShellVahe;
        fn vahe(&self) -> &ShellVahe {
            &self.vahe
        }
    }

    impl HasKahe for TestVaheContext {
        type Kahe = ShellKahe;
        fn kahe(&self) -> &ShellKahe {
            panic!("KAHE not used in messages_test")
        }
    }

    fn nz(v: u32) -> NonZeroU32 {
        NonZeroU32::new(v).unwrap()
    }

    #[gtest]
    fn committee_config_validation_and_proto_roundtrip() -> googletest::Result<()> {
        let cfg = CommitteeConfig::new(
            nz(2),
            5,
            3,
            [0x42u8; ROSTER_HASH_BYTE_LEN],
            b"session-123".to_vec(),
        )?;
        let proto = cfg.to_proto(())?;
        let roundtrip = CommitteeConfig::from_proto(proto.as_view(), ())?;
        verify_that!(roundtrip, eq(&cfg))?;

        // Boundary: n = 2, t = 1.
        verify_true!(CommitteeConfig::new(nz(1), 2, 1, [0x11; 32], b"ctx".to_vec()).is_ok())?;
        // Boundary: n = MAX_SHARES, t = MAX_SHARES - 1.
        verify_true!(CommitteeConfig::new(
            nz(MAX_SHARES),
            MAX_SHARES,
            MAX_SHARES - 1,
            [0x11; 32],
            b"ctx".to_vec(),
        )
        .is_ok())?;

        // Rejects n < 2, n > MAX_SHARES, t == 0, t >= n, my_index > n, empty session_context.
        verify_true!(CommitteeConfig::new(nz(1), 1, 1, [0; 32], b"ctx".to_vec()).is_err())?;
        verify_true!(
            CommitteeConfig::new(nz(1), MAX_SHARES + 1, 2, [0; 32], b"ctx".to_vec()).is_err()
        )?;
        verify_true!(CommitteeConfig::new(nz(1), 3, 0, [0; 32], b"ctx".to_vec()).is_err())?;
        verify_true!(CommitteeConfig::new(nz(1), 3, 3, [0; 32], b"ctx".to_vec()).is_err())?;
        verify_true!(CommitteeConfig::new(nz(4), 3, 2, [0; 32], b"ctx".to_vec()).is_err())?;
        verify_true!(CommitteeConfig::new(nz(1), 3, 2, [0; 32], vec![]).is_err())?;

        // Proto rejections: my_index == 0, bad roster_hash length.
        let mut bad_proto = cfg.to_proto(())?;
        bad_proto.set_my_index(0);
        verify_true!(CommitteeConfig::from_proto(bad_proto.as_view(), ()).is_err())?;

        let mut bad_hash_proto = cfg.to_proto(())?;
        bad_hash_proto.set_roster_hash(&[1u8; 31][..]);
        verify_true!(CommitteeConfig::from_proto(bad_hash_proto.as_view(), ()).is_err())?;

        Ok(())
    }

    #[gtest]
    fn compute_roster_hash_deterministic_and_rejects_malformed_roster() -> googletest::Result<()> {
        let mut r1 = BTreeMap::new();
        r1.insert(nz(3), b"pk3".to_vec());
        r1.insert(nz(1), b"pk1".to_vec());
        r1.insert(nz(2), b"pk2".to_vec());

        let mut r2 = BTreeMap::new();
        r2.insert(nz(1), b"pk1".to_vec());
        r2.insert(nz(2), b"pk2".to_vec());
        r2.insert(nz(3), b"pk3".to_vec());

        let h1 = compute_roster_hash(3, 2, &r1)?;
        let h2 = compute_roster_hash(3, 2, &r2)?;
        verify_that!(h1, eq(h2))?;

        // Changing threshold or a public key changes the hash.
        let h_diff_t = compute_roster_hash(3, 1, &r1)?;
        verify_that!(h1, not(eq(h_diff_t)))?;

        let mut r_tampered = r1.clone();
        r_tampered.insert(nz(2), b"pk2_tampered".to_vec());
        let h_diff_pk = compute_roster_hash(3, 2, &r_tampered)?;
        verify_that!(h1, not(eq(h_diff_pk)))?;

        // Missing contiguous index (gap at 2) rejected.
        let mut r_gap = BTreeMap::new();
        r_gap.insert(nz(1), b"pk1".to_vec());
        r_gap.insert(nz(3), b"pk3".to_vec());
        r_gap.insert(nz(4), b"pk4".to_vec());
        verify_true!(compute_roster_hash(3, 2, &r_gap).is_err())?;

        // Empty public key rejected.
        let mut r_empty_pk = r1;
        r_empty_pk.insert(nz(2), vec![]);
        verify_true!(compute_roster_hash(3, 2, &r_empty_pk).is_err())?;

        Ok(())
    }

    #[gtest]
    fn compute_setup_transcript_hash_deterministic_and_validates_commitments(
    ) -> googletest::Result<()> {
        let (c1, _) = sample_split(2, 3)?;
        let (c2, _) = sample_split(2, 3)?;
        let (c3, _) = sample_split(2, 3)?;
        let roster_hash = [0x55u8; ROSTER_HASH_BYTE_LEN];

        let mut map1 = BTreeMap::new();
        map1.insert(nz(3), c3.clone());
        map1.insert(nz(1), c1.clone());
        map1.insert(nz(2), c2.clone());

        let mut map2 = BTreeMap::new();
        map2.insert(nz(1), c1.clone());
        map2.insert(nz(2), c2);
        map2.insert(nz(3), c3.clone());

        let t1 = compute_setup_transcript_hash(&roster_hash, b"sess-ctx", 2, 3, &map1)?;
        let t2 = compute_setup_transcript_hash(&roster_hash, b"sess-ctx", 2, 3, &map2)?;
        verify_that!(t1, eq(t2))?;

        // Commitment with wrong threshold (t = 1 instead of 2) is rejected.
        let (c_wrong_t, _) = sample_split(1, 3)?;
        let mut map_wrong_t = BTreeMap::new();
        map_wrong_t.insert(nz(1), c1);
        map_wrong_t.insert(nz(2), c_wrong_t);
        map_wrong_t.insert(nz(3), c3);
        verify_true!(
            compute_setup_transcript_hash(&roster_hash, b"sess-ctx", 2, 3, &map_wrong_t,).is_err()
        )?;

        Ok(())
    }

    #[gtest]
    fn decryptor_status_roundtrip_and_rejects_unspecified() -> googletest::Result<()> {
        for status in [
            DecryptorStatus::PreSetup,
            DecryptorStatus::AwaitingDecryptionRequest,
            DecryptorStatus::AwaitingRecoveryRequest,
            DecryptorStatus::Finished,
        ] {
            let proto = status.to_proto(())?;
            let roundtrip = DecryptorStatus::from_proto(proto, ())?;
            verify_that!(roundtrip, eq(status))?;
        }
        verify_true!(DecryptorStatus::from_proto(DecryptorStatusProto::Unspecified, ()).is_err())?;
        Ok(())
    }

    #[gtest]
    fn setup_contribution_and_pd_response_indexed_fields_roundtrip() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, TEST_CONTEXT)?);
        let ctx = TestVaheContext { vahe: vahe.clone() };
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (sk_share, pk_share, proof) = vahe.verifiable_key_gen(&mut prng)?;
        let (commitment, _) = sample_split(2, 3)?;

        let mut indexed_encrypted_shares = BTreeMap::new();
        indexed_encrypted_shares.insert(nz(2), b"hpke_ct_for_2".to_vec());
        indexed_encrypted_shares.insert(nz(3), b"hpke_ct_for_3".to_vec());

        let contrib = SetupContribution::<ShellVahe> {
            key_contribution: KeyContribution {
                public_key_share: pk_share.clone(),
                proof: Some(proof),
            },
            dp_setup: None,
            encrypted_randomness_shares: Some(vec![SecretSharingContribution {
                encrypted_share: b"legacy_ct".to_vec(),
                recipient_index: Some(nz(2)),
            }]),
            decryptor_index: Some(nz(1)),
            feldman_commitment: Some(commitment),
            indexed_encrypted_shares,
        };
        let proto = contrib.to_proto(&ctx)?;
        let roundtrip = SetupContribution::<ShellVahe>::from_proto(proto.as_view(), &ctx)?;
        verify_that!(roundtrip.decryptor_index, eq(Some(nz(1))))?;
        verify_that!(roundtrip.feldman_commitment, eq(&contrib.feldman_commitment))?;
        verify_that!(roundtrip.indexed_encrypted_shares, eq(&contrib.indexed_encrypted_shares))?;
        verify_that!(
            roundtrip.encrypted_randomness_shares.as_ref().unwrap()[0].recipient_index,
            eq(Some(nz(2)))
        )?;

        // Rejects self-share (recipient_index == decryptor_index).
        let mut bad_self_share = contrib;
        bad_self_share.indexed_encrypted_shares.insert(nz(1), b"self_ct".to_vec());
        verify_true!(bad_self_share.to_proto(&ctx).is_err())?;

        // PartialDecryptionResponse with decryptor_index roundtrips.
        let pk = vahe.aggregate_public_key_shares(std::iter::once(&pk_share))?;
        let (ct, _) =
            vahe.verifiable_encrypt(&vec![7i64; 8], &pk, b"0123456789ABCDEF", &mut prng)?;
        let pd_ct = vahe.get_partial_dec_ciphertext(&ct)?;
        let pd = vahe.partial_decrypt(&pd_ct, &sk_share, &mut prng)?;
        let pd_resp = PartialDecryptionResponse::<ShellKahe, ShellVahe> {
            partial_decryption: pd,
            dp_ciphertext_contribution: None,
            decryptor_index: Some(nz(2)),
        };
        let pd_proto = pd_resp.to_proto((&ctx, None::<&ShellKahe>))?;
        let pd_roundtrip = PartialDecryptionResponse::<ShellKahe, ShellVahe>::from_proto(
            pd_proto.as_view(),
            &ctx,
        )?;
        verify_that!(pd_roundtrip.decryptor_index, eq(Some(nz(2))))?;

        Ok(())
    }

    #[gtest]
    fn recovery_request_and_response_indexed_fields_and_spoofing_rejection(
    ) -> googletest::Result<()> {
        let (c_d1, shares_d1) = sample_split(2, 3)?;
        let (c_d3, shares_d3) = sample_split(2, 3)?;
        let mut req_shares = BTreeMap::new();
        req_shares.insert(nz(1), b"ct_from_dealer_1".to_vec());
        req_shares.insert(nz(3), b"ct_from_dealer_3".to_vec());
        let mut req_commitments = BTreeMap::new();
        req_commitments.insert(nz(1), c_d1);
        req_commitments.insert(nz(3), c_d3);
        let req = RecoveryRequest {
            encrypted_shares: vec![],
            indexed_encrypted_shares: req_shares.clone(),
            dealer_commitments: req_commitments,
        };
        let req_proto = req.to_proto(())?;
        let req_roundtrip = RecoveryRequest::from_proto(req_proto.as_view(), ())?;
        verify_that!(req_roundtrip, eq(&req))?;

        // RecoveryResponse with valid shares for survivor 2 from dealers 1 and 3.
        let share_from_d1_for_2 = shares_d1.into_iter().find(|s| s.index == nz(2)).unwrap();
        let share_from_d3_for_2 = shares_d3.into_iter().find(|s| s.index == nz(2)).unwrap();

        let mut dec_shares = BTreeMap::new();
        dec_shares.insert(nz(1), share_from_d1_for_2);
        dec_shares.insert(nz(3), share_from_d3_for_2);

        let resp = RecoveryResponse {
            decrypted_shares: vec![],
            survivor_index: Some(nz(2)),
            indexed_decrypted_shares: dec_shares,
        };
        let resp_proto = resp.to_proto(())?;
        let resp_roundtrip = RecoveryResponse::from_proto(resp_proto.as_view(), ())?;
        verify_that!(resp_roundtrip, eq(&resp))?;

        // Rejects share index spoofing (survivor 2 submitting a share with share.index == 3).
        let (_, shares_spoof) = sample_split(2, 3)?;
        let share_for_3 = shares_spoof.into_iter().find(|s| s.index == nz(3)).unwrap();
        let mut spoofed_map = BTreeMap::new();
        spoofed_map.insert(nz(1), share_for_3.clone());
        let spoofed_resp = RecoveryResponse {
            decrypted_shares: vec![],
            survivor_index: Some(nz(2)),
            indexed_decrypted_shares: spoofed_map,
        };
        verify_true!(spoofed_resp.to_proto(()).is_err())?;

        // Also check proto-level spoofing rejection on FromProto.
        let mut raw_spoof_proto = resp.to_proto(())?;
        raw_spoof_proto.indexed_decrypted_shares_mut().insert(1u32, share_for_3.to_proto(())?);
        let err = RecoveryResponse::from_proto(raw_spoof_proto.as_view(), ())
            .expect_err("expected share.index mismatch error");
        verify_that!(err.message(), contains_substring("share.index must match survivor_index"))?;

        // Rejects dealer_index == survivor_index.
        let mut raw_self_dealer_proto = resp.to_proto(())?;
        let (_, shares_d2) = sample_split(2, 3)?;
        let share_for_2 = shares_d2.into_iter().find(|s| s.index == nz(2)).unwrap();
        raw_self_dealer_proto
            .indexed_decrypted_shares_mut()
            .insert(2u32, share_for_2.to_proto(())?);
        verify_true!(RecoveryResponse::from_proto(raw_self_dealer_proto.as_view(), ()).is_err())?;

        Ok(())
    }

    #[gtest]
    fn coordinator_state_committee_and_dealer_setup_info_roundtrip() -> googletest::Result<()> {
        let vahe = Rc::new(ShellVahe::new(create_shell_ahe_config(1)?, TEST_CONTEXT)?);
        let ctx = TestVaheContext { vahe: vahe.clone() };
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (_sk, pk_share, _proof) = vahe.verifiable_key_gen(&mut prng)?;
        let pk = vahe.aggregate_public_key_shares(std::iter::once(&pk_share))?;
        let (ct, _) =
            vahe.verifiable_encrypt(&vec![1i64; 8], &pk, b"0123456789ABCDEF", &mut prng)?;
        let pd_ct = vahe.get_partial_dec_ciphertext(&ct)?;

        let (commitment, _) = sample_split(2, 3)?;
        let cfg = CommitteeConfig::new(nz(1), 3, 2, [0xAA; 32], b"sess-1".to_vec())?;

        let mut dealer_enc_shares = BTreeMap::new();
        dealer_enc_shares.insert(nz(2), b"ct_1_to_2".to_vec());
        dealer_enc_shares.insert(nz(3), b"ct_1_to_3".to_vec());

        let dealer_info = DealerSetupInfo::<ShellVahe> {
            dealer_index: nz(1),
            feldman_commitment: commitment,
            public_key_share: pk_share,
            encrypted_shares: dealer_enc_shares,
        };
        let mut dealer_setup_info = BTreeMap::new();
        dealer_setup_info.insert(nz(1), dealer_info);

        let mut responded = BTreeSet::new();
        responded.insert(nz(2));
        responded.insert(nz(3));

        let state = CoordinatorState::<ShellVahe> {
            status: CoordinatorStatus::AwaitingRecovery,
            responded_decryptor_indices: responded.clone(),
            partial_dec_ciphertext: Some(pd_ct),
            dealer_setup_info,
            committee_config: Some(cfg.clone()),
            setup_transcript_hash: Some([0xBB; 32]),
            ..CoordinatorState::default()
        };

        let proto = state.to_proto(&ctx)?;
        let roundtrip = CoordinatorState::<ShellVahe>::from_proto(proto.as_view(), &ctx)?;
        verify_that!(roundtrip.status, eq(CoordinatorStatus::AwaitingRecovery))?;
        verify_that!(roundtrip.responded_decryptor_indices, eq(&responded))?;
        verify_true!(roundtrip.partial_dec_ciphertext.is_some())?;
        verify_that!(roundtrip.committee_config.as_ref(), eq(Some(&cfg)))?;
        verify_that!(roundtrip.setup_transcript_hash, eq(Some([0xBB; 32])))?;
        verify_that!(roundtrip.dealer_setup_info.len(), eq(1))?;
        let rt_info = &roundtrip.dealer_setup_info[&nz(1)];
        let orig_info = &state.dealer_setup_info[&nz(1)];
        verify_that!(rt_info.dealer_index, eq(orig_info.dealer_index))?;
        verify_that!(rt_info.feldman_commitment, eq(&orig_info.feldman_commitment))?;
        verify_that!(rt_info.encrypted_shares, eq(&orig_info.encrypted_shares))?;
        verify_that!(
            rt_info.public_key_share.to_proto(ctx.vahe())?.serialize()?,
            eq(&orig_info.public_key_share.to_proto(ctx.vahe())?.serialize()?)
        )?;

        // Rejects duplicate responded_decryptor_indices on FromProto.
        let mut dup_proto = state.to_proto(&ctx)?;
        dup_proto.responded_decryptor_indices_mut().push(2);
        verify_true!(CoordinatorState::<ShellVahe>::from_proto(dup_proto.as_view(), &ctx).is_err())?;

        // Rejects responded_decryptor_index > committee_config.num_decryptors.
        let mut out_of_range_proto = state.to_proto(&ctx)?;
        out_of_range_proto.responded_decryptor_indices_mut().push(4);
        verify_true!(CoordinatorState::<ShellVahe>::from_proto(
            out_of_range_proto.as_view(),
            &ctx
        )
        .is_err())?;

        Ok(())
    }
}
