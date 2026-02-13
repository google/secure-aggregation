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

use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint};
use merlin::Transcript as MerlinTranscript;
use shell_types::{RnsContextRef, RnsPolynomial};
use status::StatusError;

// A transcript represents a sequence of messages. This is an abstraction of
// Merlin transcripts.
// See https://github.com/dalek-cryptography/merlin/blob/master/src/transcript.rs.
pub trait Transcript {
    fn append_message(&mut self, label: &'static [u8], message: &[u8]);
    fn append_u64(&mut self, label: &'static [u8], message: u64);
    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]);
}

// Implement Transcript for merlin::Transcript.
impl Transcript for MerlinTranscript {
    fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        MerlinTranscript::append_message(self, label, message)
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        MerlinTranscript::challenge_bytes(self, label, dest)
    }

    fn append_u64(&mut self, label: &'static [u8], message: u64) {
        MerlinTranscript::append_u64(self, label, message)
    }
}

// Generic traits for zero-knowledge proofs. Will be used below to define more
// concrete traits for specific proofs we care about. The Statement contains the
// public values known to both prover and verifier, while the Witness contains
// the secret values known only to the prover.
pub trait ZeroKnowledgeProver<Statement, Witness> {
    type Proof;

    // Returns a proof that the statement is true given the witness.
    fn prove(
        &self,
        statement: &Statement,
        witness: &Witness,
        transcript: &mut (impl Transcript + Clone),
    ) -> Result<Self::Proof, StatusError>;
}

pub trait ZeroKnowledgeVerifier<Statement, Proof> {
    // Verifies that the proof is valid for the given statement.
    fn verify(
        &self,
        statement: &Statement,
        proof: &Proof,
        transcript: &mut impl Transcript,
    ) -> status::Status;
}

// Associated types for linear inner product proofs. The statement is the inner product
// of the two vectors, their length, and the public vector `b`, while the
// witness consists of the secret vector `a`.
pub struct LinearInnerProductProofStatement<T> {
    pub n: usize,
    pub b: Vec<T>,
    pub c: T,
    pub comm_a: CompressedRistretto,
}

pub struct LinearInnerProductProofWitness<T> {
    pub a: Vec<T>,
    pub delta_a: T,
}

// Associated types for inner product proofs.
#[allow(non_snake_case)]
pub struct QuadraticInnerProductParameters {
    pub n: usize,
    pub G: Vec<RistrettoPoint>,
    pub H: Vec<RistrettoPoint>,
    pub F: RistrettoPoint,
    pub F_: RistrettoPoint,
}

// The statement is a commitment C = G*a + H*b + F*<a,b> + F_*delta,
// The proof is a proof of knowledge of a, b and delta.
#[allow(non_snake_case)]
pub struct QuadraticInnerProductProofStatement {
    pub C: RistrettoPoint,
}

pub struct QuadraticInnerProductProofWitness<T> {
    pub a: Vec<T>,
    pub b: Vec<T>,
    pub delta: T,
}

// Statement of the RLWE relation that
// 1) there exist degree n polynomials r and e such that ar+e = c in the ring Z_q[X]/(X^n+1)
// 2) e < bound_e*2500*sqrt(n)
// 3) r < bound_r*2500*sqrt(n).
// Note a and c must have degree n and e and r must less than or euqal to bound_e and bound_r respectively.
// If flip_a is true, then a is replaced with -a.
pub struct RlweRelationProofStatement<'a> {
    pub n: usize,
    pub context: RnsContextRef<'a>,
    pub a: &'a RnsPolynomial,
    pub flip_a: bool,
    pub c: &'a RnsPolynomial,
    pub q: u128,
    pub bound_e: u128,
    pub bound_r: u128,
}

// v is the quotient -a*r/(X^N+1)
pub struct RlweRelationProofWitness<'a> {
    pub r: &'a RnsPolynomial,
    pub e: &'a RnsPolynomial,
    pub v: &'a RnsPolynomial,
}

// Associated types for plaintext knowledge proofs. The statement consists
// of the public key and the resulting ciphertext, while the witness is the
// plaintext we want to prove knowledge of, and the metadata (randomness) that
// results in the public ciphertext.
use ahe_traits::AheBase;

pub struct AhePlaintextKnowledgeStatement<T: AheBase> {
    pub public_key: T::PublicKey,
    pub ciphertext: T::Ciphertext,
}

pub struct AhePlaintextKnowledgeWitness<T: AheBase> {
    pub plaintext: T::Plaintext,
    pub metadata: T::EncryptionMetadata,
}
