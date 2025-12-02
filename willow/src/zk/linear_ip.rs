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

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use rand;
use std::iter;
use zk_traits::{
    LinearInnerProductProofStatement, LinearInnerProductProofWitness, Transcript,
    ZeroKnowledgeProver, ZeroKnowledgeVerifier,
};

// Inner product proof for <a,b> = c, with public b,c with O(|a|) proof size.
#[derive(Clone)]
pub struct LinearInnerProductProof {
    pub a_: Vec<Scalar>,
    pub delta_: Scalar,
    pub c_: Scalar,
    pub R: CompressedRistretto,
}

pub struct LinearInnerProductParameters {
    n: usize,
    F: RistrettoPoint,
    F_: RistrettoPoint,
    G: Vec<RistrettoPoint>,
}

pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut out = Scalar::ZERO;
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}

fn common_setup(length: usize, parameter_seed: &[u8]) -> LinearInnerProductParameters {
    use sha3::Sha3_512;
    LinearInnerProductParameters {
        n: length,
        F: RistrettoPoint::hash_from_bytes::<Sha3_512>(&[parameter_seed, b"F"].concat()),
        F_: RistrettoPoint::hash_from_bytes::<Sha3_512>(&[parameter_seed, b"F_"].concat()),
        G: (0..length)
            .map(|i| {
                RistrettoPoint::hash_from_bytes::<Sha3_512>(
                    &[parameter_seed, format!("G{}", i).as_bytes()].concat(),
                )
            })
            .collect(),
    }
}

fn append_params_to_transcript(
    transcript: &mut impl Transcript,
    params: &LinearInnerProductParameters,
) {
    transcript.append_u64(b"n", params.n as u64);
    for G_i in &params.G {
        transcript.append_message(b"G_i", G_i.compress().as_bytes());
    }
    transcript.append_message(b"F", params.F.compress().as_bytes());
    transcript.append_message(b"F_", params.F_.compress().as_bytes());
}

fn validate_and_append_point(
    transcript: &mut impl Transcript,
    label: &'static [u8],
    point: &CompressedRistretto,
) -> status::Status {
    use curve25519_dalek::traits::IsIdentity;

    if point.is_identity() {
        return Err(status::permission_denied("Proof verification failed"));
    } else {
        Ok(transcript.append_message(label, point.as_bytes()))
    }
}

pub struct LinearInnerProductProver {
    pub params: LinearInnerProductParameters,
}

impl LinearInnerProductProver {
    pub fn new(parameter_seed: &[u8], length: usize) -> Self {
        let params = common_setup(length, parameter_seed);
        Self { params }
    }

    pub fn commit(
        &self,
        a: &[Scalar],
        randomness: Scalar,
    ) -> Result<CompressedRistretto, status::StatusError> {
        if a.len() != self.params.G.len() {
            return Err(status::permission_denied(
                "Length of a doesnt match length specified at prover construction.".to_string(),
            ));
        }
        let C = RistrettoPoint::vartime_multiscalar_mul(
            a.iter().chain(iter::once(&randomness)),
            self.params.G.iter().chain(iter::once(&self.params.F_)),
        );
        Ok(C.compress())
    }

    pub fn commit_partial(
        &self,
        a: &[Scalar],
        randomness: Scalar,
        start: usize,
        end: usize,
    ) -> Result<RistrettoPoint, status::StatusError> {
        if end > self.params.G.len() {
            return Err(status::permission_denied(
                "End of range is beyond the size speicified at prover construction.".to_string(),
            ));
        }
        if (end - start) != a.len() {
            return Err(status::permission_denied(
                "Length of a doesnt match the length of the specified range of generators."
                    .to_string(),
            ));
        }
        let C = RistrettoPoint::vartime_multiscalar_mul(
            a.iter().chain(iter::once(&randomness)),
            self.params.G[start..end].iter().chain(iter::once(&self.params.F_)),
        );
        Ok(C)
    }
}

impl
    ZeroKnowledgeProver<
        LinearInnerProductProofStatement<Scalar>,
        LinearInnerProductProofWitness<Scalar>,
    > for LinearInnerProductProver
{
    type Proof = LinearInnerProductProof;

    fn prove(
        &self,
        statement: &LinearInnerProductProofStatement<Scalar>,
        witness: &LinearInnerProductProofWitness<Scalar>,
        transcript: &mut impl Transcript,
    ) -> Result<Self::Proof, status::StatusError> {
        if self.params.n != statement.n {
            return Err(status::permission_denied(
                "Number of generators doesnt match length in statement".to_string(),
            ));
        }

        if witness.a.len() != statement.n {
            return Err(status::permission_denied(
                "Length of witness doesnt match length in statement".to_string(),
            ));
        }
        if statement.b.len() != statement.n {
            return Err(status::permission_denied(
                "Length of vector b in statement doesnt match value for length in statement"
                    .to_string(),
            ));
        }

        // Compute commitment to witness and claimed inner product
        let C = self.params.F * statement.c
            + statement
                .comm_a
                .decompress()
                .ok_or(status::permission_denied("Failed to decompress comm_a"))?;

        transcript.append_message(b"dom-sep", b"LinearInnerProductProof");
        // Append all public data to the transcript
        append_params_to_transcript(transcript, &self.params);
        for b_i in &statement.b {
            transcript.append_message(b"b_i", b_i.as_bytes());
        }

        // "Send" commitments to the verifier and "receive" challenge
        transcript.append_message(b"C", C.compress().as_bytes());

        // Sample mask and compute commitment to it and its inner product with public b
        let mut rng = rand::thread_rng();
        let r: Vec<_> = (0..witness.a.len()).map(|_| Scalar::random(&mut rng)).collect();
        let delta_r = Scalar::random(&mut rng);
        let comm_r = self.commit(&r, delta_r)?;

        let c_ = inner_product(&r, &statement.b);
        let R = self.params.F * c_
            + comm_r
                .decompress()
                .ok_or(status::permission_denied("Failed to decompress comm_r"))?;

        transcript.append_message(b"R", R.compress().as_bytes());

        let mut buf = [0u8; 64];
        transcript.challenge_bytes(b"x", &mut buf);
        let x = Scalar::from_bytes_mod_order_wide(&buf);
        let a_ =
            witness.a.iter().zip(r.iter().map(|ri| ri * x)).map(|(ai, rix)| ai + rix).collect();
        let delta_ = witness.delta_a + delta_r * x;
        Ok(LinearInnerProductProof { a_: a_, delta_: delta_, c_: c_, R: R.compress() })
    }
}

pub struct LinearInnerProductVerifier {
    pub params: LinearInnerProductParameters,
}

impl LinearInnerProductVerifier {
    pub fn new(parameter_seed: &[u8], length: usize) -> Self {
        let params = common_setup(length, parameter_seed);
        Self { params }
    }
}

impl ZeroKnowledgeVerifier<LinearInnerProductProofStatement<Scalar>, LinearInnerProductProof>
    for LinearInnerProductVerifier
{
    fn verify(
        &self,
        statement: &LinearInnerProductProofStatement<Scalar>,
        proof: &LinearInnerProductProof,
        transcript: &mut impl Transcript,
    ) -> status::Status {
        if self.params.G.len() != statement.n {
            return Err(status::permission_denied(
                "Number of generators doesnt match length in statement",
            ));
        }

        if proof.a_.len() != statement.n {
            return Err(status::permission_denied(
                "Length of vector a in statement doesnt match value for length in statement",
            ));
        }

        if statement.b.len() != statement.n {
            return Err(status::permission_denied(
                "Length of vector b in statement doesnt match value for length in statement",
            ));
        }

        transcript.append_message(b"dom-sep", b"LinearInnerProductProof");
        // Append all public data to the transcript
        append_params_to_transcript(transcript, &self.params);
        for b_i in &statement.b {
            transcript.append_message(b"b_i", b_i.as_bytes());
        }

        // Combine witness commitment with its claimed inner product
        let C = self.params.F * statement.c
            + statement
                .comm_a
                .decompress()
                .ok_or(status::permission_denied("Proof verification failed"))?;

        // "Receive" proof from prover
        validate_and_append_point(transcript, b"C", &C.compress())?;
        validate_and_append_point(transcript, b"R", &proof.R)?;

        let R =
            proof.R.decompress().ok_or(status::permission_denied("Proof verification failed"))?;

        let mut buf = [0u8; 64];
        transcript.challenge_bytes(b"x", &mut buf);
        let x = Scalar::from_bytes_mod_order_wide(&buf);
        let expected_C = RistrettoPoint::vartime_multiscalar_mul(
            proof
                .a_
                .iter()
                .chain(iter::once(&inner_product(&proof.a_, &statement.b)))
                .chain(iter::once(&proof.delta_))
                .chain(iter::once(&(-x))),
            self.params
                .G
                .iter()
                .chain(iter::once(&self.params.F))
                .chain(iter::once(&self.params.F_))
                .chain(iter::once(&R)),
        );
        if C != expected_C {
            return Err(status::permission_denied("Proof verification failed at final check"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::{gtest, verify_eq, verify_that};
    use merlin::Transcript as MerlinTranscript;
    use status_matchers_rs::status_is;

    #[gtest]
    fn test_valid_linear_zk_inner_product_proof() -> googletest::Result<()> {
        let a: Vec<Scalar> = (1..5).map(|x| Scalar::from(x as u64)).collect();
        let mut rng = rand::thread_rng();

        let prover = LinearInnerProductProver::new(b"42", a.len());
        let delta_a = Scalar::random(&mut rng);
        let comm_a = prover.commit(&a, delta_a)?;
        let b: Vec<Scalar> = (5..9).map(|x| Scalar::from(x as u64)).collect();
        let c: Scalar = Scalar::from(5 + 12 + 21 + 32 as u64);
        let mut transcript = MerlinTranscript::new(b"linear_ip_zkp_test");

        let verifier = LinearInnerProductVerifier::new(b"42", a.len());
        verify_eq!(prover.params.F, verifier.params.F)?;
        verify_eq!(prover.params.F_, verifier.params.F_)?;
        verify_eq!(prover.params.G, verifier.params.G)?;
        let statement = LinearInnerProductProofStatement { n: a.len(), b: b, c: c, comm_a: comm_a };
        let proof = prover.prove(
            &statement,
            &LinearInnerProductProofWitness { a: a, delta_a: delta_a },
            &mut transcript,
        )?;

        let mut transcript = MerlinTranscript::new(b"linear_ip_zkp_test");
        verifier.verify(&statement, &proof, &mut transcript)?;
        Ok(())
    }

    #[gtest]
    fn test_invalid_linear_zk_inner_product_proof() -> googletest::Result<()> {
        let a: Vec<Scalar> = (1..5).map(|x| Scalar::from(x as u64)).collect();
        let mut rng = rand::thread_rng();
        let r: Vec<_> = (0..a.len()).map(|_| Scalar::random(&mut rng)).collect();
        let mut transcript = MerlinTranscript::new(b"linear_ip_zkp_test");

        let prover = LinearInnerProductProver::new(b"42", a.len());
        let delta_a = Scalar::random(&mut rng);
        let comm_a = prover.commit(&a, delta_a)?;
        let delta_r = Scalar::random(&mut rng);
        let comm_r = prover.commit(&r, delta_r)?;
        let b: Vec<Scalar> = (5..9).map(|x| Scalar::from(x as u64)).collect();
        let c: Scalar = Scalar::from(5 + 12 + 21 + 32 + 1 as u64);

        let verifier = LinearInnerProductVerifier::new(b"42", a.len());
        let statement = LinearInnerProductProofStatement { n: a.len(), b: b, c: c, comm_a: comm_a };
        let proof = prover.prove(
            &statement,
            &LinearInnerProductProofWitness { a: a, delta_a: delta_a },
            &mut transcript,
        )?;

        let mut transcript = MerlinTranscript::new(b"linear_ip_zkp_test");
        verify_that!(
            verifier.verify(&statement, &proof, &mut transcript),
            status_is(status::StatusErrorCode::PermissionDenied)
        )
    }
}
