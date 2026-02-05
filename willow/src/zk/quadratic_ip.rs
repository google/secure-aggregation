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
    QuadraticInnerProductParameters, QuadraticInnerProductProofStatement,
    QuadraticInnerProductProofWitness, Transcript, ZeroKnowledgeProver, ZeroKnowledgeVerifier,
};

// Inner product proof for <a,b> = c, with precommitted a, b and c with O(|a|) proof size.
#[allow(non_snake_case)]
pub struct QuadraticInnerProductProof {
    pub R: CompressedRistretto,
    pub S: CompressedRistretto,
    pub a_: Vec<Scalar>,
    pub b_: Vec<Scalar>,
    pub delta_: Scalar,
}

pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut out = Scalar::ZERO;
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}

fn generate_params(length: usize, parameter_seed: &[u8]) -> QuadraticInnerProductParameters {
    use sha3::Sha3_512;
    QuadraticInnerProductParameters {
        n: length,
        G: (0..length)
            .map(|i| {
                RistrettoPoint::hash_from_bytes::<Sha3_512>(
                    &[parameter_seed, format!("G{}", i).as_bytes()].concat(),
                )
            })
            .collect(),
        H: (0..length)
            .map(|i| {
                RistrettoPoint::hash_from_bytes::<Sha3_512>(
                    &[parameter_seed, format!("H{}", i).as_bytes()].concat(),
                )
            })
            .collect(),
        F: RistrettoPoint::hash_from_bytes::<Sha3_512>(&[parameter_seed, b"F"].concat()),
        F_: RistrettoPoint::hash_from_bytes::<Sha3_512>(&[parameter_seed, b"F_"].concat()),
    }
}

#[allow(non_snake_case)]
fn append_params_to_transcript(
    transcript: &mut impl Transcript,
    params: &QuadraticInnerProductParameters,
) {
    transcript.append_u64(b"n", params.n as u64);
    for G_i in &params.G {
        transcript.append_message(b"G_i", G_i.compress().as_bytes());
    }
    for H_i in &params.H {
        transcript.append_message(b"H_i", H_i.compress().as_bytes());
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

/// A single object that can both prove and verify quadratic inner product arguments.
pub struct QuadraticInnerProductProverVerifier {
    pub params: QuadraticInnerProductParameters,
}

impl QuadraticInnerProductProverVerifier {
    pub fn new(parameter_seed: &[u8], length: usize) -> Self {
        let params = generate_params(length, parameter_seed);
        Self { params }
    }

    #[allow(non_snake_case)]
    pub fn commit(
        &self,
        a: &[Scalar],
        b: &[Scalar],
        c: Scalar,
        delta: Scalar,
    ) -> Result<RistrettoPoint, status::StatusError> {
        if a.len() != self.params.n {
            return Err(status::permission_denied(
                "Length of a doesnt match length specified at prover construction.",
            ));
        }
        if b.len() != self.params.n {
            return Err(status::permission_denied(
                "Length of b doesnt match length specified at prover construction.",
            ));
        }
        let C = RistrettoPoint::vartime_multiscalar_mul(
            a.iter().chain(b.iter()).chain(iter::once(&c)).chain(iter::once(&delta)),
            self.params
                .G
                .iter()
                .chain(self.params.H.iter())
                .chain(iter::once(&self.params.F))
                .chain(iter::once(&self.params.F_)),
        );
        Ok(C)
    }
}

impl
    ZeroKnowledgeProver<
        QuadraticInnerProductProofStatement,
        QuadraticInnerProductProofWitness<Scalar>,
    > for QuadraticInnerProductProverVerifier
{
    type Proof = QuadraticInnerProductProof;

    #[allow(non_snake_case)]
    fn prove(
        &self,
        statement: &QuadraticInnerProductProofStatement,
        witness: &QuadraticInnerProductProofWitness<Scalar>,
        transcript: &mut impl Transcript,
    ) -> Result<Self::Proof, status::StatusError> {
        if witness.a.len() != self.params.n {
            return Err(status::permission_denied(
                "Length of witness a doesn't match length in parameters",
            ));
        }
        if witness.b.len() != self.params.n {
            return Err(status::permission_denied(
                "Length of witness b doesnt match length in parameters",
            ));
        }

        transcript.append_message(b"dom-sep", b"QuadraticInnerProductProof");
        append_params_to_transcript(transcript, &self.params);
        transcript.append_message(b"C", statement.C.compress().as_bytes());

        let mut rng = rand::thread_rng();
        let r: Vec<_> = (0..self.params.n).map(|_| Scalar::random(&mut rng)).collect();
        let s: Vec<_> = (0..self.params.n).map(|_| Scalar::random(&mut rng)).collect();
        let u = Scalar::random(&mut rng);
        let v = Scalar::random(&mut rng);

        let cross_terms = inner_product(&r, &witness.b) + inner_product(&s, &witness.a);
        let R = RistrettoPoint::vartime_multiscalar_mul(
            r.iter().chain(s.iter()).chain(iter::once(&cross_terms)).chain(iter::once(&u)),
            self.params
                .G
                .iter()
                .chain(self.params.H.iter())
                .chain(iter::once(&self.params.F))
                .chain(iter::once(&self.params.F_)),
        );

        let S = self.params.F * inner_product(&r, &s) + self.params.F_ * v;

        transcript.append_message(b"R", R.compress().as_bytes());
        transcript.append_message(b"S", S.compress().as_bytes());

        let mut buf = [0u8; 64];
        transcript.challenge_bytes(b"x", &mut buf);
        let x = Scalar::from_bytes_mod_order_wide(&buf);

        let a_ =
            witness.a.iter().zip(r.iter().map(|ri| ri * x)).map(|(ai, rix)| ai + rix).collect();
        let b_ =
            witness.b.iter().zip(s.iter().map(|si| si * x)).map(|(bi, six)| bi + six).collect();
        let delta_ = witness.delta + u * x + v * x * x;
        Ok(QuadraticInnerProductProof {
            R: R.compress(),
            S: S.compress(),
            a_: a_,
            b_: b_,
            delta_: delta_,
        })
    }
}

impl ZeroKnowledgeVerifier<QuadraticInnerProductProofStatement, QuadraticInnerProductProof>
    for QuadraticInnerProductProverVerifier
{
    #[allow(non_snake_case)]
    fn verify(
        &self,
        statement: &QuadraticInnerProductProofStatement,
        proof: &QuadraticInnerProductProof,
        transcript: &mut impl Transcript,
    ) -> status::Status {
        if proof.a_.len() != self.params.n {
            return Err(status::permission_denied(
                "Length of vector a_ in proof doesn't length in parameters",
            ));
        }

        if proof.b_.len() != self.params.n {
            return Err(status::permission_denied(
                "Length of vector b_ in proof doesn't length in parameters",
            ));
        }
        transcript.append_message(b"dom-sep", b"QuadraticInnerProductProof");
        append_params_to_transcript(transcript, &self.params);

        // "Receive" statement and proof from prover
        validate_and_append_point(transcript, b"C", &statement.C.compress())?;
        validate_and_append_point(transcript, b"R", &proof.R)?;
        validate_and_append_point(transcript, b"S", &proof.S)?;

        let Some(R) = proof.R.decompress() else {
            return Err(status::permission_denied(
                "Proof verification failed as R is not a valid point",
            ));
        };
        let Some(S) = proof.S.decompress() else {
            return Err(status::permission_denied(
                "Proof verification failed as S is not a valid point",
            ));
        };

        let mut buf = [0u8; 64];
        transcript.challenge_bytes(b"x", &mut buf);
        let x = Scalar::from_bytes_mod_order_wide(&buf);
        let expected_C = RistrettoPoint::vartime_multiscalar_mul(
            proof
                .a_
                .iter()
                .chain(proof.b_.iter())
                .chain(iter::once(&inner_product(&proof.a_, &proof.b_)))
                .chain(iter::once(&proof.delta_))
                .chain(iter::once(&(-x)))
                .chain(iter::once(&(-(x * x)))),
            self.params
                .G
                .iter()
                .chain(self.params.H.iter())
                .chain(iter::once(&self.params.F))
                .chain(iter::once(&self.params.F_))
                .chain(iter::once(&R))
                .chain(iter::once(&S)),
        );
        if statement.C != expected_C {
            return Err(status::permission_denied("Proof verification failed at final check"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::{gtest, verify_that};
    use merlin::Transcript as MerlinTranscript;
    use status_matchers_rs::status_is;

    #[gtest]
    #[allow(non_snake_case)]
    fn test_valid_quadratic_zk_inner_product_proof() -> googletest::Result<()> {
        // The large entries on the end are to ensure wrap around modulo the order is tested.
        let mut a: Vec<Scalar> = (1..5).map(|x| Scalar::from(x as u64)).collect();
        a.push(Scalar::from(85070591730234615865843651857942052865 as u128));
        let mut b: Vec<Scalar> = (5..9).map(|x| Scalar::from(x as u64)).collect();
        b.push(Scalar::from(85070591730234615865843651857942052865 as u128));
        let mut c: Scalar = Scalar::from(5 + 12 + 21 + 32 as u64);
        c += Scalar::from(142398865683096878195835365925000457236 as u128);

        let prover = QuadraticInnerProductProverVerifier::new(b"42", a.len());
        let verifier = QuadraticInnerProductProverVerifier::new(b"42", a.len());

        let delta: Scalar = Scalar::from(42 as u64);
        let C = prover.commit(&a, &b, c, delta)?;
        let statement = QuadraticInnerProductProofStatement { C: C };

        let mut transcript = MerlinTranscript::new(b"quadratic_ip_zkp_test");
        let proof = prover.prove(
            &statement,
            &QuadraticInnerProductProofWitness { a: a, b: b, delta: delta },
            &mut transcript,
        )?;

        let mut transcript = MerlinTranscript::new(b"quadratic_ip_zkp_test");
        verifier.verify(&statement, &proof, &mut transcript)?;
        Ok(())
    }

    #[gtest]
    #[allow(non_snake_case)]
    fn test_invalid_quadratic_zk_inner_product_proof() -> googletest::Result<()> {
        // The large entries on the end are to ensure wrap around modulo the order is tested.
        let mut a: Vec<Scalar> = (1..5).map(|x| Scalar::from(x as u64)).collect();
        a.push(Scalar::from(85070591730234615865843651857942052865 as u128));
        let mut b: Vec<Scalar> = (5..9).map(|x| Scalar::from(x as u64)).collect();
        b.push(Scalar::from(85070591730234615865843651857942052865 as u128));
        let mut c: Scalar = Scalar::from(5 + 12 + 21 + 32 + 1 as u64);
        c += Scalar::from(142398865683096878195835365925000457236 as u128);

        let prover = QuadraticInnerProductProverVerifier::new(b"42", a.len());
        let verifier = QuadraticInnerProductProverVerifier::new(b"42", a.len());

        let delta: Scalar = Scalar::from(42 as u64);
        let C = prover.commit(&a, &b, c, delta)?;
        let statement = QuadraticInnerProductProofStatement { C: C };

        let mut transcript = MerlinTranscript::new(b"quadratic_ip_zkp_test");
        let proof = prover.prove(
            &statement,
            &QuadraticInnerProductProofWitness { a: a, b: b, delta: delta },
            &mut transcript,
        )?;

        let mut transcript = MerlinTranscript::new(b"quadratic_ip_zkp_test");
        verify_that!(
            verifier.verify(&statement, &proof, &mut transcript),
            status_is(status::StatusErrorCode::PermissionDenied)
        )
    }
}
