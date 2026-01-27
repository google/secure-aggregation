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

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
use linear_innerproduct::LinearInnerProductProof;
use proofs_rust_proto::LinearInnerProductProofProto;
use protobuf::{proto, AsView};

#[allow(non_snake_case)]
pub fn linear_inner_product_proof_to_proto(
    proof: &LinearInnerProductProof,
) -> LinearInnerProductProofProto {
    proto!(LinearInnerProductProofProto {
        a: proof.a_.iter().map(|s| s.as_bytes().to_vec()),
        delta: proof.delta_.as_bytes().to_vec(),
        c: proof.c_.as_bytes().to_vec(),
        r: proof.R.to_bytes().to_vec(),
    })
}

#[allow(non_snake_case)]
pub fn linear_inner_product_proof_from_proto(
    proto: impl AsView<Proxied = LinearInnerProductProofProto>,
) -> Result<LinearInnerProductProof, status::StatusError> {
    let proto = proto.as_view();
    let a_: Result<Vec<Scalar>, _> = proto
        .a()
        .iter()
        .map(|bytes| {
            let array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| status::invalid_argument("a_ element has incorrect length"))?;
            Ok(Scalar::from_bytes_mod_order(array))
        })
        .collect();

    let delta_ = Scalar::from_bytes_mod_order(
        proto
            .delta()
            .try_into()
            .map_err(|_| status::invalid_argument("delta_ has incorrect length"))?,
    );

    let c_ = Scalar::from_bytes_mod_order(
        proto.c().try_into().map_err(|_| status::invalid_argument("c_ has incorrect length"))?,
    );

    let R = CompressedRistretto(
        proto.r().try_into().map_err(|_| status::invalid_argument("R has incorrect length"))?,
    );

    Ok(LinearInnerProductProof { a_: a_?, delta_, c_, R })
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use googletest::gtest;
    use linear_innerproduct::LinearInnerProductProverVerifier;
    use merlin::Transcript as MerlinTranscript;
    use rand;
    use zk_traits::{
        LinearInnerProductProofStatement, LinearInnerProductProofWitness, ZeroKnowledgeProver,
        ZeroKnowledgeVerifier,
    };

    #[gtest]
    #[allow(non_snake_case)]
    fn test_proof_proto_roundtrip() -> googletest::Result<()> {
        let a: Vec<Scalar> = (1..5).map(|x| Scalar::from(x as u64)).collect();
        let mut rng = rand::thread_rng();

        let prover = LinearInnerProductProverVerifier::new(b"42", a.len());
        let delta_a = Scalar::random(&mut rng);
        let comm_a = prover.commit(&a, delta_a)?;
        let b: Vec<Scalar> = (5..9).map(|x| Scalar::from(x as u64)).collect();
        let c: Scalar = Scalar::from(5 + 12 + 21 + 32 as u64);
        let mut transcript = MerlinTranscript::new(b"linear_ip_zkp_test");

        let verifier = LinearInnerProductProverVerifier::new(b"42", a.len());
        let statement = LinearInnerProductProofStatement { n: a.len(), b: b, c: c, comm_a: comm_a };
        let proof = prover.prove(
            &statement,
            &LinearInnerProductProofWitness { a: a, delta_a: delta_a },
            &mut transcript,
        )?;

        // Test the proto roundtrip
        let proto = linear_inner_product_proof_to_proto(&proof);
        let proof_from_proto = linear_inner_product_proof_from_proto(proto)?;

        let mut transcript = MerlinTranscript::new(b"linear_ip_zkp_test");
        verifier.verify(&statement, &proof_from_proto, &mut transcript)?;
        Ok(())
    }
}
