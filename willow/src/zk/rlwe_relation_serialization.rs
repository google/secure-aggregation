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
use linear_ip_serialization::{
    linear_inner_product_proof_from_proto, linear_inner_product_proof_to_proto,
};
use proofs_rust_proto::RlweRelationProofProto;
use protobuf::{proto, AsView};
use rlwe_relation::RlweRelationProof;

pub fn rlwe_relation_proof_to_proto(proof: &RlweRelationProof) -> RlweRelationProofProto {
    proto!(RlweRelationProofProto {
        comm_rev: proof.comm_rev.to_bytes().to_vec(),
        comm_wrho: proof.comm_wrho.to_bytes().to_vec(),
        comm_y_r: proof.comm_y_r.to_bytes().to_vec(),
        comm_y_e: proof.comm_y_e.to_bytes().to_vec(),
        comm_y_vw: proof.comm_y_vw.to_bytes().to_vec(),
        z_r: proof.z_r.iter().map(|s| s.as_bytes().to_vec()),
        z_e: proof.z_e.iter().map(|s| s.as_bytes().to_vec()),
        z_vw: proof.z_vw.iter().map(|s| s.as_bytes().to_vec()),
        lip_proof: linear_inner_product_proof_to_proto(&proof.lip_proof),
    })
}

pub fn rlwe_relation_proof_from_proto(
    proto: impl AsView<Proxied = RlweRelationProofProto>,
) -> Result<RlweRelationProof, status::StatusError> {
    let proto = proto.as_view();
    let comm_rev = CompressedRistretto(
        proto
            .comm_rev()
            .try_into()
            .map_err(|_| status::invalid_argument("comm_rev has incorrect length"))?,
    );
    let comm_wrho = CompressedRistretto(
        proto
            .comm_wrho()
            .try_into()
            .map_err(|_| status::invalid_argument("comm_wrho has incorrect length"))?,
    );
    let comm_y_r = CompressedRistretto(
        proto
            .comm_y_r()
            .try_into()
            .map_err(|_| status::invalid_argument("comm_y_r has incorrect length"))?,
    );
    let comm_y_e = CompressedRistretto(
        proto
            .comm_y_e()
            .try_into()
            .map_err(|_| status::invalid_argument("comm_y_e has incorrect length"))?,
    );
    let comm_y_vw = CompressedRistretto(
        proto
            .comm_y_vw()
            .try_into()
            .map_err(|_| status::invalid_argument("comm_y_vw has incorrect length"))?,
    );

    let z_r: Result<Vec<Scalar>, _> = proto
        .z_r()
        .iter()
        .map(|bytes| {
            let array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| status::invalid_argument("z_r element has incorrect length"))?;
            Ok(Scalar::from_bytes_mod_order(array))
        })
        .collect();

    let z_e: Result<Vec<Scalar>, _> = proto
        .z_e()
        .iter()
        .map(|bytes| {
            let array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| status::invalid_argument("z_e element has incorrect length"))?;
            Ok(Scalar::from_bytes_mod_order(array))
        })
        .collect();

    let z_vw: Result<Vec<Scalar>, _> = proto
        .z_vw()
        .iter()
        .map(|bytes| {
            let array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| status::invalid_argument("z_vw element has incorrect length"))?;
            Ok(Scalar::from_bytes_mod_order(array))
        })
        .collect();

    let lip_proof = linear_inner_product_proof_from_proto(proto.lip_proof())?;

    Ok(RlweRelationProof {
        comm_rev,
        comm_wrho,
        comm_y_r,
        comm_y_e,
        comm_y_vw,
        z_r: z_r?,
        z_e: z_e?,
        z_vw: z_vw?,
        lip_proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahe::{create_public_parameters, get_moduli, get_rns_context_ref};
    use googletest::gtest;
    use merlin::Transcript as MerlinTranscript;
    use rlwe_relation::RlweRelationProverVerifier;
    use shell_types::read_small_rns_polynomial_from_buffer;
    use single_thread_hkdf::generate_seed;
    use zk_traits::{
        RlweRelationProofStatement, RlweRelationProofWitness, ZeroKnowledgeProver,
        ZeroKnowledgeVerifier,
    };

    #[gtest]
    fn test_proof_proto_roundtrip() -> googletest::Result<()> {
        // We create an ahe_parameters instance to get the context reference and moduli objects.
        let qvec = vec![1000_000_009];
        let seed_wrapper = generate_seed()?;
        let ahe_parameters = create_public_parameters(2, 54001, &qvec, 1, 1.0, 1.0, &seed_wrapper)?;
        let context = get_rns_context_ref(&ahe_parameters);
        let n = 4;
        let q = 1000_000_009;
        let moduli = get_moduli(&ahe_parameters);

        let a_buffer = [1, 2, 3, 4];
        let r_buffer = [1, 0, 1, -1];
        let e_buffer = [5, -9, 1, 12];
        let c_buffer = [5, -8, 9, 17];
        let v_buffer = [-1, -1, 4, 0];

        let a = read_small_rns_polynomial_from_buffer(&a_buffer, n as u64, &moduli)?;
        let c = read_small_rns_polynomial_from_buffer(&c_buffer, n as u64, &moduli)?;
        let r = read_small_rns_polynomial_from_buffer(&r_buffer, n as u64, &moduli)?;
        let e = read_small_rns_polynomial_from_buffer(&e_buffer, n as u64, &moduli)?;
        let v = read_small_rns_polynomial_from_buffer(&v_buffer, n as u64, &moduli)?;

        let statement = RlweRelationProofStatement {
            n: n,
            context: context,
            a: &a,
            flip_a: false,
            c: &c,
            q: q,
            bound_e: 16,
            bound_r: 1,
        };
        let witness = RlweRelationProofWitness { r: &r, e: &e, v: &v };
        let transcript_initializer = b"Rlwe Test Transcript";

        let prover = RlweRelationProverVerifier::new(b"42", statement.n);
        let mut transcript = MerlinTranscript::new(transcript_initializer);
        let proof = prover.prove(&statement, &witness, &mut transcript)?;

        // Test the proto roundtrip
        let proto = rlwe_relation_proof_to_proto(&proof);
        let proof_from_proto = rlwe_relation_proof_from_proto(proto)?;

        let verifier = RlweRelationProverVerifier::new(b"42", statement.n);
        let mut transcript = MerlinTranscript::new(transcript_initializer);
        verifier.verify(&statement, &proof_from_proto, &mut transcript)?;
        Ok(())
    }
}
