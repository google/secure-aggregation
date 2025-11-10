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

use ahe_shell::{ShellAhe, ShellAheConfig};
use ahe_traits::Recover as AheRecover;
use ahe_traits::{AheBase, AheKeygen, PartialDec};
use merlin::Transcript as MerlinTranscript;
use rlwe_relation::{RlweRelationProof, RlweRelationProver, RlweRelationVerifier};
use single_thread_hkdf::{compute_hkdf, Seed};
use status::Status;
use status::StatusError;
use vahe_traits::{
    EncryptVerify, KeyGenVerify, PartialDecVerify, Recover, VaheBase, VerifiableEncrypt,
    VerifiableKeyGen, VerifiablePartialDec,
};
use zk_traits::{
    RlweRelationProofStatement, RlweRelationProofWitness, ZeroKnowledgeProver,
    ZeroKnowledgeVerifier,
};

/// Base type holding public VAHE configuration and C++ parameters.
pub struct ShellVahe {
    ahe: ShellAhe,
    q: u128,
    public_seed: Seed,
}

impl ShellVahe {
    fn get_transcript_and_proof_seed(
        &self,
        operation_name: &'static [u8],
    ) -> Result<(MerlinTranscript, Seed), status::StatusError> {
        let proof_seed = compute_hkdf(
            self.public_seed.as_bytes(),
            b"",
            &[operation_name, b"_proof_seed"].concat(),
            16,
        )?;
        let mut transcript = MerlinTranscript::new(operation_name);
        transcript.append_message(b"public_seed:", self.public_seed.as_bytes());
        Ok((transcript, proof_seed))
    }
}

impl AheBase for ShellVahe {
    // This entire implementation is just a simulation of inheritance from ShellAhe.
    type KeyGenMetadata = <ShellAhe as AheBase>::KeyGenMetadata;
    type EncryptionMetadata = <ShellAhe as AheBase>::EncryptionMetadata;
    type PartialDecryptionMetadata = <ShellAhe as AheBase>::PartialDecryptionMetadata;

    type SecretKeyShare = <ShellAhe as AheBase>::SecretKeyShare;
    type PublicKeyShare = <ShellAhe as AheBase>::PublicKeyShare;
    type Plaintext = <ShellAhe as AheBase>::Plaintext;
    type Ciphertext = <ShellAhe as AheBase>::Ciphertext;
    type PartialDecCiphertext = <ShellAhe as AheBase>::PartialDecCiphertext;
    type RecoverCiphertext = <ShellAhe as AheBase>::RecoverCiphertext;
    type PartialDecryption = <ShellAhe as AheBase>::PartialDecryption;
    type PublicKey = <ShellAhe as AheBase>::PublicKey;
    type Rng = <ShellAhe as AheBase>::Rng;
    type Config = ShellAheConfig;

    fn new(config: Self::Config, context_string: &[u8]) -> Result<Self, status::StatusError> {
        let public_seed = single_thread_hkdf::compute_hkdf(
            context_string,
            b"",
            b"ShellVahe.public_seed",
            single_thread_hkdf::seed_length(),
        )?;
        let mut q = 1;
        for modulus in &config.qs {
            q *= *modulus as u128;
        }
        let ahe = ShellAhe::new(config, context_string)?;
        Ok(ShellVahe { ahe: ahe, q: q, public_seed: public_seed })
    }

    fn aggregate_public_key_shares(
        &self,
        public_key_shares: &[Self::PublicKeyShare],
    ) -> Result<Self::PublicKey, StatusError> {
        self.ahe.aggregate_public_key_shares(public_key_shares)
    }

    fn add_plaintexts_in_place(
        &self,
        left: &Self::Plaintext,
        right: &mut Self::Plaintext,
    ) -> Result<(), StatusError> {
        self.ahe.add_plaintexts_in_place(left, right)
    }

    fn add_ciphertexts_in_place(
        &self,
        left: &Self::Ciphertext,
        right: &mut Self::Ciphertext,
    ) -> Result<(), StatusError> {
        self.ahe.add_ciphertexts_in_place(left, right)
    }

    fn add_pd_ciphertexts_in_place(
        &self,
        left: &Self::PartialDecCiphertext,
        right: &mut Self::PartialDecCiphertext,
    ) -> Result<(), StatusError> {
        self.ahe.add_pd_ciphertexts_in_place(left, right)
    }

    fn add_recover_ciphertexts_in_place(
        &self,
        left: &Self::RecoverCiphertext,
        right: &mut Self::RecoverCiphertext,
    ) -> Result<(), StatusError> {
        self.ahe.add_recover_ciphertexts_in_place(left, right)
    }

    fn get_partial_dec_ciphertext(
        &self,
        ct: &Self::Ciphertext,
    ) -> Result<Self::PartialDecCiphertext, StatusError> {
        self.ahe.get_partial_dec_ciphertext(ct)
    }

    fn get_recover_ciphertext(
        &self,
        ct: &Self::Ciphertext,
    ) -> Result<Self::RecoverCiphertext, StatusError> {
        self.ahe.get_recover_ciphertext(ct)
    }

    fn add_partial_decryptions_in_place(
        &self,
        left: &Self::PartialDecryption,
        right: &mut Self::PartialDecryption,
    ) -> Result<(), StatusError> {
        self.ahe.add_partial_decryptions_in_place(left, right)
    }
}

impl VaheBase for ShellVahe {
    type KeyGenProof = RlweRelationProof;
    type EncryptionProof = Vec<RlweRelationProof>;
    type PartialDecProof = Vec<RlweRelationProof>;
}

impl VerifiableKeyGen for ShellVahe {
    fn verifiable_key_gen(
        &self,
        prng: &mut Self::Rng,
    ) -> Result<(Self::SecretKeyShare, Self::PublicKeyShare, Self::KeyGenProof), StatusError> {
        let (sk_share, pk_share_b, pk_share_error, pk_wraparound) =
            self.ahe.key_gen_with_verification_metadata(prng)?;
        let rlwe_statement = RlweRelationProofStatement {
            n: self.ahe.num_coeffs(),
            context: self.ahe.rns_context(),
            a: &self.ahe.public_key_component_a()?,
            flip_a: true,
            c: &pk_share_b,
            q: self.q,
            bound_r: 1,
            bound_e: 16,
        };
        let rlwe_witness =
            RlweRelationProofWitness { r: &sk_share, e: &pk_share_error, v: &pk_wraparound };

        let (mut transcript, proof_seed) = self.get_transcript_and_proof_seed(b"key_gen")?;
        let prover = RlweRelationProver::new(proof_seed.as_bytes(), self.ahe.num_coeffs());
        let key_gen_proof = prover.prove(&rlwe_statement, &rlwe_witness, &mut transcript)?;
        Ok((sk_share, pk_share_b, key_gen_proof))
    }
}

impl KeyGenVerify for ShellVahe {
    fn verify_key_gen(
        &self,
        proof: &RlweRelationProof,
        key_share: &Self::PublicKeyShare,
    ) -> Status {
        let statement = RlweRelationProofStatement {
            n: self.ahe.num_coeffs(),
            context: self.ahe.rns_context(),
            a: &self.ahe.public_key_component_a()?,
            flip_a: true,
            c: key_share,
            q: self.q,
            bound_r: 1,
            bound_e: 16,
        };

        let (mut transcript, proof_seed) = self.get_transcript_and_proof_seed(b"key_gen")?;
        let verifier = RlweRelationVerifier::new(proof_seed.as_bytes(), self.ahe.num_coeffs());
        verifier.verify(&statement, &proof, &mut transcript)
    }
}

impl VerifiableEncrypt for ShellVahe {
    fn verifiable_encrypt(
        &self,
        plaintext: &Self::Plaintext,
        pk: &Self::PublicKey,
        nonce: &[u8],
        prng: &mut Self::Rng,
    ) -> Result<(Self::Ciphertext, Self::EncryptionProof), StatusError> {
        let (ciphertext, metadata, wraparounds) =
            self.ahe.encrypt_with_verification_metadata(plaintext, pk, prng)?;
        let num_polynomials = ciphertext.component_a.0.len();
        if metadata.secret_r.len() != num_polynomials
            || metadata.error_e.len() != num_polynomials
            || wraparounds.len() != num_polynomials
            || ciphertext.component_b.0.len() != num_polynomials
        {
            return Err(status::internal("Ciphertexts from encryption library are malformed."));
        }

        let (mut transcript, proof_seed) = self.get_transcript_and_proof_seed(b"encryption")?;
        transcript.append_message(b"nonce:", nonce);
        let prover = RlweRelationProver::new(proof_seed.as_bytes(), self.ahe.num_coeffs());
        let mut proof = vec![];
        for i in 0..num_polynomials {
            let rlwe_statement = RlweRelationProofStatement {
                n: self.ahe.num_coeffs(),
                context: self.ahe.rns_context(),
                a: &self.ahe.public_key_component_a()?,
                flip_a: false,
                c: &ciphertext.component_a.0[i],
                q: self.q,
                bound_r: 1,
                bound_e: 16,
            };
            let rlwe_witness = RlweRelationProofWitness {
                r: &metadata.secret_r[i],
                e: &metadata.error_e[i],
                v: &wraparounds[i],
            };
            proof.push(prover.prove(&rlwe_statement, &rlwe_witness, &mut transcript)?);
        }
        Ok((ciphertext, proof))
    }
}

impl EncryptVerify for ShellVahe {
    fn verify_encrypt(
        &self,
        proof: &Vec<RlweRelationProof>,
        ciphertext_component_a: &Self::PartialDecCiphertext,
        nonce: &[u8],
    ) -> Status {
        let num_polynomials = ciphertext_component_a.0.len();
        if proof.len() != num_polynomials {
            return Err(status::permission_denied(
                "Invalid proof. Proof length does not match number of polynomials in ciphertext.",
            ));
        }

        let (mut transcript, proof_seed) = self.get_transcript_and_proof_seed(b"encryption")?;
        transcript.append_message(b"nonce:", nonce);
        let verifier = RlweRelationVerifier::new(proof_seed.as_bytes(), self.ahe.num_coeffs());
        for i in 0..num_polynomials {
            let statement = RlweRelationProofStatement {
                n: self.ahe.num_coeffs(),
                context: self.ahe.rns_context(),
                a: &self.ahe.public_key_component_a()?,
                flip_a: false,
                c: &ciphertext_component_a.0[i],
                q: self.q,
                bound_r: 1,
                bound_e: 16,
            };
            verifier.verify(&statement, &proof[i], &mut transcript)?;
        }
        Ok(())
    }
}

impl VerifiablePartialDec for ShellVahe {
    fn verifiable_partial_dec(
        &self,
        ct_1: &Self::PartialDecCiphertext,
        sk: &Self::SecretKeyShare,
        prng: &mut Self::Rng,
    ) -> Result<(Self::PartialDecryption, Self::PartialDecProof), StatusError> {
        let (pd, metadata) = self.ahe.partial_decrypt_with_verification_metadata(ct_1, sk, prng)?;
        let errors = metadata.errors;
        let wraparounds = metadata.wraparounds;
        let num_polynomials = pd.len();
        if errors.len() != num_polynomials || wraparounds.len() != num_polynomials {
            return Err(status::internal(
                "Partial decryption/metadata from encryption library is malformed.",
            ));
        }

        let (mut transcript, proof_seed) =
            self.get_transcript_and_proof_seed(b"partial_decryption")?;
        let prover = RlweRelationProver::new(proof_seed.as_bytes(), self.ahe.num_coeffs());
        let mut proof = vec![];
        for i in 0..num_polynomials {
            let rlwe_statement = RlweRelationProofStatement {
                n: self.ahe.num_coeffs(),
                context: self.ahe.rns_context(),
                a: &ct_1.0[i],
                flip_a: false,
                c: &pd[i],
                q: self.q,
                bound_r: 1,
                bound_e: self.ahe.flood_bound()?,
            };
            let rlwe_witness =
                RlweRelationProofWitness { r: &sk, e: &errors[i], v: &wraparounds[i] };
            proof.push(prover.prove(&rlwe_statement, &rlwe_witness, &mut transcript)?);
        }
        Ok((pd, proof))
    }
}

impl PartialDecVerify for ShellVahe {
    fn verify_partial_dec(
        &self,
        proof: &Vec<RlweRelationProof>,
        ct_1: &Self::PartialDecCiphertext,
        pd: &Self::PartialDecryption,
    ) -> Status {
        let num_polynomials = pd.len();
        if proof.len() != num_polynomials {
            return Err(status::permission_denied(
                "Invalid proof. Proof length does not match number of polynomials in decryption.",
            ));
        }

        let (mut transcript, proof_seed) =
            self.get_transcript_and_proof_seed(b"partial_decryption")?;
        let verifier = RlweRelationVerifier::new(proof_seed.as_bytes(), self.ahe.num_coeffs());
        for i in 0..num_polynomials {
            let statement = RlweRelationProofStatement {
                n: self.ahe.num_coeffs(),
                context: self.ahe.rns_context(),
                a: &ct_1.0[i],
                flip_a: false,
                c: &pd[i],
                q: self.q,
                bound_r: 1,
                bound_e: self.ahe.flood_bound()?,
            };
            verifier.verify(&statement, &proof[i], &mut transcript)?;
        }
        Ok(())
    }
}

impl AheKeygen for ShellVahe {
    /// Sample a new secret key and public key share.
    fn key_gen(
        &self,
        prng: &mut Self::Rng,
    ) -> Result<(Self::SecretKeyShare, Self::PublicKeyShare, Self::KeyGenMetadata), StatusError>
    {
        self.ahe.key_gen(prng)
    }
}

impl PartialDec for ShellVahe {
    /// Partial decryption.
    fn partial_decrypt(
        &self,
        ct_1: &Self::PartialDecCiphertext,
        sk: &Self::SecretKeyShare,
        prng: &mut Self::Rng,
    ) -> Result<Self::PartialDecryption, StatusError> {
        self.ahe.partial_decrypt(ct_1, sk, prng)
    }
}

impl Recover for ShellVahe {
    /// Decrypt a ciphertext with aggregated partial decryptions. We expect the
    /// partial decryptions and ciphertexts to be already summed (e.g. to
    /// let the server accumulate as they wish).
    fn recover(
        &self,
        pd: &Self::PartialDecryption,
        ct_0: &Self::RecoverCiphertext,
        plaintex_len: Option<usize>,
    ) -> Result<Self::Plaintext, StatusError> {
        self.ahe.recover(pd, ct_0, plaintex_len)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use googletest::gtest;
    use prng_traits::SecurePrng;
    use shell_testing_parameters::make_ahe_config;
    use single_thread_hkdf::SingleThreadHkdfPrng;

    const CONTEXT_STRING: &[u8] = b"testing_context_string";
    const NONCE: &[u8] = b"0123456789ABCDEF";

    #[gtest]
    fn test_verifiable_key_gen() -> googletest::Result<()> {
        let vahe = ShellVahe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (_, pk_share, key_gen_proof) = vahe.verifiable_key_gen(&mut prng)?;
        vahe.verify_key_gen(&key_gen_proof, &pk_share)?;
        Ok(())
    }

    #[gtest]
    fn test_verifiable_key_gen_with_bad_proof() -> googletest::Result<()> {
        let vahe = ShellVahe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (_, pk_share, _) = vahe.verifiable_key_gen(&mut prng)?;
        let (_, _, proof) = vahe.verifiable_key_gen(&mut prng)?;

        let status = vahe.verify_key_gen(&proof, &pk_share);
        assert!(status.is_err());
        Ok(())
    }

    #[gtest]
    fn test_verifiable_encrypt() -> googletest::Result<()> {
        let vahe = ShellVahe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (_, pk_share, _) = vahe.verifiable_key_gen(&mut prng)?;
        let plaintext = vec![47i64; 8];
        let (ciphertext, proof) =
            vahe.verifiable_encrypt(&plaintext, &pk_share, NONCE, &mut prng)?;
        vahe.verify_encrypt(&proof, &ciphertext.component_a, NONCE)?;
        Ok(())
    }

    #[gtest]
    fn test_verifiable_encrypt_long_plaintext() -> googletest::Result<()> {
        let vahe = ShellVahe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (_, pk_share, _) = vahe.verifiable_key_gen(&mut prng)?;
        let plaintext = vec![47i64; 256];
        let (ciphertext, proof) =
            vahe.verifiable_encrypt(&plaintext, &pk_share, NONCE, &mut prng)?;
        vahe.verify_encrypt(&proof, &ciphertext.component_a, NONCE)?;
        Ok(())
    }

    #[gtest]
    fn test_verifiable_encrypt_with_bad_nonce() -> googletest::Result<()> {
        let vahe = ShellVahe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (_, pk_share, _) = vahe.verifiable_key_gen(&mut prng)?;
        let plaintext = vec![47i64; 8];
        let (ciphertext, proof) =
            vahe.verifiable_encrypt(&plaintext, &pk_share, NONCE, &mut prng)?;
        let bad_nonce = b"BADBADBADBAD";
        let status = vahe.verify_encrypt(&proof, &ciphertext.component_a, bad_nonce);
        // bad_nonce doesn't match NONCE, so the proof verification should fail.
        assert!(status.is_err());
        Ok(())
    }

    #[gtest]
    fn test_verifiable_encrypt_with_bad_length_proof() -> googletest::Result<()> {
        let vahe = ShellVahe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (_, pk_share, key_gen_proof) = vahe.verifiable_key_gen(&mut prng)?;
        let plaintext = vec![47i64; 8];
        let (ciphertext, mut proof) =
            vahe.verifiable_encrypt(&plaintext, &pk_share, NONCE, &mut prng)?;
        proof.push(key_gen_proof);
        let status = vahe.verify_encrypt(&proof, &ciphertext.component_a, NONCE);
        assert!(status.is_err());
        Ok(())
    }

    #[gtest]
    fn test_verifiable_encrypt_with_bad_proof() -> googletest::Result<()> {
        let vahe = ShellVahe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (_, pk_share, key_gen_proof) = vahe.verifiable_key_gen(&mut prng)?;
        let plaintext = vec![47i64; 8];
        let (ciphertext, mut proof) =
            vahe.verifiable_encrypt(&plaintext, &pk_share, NONCE, &mut prng)?;
        proof[0] = key_gen_proof;
        let status = vahe.verify_encrypt(&proof, &ciphertext.component_a, NONCE);
        assert!(status.is_err());
        Ok(())
    }

    #[gtest]
    fn test_verifiable_partial_dec() -> googletest::Result<()> {
        let vahe = ShellVahe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (sk_share, pk_share, _) = vahe.verifiable_key_gen(&mut prng)?;
        let plaintext = vec![47i64; 8];
        let (ciphertext, _) = vahe.verifiable_encrypt(&plaintext, &pk_share, NONCE, &mut prng)?;
        let (pd, proof) =
            vahe.verifiable_partial_dec(&ciphertext.component_a, &sk_share, &mut prng)?;
        vahe.verify_partial_dec(&proof, &ciphertext.component_a, &pd)?;
        Ok(())
    }

    #[gtest]
    fn test_verifiable_partial_dec_long_plaintext() -> googletest::Result<()> {
        let vahe = ShellVahe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (sk_share, pk_share, _) = vahe.verifiable_key_gen(&mut prng)?;
        let plaintext = vec![47i64; 256];
        let (ciphertext, _) = vahe.verifiable_encrypt(&plaintext, &pk_share, NONCE, &mut prng)?;
        let (pd, proof) =
            vahe.verifiable_partial_dec(&ciphertext.component_a, &sk_share, &mut prng)?;
        vahe.verify_partial_dec(&proof, &ciphertext.component_a, &pd)?;
        Ok(())
    }

    #[gtest]
    fn test_verifiable_partial_dec_with_bad_length_proof() -> googletest::Result<()> {
        let vahe = ShellVahe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (sk_share, pk_share, key_gen_proof) = vahe.verifiable_key_gen(&mut prng)?;
        let plaintext = vec![47i64; 8];
        let (ciphertext, _) = vahe.verifiable_encrypt(&plaintext, &pk_share, NONCE, &mut prng)?;
        let (pd, mut proof) =
            vahe.verifiable_partial_dec(&ciphertext.component_a, &sk_share, &mut prng)?;
        proof.push(key_gen_proof);
        let status = vahe.verify_partial_dec(&proof, &ciphertext.component_a, &pd);
        assert!(status.is_err());
        Ok(())
    }

    #[gtest]
    fn test_verifiable_partial_dec_with_bad_proof() -> googletest::Result<()> {
        let vahe = ShellVahe::new(make_ahe_config(), CONTEXT_STRING)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let (sk_share, pk_share, key_gen_proof) = vahe.verifiable_key_gen(&mut prng)?;
        let plaintext = vec![47i64; 8];
        let (ciphertext, _) = vahe.verifiable_encrypt(&plaintext, &pk_share, NONCE, &mut prng)?;
        let (pd, mut proof) =
            vahe.verifiable_partial_dec(&ciphertext.component_a, &sk_share, &mut prng)?;
        proof[0] = key_gen_proof;
        let status = vahe.verify_partial_dec(&proof, &ciphertext.component_a, &pd);
        assert!(status.is_err());
        Ok(())
    }
}
