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
use linear_innerproduct::{
    LinearInnerProductProof, LinearInnerProductProver, LinearInnerProductVerifier,
};
use rand::Rng;
use shell_types::{write_rns_polynomial_to_buffer_128, RnsContextRef, RnsPolynomial};
use zk_traits::{
    LinearInnerProductProofStatement, LinearInnerProductProofWitness, RlweRelationProofStatement,
    RlweRelationProofWitness, Transcript, ZeroKnowledgeProver, ZeroKnowledgeVerifier,
};

const MAX_RHOS: usize = 32;

// This function computes ((prodand_1*prodand_2) / q, (prodand_1*prodand_2) % q) over the integers
// i.e. without overflow in the multiplication.
fn multiply_and_divide(prodand_1: u128, prodand_2: u128, q: u128) -> (u128, u128) {
    assert!(q < (1u128 << 126));
    assert!(prodand_1 < q);
    assert!(prodand_2 < q);
    if q < 1u128 << 63 {
        let product = prodand_1 * prodand_2;
        let quotient = product / q;
        let remainder = product - (quotient * q);
        return (quotient, remainder);
    }
    let q = q as i128;
    let prodand_1 = prodand_1 as i128;
    let prodand_2 = prodand_2 as i128;
    let m = 1i128 << 63;
    // Break the prodands and q into higher and lower order bits.
    let d = (q >> 63) as i128;
    let e = (q & (m - 1)) as i128;
    let hi_1 = prodand_1 >> 63;
    let lo_1 = prodand_1 & (m - 1);
    let hi_2 = prodand_2 >> 63;
    let lo_2 = prodand_2 & (m - 1);
    // Get the coefficients of the product in powers of m.
    let a = (hi_1 * hi_2) as i128;
    let b = (hi_1 * lo_2 + lo_1 * hi_2) as i128;
    let c = (lo_1 * lo_2) as i128;
    // result is congruent to a*m*m + b*m + c mod q.
    let quot1 = a / d;
    let alpha = a - (quot1 * d);
    let beta = b - (quot1 * e);
    // result is congruent to alpha*m*m + beta*m + c mod q, and alpha unlike a is < 2^63.
    let gamma = alpha * m + beta;
    // result is congruent to gamma*m + c mod q.
    let quot2 = gamma / d;
    let delta = gamma - (quot2 * d);
    let epsilon = c - (quot2 * e);
    // result is congruent to delta*m + epsilon mod q and delta is < 2^63.
    let mut remainder = delta * m + epsilon;
    let quot3 = remainder / q;
    remainder = remainder - (quot3 * q);
    let mut quotient = quot1 * m + quot2 + quot3;

    // Fix the sign before conversion to u128 as integer division truncates towards zero.
    if remainder < 0 {
        remainder += q;
        quotient -= 1;
    }
    (quotient as u128, remainder as u128)
}

fn mod_mult(prodand_1: u128, prodand_2: u128, q: u128) -> u128 {
    // Implements (a*b)% q, without overflow in the multiplication.
    // a and b should be < q and q should be < 2^126.
    multiply_and_divide(prodand_1, prodand_2, q).1
}

// Implements (a*b)/q, without overflow in the multiplication.
// abs(a) and b should be < q and q should be < 2^126.
// These invariants are enforced by the multiply_and_divide function that this always calls.
// product = upper*q + lower and lower in [0,q).
fn multiply_and_divide_signed(prodand_1: i128, prodand_2: u128, q: u128) -> (i128, u128) {
    if prodand_1 >= 0 {
        let (upper, lower) = multiply_and_divide(prodand_1 as u128, prodand_2, q);
        return (upper as i128, lower);
    } else {
        let (upper, lower) = multiply_and_divide((-prodand_1) as u128, prodand_2, q as u128);
        if lower == 0 {
            return (-(upper as i128), 0);
        } else {
            return (-(upper as i128) - 1, q - lower);
        }
    }
}

fn ceil_log_2(x: u128) -> u32 {
    x.next_power_of_two().trailing_zeros()
}

fn unpack_rns_polynomial(
    context: &RnsContextRef,
    rns_polynomial: &RnsPolynomial,
    n: usize,
) -> Result<Vec<u128>, status::StatusError> {
    let mut buf = vec![0 as u64; 2 * n];
    write_rns_polynomial_to_buffer_128(context, rns_polynomial, &mut buf)?;
    let mut coeffs = vec![0 as u128; n];
    for i in 0..n {
        coeffs[i] = ((buf[2 * i + 1] as u128) << 64) + (buf[2 * i] as u128);
    }
    Ok(coeffs)
}

fn scalar_vec_from_u128_vec(v: &[u128], q: u128) -> Vec<Scalar> {
    let half_q = q / 2;
    let scalar_q = Scalar::from(q);
    let n = v.len();
    let mut result = vec![Scalar::from(0 as u64); n];
    for i in 0..n {
        if v[i] > half_q {
            result[i] = Scalar::from(v[i]) - scalar_q;
        } else {
            result[i] = Scalar::from(v[i]);
        }
    }
    result
}

// Converts a vector of u128 in [0,q) to a vector of i128 in [-q/2, q/2], by possibly subtracting q
// from each element.
pub fn i128_vec_from_u128_vec(v: &[u128], q: u128) -> Vec<i128> {
    let n = v.len();
    let signed_q = q as i128;
    let half_q = signed_q / 2;
    let mut result = vec![0 as i128; n];
    for i in 0..n {
        result[i] = v[i] as i128;
        if result[i] > half_q {
            result[i] -= signed_q;
        }
    }
    result
}

// Returns the number of points a degree n polynomial over Z_q needs to be sampled at in order to
// prove that it is equal to another polynomial with failure probability < 2^{-lambda}.
fn calculate_samples_required(n: usize, q: u128, lambda: u128) -> u128 {
    let bits_per_sample = ((q as f64) / (n as f64)).log2();
    let samples_required = ((lambda as f64) / bits_per_sample).ceil() as u128;
    samples_required
}

fn check_statement_can_be_handled(
    statement: &RlweRelationProofStatement,
    n: usize,
) -> Result<(), status::StatusError> {
    // Check that the n of the statement matches that used at construction.
    if n != statement.n {
        return Err(status::failed_precondition(
            "n in statement does not match n specified at construction.".to_string(),
        ));
    }
    let q = statement.q;
    let bound_e = statement.bound_e;
    let bound_r = statement.bound_r;

    // Check that the proof won't overflow.
    let log_q = ceil_log_2(q);
    let log_q_plus_bounds = ceil_log_2(q + bound_e + bound_r);
    let log_bound_w = log_q_plus_bounds + ceil_log_2(n as u128);
    let log_gap = ceil_log_2(2500 * (usize::isqrt(n) as u128 + 1));
    if log_bound_w + log_gap + log_q > 251 {
        return Err(status::failed_precondition(
            "q^2*n^(3/2)*2500 exceeds (or almost exceeds) 2^251 so the proof would overflow."
                .to_string(),
        ));
    }
    let samples_required = calculate_samples_required(n, q, 128) as usize;
    if samples_required > MAX_RHOS {
        return Err(status::failed_precondition(
            "Too many samples required to prove the relation. n is too close to q, if we can't use a larger q or smaller n. We could change the constant MAX_RHOS to be larger.".to_string(),
        ));
    }
    Ok(())
}

fn evaluate_public_polynomials(
    rho_vec: &[u128],
    a: &[u128],
    c: &[u128],
    n: usize,
    q: u128,
    samples_required: usize,
) -> (Vec<u128>, Vec<u128>, Vec<u128>) {
    let mut arho_vec = vec![0u128; MAX_RHOS];
    let mut crho_vec = vec![0u128; MAX_RHOS];
    let mut prho_vec = vec![0u128; MAX_RHOS];
    for j in 0..samples_required {
        let rho = rho_vec[j];
        // To avoid overflow we must reduce after every set number of additions.
        let gap_between_reductions = 1u128 << (128 - ceil_log_2(q));
        let final_i_mod_gap = (n as u128 - 1) % gap_between_reductions;
        let mut rho_pow = 1u128;
        for i in 0..n {
            arho_vec[j] += mod_mult(a[i], rho_pow, q);
            crho_vec[j] += mod_mult(c[i], rho_pow, q);
            if (i as u128) % gap_between_reductions == final_i_mod_gap {
                arho_vec[j] %= q;
                crho_vec[j] %= q;
            }
            rho_pow = mod_mult(rho_pow, rho, q);
        }
        prho_vec[j] = rho_pow + 1;
    }
    (arho_vec, crho_vec, prho_vec)
}

// Computes the public vector and expected result for the inner product required for the part of the
// RLWE relation proof that is modulo P (i.e. not the range proof part which is added separately).
fn create_public_vec(
    rho_vec: &[u128],
    arho_vec: &[u128],
    crho_vec: &[u128],
    prho_vec: &[u128],
    tau: Scalar,
    q: u128,
    n: usize,
    samples_required: usize,
) -> (Vec<Scalar>, Scalar) {
    let mut tau_pow = Scalar::from(1u128);
    let mut public_vec = vec![Scalar::from(0 as u64); 3 * n + MAX_RHOS + 3 * 128];
    for j in 0..samples_required {
        let rho = rho_vec[j];
        let mut rho_pow = 1u128;
        for i in 0..n {
            public_vec[i] += Scalar::from(mod_mult(arho_vec[j], rho_pow, q)) * tau_pow;
            public_vec[i + n] += Scalar::from(rho_pow) * tau_pow;
            public_vec[i + n + n] += Scalar::from(mod_mult(prho_vec[j], rho_pow, q)) * tau_pow;
            rho_pow = mod_mult(rho_pow, rho, q);
        }
        public_vec[3 * n + j] = -Scalar::from(q) * tau_pow;
        tau_pow = tau_pow * tau;
    }

    // Compute the contribution of the above to the result of the inner product relation
    let mut result = Scalar::from(0 as u64);
    tau_pow = Scalar::from(1u128);
    for j in 0..samples_required {
        result += Scalar::from(crho_vec[j]) * tau_pow;
        tau_pow = tau_pow * tau;
    }

    (public_vec, result)
}

// Updates the public vector and result of the inner product relation with the products required by
// the range proofs. Thus combining them into a single inner product statement.
fn update_public_vec_for_range_proof(
    public_vec: &mut Vec<Scalar>,
    result: &mut Scalar,
    R_r: &Vec<Scalar>,
    R_e: &Vec<Scalar>,
    R_vw: &Vec<Scalar>,
    z_r: &Vec<Scalar>,
    z_e: &Vec<Scalar>,
    z_vw: &Vec<Scalar>,
    psi_r: Scalar,
    psi_e: Scalar,
    psi_vw: Scalar,
    n: usize,
    range_comm_offset: usize,
    samples_required: usize,
    transcript: &mut impl Transcript,
) -> () {
    // These range proofs require proving inner products with the same private vector.
    // We can combine the range proof public vectors with the previous ones by adding them
    // multiplied by powers of a 'verifier chosen' challenge phi.
    let mut buf = [0u8; 64];
    transcript.challenge_bytes(b"phi", &mut buf);
    let phi = Scalar::from_bytes_mod_order_wide(&buf);
    let phi2 = phi * phi;
    let phi3 = phi2 * phi;
    for i in 0..n {
        public_vec[i] += R_r[i] * phi;
        public_vec[i + n] += R_e[i] * phi2;
    }
    for i in 0..(n + samples_required) {
        public_vec[i + n + n] += R_vw[i] * phi3;
    }

    // The range proofs equation also involves length 128 innerproducts involving the relevant
    // psi these are included in the last 3*128 entries of the inner product vectors.
    let mut phi_psi_r_pow = phi;
    let mut phi2_psi_e_pow = phi2;
    let mut phi3_psi_vw_pow = phi3;
    for i in 0..128 {
        public_vec[i + range_comm_offset] = phi_psi_r_pow;
        public_vec[i + range_comm_offset + 128] = phi2_psi_e_pow;
        public_vec[i + range_comm_offset + 256] = phi3_psi_vw_pow;
        // Add contributions of the range proofs to the overall inner product result.
        *result += z_r[i] * phi_psi_r_pow;
        *result += z_e[i] * phi2_psi_e_pow;
        *result += z_vw[i] * phi3_psi_vw_pow;
        phi_psi_r_pow *= psi_r;
        phi2_psi_e_pow *= psi_e;
        phi3_psi_vw_pow *= psi_vw;
    }
}

// Generates a binary challenge matrix of n * 128 bits from the given transcript.
pub fn generate_challenge_matrix(
    transcript: &mut impl Transcript,
    label: &'static [u8],
    n: usize,
) -> Vec<u128> {
    let num_bytes = n * 16;
    let mut buf = vec![0u8; num_bytes];
    transcript.challenge_bytes(label, &mut buf);

    let mut result = Vec::<u128>::with_capacity(n);
    for i in 0..n {
        let buf_i = &buf[i * 16..(i + 1) * 16];
        result.push(u128::from_le_bytes(buf_i.try_into().unwrap()));
    }
    result
}

// Multiplies a 128 by n matrix m and a length n vector v.
// m is a binary matrix each column of which has entries given by the bits of a single entry in the
// input vector m.
// Both the output and v are vectors of 128 bit signed integers.
pub fn multiply_by_challenge_matrix(
    v: &[i128],
    m: &[u128],
) -> Result<Vec<i128>, status::StatusError> {
    let n = v.len();
    if m.len() != n {
        return Err(status::failed_precondition("m and v have different lengths".to_string()));
    }

    let mut result = vec![0 as i128; 128];
    for i in 0..n {
        for j in 0..128 {
            if m[i] & (1u128 << j) != 0 {
                result[j] += v[i];
            }
        }
    }
    Ok(result)
}

// Linearly combines the 128 vector challenges of a challenge matrix into a single vector challenge
// uses powers of a scalar challenge psi
pub fn flatten_challenge_matrix(
    transcript: &mut impl Transcript,
    R1: Vec<u128>,
    R2: Vec<u128>,
    challenge_label: &'static [u8],
) -> Result<(Vec<Scalar>, Scalar), status::StatusError> {
    let n = R1.len();
    if n != R2.len() {
        return Err(status::failed_precondition("R1 and R2 have different lengths".to_string()));
    }

    let mut buf = [0u8; 64];
    transcript.challenge_bytes(challenge_label, &mut buf);
    let psi = Scalar::from_bytes_mod_order_wide(&buf);

    let mut R = vec![Scalar::from(0 as u64); n];
    let mut psi_powers = [Scalar::from(1 as u64); 128];
    for j in 1..128 {
        psi_powers[j] = psi_powers[j - 1] * psi;
    }
    for i in 0..n {
        for j in 0..128 {
            if R1[i] & (1u128 << j) != 0 {
                R[i] += psi_powers[j];
            }
            if R2[i] & (1u128 << j) != 0 {
                R[i] -= psi_powers[j];
            }
        }
    }

    Ok((R, psi))
}

// Check that loose_bound = bound*2500*sqrt(v.len()+1) fits within an i128.
fn check_loose_bound_will_not_overflow(bound: u128, n: usize) -> Result<(), status::StatusError> {
    let log_loose_bound =
        (bound as f64).log2() + (2500 as f64).log2() + ((u128::isqrt(n as u128) + 1) as f64).log2();
    // We need the log of the loose bound to be less than 127 to fit in an i128, we allow a 0.01 gap
    // to account for machine precision errors.
    if log_loose_bound > 126.99 {
        return Err(status::failed_precondition(
            "The bound requested is too large, the product would overflow".to_string(),
        ));
    }
    Ok(())
}

// Return the inner product that needs to be checked for the range proof, the commitment to y that
// the verifier will need to verify it and the blinding information required for the proof.
//
// The proof uses the approximate proofs of smallness from https://eprint.iacr.org/2021/1397.pdf.
//
// Let gamma = 2500*sqrt(v.len()).
// The prover first samples a mask y whose entries are uniform in [+- bound*gamma*(1+1/lambda)/2]
// and after commiting to it receives a ternary challenge matrix R from the verifier.
// It then computes vR and z = vR+y. If ||vR|| < bound*gamma/(2*lambda) and
// ||z|| < bound*gamma/lambda, then z can be revealed to the verifier without leaking
// anything about v. If those bounds don't hold then the prover must start again with a different y.
//
// If ||v|| > bound*gamma then the probability of ||z|| < bound*gamma/lambda is negligible.
// Thus the prover need only reveal z to the verifier along with a proof that z = vR+y.
// This function returns z and the required inner product statement to prove that z = vR+y.
fn generate_range_product(
    v: &[i128],
    bound: u128,
    prover: &LinearInnerProductProver,
    start: usize,
    transcript: &mut (impl Transcript + Clone),
    challenge_label: &'static [u8],
) -> Result<
    (Vec<Scalar>, RistrettoPoint, Vec<Scalar>, Scalar, Scalar, Vec<Scalar>),
    status::StatusError,
> {
    // Check that computing loose bound does not result in an overflow.
    check_loose_bound_will_not_overflow(bound, v.len())?;

    let mut rng = rand::thread_rng();
    let loose_bound = bound * 2500 * (u128::isqrt(v.len() as u128) + 1);
    let half_loose_bound = (loose_bound / 2) as i128;
    let max_y = half_loose_bound + (half_loose_bound + 127) / 128;
    let possible_y = max_y * 2 + 1;
    // Backup the transcript to restore it in case rejection sampling fails.
    // This way the verifier only needs to check the attempt that ultimately works.
    let transcript_backup = transcript.clone();
    let mut y: Vec<i128>;
    let mut scalar_y = vec![Scalar::from(0 as u64); 128];
    let mut delta_y: Scalar;
    let mut comm_y: RistrettoPoint;
    let mut R1: Vec<u128>;
    let mut R2: Vec<u128>;
    let mut z = vec![0 as i128; 128];
    let mut attempts = 0;
    loop {
        let mut done = true;
        attempts += 1;
        y = (0..128).map(|_| (rng.gen_range(0..possible_y) as i128)).collect();
        for i in 0..128 {
            scalar_y[i] = Scalar::from(y[i] as u128);
            y[i] -= max_y;
            scalar_y[i] -= Scalar::from(max_y as u128);
        }
        delta_y = Scalar::random(&mut rng);
        comm_y = prover.commit_partial(&scalar_y, delta_y, start, start + 128)?;
        transcript.append_message(b"comm_y", &comm_y.compress().to_bytes());
        // We generate two challenge matrices with uniform 1/0 entries, by adding one and
        // subtracting the other we get a challenge matrix with the correct distribution.
        R1 = generate_challenge_matrix(transcript, challenge_label, v.len());
        R2 = generate_challenge_matrix(transcript, challenge_label, v.len());
        let u1 = multiply_by_challenge_matrix(v, &R1)?;
        let u2 = multiply_by_challenge_matrix(v, &R2)?;
        for i in 0..128 {
            let u = u1[i] - u2[i];
            if u.abs() > half_loose_bound / 128 {
                done = false;
                break;
            }
            z[i] = u + y[i];
            if z[i].abs() > half_loose_bound {
                done = false;
                break;
            }
        }
        if done {
            break;
        }
        if attempts > 1000 {
            for x in v {
                if x.abs() > bound as i128 {
                    return Err(status::failed_precondition(
                        "Provided vector doesn't satisfy the given bound.".to_string(),
                    ));
                }
            }
            return Err(status::internal(
                "Rejection sampling failed too many times. This should never happen by chance and is likely a bug.".to_string(),
            ));
        }
        // Restore the backup transcript to try again.
        *transcript = transcript_backup.clone();
    }

    // Flatten the matrix R for the inner product relation, combining the 128 rows.
    let (R, psi) = flatten_challenge_matrix(transcript, R1, R2, b"matrix flattening")?;

    // Adding half_loose_bound makes sure the conversion to u128 is valid.
    let scalar_z = z
        .into_iter()
        .map(|z| {
            Scalar::from((z + half_loose_bound) as u128) - Scalar::from(half_loose_bound as u128)
        })
        .collect();

    Ok((R, comm_y, scalar_y, delta_y, psi, scalar_z))
}

fn generate_range_product_for_verification_and_verify_z_bound(
    n: usize,
    bound: u128,
    comm_y: RistrettoPoint,
    z: &Vec<Scalar>,
    transcript: &mut impl Transcript,
    challenge_label: &'static [u8],
) -> Result<(Vec<Scalar>, Scalar), status::StatusError> {
    // Check that computing loose bound does not result in an overflow.
    check_loose_bound_will_not_overflow(bound, n)?;

    // Check that the z vector has all entries less than or equal to half_loose_bound.
    let loose_bound = bound * 2500 * (u128::isqrt(n as u128) + 1);
    let half_loose_bound = Scalar::from(loose_bound / 2);
    // Shift so requirement becomes they are between 0 and loose bound.
    let shifted_z: Vec<Scalar> = z.into_iter().map(|x| x + half_loose_bound).collect();
    for i in 0..128 {
        // Convert Scalar to integer as bytes (guaranteed to be 32 little endian bytes).
        let z_bytes = shifted_z[i].as_bytes();
        // Check that the integer is less than the loose bound.
        if z_bytes[16..32] != [0x00; 16]
            || u128::from_le_bytes(z_bytes[0..16].try_into().unwrap()) > loose_bound
        {
            return Err(status::permission_denied(
                "Provided z doesn't satisfy the required uniform bound.".to_string(),
            ));
        }
    }

    transcript.append_message(b"comm_y", &comm_y.compress().to_bytes());
    // We generate two challenge matrices with uniform 1/0 entries, by adding one and
    // subtracting the other we get a challenge matrix with the correct distribution.
    let R1 = generate_challenge_matrix(transcript, challenge_label, n);
    let R2 = generate_challenge_matrix(transcript, challenge_label, n);
    // Flatten the matrix R for the inner product relation, combining the 128 rows.
    flatten_challenge_matrix(transcript, R1, R2, b"matrix flattening")
}

// To prove that there exists small degree n polynomials r and e such that
// -ar+e = c in the ring Z_q[X]/(X^n+1)
// it suffices to prove that there exists small degree n polynomials r,e and v such that
// -ar+e+vp = c mod q where p = X^n + 1.
//
// We will prove this by first committing to r,e and v and selecting a random challenge rho in Z_q and
// checking that -a(rho) *r(rho) + e(rho) + v(rho)*p(rho) + q*wrho = c mod P
// for some integer wrho, with P the modulus of the ristretto group.
// And then proving that r,e,v and wrho are small so there is no wrap around mod P.
#[derive(Clone)]
pub struct RlweRelationProof {
    comm_rev: CompressedRistretto,  // commitments to polynomials
    comm_wrho: CompressedRistretto, // commitments to the integer wrho
    // commitments to the blinding factors for the range proofs.
    comm_y_r: CompressedRistretto,
    comm_y_e: CompressedRistretto,
    comm_y_vw: CompressedRistretto,
    // Final message of the range proofs.
    z_r: Vec<Scalar>,
    z_e: Vec<Scalar>,
    z_vw: Vec<Scalar>,
    // Proof of the polynomial relation mod P as an inner product proof.
    lip_proof: LinearInnerProductProof,
}

pub struct RlweRelationProver {
    prover: LinearInnerProductProver,
    n: usize,
}

impl RlweRelationProver {
    // The seed is public information and must match the seed used to create the verifier that will
    // verify the proof. The size n is the degree if the RLWE polynomials.
    pub fn new(seed: &[u8], n: usize) -> Self {
        Self { prover: LinearInnerProductProver::new(seed, 3 * (n + 128) + MAX_RHOS), n: n }
    }
}

impl<'a> ZeroKnowledgeProver<RlweRelationProofStatement<'a>, RlweRelationProofWitness<'a>>
    for RlweRelationProver
{
    type Proof = RlweRelationProof;

    // See comment above RlweRelationProof for more details.
    fn prove(
        &self,
        statement: &RlweRelationProofStatement,
        witness: &RlweRelationProofWitness,
        transcript: &mut (impl Transcript + Clone),
    ) -> Result<Self::Proof, status::StatusError> {
        check_statement_can_be_handled(statement, self.n)?;

        let n = self.n;
        let q = statement.q;
        let bound_e = statement.bound_e;
        let bound_r = statement.bound_r;


        let context = &statement.context;
        // Unpack the polynomials.
        let mut a = unpack_rns_polynomial(context, &statement.a, n)?;
        let c = unpack_rns_polynomial(context, &statement.c, n)?;
        let r = unpack_rns_polynomial(context, &witness.r, n)?;
        let e = unpack_rns_polynomial(context, &witness.e, n)?;
        let v = unpack_rns_polynomial(context, &witness.v, n)?;
        if statement.flip_a {
            for i in 0..n {
                if a[i] != 0 {
                    a[i] = q - a[i];
                }
            }
        }

        let mut rng = rand::thread_rng();

        let range_comm_offset = 3 * n + MAX_RHOS;

        // Add commit messages for r, e, and v to transcript
        let comm_rev: RistrettoPoint;
        let delta_rev: Scalar;
        let scalar_r = scalar_vec_from_u128_vec(&r, q);
        let scalar_e = scalar_vec_from_u128_vec(&e, q);
        let scalar_v = scalar_vec_from_u128_vec(&v, q);
        {
            let delta_r = Scalar::random(&mut rng);
            let delta_e = Scalar::random(&mut rng);
            let delta_v = Scalar::random(&mut rng);
            let comm_r = self.prover.commit_partial(&scalar_r, delta_r, 0, n)?;
            let comm_e = self.prover.commit_partial(&scalar_e, delta_e, n, 2 * n)?;
            let comm_v = self.prover.commit_partial(&scalar_v, delta_v, 2 * n, 3 * n)?;
            comm_rev = comm_r + comm_e + comm_v;
            delta_rev = delta_r + delta_e + delta_v;
            transcript.append_message(b"witness commitment", &comm_rev.compress().to_bytes());
        }

        // Select points rho at which to test that ar+e+vp = c mod q, where p(X) = X^n + 1.
        let samples_required = calculate_samples_required(n, q, 128) as usize;
        let mut rho_vec = vec![0u128; MAX_RHOS];
        let mut buf = [0u8; 16];
        for j in 0..samples_required {
            transcript.challenge_bytes(b"rho", &mut buf);
            rho_vec[j] = u128::from_le_bytes(buf) % q;
        }

        let (arho_vec, crho_vec, prho_vec) =
            evaluate_public_polynomials(&rho_vec, &a, &c, n, q, samples_required);

        // Convert r, e, and v to signed vectors mapping values > half_q to (-half_q, -1] modulo q.
        let signed_r = i128_vec_from_u128_vec(&r, q);
        let signed_e = i128_vec_from_u128_vec(&e, q);
        let signed_v = i128_vec_from_u128_vec(&v, q);

        // We must compute the number of wrap arounds that the relation arho*rrho + erho + vrho*prho
        // does. We store this in wrho_vec.
        let mut wrho_vec = vec![0i128; MAX_RHOS];
        for j in 0..samples_required {
            let rho = rho_vec[j];
            // Evaluate the private polynomials at rho.
            // Unlike the other polynomials we are evaluating (a*r) and (v*p) can exceed 2^128 (for large q) so we
            // split the polynomials in this section into upper and lower parts to avoid overflow.
            // We use base q as this will  be convenient in the following calculations and we don't
            // mind the smaller part exceeding q so long as it doesn't overflow the 128bit type.
            //
            // We make the upper part signed so we can represent negative numbers.
            let mut arrho_upper = 0i128;
            let mut arrho_lower = 0u128;
            let mut vprho_upper = 0i128;
            let mut vprho_lower = 0u128;
            let mut erho_upper = 0i128;
            let mut erho_lower = 0u128;
            let mut rho_pow = 1u128;
            for i in 0..n {
                let (upper, lower) =
                    multiply_and_divide_signed(signed_r[i], mod_mult(rho_pow, arho_vec[j], q), q);
                arrho_upper += upper;
                arrho_lower += lower;
                let (upper, lower) = multiply_and_divide_signed(signed_e[i], rho_pow, q);
                erho_upper += upper;
                erho_lower += lower;
                let (upper, lower) =
                    multiply_and_divide_signed(signed_v[i], mod_mult(rho_pow, prho_vec[j], q), q);
                vprho_upper += upper;
                vprho_lower += lower;
                rho_pow = mod_mult(rho_pow, rho, q);
            }

            // Compute wrho = (arho*rrho + erho + vrho*prho - crho)/q i.e. the number of times
            // arho*rrho + erho + vrho*prho wraps around the modulus q. We can then express the
            // relation arho*rrho + erho + vrho*prho = crho mod q, as arho*rrho + erho + vrho*prho
            // = crho + q*wrho over the integers.
            if (arrho_lower + erho_lower + vprho_lower) % q != crho_vec[j] {
                return Err(status::failed_precondition(
                    "The provided witness does not satisfy the relation.".to_string(),
                ));
            }
            wrho_vec[j] = arrho_upper
                + vprho_upper
                + erho_upper
                + ((arrho_lower + erho_lower + vprho_lower - crho_vec[j]) / q) as i128;
        }

        let delta_w = Scalar::random(&mut rng);
        let bound_w = q * (n as u128);
        let mut scalar_wrho_vec = vec![Scalar::from(0 as u64); MAX_RHOS];
        for j in 0..samples_required {
            scalar_wrho_vec[j] =
                Scalar::from((wrho_vec[j] + (bound_w as i128)) as u128) - Scalar::from(bound_w);
        }
        let comm_wrho =
            self.prover.commit_partial(&scalar_wrho_vec, delta_w, 3 * n, 3 * n + MAX_RHOS)?;
        transcript.append_message(b"w(rho) commitment", &comm_wrho.compress().to_bytes());

        // We will use powers of tau to linearly combine the required polynomial evaluations into
        // one vector.
        let mut buf = [0u8; 16];
        transcript.challenge_bytes(b"tau", &mut buf);
        let tau = Scalar::from(u128::from_le_bytes(buf));

        // We wish to check that a(rho)*r(rho) + e(rho) + v(rho)*p(rho) - q*wrho = c(rho)  for some
        // integer wrho. We can write
        // r(rho) = (vector of coefficients of r) inner product (vector of powers of rho)
        // where the powers of rho are public but the coefficients are private.
        // a(rho) is publically known so we can write
        // a(rho)*r(rho) =
        // (vector of coefficients of r) inner product (a(rho) * (vector of powers of rho))
        // where the first inner prodand is private and the second is public.
        // We can do similarly for v(rho)*p(rho) and e(rho) is just a private vector times the
        // powers of rho.
        // The concatenation of these public vectors we now write into the public_vec for the inner
        // product proof. Followed by the public half of -q*wrho i.e. just the scalar -q (with the relevant tau powers).
        // The expected result of the inner product is also computed here.
        let (mut public_vec, mut result) = create_public_vec(
            &rho_vec,
            &arho_vec,
            &crho_vec,
            &prho_vec,
            tau,
            q,
            n,
            samples_required,
        );

        // Combine v and w into one vector which we can bound with a single range proof.
        let mut signed_vw = signed_v.clone();
        signed_vw.extend(&wrho_vec);

        // Get inner products to prove for range proofs. We then need to check
        // <R_r,r> + <psi_r^128,y_r> = <psi_r^128,z_r> mod P etc.
        // This is explained in more detail in the comment above generate_range_product.
        let (R_r, comm_y_r, y_r, delta_y_r, psi_r, z_r) = generate_range_product(
            &signed_r,
            bound_r,
            &self.prover,
            range_comm_offset,
            transcript,
            b"range matrix r",
        )?;
        let (R_e, comm_y_e, y_e, delta_y_e, psi_e, z_e) = generate_range_product(
            &signed_e,
            bound_e,
            &self.prover,
            range_comm_offset + 128,
            transcript,
            b"range matrix e",
        )?;
        let (R_vw, comm_y_vw, y_vw, delta_y_vw, psi_vw, z_vw) = generate_range_product(
            &signed_vw,
            q * (n as u128),
            &self.prover,
            range_comm_offset + 256,
            transcript,
            b"range matrix v || w",
        )?;

        // We can combine the product proofs required for the range proofs into the existing
        // inner product to be proven.
        update_public_vec_for_range_proof(
            &mut public_vec,
            &mut result,
            &R_r,
            &R_e,
            &R_vw,
            &z_r,
            &z_e,
            &z_vw,
            psi_r,
            psi_e,
            psi_vw,
            n,
            range_comm_offset,
            samples_required,
            transcript,
        );

        // Combine Private vector parts together
        let mut private_vec = vec![Scalar::from(0 as u64); range_comm_offset + 384];
        for i in 0..n {
            private_vec[i] = scalar_r[i];
            private_vec[i + n] = scalar_e[i];
            private_vec[i + n + n] = scalar_v[i];
        }
        for i in 0..MAX_RHOS {
            private_vec[i + n + n + n] = scalar_wrho_vec[i];
        }
        for i in 0..128 {
            private_vec[i + range_comm_offset] = y_r[i];
            private_vec[i + range_comm_offset + 128] = y_e[i];
            private_vec[i + range_comm_offset + 256] = y_vw[i];
        }

        let private_vec_comm = comm_rev + comm_wrho + comm_y_r + comm_y_e + comm_y_vw;
        let blinding_factor = delta_rev + delta_w + delta_y_r + delta_y_e + delta_y_vw;

        // Set up linear product statement and prove it
        let lip_statement = LinearInnerProductProofStatement {
            n: range_comm_offset + 3 * 128,
            b: public_vec,
            c: result,
            comm_a: private_vec_comm.compress(),
        };
        let lip_witness =
            LinearInnerProductProofWitness { a: private_vec, delta_a: blinding_factor };
        let lip_proof = self.prover.prove(&lip_statement, &lip_witness, transcript)?;

        // Return the proof
        Ok(RlweRelationProof {
            comm_rev: comm_rev.compress(),
            comm_wrho: comm_wrho.compress(),
            comm_y_r: comm_y_r.compress(),
            comm_y_e: comm_y_e.compress(),
            comm_y_vw: comm_y_vw.compress(),
            z_r: z_r,
            z_e: z_e,
            z_vw: z_vw,
            lip_proof: lip_proof,
        })
    }
}

pub struct RlweRelationVerifier {
    lip_verifier: LinearInnerProductVerifier,
    n: usize,
}

impl RlweRelationVerifier {
    // The seed is public information and must match the seed used to create the prover which
    // created the proof that is to be verified. The size n is the degree if the RLWE polynomials.
    pub fn new(seed: &[u8], n: usize) -> Self {
        Self { lip_verifier: LinearInnerProductVerifier::new(seed, 3 * (n + 128) + MAX_RHOS), n: n }
    }
}

impl<'a> ZeroKnowledgeVerifier<RlweRelationProofStatement<'a>, RlweRelationProof>
    for RlweRelationVerifier
{
    fn verify(
        &self,
        statement: &RlweRelationProofStatement<'a>,
        proof: &RlweRelationProof,
        transcript: &mut impl Transcript,
    ) -> status::Status {
        check_statement_can_be_handled(statement, self.n)?;

        let n = self.n;
        let q = statement.q;
        let bound_e = statement.bound_e;
        let bound_r = statement.bound_r;

        let context = &statement.context;
        // Unpack polynomials.
        let mut a = unpack_rns_polynomial(context, &statement.a, n)?;
        let c = unpack_rns_polynomial(context, &statement.c, n)?;
        if statement.flip_a {
            for i in 0..n {
                if a[i] != 0 {
                    a[i] = q - a[i];
                }
            }
        }

        let decompression_error = status::permission_denied(
            "Proof verification failed, failed to decompress a commitment.",
        );
        let comm_rev = proof.comm_rev.decompress().ok_or(decompression_error.clone())?;
        let comm_wrho = proof.comm_wrho.decompress().ok_or(decompression_error.clone())?;
        let comm_y_r = proof.comm_y_r.decompress().ok_or(decompression_error.clone())?;
        let comm_y_e = proof.comm_y_e.decompress().ok_or(decompression_error.clone())?;
        let comm_y_vw = proof.comm_y_vw.decompress().ok_or(decompression_error.clone())?;
        if proof.z_r.len() != 128 || proof.z_e.len() != 128 || proof.z_vw.len() != 128 {
            return Err(status::permission_denied(
                "Proof verification failed, z_r, z_e, z_vw are not of correct length (128).",
            ));
        }

        let range_comm_offset = 3 * n + MAX_RHOS;

        transcript.append_message(b"witness commitment", &proof.comm_rev.to_bytes());

        // Select points rho at which to test that ar+e+vp = c mod q, where p(X) = X^n + 1.
        let samples_required = calculate_samples_required(n, q, 128) as usize;
        let mut rho_vec = vec![0u128; MAX_RHOS];
        let mut buf = [0u8; 16];
        for j in 0..samples_required {
            transcript.challenge_bytes(b"rho", &mut buf);
            rho_vec[j] = u128::from_le_bytes(buf) % q;
        }

        transcript.append_message(b"w(rho) commitment", &proof.comm_wrho.to_bytes());

        let (arho_vec, crho_vec, prho_vec) =
            evaluate_public_polynomials(&rho_vec, &a, &c, n, q, samples_required);

        // We will use powers of tau to linearly combine the require polynomial evaluations into one vector.
        let mut buf = [0u8; 16];
        transcript.challenge_bytes(b"tau", &mut buf);
        let tau = Scalar::from(u128::from_le_bytes(buf));

        let (mut public_vec, mut result) = create_public_vec(
            &rho_vec,
            &arho_vec,
            &crho_vec,
            &prho_vec,
            tau,
            q,
            n,
            samples_required,
        );

        let (R_r, psi_r) = generate_range_product_for_verification_and_verify_z_bound(
            n,
            bound_r,
            comm_y_r,
            &proof.z_r,
            transcript,
            b"range matrix r",
        )?;
        let (R_e, psi_e) = generate_range_product_for_verification_and_verify_z_bound(
            n,
            bound_e,
            comm_y_e,
            &proof.z_e,
            transcript,
            b"range matrix e",
        )?;
        let (R_vw, psi_vw) = generate_range_product_for_verification_and_verify_z_bound(
            n + MAX_RHOS,
            q * (n as u128),
            comm_y_vw,
            &proof.z_vw,
            transcript,
            b"range matrix v || w",
        )?;

        // We can combine the product proofs required for the range proofs into the existing
        // inner product to be proven.
        update_public_vec_for_range_proof(
            &mut public_vec,
            &mut result,
            &R_r,
            &R_e,
            &R_vw,
            &proof.z_r,
            &proof.z_e,
            &proof.z_vw,
            psi_r,
            psi_e,
            psi_vw,
            n,
            range_comm_offset,
            samples_required,
            transcript,
        );

        let private_vec_comm = comm_rev + comm_wrho + comm_y_r + comm_y_e + comm_y_vw;

        // Set up linear product statement and prove it
        let lip_statement = LinearInnerProductProofStatement {
            n: range_comm_offset + 3 * 128,
            b: public_vec,
            c: result,
            comm_a: private_vec_comm.compress(),
        };
        self.lip_verifier.verify(&lip_statement, &proof.lip_proof, transcript)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahe::{create_public_parameters, get_moduli, get_rns_context_ref};
    use googletest::verify_eq;
    use merlin::Transcript as MerlinTranscript;
    use sha3::Sha3_512;
    use shell_types::read_small_rns_polynomial_from_buffer;
    use single_thread_hkdf::generate_seed;

    #[test]
    fn test_multiply_and_divide_small() -> googletest::Result<()> {
        let q = 1000_000_009;
        let a = 1000_000_001;
        let b = 1000_000_007;
        let (quot, rem) = multiply_and_divide(a, b, q);
        verify_eq!(rem, 16)?;
        verify_eq!(quot, 999_999_999)?;
        Ok(())
    }

    #[test]
    fn test_multiply_and_divide_large() -> googletest::Result<()> {
        let q = 161803398874989484820458683;
        let a = 31415926535897932384626433;
        let b = 27182818284590452353602874;
        let (quot, rem) = multiply_and_divide(a, b, q);
        verify_eq!(rem, 10914181099362234268679427)?;
        verify_eq!(quot, 5277846004502927374273205)?;
        Ok(())
    }

    #[test]
    fn test_multiply_and_divide_signed() -> googletest::Result<()> {
        let q1 = 5038389;
        let q2 = 32114114030296089647;
        let q = q1 * q2;
        let a = 31415926535897932384626433;
        let b = 27182818284590452353602874;
        let (quot, rem) = multiply_and_divide_signed(a, b, q);
        verify_eq!(rem, 10914181099362234268679427)?;
        verify_eq!(quot, 5277846004502927374273205)?;
        let (quot, rem) = multiply_and_divide_signed(-a, b, q);
        verify_eq!(rem, 150889217775627250551779256)?;
        verify_eq!(quot, -5277846004502927374273206)?;
        let (quot, rem) = multiply_and_divide_signed(-(12345 * q1 as i128), q2, q);
        verify_eq!(rem, 0)?;
        verify_eq!(quot, -12345)?;
        Ok(())
    }

    #[test]
    fn test_unpack_rns_polynomial() -> googletest::Result<()> {
        // We create an ahe_parameters instance to get the context reference and moduli objects.
        let qvec = vec![1000_000_009];
        let seed_wrapper = generate_seed()?;
        let ahe_parameters = create_public_parameters(2, 54001, &qvec, 1, 1.0, 1.0, &seed_wrapper)?;
        let context = get_rns_context_ref(&ahe_parameters);
        let moduli = get_moduli(&ahe_parameters);
        let a_buffer = [1, 2, 3, 4];
        let expected_result = [1 as u128, 2 as u128, 3 as u128, 4 as u128];
        let n = 4;
        let a = read_small_rns_polynomial_from_buffer(&a_buffer, n as u64, &moduli)?;
        let a_unpacked = unpack_rns_polynomial(&context, &a, n)?;
        assert!(a_unpacked.eq(&expected_result));
        Ok(())
    }

    #[test]
    fn test_i128_vec_from_u128_vec() -> googletest::Result<()> {
        let q = 1000_000_009;
        let unsigned_vector = [1, 1000_000_007, 3, 1000_000_005];
        let expected_signed_vector = [1, -2, 3, -4];
        let resultant_signed_vector = i128_vec_from_u128_vec(&unsigned_vector, q);
        assert!(resultant_signed_vector.eq(&expected_signed_vector));
        Ok(())
    }

    #[test]
    fn test_calculate_samples_required() -> googletest::Result<()> {
        let q = 1000_000_009;
        let samples_required = calculate_samples_required(1000, q, 128) as usize;
        verify_eq!(samples_required, 7)?;
        let q = 1000_000_000_000_000_000_000_009;
        let samples_required = calculate_samples_required(4096, q, 128) as usize;
        verify_eq!(samples_required, 2)?;
        Ok(())
    }

    #[test]
    fn test_check_statement_can_be_handled_verifies_n() -> googletest::Result<()> {
        // We create an ahe_parameters instance to get the context reference and moduli objects.
        let qvec = vec![288230376151760897];
        let seed_wrapper = generate_seed()?;
        let ahe_parameters =
            create_public_parameters(12, 54001, &qvec, 1, 1.0, 1.0, &seed_wrapper)?;
        let context = get_rns_context_ref(&ahe_parameters);
        let n = 4096;
        let q = 288230376151760897;
        let moduli = get_moduli(&ahe_parameters);

        let poly_buffer = [1; 4096];

        let a = read_small_rns_polynomial_from_buffer(&poly_buffer, n as u64, &moduli)?;
        let c = read_small_rns_polynomial_from_buffer(&poly_buffer, n as u64, &moduli)?;

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
        check_statement_can_be_handled(&statement, n)?;
        assert!(check_statement_can_be_handled(&statement, 2048)
            .err()
            .expect("The n don't match so there should have been an error returned here.")
            .message()
            .contains("not match"));
        Ok(())
    }

    #[test]
    fn test_check_statement_can_be_handled_checks_for_overflow() -> googletest::Result<()> {
        // We create an ahe_parameters instance to get the context reference and moduli objects.
        let q1 = 288230376152137729;
        let q2 = 288230376151760897; // First two 58 bit primes congruent to 1 mod 8192
        let qvec = vec![q1, q2];
        let seed_wrapper = generate_seed()?;
        let ahe_parameters =
            create_public_parameters(12, 54001, &qvec, 1, 1.0, 1.0, &seed_wrapper)?;
        let context = get_rns_context_ref(&ahe_parameters);
        let n = 4096;
        let q = (q1 as u128) * (q2 as u128);
        let moduli = get_moduli(&ahe_parameters);

        let poly_buffer = [1; 4096];

        let a = read_small_rns_polynomial_from_buffer(&poly_buffer, n as u64, &moduli)?;
        let c = read_small_rns_polynomial_from_buffer(&poly_buffer, n as u64, &moduli)?;

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
        assert!(check_statement_can_be_handled(&statement, 4096)
            .err()
            .expect("There should have been an overflow error returned here.")
            .message()
            .contains("overflow"));
        Ok(())
    }

    #[test]
    fn test_check_statement_can_be_handled_with_valid_statement() -> googletest::Result<()> {
        // We create an ahe_parameters instance to get the context reference and moduli objects.
        let q1 = 18014398509506561;
        let q2 = 18014398509998081; // First two 54 bit primes congruent to 1 mod 8192
        let qvec = vec![q1, q2];
        let seed_wrapper = generate_seed()?;
        let ahe_parameters =
            create_public_parameters(12, 54001, &qvec, 1, 1.0, 1.0, &seed_wrapper)?;
        let context = get_rns_context_ref(&ahe_parameters);
        let n = 4096;
        let q = (q1 as u128) * (q2 as u128);
        let moduli = get_moduli(&ahe_parameters);

        let poly_buffer = [1; 4096];

        let a = read_small_rns_polynomial_from_buffer(&poly_buffer, n as u64, &moduli)?;
        let c = read_small_rns_polynomial_from_buffer(&poly_buffer, n as u64, &moduli)?;

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
        Ok(check_statement_can_be_handled(&statement, 4096)?)
    }

    #[test]
    fn test_check_statement_can_be_handled_checks_for_max_rhos() -> googletest::Result<()> {
        // We create an ahe_parameters instance to get the context reference and moduli objects.
        let qvec = vec![40961];
        let seed_wrapper = generate_seed()?;
        let ahe_parameters =
            create_public_parameters(12, 14001, &qvec, 1, 1.0, 1.0, &seed_wrapper)?;
        let context = get_rns_context_ref(&ahe_parameters);
        let n = 4096;
        let q = 40961;
        let moduli = get_moduli(&ahe_parameters);

        let poly_buffer = [1; 4096];

        let a = read_small_rns_polynomial_from_buffer(&poly_buffer, n as u64, &moduli)?;
        let c = read_small_rns_polynomial_from_buffer(&poly_buffer, n as u64, &moduli)?;

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

        assert!(check_statement_can_be_handled(&statement, 4096).err()
        .expect("These parameters required too many MAX_RHOS so this should have returned an error.")
        .message().contains("samples"));
        Ok(())
    }

    #[test]
    fn test_multiply_by_challenge_matrix_basic_case() -> googletest::Result<()> {
        let v = &[10i128, 20i128];
        let m = &[(1u128 << 0) | (1u128 << 2), (1u128 << 1) | (1u128 << 2)];

        let mut expected_result = vec![0i128; 128];
        expected_result[0] = 10;
        expected_result[1] = 20;
        expected_result[2] = 30;

        assert_eq!(multiply_by_challenge_matrix(v, m).unwrap(), expected_result);
        Ok(())
    }

    #[test]
    fn test_generate_range_product() -> googletest::Result<()> {
        let bound = 10;
        let v = [1, -2, 3, -4];
        let prover = LinearInnerProductProver::new(b"42", 132);
        let mut transcript = MerlinTranscript::new(b"42");
        let (R, comm_y, y, delta_y, psi, z) =
            generate_range_product(&v, bound, &prover, 4, &mut transcript, b"test vector")?;
        let mut private_vec = [Scalar::from(0u128); 132];
        for i in 0..4 {
            private_vec[i] = Scalar::from((v[i] + (bound as i128)) as u128) - Scalar::from(bound);
        }
        for i in 4..132 {
            private_vec[i] = y[i - 4];
        }
        let mut public_vec = [Scalar::from(0u128); 132];
        for i in 0..4 {
            public_vec[i] = R[i];
        }
        let mut psi_pow = Scalar::from(1u128);
        let mut result = Scalar::from(0u128);
        for i in 4..132 {
            public_vec[i] = psi_pow;
            result += z[i - 4] * psi_pow;
            psi_pow *= psi;
        }
        let mut expected_result = Scalar::from(0u128);
        for j in 0..132 {
            expected_result += public_vec[j] * private_vec[j];
        }
        assert_eq!(result, expected_result);
        let expected_comm_y = prover.commit_partial(&y, delta_y, 4, 132)?;
        assert_eq!(comm_y, expected_comm_y);
        Ok(())
    }

    #[test]
    fn test_valid_rlwe_relation_proof() -> googletest::Result<()> {
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

        let prover = RlweRelationProver::new(b"42", statement.n);
        let mut transcript = MerlinTranscript::new(transcript_initializer);
        let proof = prover.prove(&statement, &witness, &mut transcript)?;

        let verifier = RlweRelationVerifier::new(b"42", statement.n);
        let mut transcript = MerlinTranscript::new(transcript_initializer);
        verifier.verify(&statement, &proof, &mut transcript)?;
        Ok(())
    }

    #[test]
    fn test_valid_flipped_rlwe_relation_proof() -> googletest::Result<()> {
        // We create an ahe_parameters instance to get the context reference and moduli objects.
        let qvec = vec![1000_000_009];
        let seed_wrapper = generate_seed()?;
        let ahe_parameters = create_public_parameters(2, 54001, &qvec, 1, 1.0, 1.0, &seed_wrapper)?;
        let context = get_rns_context_ref(&ahe_parameters);
        let n = 4;
        let q = 1000_000_009;
        let moduli = get_moduli(&ahe_parameters);

        let a_buffer = [-1, -2, -3, -4];
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
            flip_a: true,
            c: &c,
            q: q,
            bound_e: 16,
            bound_r: 1,
        };
        let witness = RlweRelationProofWitness { r: &r, e: &e, v: &v };
        let transcript_initializer = b"Rlwe Test Transcript";

        let prover = RlweRelationProver::new(b"42", statement.n);
        let mut transcript = MerlinTranscript::new(transcript_initializer);
        let proof = prover.prove(&statement, &witness, &mut transcript)?;

        let verifier = RlweRelationVerifier::new(b"42", statement.n);
        let mut transcript = MerlinTranscript::new(transcript_initializer);
        verifier.verify(&statement, &proof, &mut transcript)?;
        Ok(())
    }

    #[test]
    fn test_verifier_rejects_invalid_lip_proof() -> googletest::Result<()> {
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

        let mut statement = RlweRelationProofStatement {
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

        let prover = RlweRelationProver::new(b"42", statement.n);
        let mut transcript = MerlinTranscript::new(transcript_initializer);
        let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

        // We prove a different LIP with the same length to provide an invalid LIP proof.
        let lip_length = 3 * n + MAX_RHOS + 3 * 128;
        let lip_prover = LinearInnerProductProver::new(b"42", lip_length);
        let lip_a = vec![Scalar::from(13u128); lip_length];
        let lip_statement = LinearInnerProductProofStatement {
            n: lip_length,
            b: vec![Scalar::from(7u128); lip_length],
            c: Scalar::from(91u128 * (lip_length as u128)),
            comm_a: lip_prover
                .commit_partial(&lip_a, Scalar::from(42u128), 0, lip_length)?
                .compress(),
        };
        let lip_witness =
            LinearInnerProductProofWitness { a: lip_a, delta_a: Scalar::from(42u128) };
        let mut lip_transcript = MerlinTranscript::new(transcript_initializer);
        proof.lip_proof = lip_prover.prove(&lip_statement, &lip_witness, &mut lip_transcript)?;

        let verifier = RlweRelationVerifier::new(b"42", statement.n);
        let mut transcript = MerlinTranscript::new(transcript_initializer);
        let res = verifier.verify(&statement, &proof, &mut transcript);
        println!("res: {:?}", res);
        assert!(res
            .err()
            .expect("Unrelated lip proof should have been rejected.")
            .message()
            .contains("final check"));
        Ok(())
    }

    #[test]
    fn test_verifer_checks_z_bounds() -> googletest::Result<()> {
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

        let mut statement = RlweRelationProofStatement {
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

        let prover = RlweRelationProver::new(b"42", statement.n);
        let mut verifier = RlweRelationVerifier::new(b"42", statement.n);
        {
            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

            proof.z_r = vec![Scalar::from(1_000_000_000u128); 128];

            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let err = verifier.verify(&statement, &proof, &mut transcript).err();
            assert!(!err
                .expect("Incorrect z_r should have invalidated the proof.")
                .message()
                .contains("final check"));
        }
        {
            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

            proof.z_e = vec![Scalar::from(1_000_000_000u128); 128];

            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let err = verifier.verify(&statement, &proof, &mut transcript).err();
            assert!(!err
                .expect("Incorrect z_e should have invalidated the proof.")
                .message()
                .contains("final check"));
        }
        {
            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

            proof.z_vw = vec![Scalar::from(1_000_000_000_000_000_000u128); 128];

            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let err = verifier.verify(&statement, &proof, &mut transcript).err();
            assert!(!err
                .expect("Incorrect z_vw should have invalidated the proof.")
                .message()
                .contains("final check"));
        }
        Ok(())
    }

    #[test]
    fn test_verifer_tests_z() -> googletest::Result<()> {
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

        let mut statement = RlweRelationProofStatement {
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

        let prover = RlweRelationProver::new(b"42", statement.n);
        let mut verifier = RlweRelationVerifier::new(b"42", statement.n);
        {
            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

            proof.z_r = vec![Scalar::from(1u128); 128];

            let mut transcript = MerlinTranscript::new(transcript_initializer);
            assert!(verifier
                .verify(&statement, &proof, &mut transcript)
                .err()
                .expect("Incorrect z_r should have been rejected.")
                .message()
                .contains("final check"));
        }
        {
            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

            proof.z_e = vec![Scalar::from(1u128); 128];

            let mut transcript = MerlinTranscript::new(transcript_initializer);
            assert!(verifier
                .verify(&statement, &proof, &mut transcript)
                .err()
                .expect("Incorrect z_e should have been rejected.")
                .message()
                .contains("final check"));
        }
        {
            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

            proof.z_vw = vec![Scalar::from(1u128); 128];

            let mut transcript = MerlinTranscript::new(transcript_initializer);
            assert!(verifier
                .verify(&statement, &proof, &mut transcript)
                .err()
                .expect("Incorrect z_vw should have been rejected.")
                .message()
                .contains("final check"));
        }
        Ok(())
    }

    #[test]
    fn test_verifer_tests_commitments() -> googletest::Result<()> {
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

        let mut statement = RlweRelationProofStatement {
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

        let prover = RlweRelationProver::new(b"42", statement.n);
        let mut verifier = RlweRelationVerifier::new(b"42", statement.n);
        {
            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

            proof.comm_rev = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"6").compress();

            let mut transcript = MerlinTranscript::new(transcript_initializer);
        }
        {
            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

            proof.comm_wrho = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"28").compress();

            let mut transcript = MerlinTranscript::new(transcript_initializer);
            assert!(verifier
                .verify(&statement, &proof, &mut transcript)
                .err()
                .expect("Incorrect commitment should have been rejected.")
                .message()
                .contains("final check"));
        }
        {
            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

            proof.comm_y_r = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"496").compress();

            let mut transcript = MerlinTranscript::new(transcript_initializer);
            assert!(verifier
                .verify(&statement, &proof, &mut transcript)
                .err()
                .expect("Incorrect commitment should have been rejected.")
                .message()
                .contains("final check"));
        }
        {
            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

            proof.comm_y_e = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"8128").compress();

            let mut transcript = MerlinTranscript::new(transcript_initializer);
            assert!(verifier
                .verify(&statement, &proof, &mut transcript)
                .err()
                .expect("Incorrect commitment should have been rejected.")
                .message()
                .contains("final check"));
        }
        {
            let mut transcript = MerlinTranscript::new(transcript_initializer);
            let mut proof = prover.prove(&statement, &witness, &mut transcript)?;

            proof.comm_y_vw = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"33550336").compress();

            let mut transcript = MerlinTranscript::new(transcript_initializer);
            assert!(verifier
                .verify(&statement, &proof, &mut transcript)
                .err()
                .expect("Incorrect commitment should have been rejected.")
                .message()
                .contains("final check"));
        }
        Ok(())
    }
}
