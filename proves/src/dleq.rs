use std::io::Read;

use ark_ec::pairing::Pairing;
use ark_ec::Group as PrimeGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use crypto_bigint::{AddMod, MulMod};
use group::{Group, ScalarElement};
use num_bigint::BigUint;
use rand::rngs::OsRng;
use sha2::Sha256;

use crate::pedersen::{read_point, Commitment, PedersenParams};

pub struct DlEqPart<G1: Group<N1>, const N1: usize, BbsGroup: Pairing> {
    c_1_i: G1,
    c_2_i: BbsGroup::G1,
    k_p: G1,
    k_q: BbsGroup::G1,
    z: G1::FieldElement,
    s_p: G1::FieldElement,
    s_q: BbsGroup::ScalarField,
}

impl<G1: Group<N1>, const N1: usize, BbsGroup: Pairing> DlEqPart<G1, N1, BbsGroup> {
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(self.c_1_i.to_bytes());
        self.c_2_i.serialize_uncompressed(&mut result).unwrap();
        result.extend(self.k_p.to_bytes());
        self.k_q.serialize_uncompressed(&mut result).unwrap();
        result.extend(self.z.to_be_bytes());
        result.extend(self.s_p.to_be_bytes());
        self.s_q.serialize_uncompressed(&mut result).unwrap();
        result
    }
    pub fn deserialize<R: Read>(mut reader: R) -> Option<Self> {
        use crate::pedersen::read_field_element;
        use ark_serialize::CanonicalDeserialize;
        Some(Self {
            c_1_i: read_point(&mut reader)?,
            c_2_i: BbsGroup::G1::deserialize_uncompressed(&mut reader).ok()?,
            k_p: read_point(&mut reader)?,
            k_q: BbsGroup::G1::deserialize_uncompressed(&mut reader).ok()?,
            z: read_field_element::<G1, N1>(&mut reader)?,
            s_p: read_field_element::<G1, N1>(&mut reader)?,
            s_q: BbsGroup::ScalarField::deserialize_uncompressed(&mut reader).ok()?,
        })
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub struct DlEq<
    const Bx: u8,
    const Bc: u8,
    const Bf: u8,
    const tau: u8,
    G1: Group<N1>,
    const N1: usize,
    BbsGroup: Pairing,
> {
    g1_params: PedersenParams<G1, N1>,
    pub g2_params: PairingPedersenParams<BbsGroup>,
    c1: G1,
    pub c2: BbsGroup::G1,
    sub_parts: Vec<DlEqPart<G1, N1, BbsGroup>>,
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
impl<
        const Bx: u8,
        const Bc: u8,
        const Bf: u8,
        const tau: u8,
        G1: Group<N1>,
        const N1: usize,
        BbsGroup: Pairing,
    > DlEq<Bx, Bc, Bf, tau, G1, N1, BbsGroup>
{
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(&self.g1_params.serialize());
        result.extend(&self.g2_params.serialize());
        result.extend(self.c1.to_bytes());
        self.c2.serialize_uncompressed(&mut result).unwrap();
        let len = (self.sub_parts.len() as u64).to_be_bytes();
        result.extend(&len);
        for sub_part in &self.sub_parts {
            result.extend(sub_part.serialize());
        }
        result
    }
    pub fn deserialize<R: Read>(mut reader: R) -> Option<Self> {
        let g1_params = PedersenParams::deserialize(&mut reader)?;
        let g2_params = PairingPedersenParams::deserialize(&mut reader)?;
        let c1 = read_point(&mut reader)?;
        let c2 = BbsGroup::G1::deserialize_uncompressed(&mut reader).ok()?;
        let mut sub_length = [0u8; 8];
        reader.read_exact(&mut sub_length).unwrap();
        let sub_length = u64::from_be_bytes(sub_length);
        let mut sub_parts = vec![];
        for _ in 0..sub_length {
            sub_parts.push(DlEqPart::deserialize(&mut reader)?);
        }
        Some(Self {
            g1_params,
            g2_params,
            c1,
            c2,
            sub_parts,
        })
    }
    // we currently ignore tau, we would need it to achieve the needed 120 bit security
    pub fn prove(
        g1_params: PedersenParams<G1, N1>,
        g2_params: PairingPedersenParams<BbsGroup>,
        c1: Commitment<G1, N1>,
        c2: PairingCommitment<BbsGroup>,
        x: G1::FieldElement,
    ) -> Self {
        let x_bit_size = x.bits();
        let breakup: u32 = (x_bit_size as f32 / Bx as f32).ceil() as u32;
        let mut x_to_basis_bx = vec![];
        let mut commitments_to_g1 = vec![];
        let mut commitments_to_g2 = vec![];
        let mut r_i_p = vec![];
        let mut r_i_q = vec![];
        let mut tmp_x = x;
        let r_p = c1.blinding;
        let mut tmp_r_p = r_p;
        let r_q = c2.blinding;
        let mut tmp_r_q: BigUint = r_q.into();
        // split our X to fit our length requirements
        // We still would need range proofs for each of our parts
        for _ in 0..breakup {
            let one: G1::FieldElement = 1u32.into();
            let bx_i: G1::FieldElement = one << Bx as u32;
            let bx_i_nz = G1::to_nonzero(bx_i);
            let x = tmp_x % bx_i_nz;
            // we'd need to sample that randomly according to https://eprint.iacr.org/2022/1593.pdf Section 5
            let rp = tmp_r_p % bx_i_nz;
            x_to_basis_bx.push(x);
            r_i_p.push(rp);
            tmp_x = tmp_x / bx_i_nz;
            tmp_r_p = tmp_r_p / bx_i_nz;
            commitments_to_g1.push(g1_params.g * x + g1_params.h * rp);
            // bbs group
            let x = x.to_be_bytes();
            let x = BbsGroup::ScalarField::from_be_bytes_mod_order(&x);
            let bx_i = bx_i.to_be_bytes();
            let bx_i = BbsGroup::ScalarField::from_be_bytes_mod_order(&bx_i);
            let bx_i: BigUint = bx_i.into();
            let rq = &tmp_r_q % &bx_i;
            tmp_r_q = (tmp_r_q / &bx_i).into();
            r_i_q.push(rq.clone());

            let rq: BbsGroup::ScalarField = rq.into();
            commitments_to_g2.push(g2_params.g * x + g2_params.h * rq);
        }
        // do proof protocol for each part
        //
        let mut sub_parts = vec![];
        let two: G1::FieldElement = 2u32.into();
        for i in 0..breakup {
            'abortion_loop: loop {
                //Phase 1
                let max: G1::FieldElement =
                    (two << Bx as u32 + Bc as u32 + Bf as u32) - G1::FieldElement::ONE;

                // make this randomness better
                let k = G1::random_scalar() % G1::to_nonzero(max);
                let k_q = k.to_be_bytes();
                let k_q = BbsGroup::ScalarField::from_be_bytes_mod_order(&k_q);
                let t_p = G1::random_scalar();
                let t_q = BbsGroup::ScalarField::rand(&mut OsRng);

                let K_p = g1_params.g * k + g1_params.h * t_p;
                let K_q = g2_params.g * k_q + g2_params.h * t_q;
                //Phase 2
                // we should also include the public parameters of g2
                let c_i = commitments_to_g1[i as usize];
                let r_i = r_i_p[i as usize];
                let c_2_i = commitments_to_g2[i as usize];
                let r_2_i = r_i_q[i as usize].clone();
                // find better way as this produces a bias and is not uniform

                let challenge_length: G1::FieldElement =
                    (G1::powe(two, Bc as u32) - G1::FieldElement::ONE).into();
                let challenge = G1::hash_points::<Sha256>(vec![K_p, c_i, c1.commitment])
                    % G1::to_nonzero(challenge_length);

                let challenge_q = challenge.to_be_bytes();
                let challenge_q = BbsGroup::ScalarField::from_be_bytes_mod_order(&challenge_q);

                // this should be in z, so maybe with bigint?
                let z = k + challenge.mul_mod(&x_to_basis_bx[i as usize], &G1::PRIME_MOD);

                let lower_bound: G1::FieldElement = two << Bx as u32 + Bc as u32;
                let upper_bound: G1::FieldElement = two << Bx as u32 + Bc as u32 + Bf as u32;

                // if we are out of range, restart protocol
                if z < lower_bound || z > upper_bound {
                    continue 'abortion_loop;
                }
                let s_p = t_p.add_mod(&challenge.mul_mod(&r_i, &G1::ORDER), &G1::ORDER);
                let r_2_i: BbsGroup::ScalarField = r_2_i.into();
                let s_q = t_q + challenge_q * r_2_i;

                sub_parts.push(DlEqPart::<G1, N1, BbsGroup> {
                    c_1_i: c_i,
                    c_2_i,
                    k_p: K_p,
                    k_q: K_q,
                    z,
                    s_p,
                    s_q,
                });

                break 'abortion_loop;
            }
        }
        DlEq {
            g1_params,
            g2_params,
            c1: c1.commitment,
            c2: c2.commitment,
            sub_parts,
        }
    }
    pub fn verify(&self, c1: G1, c2: BbsGroup::G1) -> bool {
        use ark_std::Zero;
        let mut c1_sum = c1;
        let mut c2_sum = c2;
        let one: G1::FieldElement = 1u32.into();
        let two: G1::FieldElement = 2u32.into();
        for (part, exponent) in self.sub_parts.iter().zip(0..self.sub_parts.len()) {
            let power = one << exponent as u32 * Bx as u32;
            c1_sum = c1_sum - part.c_1_i * power;
            let power = power.to_be_bytes();
            let power: BbsGroup::ScalarField =
                BbsGroup::ScalarField::from_be_bytes_mod_order(&power);
            c2_sum = c2_sum - part.c_2_i * power;
            let challenge_length: G1::FieldElement =
                (G1::powe(two, Bc as u32) - G1::FieldElement::ONE).into();
            let challenge = G1::hash_points::<Sha256>(vec![part.k_p, part.c_1_i, c1])
                % G1::to_nonzero(challenge_length);
            let check_g1 = self.g1_params.g * part.z + self.g1_params.h * part.s_p
                - part.k_p
                - part.c_1_i * challenge;
            if !check_g1.is_identity() {
                return false;
            }
            let z_q = part.z.to_be_bytes();
            let z_q = BbsGroup::ScalarField::from_be_bytes_mod_order(&z_q);
            let challenge_q = challenge.to_be_bytes();
            let challenge_q = BbsGroup::ScalarField::from_be_bytes_mod_order(&challenge_q);
            let check_g2 = self.g2_params.g * z_q + self.g2_params.h * part.s_q
                - part.k_q
                - part.c_2_i * challenge_q;
            if !check_g2.is_zero() {
                return false;
            }
            let lower_bound: G1::FieldElement = two << Bx as u32 + Bc as u32;
            let upper_bound: G1::FieldElement = two << Bx as u32 + Bc as u32 + Bf as u32;
            // if we are out of range, return false
            if part.z < lower_bound || part.z > upper_bound {
                return false;
            }
        }
        if !c1_sum.is_identity() {
            return false;
        }
        if !c2_sum.is_zero() {
            return false;
        }
        true
    }
}

#[derive(Clone, Copy)]
pub struct PairingCommitment<BbsGroup: Pairing> {
    commitment: BbsGroup::G1,
    blinding: BbsGroup::ScalarField,
}
#[derive(Copy, Clone)]
pub struct PairingPedersenParams<BbsGroup: Pairing> {
    pub g: BbsGroup::G1,
    pub h: BbsGroup::G1,
}
impl<BbsGroup: Pairing> PairingPedersenParams<BbsGroup> {
    pub fn serialize(&self) -> Vec<u8> {
        use ark_serialize::CanonicalSerialize;
        let mut result = vec![];
        self.g.serialize_uncompressed(&mut result).unwrap();
        self.h.serialize_uncompressed(&mut result).unwrap();
        result
    }
    pub fn deserialize<R: Read>(mut reader: R) -> Option<Self> {
        Some(Self {
            g: BbsGroup::G1::deserialize_uncompressed(&mut reader).ok()?,
            h: BbsGroup::G1::deserialize_uncompressed(&mut reader).ok()?,
        })
    }
    pub fn commit(&self, x: BbsGroup::ScalarField) -> PairingCommitment<BbsGroup> {
        let blinding = BbsGroup::ScalarField::rand(&mut OsRng);
        PairingCommitment {
            commitment: self.g * x + self.h * blinding,
            blinding,
        }
    }
    pub fn commit_with_blinding(
        &self,
        x: BbsGroup::ScalarField,
        blinding: BbsGroup::ScalarField,
    ) -> PairingCommitment<BbsGroup> {
        PairingCommitment {
            commitment: self.g * x + self.h * blinding,
            blinding,
        }
    }
    pub fn new() -> Self {
        let g = BbsGroup::G1::generator();
        let r = BbsGroup::ScalarField::rand(&mut OsRng);
        let h = g * r;
        Self { g, h }
    }
    pub fn new_with_params(g: BbsGroup::G1, h: BbsGroup::G1) -> Self {
        Self { g, h }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use group::Group;
    use tom256::U320;

    use crate::{dleq::DlEq, pedersen::PedersenParams};

    use super::PairingPedersenParams;

    #[test]
    fn test_equality() {
        use ark_ff::PrimeField;
        let x = <tom256::ProjectivePoint as Group<40>>::ORDER - U320::from_u32(1524);
        let x_q = x.to_be_bytes();
        let x_q: <Bls12_381 as Pairing>::ScalarField =
            <Bls12_381 as Pairing>::ScalarField::from_be_bytes_mod_order(&x_q);
        let x_p: <tom256::ProjectivePoint as Group<40>>::FieldElement = x.into();
        let g1_params = PedersenParams::<tom256::ProjectivePoint, 40>::new();
        let g2_params = PairingPedersenParams::<Bls12_381>::new();

        let c1 = g1_params.commit(x_p);
        let c2 = g2_params.commit(x_q);

        let proof = DlEq::<180, 64, 8, 2, _, 40, _>::prove(g1_params, g2_params, c1, c2, x);
        println!("proof done, verify");
        assert!(proof.verify(c1.commitment, c2.commitment));

        let mut serialized_proof = Cursor::new(proof.serialize());
        let deserialzied_proof =
            DlEq::<180, 64, 8, 2, tom256::ProjectivePoint, 40, Bls12_381>::deserialize(
                &mut serialized_proof,
            )
            .unwrap();
        assert!(deserialzied_proof.verify(c1.commitment, c2.commitment));
    }
    #[test]
    fn inequality() {
        use ark_ff::PrimeField;
        let x = <tom256::ProjectivePoint as Group<40>>::ORDER - U320::from_u32(1524);
        let y = <tom256::ProjectivePoint as Group<40>>::ORDER - U320::from_u32(192001213);
        let x_q = y.to_be_bytes();
        let x_q: <Bls12_381 as Pairing>::ScalarField =
            <Bls12_381 as Pairing>::ScalarField::from_be_bytes_mod_order(&x_q);
        let x_p: <tom256::ProjectivePoint as Group<40>>::FieldElement = x.into();
        let g1_params = PedersenParams::<tom256::ProjectivePoint, 40>::new();
        let g2_params = PairingPedersenParams::<Bls12_381>::new();

        let c1 = g1_params.commit(x_p);
        let c2 = g2_params.commit(x_q);

        let proof = DlEq::<180, 64, 8, 2, _, 40, _>::prove(g1_params, g2_params, c1, c2, x);
        println!("proof done, verify");
        assert!(!proof.verify(c1.commitment, c2.commitment));
    }
    #[test]
    fn test_random() {
        for _ in 0..100 {
            use ark_ff::PrimeField;
            let x = <tom256::ProjectivePoint as Group<40>>::random_scalar();
            let y = <tom256::ProjectivePoint as Group<40>>::random_scalar();
            let y_q = y.to_be_bytes();
            let y_q: <Bls12_381 as Pairing>::ScalarField =
                <Bls12_381 as Pairing>::ScalarField::from_be_bytes_mod_order(&y_q);
            let x_q = x.to_be_bytes();
            let x_q: <Bls12_381 as Pairing>::ScalarField =
                <Bls12_381 as Pairing>::ScalarField::from_be_bytes_mod_order(&x_q);
            let x_p: <tom256::ProjectivePoint as Group<40>>::FieldElement = x.into();
            let g1_params = PedersenParams::<tom256::ProjectivePoint, 40>::new();
            let g2_params = PairingPedersenParams::<Bls12_381>::new();

            let c1 = g1_params.commit(x_p);
            let c2 = g2_params.commit(x_q);
            let c_prime = g2_params.commit(y_q);

            let proof = DlEq::<180, 64, 8, 2, _, 40, _>::prove(g1_params, g2_params, c1, c2, x);
            assert!(proof.verify(c1.commitment, c2.commitment));

            let invalid_proof =
                DlEq::<180, 64, 8, 2, _, 40, _>::prove(g1_params, g2_params, c1, c_prime, x);
            assert!(!invalid_proof.verify(c1.commitment, c_prime.commitment));
        }
    }
}
