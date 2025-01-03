use std::{
    io::{Cursor, Read},
    ops::{Add, Mul, Sub},
};

use crypto_bigint::{AddMod, Integer, InvMod, MulMod, SubMod};
use group::{transform_field_element, Coords, Group, ScalarElement};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sha2::Sha256;

#[derive(Debug, Copy, Clone)]
pub struct Commitment<G, const N: usize>
where
    G: Group<N>,
{
    commitment: G,
    blinding: <G as Group<N>>::FieldElement,
}

impl<G, const N: usize> PartialEq for Commitment<G, N>
where
    G: Group<N>,
{
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment && self.blinding == other.blinding
    }
}

impl<G, const N: usize> Add for Commitment<G, N>
where
    G: Group<N>,
{
    type Output = Commitment<G, N>;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            commitment: self.commitment + rhs.commitment,
            blinding: self.blinding.add_mod(&rhs.blinding, &G::ORDER),
        }
    }
}

impl<G, const N: usize> Mul<<G as Group<N>>::FieldElement> for Commitment<G, N>
where
    G: Group<N>,
{
    type Output = Commitment<G, N>;

    fn mul(self, rhs: <G as Group<N>>::FieldElement) -> Self::Output {
        let sk = G::new_scalar(rhs);
        Self {
            commitment: self.commitment * sk,
            blinding: self.blinding.mul_mod(&sk, &G::ORDER),
        }
    }
}

impl<G, const N: usize> Sub for Commitment<G, N>
where
    G: Group<N>,
{
    type Output = Commitment<G, N>;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            commitment: self.commitment - rhs.commitment,
            blinding: self.blinding.sub_mod(&rhs.blinding, &G::ORDER),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PedersenParams<G, const N: usize>
where
    G: Group<N>,
{
    g: G,
    h: G,
}

impl<G, const N: usize> PedersenParams<G, N>
where
    G: Group<N>,
{
    pub fn commit(&self, input: G::FieldElement) -> Commitment<G, N> {
        let r = G::random_scalar();
        let v = G::new_scalar(input);
        let p = self.h.dblmul(r, self.g, v);
        Commitment {
            commitment: p,
            blinding: r,
        }
    }
    pub fn new() -> Self {
        let g = G::generator();
        let r = G::random_scalar();
        let h = r * g;
        Self { g, h }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct EqualityProof<G, const N: usize>
where
    G: Group<N>,
{
    params: PedersenParams<G, N>,
    a_1: G,
    a_2: G,
    t_x: G::FieldElement,
    t_r1: G::FieldElement,
    t_r2: G::FieldElement,
}

impl<G, const N: usize> EqualityProof<G, N>
where
    G: Group<N>,
{
    pub fn serialize(&self) -> Vec<u8> {
        let mut output = vec![];
        output.extend(self.params.g.to_bytes());
        output.extend(self.params.h.to_bytes());
        output.extend(self.a_1.to_bytes());
        output.extend(self.a_2.to_bytes());
        output.extend(self.t_x.to_be_bytes());
        output.extend(self.t_r1.to_be_bytes());
        output.extend(self.t_r2.to_be_bytes());
        output
    }
    pub fn deserialize(cursor: &mut dyn Read) -> Option<Self> {
        Some(Self {
            params: PedersenParams {
                g: read_point(cursor)?,
                h: read_point(cursor)?,
            },
            a_1: read_point(cursor)?,
            a_2: read_point(cursor)?,
            t_x: read_field_element::<G, N>(cursor)?,
            t_r1: read_field_element::<G, N>(cursor)?,
            t_r2: read_field_element::<G, N>(cursor)?,
        })
    }
    pub fn prove(
        params: PedersenParams<G, N>,
        x: G::FieldElement,
        c1: Commitment<G, N>,
        c2: Commitment<G, N>,
    ) -> Self {
        let k = G::random_scalar();
        let a1 = params.commit(k);
        let a2 = params.commit(k);
        let c = G::hash_points::<Sha256>(vec![
            c1.commitment,
            c2.commitment,
            a1.commitment,
            a2.commitment,
        ]);
        let cc = G::new_scalar(c);
        let xx = G::new_scalar(x);
        let kk = G::new_scalar(k);
        let t_x = kk.sub_mod(&cc.mul_mod(&xx, &G::ORDER), &G::ORDER);
        let t_r1 = a1
            .blinding
            .sub_mod(&cc.mul_mod(&c1.blinding, &G::ORDER), &G::ORDER);

        let t_r2 = a2
            .blinding
            .sub_mod(&cc.mul_mod(&c2.blinding, &G::ORDER), &G::ORDER);
        EqualityProof {
            params,
            a_1: a1.commitment,
            a_2: a2.commitment,
            t_x,
            t_r1,
            t_r2,
        }
    }
    pub fn verify(&self, c1: G, c2: G) -> bool {
        let c = G::hash_points::<Sha256>(vec![c1, c2, self.a_1, self.a_2]);
        let cc = G::new_scalar(c);
        let a = self.params.g * self.t_x;
        let b1 = self.params.h * self.t_r1;
        let cc1 = c1 * cc;
        let sum1 = a + b1 + cc1 - self.a_1;

        if !G::is_on_group(sum1) || sum1 != G::identity() {
            return false;
        }

        let b2 = self.params.h * self.t_r2;
        let cc2 = c2 * cc;
        let sum2 = self.a_2 - cc2 - (a + b2);
        if !G::is_on_group(sum2) || sum2 != G::identity() {
            return false;
        }
        return true;
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MultiplicationProof<G, const N: usize>
where
    G: Group<N>,
{
    params: PedersenParams<G, N>,
    c_4: G,
    a_x: G,
    a_y: G,
    a_z: G,
    a_4_1: G,
    a_4_2: G,
    t_x: G::FieldElement,
    t_y: G::FieldElement,
    t_z: G::FieldElement,
    t_rx: G::FieldElement,
    t_ry: G::FieldElement,
    t_rz: G::FieldElement,
    t_r4: G::FieldElement,
}

pub fn read_point<G: Group<N>, const N: usize>(reader: &mut dyn Read) -> Option<G> {
    let mut g_bytes = vec![0u8; G::size_point_bytes()];
    reader.read_exact(&mut g_bytes).ok()?;
    G::from_bytes(&g_bytes)
}
pub fn read_field_element<G: Group<N>, const N: usize>(
    reader: &mut dyn Read,
) -> Option<G::FieldElement> {
    let mut s_bytes = vec![0u8; N];
    reader.read_exact(&mut s_bytes).ok()?;
    Some(G::FieldElement::from_slice(&s_bytes))
}
impl<G, const N: usize> MultiplicationProof<G, N>
where
    G: Group<N>,
{
    pub fn deserialize(cursor: &mut dyn Read) -> Option<Self> {
        Some(Self {
            params: PedersenParams {
                g: read_point(cursor)?,
                h: read_point(cursor)?,
            },
            c_4: read_point(cursor)?,
            a_x: read_point(cursor)?,
            a_y: read_point(cursor)?,
            a_z: read_point(cursor)?,
            a_4_1: read_point(cursor)?,
            a_4_2: read_point(cursor)?,
            t_x: read_field_element::<G, N>(cursor)?,
            t_y: read_field_element::<G, N>(cursor)?,
            t_z: read_field_element::<G, N>(cursor)?,
            t_rx: read_field_element::<G, N>(cursor)?,
            t_ry: read_field_element::<G, N>(cursor)?,
            t_rz: read_field_element::<G, N>(cursor)?,
            t_r4: read_field_element::<G, N>(cursor)?,
        })
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut output = vec![];
        output.extend(self.params.g.to_bytes());
        output.extend(self.params.h.to_bytes());
        output.extend(self.c_4.to_bytes());
        output.extend(self.a_x.to_bytes());
        output.extend(self.a_y.to_bytes());
        output.extend(self.a_z.to_bytes());
        output.extend(self.a_4_1.to_bytes());
        output.extend(self.a_4_2.to_bytes());
        output.extend(self.t_x.to_be_bytes());
        output.extend(self.t_y.to_be_bytes());
        output.extend(self.t_z.to_be_bytes());
        output.extend(self.t_rx.to_be_bytes());
        output.extend(self.t_ry.to_be_bytes());
        output.extend(self.t_rz.to_be_bytes());
        output.extend(self.t_r4.to_be_bytes());
        output
    }
    pub fn prove(
        params: PedersenParams<G, N>,
        x: G::FieldElement,
        y: G::FieldElement,
        z: G::FieldElement,
        cx: Commitment<G, N>,
        cy: Commitment<G, N>,
        cz: Commitment<G, N>,
    ) -> MultiplicationProof<G, N> {
        let xx = G::new_scalar(x);
        let c4 = cy * xx;
        let kx = G::random_scalar();
        let ky = G::random_scalar();
        let kz = G::random_scalar();
        let ax = params.commit(kx);
        let ay = params.commit(ky);
        let az = params.commit(kz);
        let a4_1 = params.commit(kz);
        let a4_2 = cy * kx;
        let c = G::hash_points::<Sha256>(vec![
            cx.commitment,
            cy.commitment,
            cz.commitment,
            c4.commitment,
            ax.commitment,
            ay.commitment,
            az.commitment,
            a4_1.commitment,
            a4_2.commitment,
        ]);
        let cc = G::new_scalar(c);
        let yy = G::new_scalar(y);
        let zz = G::new_scalar(z);

        let t_x = kx.sub_mod(&cc.mul_mod(&xx, &G::ORDER), &G::ORDER);
        let t_y = ky.sub_mod(&cc.mul_mod(&yy, &G::ORDER), &G::ORDER);
        let t_z = kz.sub_mod(&cc.mul_mod(&zz, &G::ORDER), &G::ORDER);

        let t_rx = ax
            .blinding
            .sub_mod(&cc.mul_mod(&cx.blinding, &G::ORDER), &G::ORDER);
        let t_ry = ay
            .blinding
            .sub_mod(&cc.mul_mod(&cy.blinding, &G::ORDER), &G::ORDER);
        let t_rz = az
            .blinding
            .sub_mod(&cc.mul_mod(&cz.blinding, &G::ORDER), &G::ORDER);
        let t_r4 = a4_1
            .blinding
            .sub_mod(&cc.mul_mod(&c4.blinding, &G::ORDER), &G::ORDER);
        Self {
            params,
            c_4: c4.commitment,
            a_x: ax.commitment,
            a_y: ay.commitment,
            a_z: az.commitment,
            a_4_1: a4_1.commitment,
            a_4_2: a4_2.commitment,
            t_x,
            t_y,
            t_z,
            t_rx,
            t_ry,
            t_rz,
            t_r4,
        }
    }
    pub fn verify(&self, cx: G, cy: G, cz: G) -> bool {
        let c = G::hash_points::<Sha256>(vec![
            cx, cy, cz, self.c_4, self.a_x, self.a_y, self.a_z, self.a_4_1, self.a_4_2,
        ]);
        let cc = G::new_scalar(c);
        let sum = self.a_x - cc * cx - (self.params.g * self.t_x + self.params.h * self.t_rx);
        if !G::is_on_group(sum) || sum != G::identity() {
            return false;
        }
        let sum = self.a_y - cc * cy - (self.params.g * self.t_y + self.params.h * self.t_ry);
        if !G::is_on_group(sum) || sum != G::identity() {
            return false;
        }
        let sum = self.a_z - cc * cz - (self.params.g * self.t_z + self.params.h * self.t_rz);
        if !G::is_on_group(sum) || sum != G::identity() {
            return false;
        }
        let sum =
            self.a_4_1 - cc * self.c_4 - (self.params.g * self.t_z + self.params.h * self.t_r4);
        if !G::is_on_group(sum) || sum != G::identity() {
            return false;
        }
        let sum = self.a_4_2 - cc * self.c_4 - (cy * self.t_x);
        if !G::is_on_group(sum) || sum != G::identity() {
            return false;
        }
        true
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PointAddProof<G, const N: usize>
where
    G: Group<N>,
{
    params: PedersenParams<G, N>,
    c_8: G,
    c_10: G,
    c_11: G,
    c_13: G,
    pi_8: MultiplicationProof<G, N>,
    pi_10: MultiplicationProof<G, N>,
    pi_11: MultiplicationProof<G, N>,
    pi_13: MultiplicationProof<G, N>,
    pi_x: EqualityProof<G, N>,
    pi_y: EqualityProof<G, N>,
}
impl<G, const N: usize> PointAddProof<G, N>
where
    G: Group<N>,
{
    pub fn serialize(&self) -> Vec<u8> {
        let mut output = vec![];
        output.extend(self.params.g.to_bytes());
        output.extend(self.params.h.to_bytes());
        output.extend(self.c_8.to_bytes());
        output.extend(self.c_10.to_bytes());
        output.extend(self.c_11.to_bytes());
        output.extend(self.c_13.to_bytes());
        output.extend(self.pi_8.serialize());
        output.extend(self.pi_10.serialize());
        output.extend(self.pi_11.serialize());
        output.extend(self.pi_13.serialize());
        output.extend(self.pi_x.serialize());
        output.extend(self.pi_y.serialize());
        output
    }
    pub fn deserialize(cursor: &mut (dyn Read)) -> Option<Self> {
        Some(Self {
            params: PedersenParams {
                g: read_point(cursor)?,
                h: read_point(cursor)?,
            },
            c_8: read_point(cursor)?,
            c_10: read_point(cursor)?,
            c_11: read_point(cursor)?,
            c_13: read_point(cursor)?,
            pi_8: MultiplicationProof::deserialize(cursor)?,
            pi_10: MultiplicationProof::deserialize(cursor)?,
            pi_11: MultiplicationProof::deserialize(cursor)?,
            pi_13: MultiplicationProof::deserialize(cursor)?,
            pi_x: EqualityProof::deserialize(cursor)?,
            pi_y: EqualityProof::deserialize(cursor)?,
        })
    }

    /// We assume that p q and r are correct (e.g. the signature verifies)
    pub fn prove(
        params: PedersenParams<G, N>,
        x1: G::FieldElement,
        y1: G::FieldElement,
        x2: G::FieldElement,
        y2: G::FieldElement,
        x3: G::FieldElement,
        px: Commitment<G, N>,
        py: Commitment<G, N>,
        qx: Commitment<G, N>,
        qy: Commitment<G, N>,
        rx: Commitment<G, N>,
        ry: Commitment<G, N>,
    ) -> Self {
        let prime = G::ORDER;
        let c1 = px;
        let c2 = qx;
        let c3 = rx;
        let c4 = py;
        let c5 = qy;
        let c6 = ry;

        let i7 = x2.sub_mod(&x1, &prime);
        let i8 = i7.inv_mod(&prime).unwrap();
        let i9 = y2.sub_mod(&y1, &prime);
        let i10 = i8.mul_mod(&i9, &prime);
        let i11 = i10.mul_mod(&i10, &prime);
        let i12 = x1.sub_mod(&x3, &prime);
        let i13 = i10.mul_mod(&i12, &prime);

        let c7 = c2 - c1;
        let c8 = params.commit(i8);
        let c9 = c5 - c4;
        let c10 = params.commit(i10);
        let c11 = params.commit(i11);
        let c12 = c1 - c3;
        let c13 = params.commit(i13);
        let c14 = Commitment {
            commitment: params.g,
            blinding: <G::FieldElement as group::ScalarElement<G::FieldElement, N>>::ZERO,
        };
        let pi8 = MultiplicationProof::prove(
            params,
            i7,
            i8,
            <G::FieldElement as group::ScalarElement<G::FieldElement, N>>::ONE,
            c7,
            c8,
            c14,
        );
        let pi10 = MultiplicationProof::prove(params, i8, i9, i10, c8, c9, c10);
        let pi11 = MultiplicationProof::prove(params, i10, i10, i11, c10, c10, c11);
        let cint = c3 + c1 + c2;
        let pix = EqualityProof::prove(params, i11, c11, cint);
        let pi13 = MultiplicationProof::prove(params, i10, i12, i13, c10, c12, c13);
        let cint = c6 + c4;
        let piy = EqualityProof::prove(params, i13, c13, cint);
        Self {
            params,
            c_8: c8.commitment,
            c_10: c10.commitment,
            c_11: c11.commitment,
            c_13: c13.commitment,
            pi_8: pi8,
            pi_10: pi10,
            pi_11: pi11,
            pi_13: pi13,
            pi_x: pix,
            pi_y: piy,
        }
    }
    pub fn verify(&self, px: G, py: G, qx: G, qy: G, rx: G, ry: G) -> bool {
        let c1 = px;
        let c2 = qx;
        let c3 = rx;
        let c4 = py;
        let c5 = qy;
        let c6 = ry;
        let c7 = c2 - c1;
        let c9 = c5 - c4;
        let c12 = c1 - c3;
        let c_14 = self.params.g;
        if !self.pi_8.verify(c7, self.c_8, c_14) {
            return false;
        }
        if !self.pi_10.verify(self.c_8, c9, self.c_10) {
            return false;
        }
        if !self.pi_11.verify(self.c_10, self.c_10, self.c_11) {
            return false;
        }
        let cint = c3 + c1 + c2;
        if !self.pi_x.verify(self.c_11, cint) {
            return false;
        }
        if !self.pi_13.verify(self.c_10, c12, self.c_13) {
            return false;
        }
        let cint = c4 + c6;
        if !self.pi_y.verify(self.c_13, cint) {
            return false;
        }
        true
    }
}

//G1 Nist
//G2 Tom
#[derive(Clone, Copy, Debug)]
pub struct SignatureProofOdd<G1, const N1: usize, G2, const N2: usize>
where
    G1: Group<N1>,
    G2: Group<N2>,
{
    a: G1,
    tx: G2,
    ty: G2,
    alpha: G1::FieldElement,
    beta1: G1::FieldElement,
    beta2: G2::FieldElement,
    beta3: G2::FieldElement,
}
#[derive(Clone, Copy, Debug)]
pub struct SignatureProofEven<G1, const N1: usize, G2, const N2: usize>
where
    G1: Group<N1>,
    G2: Group<N2>,
{
    a: G1,
    tx: G2,
    ty: G2,
    z: G1::FieldElement,
    z2: G1::FieldElement,
    proof: PointAddProof<G2, N2>,
    r1: G2::FieldElement,
    r2: G2::FieldElement,
}

#[derive(Clone, Copy, Debug)]
pub enum SignatureProof<G1, const N1: usize, G2, const N2: usize>
where
    G1: Group<N1>,
    G2: Group<N2>,
{
    Odd(SignatureProofOdd<G1, N1, G2, N2>),
    Even(SignatureProofEven<G1, N1, G2, N2>),
    Empty,
}

pub struct SignatureProofList<G1, const N1: usize, G2, const N2: usize>
where
    G1: Group<N1>,
    G2: Group<N2>,
{
    g1_params: PedersenParams<G1, N1>,
    g2_params: PedersenParams<G2, N2>,
    r: G1,
    c_lambda: G1,
    p_x: G2,
    p_y: G2,
    proofs: Vec<SignatureProof<G1, N1, G2, N2>>,
    secparam: usize,
}

fn truncate_to_order<G1: Group<N1>, const N1: usize, G2: Group<N2>, const N2: usize>(
    element: G2::FieldElement,
) -> G1::FieldElement {
    let mut msb_bytes: [u8; N1] = [0; N1];
    if N2 < N1 {
        transform_field_element(element)
    } else {
        let bytes = element.to_be_bytes();
        msb_bytes.copy_from_slice(&bytes[..N1]);
        G1::FieldElement::from_slice(&bytes)
    }
}
//G1 Nist
//G2 Tom
#[allow(non_snake_case)]
impl<G1, const N1: usize, G2, const N2: usize> SignatureProofList<G1, N1, G2, N2>
where
    G1: Group<N1>,
    G2: Group<N2>,
{
    pub fn from_signature(
        g1_params: PedersenParams<G1, N1>,
        g2_params: PedersenParams<G2, N2>,
        signature: &[u8],
        msg_hash: &[u8],
        public_key: &[u8],
        secparam: usize,
    ) -> Self {
        use group::ScalarElement;
        let pub_key = G1::from_bytes(&public_key).unwrap();
        let pub_key_affine = pub_key.to_affine();
        let group_order = G1::ORDER;

        let z: G1::FieldElement =
            truncate_to_order::<G1, N1, G2, N2>(G2::FieldElement::from_slice(&msg_hash));
        let r = G1::FieldElement::from_slice(&signature[..signature.len() / 2]);
        let s = G1::FieldElement::from_slice(&signature[signature.len() / 2..]);

        let sinv = s.inv_mod(&group_order).unwrap();
        let u1 = sinv.mul_mod(&z, &group_order);
        let u2 = sinv.mul_mod(&r, &group_order);
        let R = G1::generator() * u1 + pub_key * u2;

        let rinv = r.inv_mod(&group_order).unwrap();
        let s1 = rinv.mul_mod(&s, &group_order);
        let z1 = rinv.mul_mod(&z, &group_order);
        let Q = G1::generator() * z1;
        let params_sig_exp = PedersenParams {
            g: R,
            h: g1_params.h,
        };
        let com_s1 = params_sig_exp.commit(s1);
        let pk_x = g2_params.commit(transform_field_element(pub_key_affine.x()));
        let pk_y = g2_params.commit(transform_field_element(pub_key_affine.y()));
        Self::prove(
            params_sig_exp,
            g2_params,
            s1,
            com_s1,
            pub_key,
            pk_x,
            pk_y,
            Q,
            R,
            secparam,
        )
    }
    pub fn prove(
        g1_params: PedersenParams<G1, N1>,
        g2_params: PedersenParams<G2, N2>,
        s: G1::FieldElement,
        cs: Commitment<G1, N1>,
        p: G1,
        px: Commitment<G2, N2>,
        py: Commitment<G2, N2>,
        q: G1,
        R: G1,
        secparam: usize,
    ) -> Self {
        use group::ScalarElement;
        let mut alpha: Vec<G1::FieldElement> = vec![G1::FieldElement::ZERO; secparam];
        let mut r: Vec<G1::FieldElement> = vec![G1::FieldElement::ZERO; secparam];
        let mut t: Vec<G1> = vec![G1::identity(); secparam];
        let mut a: Vec<G1> = vec![G1::identity(); secparam];
        let mut tx: Vec<Commitment<G2, N2>> = vec![
            Commitment {
                commitment: G2::identity(),
                blinding: G2::FieldElement::ZERO
            };
            secparam
        ];
        let mut ty: Vec<Commitment<G2, N2>> = vec![
            Commitment {
                commitment: G2::identity(),
                blinding: G2::FieldElement::ZERO
            };
            secparam
        ];
        for i in 0..secparam {
            alpha[i] = G1::random_scalar();
            r[i] = G1::random_scalar();
            t[i] = g1_params.g * alpha[i];
            a[i] = t[i] + g1_params.h * r[i];
            let coord_t = t[i].to_affine();
            let (x, y) = (coord_t.x(), coord_t.y());
            let x = transform_field_element(x);
            let y = transform_field_element(y);

            tx[i] = g2_params.commit(x);
            ty[i] = g2_params.commit(y);
        }
        let mut pt_hasher = group::Hasher::<Sha256, G1, N1>::new();
        pt_hasher.update(px.commitment);
        pt_hasher.update(py.commitment);
        for i in 0..secparam {
            pt_hasher.update(a[i]);
            pt_hasher.update(tx[i].commitment);
            pt_hasher.update(ty[i].commitment);
        }
        let mut challenge = pt_hasher.finalize();
        let mut challenges = vec![];
        for _ in 0..secparam {
            challenges.push(challenge);
            challenge >>= 1;
        }
        let all_proofs: Vec<SignatureProof<G1, N1, G2, N2>> = (0..secparam)
            .into_par_iter()
            .map(|i| {
                if challenges[i].is_odd().unwrap_u8() == 1 {
                    SignatureProof::Odd(SignatureProofOdd {
                        a: a[i],
                        tx: tx[i].commitment,
                        ty: ty[i].commitment,
                        alpha: alpha[i],
                        beta1: r[i],
                        beta2: tx[i].blinding,
                        beta3: ty[i].blinding,
                    })
                } else {
                    let z = alpha[i].sub_mod(&G1::new_scalar(s), &G1::ORDER);
                    let t1 = z * g1_params.g + q;
                    let coord_t1 = t1.to_affine();
                    let (x, y) = (
                        transform_field_element(coord_t1.x()),
                        transform_field_element(coord_t1.y()),
                    );
                    let t1x = g2_params.commit(x);
                    let t1y = g2_params.commit(y);
                    let p_affine = p.to_affine();
                    let t_affine = t[i].to_affine();
                    let t1_affine = t1.to_affine();
                    let t1_x = transform_field_element(t1_affine.x());
                    let t1_y = transform_field_element(t1_affine.y());
                    let point_add_proof = PointAddProof::prove(
                        g2_params,
                        t1_x,
                        t1_y,
                        transform_field_element(p_affine.x()),
                        transform_field_element(p_affine.y()),
                        transform_field_element(t_affine.x()),
                        t1x,
                        t1y,
                        px,
                        py,
                        tx[i],
                        ty[i],
                    );
                    SignatureProof::Even(SignatureProofEven {
                        a: a[i],
                        tx: tx[i].commitment,
                        ty: ty[i].commitment,
                        z,
                        z2: r[i].sub_mod(&cs.blinding, &G1::ORDER),
                        proof: point_add_proof,
                        r1: t1x.blinding,
                        r2: t1y.blinding,
                    })
                }
            })
            .collect::<Vec<_>>();

        SignatureProofList {
            proofs: all_proofs,
            secparam,
            g1_params,
            g2_params,
            r: R,
            c_lambda: cs.commitment,
            p_x: px.commitment,
            p_y: py.commitment,
        }
    }
    pub fn verify_from_hash(&self, msg_hash: &[u8]) -> bool {
        use group::ScalarElement;

        let z: G1::FieldElement =
            truncate_to_order::<G1, N1, G2, N2>(G2::FieldElement::from_slice(&msg_hash));
        let r_affine = self.r.to_affine();
        let r_inv = r_affine.x().inv_mod(&G1::ORDER).unwrap();
        let z1 = r_inv.mul_mod(&z, &G1::ORDER);
        let Q = G1::generator() * z1;
        self.verify(Q)
    }
    fn verify(&self, q: G1) -> bool {
        let mut pt_hasher = group::Hasher::<Sha256, G1, N1>::new();
        pt_hasher.update(self.p_x);
        pt_hasher.update(self.p_y);
        for i in 0..self.secparam {
            match self.proofs[i] {
                SignatureProof::Odd(SignatureProofOdd { a, tx, ty, .. })
                | SignatureProof::Even(SignatureProofEven { a, tx, ty, .. }) => {
                    pt_hasher.update(a);
                    pt_hasher.update(tx);
                    pt_hasher.update(ty);
                }
                SignatureProof::Empty => return false,
            }
        }
        let mut challenge = pt_hasher.finalize();
        let mut challenges = vec![];
        for _ in 0..self.secparam {
            challenges.push(challenge);
            challenge >>= 1;
        }
        let slice = self.proofs.as_slice();
        // why do we need a shuffle?
        // slice.shuffle(&mut OsRng);
        (0..self.secparam).into_par_iter().all(|i| match slice[i] {
            SignatureProof::Odd(SignatureProofOdd {
                a,
                tx,
                ty,
                alpha,
                beta1,
                beta2,
                beta3,
            }) if challenges[i].is_odd().unwrap_u8() == 1 => {
                let t = self.g1_params.g * alpha;
                let b = self.g1_params.h * beta1;
                let sum = a - (t + b);
                if !G1::is_on_group(sum) || sum != G1::identity() {
                    println!("odd first");
                    return false;
                }
                let coord_t = t.to_affine();
                let sx = G2::new_scalar(transform_field_element(coord_t.x()));
                let sum = tx - (self.g2_params.g * sx + self.g2_params.h * beta2);
                if !G2::is_on_group(sum) || sum != G2::identity() {
                    println!("odd second");
                    return false;
                }
                let sy = G2::new_scalar(transform_field_element(coord_t.y()));
                let sum = ty - (self.g2_params.g * sy + self.g2_params.h * beta3);
                if !G2::is_on_group(sum) || sum != G2::identity() {
                    println!("odd third");
                    return false;
                }
                true
            }
            SignatureProof::Even(SignatureProofEven {
                a,
                tx,
                ty,
                z,
                z2,
                proof,
                r1,
                r2,
            }) if challenges[i].is_even().unwrap_u8() == 1 => {
                let t1 = self.g1_params.g * z;
                let sum = self.c_lambda + t1 + self.g1_params.h * z2 - a;
                if !G1::is_on_group(sum) || sum != G1::identity() {
                    println!("even first");
                    return false;
                }
                let t1 = t1 + q;

                let coord_t1 = t1.to_affine();
                let sx = G2::new_scalar(transform_field_element(coord_t1.x()));
                let sy = G2::new_scalar(transform_field_element(coord_t1.y()));
                let t1x = self.g2_params.g.dblmul(sx, self.g2_params.h, r1);
                let t1y = self.g2_params.g.dblmul(sy, self.g2_params.h, r2);

                if !proof.verify(t1x, t1y, self.p_x, self.p_y, tx, ty) {
                    println!("even second");
                    return false;
                }
                true
            }
            _ => return false,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crypto_bigint::Encoding;
    use group::Group;
    use p256::{
        ecdsa::{signature::SignerMut, Signature},
        elliptic_curve::{sec1::Coordinates, Field},
        EncodedPoint,
    };
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};
    use tom256::{ProjectivePoint, U320};

    use crate::pedersen::EqualityProof;

    use super::{MultiplicationProof, PedersenParams, PointAddProof, SignatureProofList};

    #[test]
    fn test_equality() {
        let x = ProjectivePoint::new_scalar(U320::from_u64(5));
        let ped_param = PedersenParams::<ProjectivePoint, 40>::new();
        let c1 = ped_param.commit(x);
        let c2 = ped_param.commit(x);
        assert_ne!(c1, c2);
        assert_eq!(c1.commitment, ped_param.g * x + c1.blinding * ped_param.h);

        let proof = EqualityProof::prove(ped_param, x, c1, c2);
        assert!(proof.verify(c1.commitment, c2.commitment));

        let mut serialized_proof = Cursor::new(proof.serialize());
        let deserialized_proof =
            EqualityProof::<ProjectivePoint, 40>::deserialize(&mut serialized_proof).unwrap();
        assert!(deserialized_proof.verify(c1.commitment, c2.commitment))
    }
    #[test]
    fn test_multiplication() {
        let ped_param = PedersenParams::<ProjectivePoint, 40>::new();
        let x = ProjectivePoint::random_scalar();
        let y = ProjectivePoint::random_scalar();
        let cx = ped_param.commit(x);
        let cy = ped_param.commit(y);
        let z = x.mul_mod(&y, &ProjectivePoint::ORDER.to_nz().unwrap());
        let cz = ped_param.commit(z);
        let proof = MultiplicationProof::prove(ped_param, x, y, z, cx, cy, cz);
        assert!(proof.verify(cx.commitment, cy.commitment, cz.commitment));

        let mut serialized_proof = Cursor::new(proof.serialize());
        let deserialized_proof =
            MultiplicationProof::<ProjectivePoint, 40>::deserialize(&mut serialized_proof).unwrap();
        assert!(deserialized_proof.verify(cx.commitment, cy.commitment, cz.commitment));
    }
    #[test]
    fn test_point_add() {
        let p1 = p256::ProjectivePoint::GENERATOR * p256::Scalar::random(&mut OsRng);
        let p2 = p256::ProjectivePoint::GENERATOR * p256::Scalar::random(&mut OsRng);
        let p3 = p1 + p2;
        let (x1, y1) = get_pts(p1);
        let (x2, y2) = get_pts(p2);
        let (x3, y3) = get_pts(p3);

        let params = PedersenParams::<tom256::ProjectivePoint, 40>::new();
        let p1x = params.commit(x1);
        let p2x = params.commit(x2);
        let p3x = params.commit(x3);
        let p1y = params.commit(y1);
        let p2y = params.commit(y2);
        let p3y = params.commit(y3);

        let proof = PointAddProof::prove(params, x1, y1, x2, y2, x3, p1x, p1y, p2x, p2y, p3x, p3y);
        assert!(proof.verify(
            p1x.commitment,
            p1y.commitment,
            p2x.commitment,
            p2y.commitment,
            p3x.commitment,
            p3y.commitment
        ));

        let mut serialized_proof = Cursor::new(proof.serialize());
        let deserialized_proof =
            PointAddProof::<tom256::ProjectivePoint, 40>::deserialize(&mut serialized_proof)
                .unwrap();
        assert!(deserialized_proof.verify(
            p1x.commitment,
            p1y.commitment,
            p2x.commitment,
            p2y.commitment,
            p3x.commitment,
            p3y.commitment
        ));
    }
    #[test]
    fn test_signature() {
        let mut kp = p256::ecdsa::SigningKey::random(&mut OsRng);
        let pub_key = kp.verifying_key().to_sec1_bytes().to_vec();
        let sig: Signature = kp.sign(b"hallo");
        let msg_hash = Sha256::digest(b"hallo").to_vec();
        let signature = sig.to_vec();
        let params_nist = PedersenParams::<p256_arithmetic::ProjectivePoint, 32>::new();
        let params_tom = PedersenParams::<tom256::ProjectivePoint, 40>::new();
        let proof = SignatureProofList::from_signature(
            params_nist,
            params_tom,
            &signature,
            &msg_hash,
            &pub_key,
            80,
        );
        assert!(proof.verify_from_hash(&msg_hash))
    }

    fn get_pts(p: p256::ProjectivePoint) -> (U320, U320) {
        use p256::elliptic_curve::bigint::ArrayEncoding;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let point_bytes: EncodedPoint = p.to_encoded_point(false);
        let Coordinates::Uncompressed {
            x: x_bytes,
            y: y_bytes,
        } = point_bytes.coordinates()
        else {
            panic!("")
        };
        let x_fe = p256::FieldElement::from_bytes(x_bytes).unwrap();
        let y_fe = p256::FieldElement::from_bytes(y_bytes).unwrap();
        let mut x: [u8; 40] = [0; 40];
        let mut y: [u8; 40] = [0; 40];
        let x_c = x_fe.to_canonical();
        let y_c = y_fe.to_canonical();
        let x_c = x_c.to_be_byte_array();
        let y_c = y_c.to_be_byte_array();
        x[8..].copy_from_slice(x_c.as_slice());
        y[8..].copy_from_slice(y_c.as_slice());
        (U320::from_be_slice(&x), U320::from_be_bytes(y))
    }
}
