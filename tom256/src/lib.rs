use std::ops::{Add, Mul, Neg, Sub};

pub use crypto_bigint::U320;
use crypto_bigint::{NonZero, RandomMod};
use group::{Coords, EdwardsGroup, Group};
use rand::rngs::OsRng;
use sha2::Digest;

#[derive(Debug, Clone, Copy)]
pub struct Scalar(pub U320);
pub type FieldElement = U320;

// pub const ORDER: Scalar = Scalar(U320::from_be_hex(
//     "0000000000000000ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
// ));

// pub const PRIME_MOD: NonZero<U320> = NonZero::<U320>::new_unwrap(U320::from_be_hex(
//     "0000000000000003fffffffc000000040000000000000002ae382c7957cc4ff9713c3d82bc47d3af",
// ));

// pub const A: NonZero<U320> = NonZero::<U320>::new_unwrap(U320::from_be_hex(
//     "0000000000000001abce3fd8e1d7a21252515332a512e09d4249bd5b1ec35e316c02254fe8cedf5d",
// ));
// pub const D: NonZero<U320> = NonZero::<U320>::new_unwrap(U320::from_be_hex(
//     "000000000000000051781d9823abde00ec99295ba542c8b1401874bcbeb9e9c861174c7bca6a02aa",
// ));

// pub struct Tom256;
#[derive(Debug, Clone, Copy)]
pub struct AffinePoint {
    pub x: FieldElement,
    pub y: FieldElement,
}

#[derive(Debug, Clone, Copy)]
pub struct ProjectivePoint {
    pub affine_point: AffinePoint,
    pub z: FieldElement,
    pub t: FieldElement,
}
impl Coords<U320> for AffinePoint {
    fn x(&self) -> U320 {
        self.x
    }

    fn y(&self) -> U320 {
        self.y
    }
}

impl Group<40> for ProjectivePoint {
    type FieldElement = U320;

    type NonZeroFieldElement = NonZero<U320>;

    type AffinePoint = AffinePoint;

    const ORDER: Self::FieldElement = U320::from_be_hex(
        "0000000000000000ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );

    const PRIME_MOD: Self::FieldElement = U320::from_be_hex(
        "0000000000000003fffffffc000000040000000000000002ae382c7957cc4ff9713c3d82bc47d3af",
    );

    fn identity() -> Self {
        ProjectivePoint {
            affine_point: AffinePoint {
                x: U320::from_u8(0),
                y: U320::from_u8(1),
            },
            t: U320::from_u8(0),
            z: U320::from_u8(1),
        }
    }

    fn is_identity(&self) -> bool {
        EdwardsGroup::is_identity(self)
    }

    fn generator() -> Self {
        GENERATOR.into()
    }

    fn new_scalar(s: Self::FieldElement) -> Self::FieldElement {
        s % Self::ORDER.to_nz().unwrap()
    }

    fn random_scalar() -> Self::FieldElement {
        U320::random_mod(&mut OsRng, &Self::ORDER.to_nz().unwrap())
    }

    fn is_on_group(point: Self) -> bool {
        EdwardsGroup::is_on_group(point)
    }

    fn size_point_bytes() -> usize {
        67
    }

    fn equal(&self, other: Self) -> bool {
        EdwardsGroup::equal(self, other)
    }

    fn dblmul(&self, left: Self::FieldElement, point: Self, right: Self::FieldElement) -> Self {
        EdwardsGroup::dblmul(&self, left, point, right)
    }

    fn to_bytes(&self) -> Vec<u8> {
        EdwardsGroup::to_bytes(self)
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        ProjectivePoint::from_slice(bytes)
    }

    fn hash_points<D: Digest>(pts: Vec<Self>) -> Self::FieldElement {
        EdwardsGroup::hash_points::<D>(pts)
    }
    fn to_affine(&self) -> Self::AffinePoint {
        EdwardsGroup::to_affine(self)
    }

    fn to_nonzero(fe: Self::FieldElement) -> Self::NonZeroFieldElement {
        fe.to_nz().unwrap()
    }
}

impl EdwardsGroup<40> for ProjectivePoint {
    const a: Self::FieldElement = U320::from_be_hex(
        "0000000000000001abce3fd8e1d7a21252515332a512e09d4249bd5b1ec35e316c02254fe8cedf5d",
    );

    const d: Self::FieldElement = U320::from_be_hex(
        "000000000000000051781d9823abde00ec99295ba542c8b1401874bcbeb9e9c861174c7bca6a02aa",
    );

    fn x(&self) -> Self::FieldElement {
        self.affine_point.x
    }

    fn y(&self) -> Self::FieldElement {
        self.affine_point.y
    }

    fn z(&self) -> Self::FieldElement {
        self.z
    }

    fn t(&self) -> Self::FieldElement {
        self.t
    }

    fn new(
        x: Self::FieldElement,
        y: Self::FieldElement,
        t: Self::FieldElement,
        z: Self::FieldElement,
    ) -> Self {
        Self {
            affine_point: AffinePoint { x, y },
            t,
            z,
        }
    }

    fn to_affine(&self) -> Self::AffinePoint {
        let z_inv = self.z.inv_mod(&Self::PRIME_MOD.to_nz().unwrap()).unwrap();
        let x = self
            .affine_point
            .x
            .mul_mod(&z_inv, &Self::PRIME_MOD.to_nz().unwrap());
        let y = self
            .affine_point
            .y
            .mul_mod(&z_inv, &Self::PRIME_MOD.to_nz().unwrap());
        AffinePoint { x, y }
    }

    fn to_bytes(&self) -> Vec<u8> {
        ProjectivePoint::to_bytes(&self).to_vec()
    }
}

impl Mul<U320> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, rhs: U320) -> Self::Output {
        self.scalar_mul(rhs)
    }
}
impl Sub for ProjectivePoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.add(rhs.neg())
    }
}

impl From<AffinePoint> for ProjectivePoint {
    fn from(value: AffinePoint) -> Self {
        let t = value.x.mul_mod(&value.y, &Self::PRIME_MOD.to_nz().unwrap());
        ProjectivePoint {
            affine_point: value,
            t,
            z: U320::from_u8(1),
        }
    }
}
impl From<&AffinePoint> for ProjectivePoint {
    fn from(value: &AffinePoint) -> Self {
        ProjectivePoint {
            affine_point: value.clone(),
            t: value.x.mul_mod(&value.y, &Self::PRIME_MOD.to_nz().unwrap()),
            z: U320::from_u8(1),
        }
    }
}
const fn as_point(arr: [Scalar; 2]) -> AffinePoint {
    AffinePoint {
        x: arr[0].0,
        y: arr[1].0,
    }
}

pub const GENERATOR: AffinePoint = as_point([
    Scalar(U320::from_be_hex(
        "00000000000000007907055d0a7d4abc3eafdc25d431d9659fbe007ee2d8ddc4e906206ea9ba4fdb",
    )),
    Scalar(U320::from_be_hex(
        "0000000000000000be231cb9f9bf18319c9f081141559b0a33dddccd2221f0464a9cd57081b01a01",
    )),
]);

impl ProjectivePoint {
    pub fn from_slice(bytes: &[u8]) -> Option<ProjectivePoint> {
        if bytes.len() != 67 {
            return None;
        }
        if bytes[0] != 0x04 {
            return None;
        }
        let x_tmp = &bytes[1..34];
        let y_tmp = &bytes[34..];
        let mut x = [0; 40];
        let mut y = [0; 40];
        x[7..].copy_from_slice(x_tmp);
        y[7..].copy_from_slice(y_tmp);
        let x = U320::from_be_slice(&x);
        let y = U320::from_be_slice(&y);
        let point = AffinePoint { x, y };
        Some(point.into())
    }
    pub fn to_bytes(&self) -> [u8; 67] {
        let affine_point = Group::to_affine(self);
        let mut result = [0; 67];
        result[0] = 0x04;
        let x = affine_point.x.to_be_bytes();
        let y = affine_point.y.to_be_bytes();
        result[1..34].copy_from_slice(&x[7..]);
        result[34..].copy_from_slice(&y[7..]);
        result
    }
}

impl PartialEq for ProjectivePoint {
    fn eq(&self, other: &Self) -> bool {
        EdwardsGroup::equal(self, *other)
    }
}

impl Neg for ProjectivePoint {
    type Output = ProjectivePoint;

    fn neg(self) -> Self::Output {
        EdwardsGroup::neg(&self)
    }
}

impl Add for ProjectivePoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        EdwardsGroup::add(&self, rhs)
    }
}

impl Sub for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, rhs: Self) -> Self::Output {
        *self + rhs.neg()
    }
}
impl Mul<ProjectivePoint> for Scalar {
    type Output = ProjectivePoint;

    fn mul(self, rhs: ProjectivePoint) -> Self::Output {
        &rhs * self
    }
}
impl Mul<ProjectivePoint> for U320 {
    type Output = ProjectivePoint;

    fn mul(self, rhs: ProjectivePoint) -> Self::Output {
        rhs.scalar_mul(self)
    }
}

impl Mul<Scalar> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, rhs: Scalar) -> Self::Output {
        self.scalar_mul(rhs.0)
    }
}

impl Mul<u128> for ProjectivePoint {
    type Output = Self;

    fn mul(self, rhs: u128) -> Self::Output {
        &self * Scalar::from(rhs)
    }
}

impl Mul<ProjectivePoint> for u128 {
    type Output = ProjectivePoint;

    fn mul(self, rhs: ProjectivePoint) -> Self::Output {
        &rhs * Scalar::from(self)
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, rhs: Scalar) -> Self::Output {
        Scalar(self.0.add_mod(&rhs.0, &ProjectivePoint::PRIME_MOD))
    }
}
impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, rhs: Scalar) -> Self::Output {
        Scalar(self.0.sub_mod(&rhs.0, &ProjectivePoint::PRIME_MOD))
    }
}
impl Mul<Scalar> for Scalar {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Scalar(
            self.0
                .mul_mod(&rhs.0, &ProjectivePoint::PRIME_MOD.to_nz().unwrap()),
        )
    }
}

impl From<u8> for Scalar {
    fn from(value: u8) -> Self {
        Scalar(U320::from_u8(value) % ProjectivePoint::PRIME_MOD.to_nz().unwrap())
    }
}
impl From<u16> for Scalar {
    fn from(value: u16) -> Self {
        Scalar(U320::from_u16(value) % ProjectivePoint::PRIME_MOD.to_nz().unwrap())
    }
}
impl From<u32> for Scalar {
    fn from(value: u32) -> Self {
        Scalar(U320::from_u32(value) % ProjectivePoint::PRIME_MOD.to_nz().unwrap())
    }
}
impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Scalar(U320::from_u64(value) % ProjectivePoint::PRIME_MOD.to_nz().unwrap())
    }
}
impl From<u128> for Scalar {
    fn from(value: u128) -> Self {
        Scalar(U320::from_u128(value) % ProjectivePoint::PRIME_MOD.to_nz().unwrap())
    }
}

impl From<U320> for Scalar {
    fn from(value: U320) -> Self {
        Scalar(value)
    }
}

#[cfg(test)]
mod tests {

    use crypto_bigint::{BitOps, U320};
    use group::{EdwardsGroup, Group};

    use crate::{ProjectivePoint, Scalar};

    #[test]
    fn test_to_bytes() {
        let a = ProjectivePoint::generator();
        let serialized = a.to_bytes();
        let b = ProjectivePoint::from_slice(&serialized).unwrap();
        assert_eq!(a.affine_point.x, b.affine_point.x);
        assert_eq!(a.affine_point.y, b.affine_point.y);
    }

    #[test]
    fn generator_is_on_curve() {
        assert!(EdwardsGroup::is_on_group(ProjectivePoint::generator()));
    }
    #[test]
    fn identity_is_identity() {
        assert!(Group::is_identity(&ProjectivePoint::identity()))
    }
    #[test]
    fn identity_leaves_invariant() {
        let id = ProjectivePoint::identity() + ProjectivePoint::identity();
        assert_eq!(id, ProjectivePoint::identity());
        let gen = ProjectivePoint::generator() + U320::from_u8(3) * ProjectivePoint::identity();
        assert_eq!(ProjectivePoint::generator(), gen);
    }
    #[test]
    fn test_dbl() {
        let d = ProjectivePoint::identity().dbl();
        assert_eq!(d, ProjectivePoint::identity());
    }
    #[test]
    fn inverse_is_identity() {
        let two = U320::from_u8(2);
        let inv_two = two
            .inv_mod(&ProjectivePoint::PRIME_MOD.to_nz().unwrap())
            .unwrap();
        let id = two.mul_mod(&inv_two, &ProjectivePoint::PRIME_MOD.to_nz().unwrap());
        assert_eq!(id, U320::ONE);
        let test = 3 * ProjectivePoint::generator();
        let test2 = ProjectivePoint::generator()
            + ProjectivePoint::generator()
            + ProjectivePoint::generator();
        let test3 = &test2 - &test;
        assert_eq!(test, test2);
        assert!(Group::is_identity(&test3));
    }
    #[test]
    #[allow(non_snake_case)]
    fn cloudflare_tests() {
        let P1 = ProjectivePoint::ORDER * ProjectivePoint::generator();
        assert!(Group::is_identity(&P1));
        assert!(EdwardsGroup::is_on_group(P1));

        let mut k = ProjectivePoint::random_scalar();
        let mut p = k * ProjectivePoint::generator();
        for _ in 0..10 {
            k = ProjectivePoint::random_scalar();
            p = k * p;
            assert!(EdwardsGroup::is_on_group(p));
        }

        let r1 = ProjectivePoint::new_scalar(ProjectivePoint::ORDER - Scalar::from(1u128).0);
        let q = r1 * p;
        let r = p + q;
        assert!(Group::is_identity(&r));

        let k1 = ProjectivePoint::random_scalar();
        let k2 = ProjectivePoint::random_scalar();
        let s = EdwardsGroup::dblmul(&p, k1, q, k2);
        assert_eq!(s, k1 * p + k2 * q);
        let id = ProjectivePoint::identity();
        let b = id.to_bytes();
        let des_id = ProjectivePoint::from_slice(&b).unwrap();
        assert!(Group::is_identity(&des_id));
        assert_eq!(id, des_id);

        for _ in 0..10 {
            let sk = ProjectivePoint::random_scalar();
            let pt = sk * ProjectivePoint::generator();
            let bs = pt.to_bytes();
            let deser_p = ProjectivePoint::from_slice(&bs).unwrap();
            assert_eq!(pt, deser_p)
        }
    }
    #[test]
    fn order() {
        println!("{}", ProjectivePoint::PRIME_MOD.log2_bits())
    }
}
