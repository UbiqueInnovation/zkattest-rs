use std::ops::{Add, Mul, Neg, Sub};

use crypto_bigint::{ConstZero, Constants, NonZero, U256};
use group::{Coords, Group, ScalarElement, WeierstrassGroup};
use sha2::Digest;

pub type FieldElement = U256;

#[derive(Debug, Clone, Copy)]
pub struct AffinePoint {
    pub x: FieldElement,
    pub y: FieldElement,
}

#[derive(Debug, Clone, Copy)]
pub struct ProjectivePoint {
    pub affine_point: AffinePoint,
    pub z: FieldElement,
}

impl Coords<U256> for AffinePoint {
    fn x(&self) -> U256 {
        self.x
    }

    fn y(&self) -> U256 {
        self.y
    }
}

impl Group<32> for ProjectivePoint {
    type FieldElement = U256;

    type NonZeroFieldElement = NonZero<U256>;

    type AffinePoint = AffinePoint;

    const ORDER: Self::FieldElement =
        U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

    const PRIME_MOD: Self::FieldElement =
        U256::from_be_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

    fn identity() -> Self {
        Self {
            affine_point: AffinePoint {
                x: U256::ZERO,
                y: U256::ONE,
            },
            z: U256::ZERO,
        }
    }

    fn generator() -> Self {
        Self {
            affine_point: AffinePoint {
                x: U256::from_be_hex(
                    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                ),
                y: U256::from_be_hex(
                    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                ),
            },
            z: U256::ONE,
        }
    }

    fn new_scalar(s: Self::FieldElement) -> Self::FieldElement {
        s % Self::ORDER.to_nz().unwrap()
    }

    fn random_scalar() -> Self::FieldElement {
        let val: [u64; U256::LIMBS] = rand::random();
        U256::from_words(val)
            .rem(&Self::ORDER.to_nz().unwrap())
            .into()
    }

    fn is_on_group(point: Self) -> bool {
        WeierstrassGroup::is_on_group(point)
    }

    fn size_point_bytes() -> usize {
        32
    }

    fn equal(&self, other: Self) -> bool {
        WeierstrassGroup::equal(self, other)
    }

    fn dblmul(&self, left: Self::FieldElement, point: Self, right: Self::FieldElement) -> Self {
        WeierstrassGroup::dblmul(&self, left, point, right)
    }

    fn to_bytes(&self) -> Vec<u8> {
        WeierstrassGroup::to_bytes(self)
    }

    fn hash_points<D: Digest>(pts: Vec<Self>) -> Self::FieldElement {
        WeierstrassGroup::hash_points::<D>(pts)
    }

    fn to_affine(&self) -> Self::AffinePoint {
        WeierstrassGroup::to_affine(self)
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        ProjectivePoint::from_slice(bytes)
    }
}

impl WeierstrassGroup<32> for ProjectivePoint {
    const a: Self::FieldElement =
        U256::from_be_hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");

    const b: Self::FieldElement =
        U256::from_be_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

    fn x(&self) -> Self::FieldElement {
        self.affine_point.x
    }

    fn y(&self) -> Self::FieldElement {
        self.affine_point.y
    }

    fn z(&self) -> Self::FieldElement {
        self.z
    }

    fn new(x: Self::FieldElement, y: Self::FieldElement, z: Self::FieldElement) -> Self {
        Self {
            affine_point: AffinePoint { x, y },
            z,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        ProjectivePoint::to_bytes(&self).to_vec()
    }

    fn to_affine(&self) -> Self::AffinePoint {
        let z_inv = self.z.inv_mod(&Self::PRIME_MOD).unwrap();
        let x = Self::mulfe(self.x(), z_inv);
        let y = Self::mulfe(self.y(), z_inv);
        AffinePoint { x, y }
    }
}

impl ProjectivePoint {
    pub fn from_slice(bytes: &[u8]) -> Option<ProjectivePoint> {
        if bytes.len() != 65 {
            return None;
        }
        if bytes[0] == 0 {
            return Some(Self::identity());
        }
        if bytes[0] != 0x04 {
            return None;
        }
        let x_tmp = &bytes[1..33];
        let y_tmp = &bytes[33..];
        let mut x = [0; 32];
        let mut y = [0; 32];
        x.copy_from_slice(x_tmp);
        y.copy_from_slice(y_tmp);
        let x = U256::from_be_slice(&x);
        let y = U256::from_be_slice(&y);
        let point = AffinePoint { x, y };
        Some(point.into())
    }
    pub fn to_bytes(&self) -> [u8; 65] {
        if self.is_identity() {
            return [0; 65];
        }
        let affine_point = Group::to_affine(self);
        let mut result = [0; 65];
        result[0] = 0x04;
        let x = affine_point.x.to_be_bytes();
        let y = affine_point.y.to_be_bytes();
        result[1..33].copy_from_slice(&x);
        result[33..].copy_from_slice(&y);
        result
    }
}

impl From<AffinePoint> for ProjectivePoint {
    fn from(value: AffinePoint) -> Self {
        ProjectivePoint {
            affine_point: value,
            z: U256::from_u8(1),
        }
    }
}
impl From<&AffinePoint> for ProjectivePoint {
    fn from(value: &AffinePoint) -> Self {
        ProjectivePoint {
            affine_point: value.clone(),
            z: U256::from_u8(1),
        }
    }
}

impl Mul<U256> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, rhs: U256) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl Sub for ProjectivePoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.add(rhs.neg())
    }
}

impl PartialEq for ProjectivePoint {
    fn eq(&self, other: &Self) -> bool {
        WeierstrassGroup::equal(self, *other)
    }
}
impl Add for ProjectivePoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        WeierstrassGroup::add(&self, rhs)
    }
}
impl Neg for ProjectivePoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        WeierstrassGroup::neg(&self)
    }
}

impl Mul<ProjectivePoint> for U256 {
    type Output = ProjectivePoint;

    fn mul(self, rhs: ProjectivePoint) -> Self::Output {
        rhs.scalar_mul(self)
    }
}

#[cfg(test)]
mod tests {

    use crypto_bigint::U256;
    use group::{Group, WeierstrassGroup};

    use crate::ProjectivePoint;

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
        assert!(WeierstrassGroup::is_on_group(ProjectivePoint::generator()));
    }
    #[test]
    fn identity_is_identity() {
        assert!(ProjectivePoint::identity().is_identity())
    }
    #[test]
    fn identity_leaves_invariant() {
        let id = ProjectivePoint::identity() + ProjectivePoint::identity();
        assert_eq!(id, ProjectivePoint::identity());
        let gen = ProjectivePoint::generator() + U256::from_u8(3) * ProjectivePoint::identity();
        assert_eq!(ProjectivePoint::generator(), gen);
    }
    #[test]
    fn test_dbl() {
        let d = ProjectivePoint::generator().dbl();
        assert_eq!(
            d,
            ProjectivePoint::generator() + ProjectivePoint::generator()
        );
    }
    #[test]
    fn inverse_is_identity() {
        let two = U256::from_u8(2);
        let inv_two = two
            .inv_mod(&ProjectivePoint::PRIME_MOD.to_nz().unwrap())
            .unwrap();
        let id = two.mul_mod(&inv_two, &ProjectivePoint::PRIME_MOD.to_nz().unwrap());
        assert_eq!(id, U256::ONE);
        let test = U256::from_u8(3) * ProjectivePoint::generator();
        let test2 = ProjectivePoint::generator()
            + ProjectivePoint::generator()
            + ProjectivePoint::generator();
        let test3 = test2 - test;
        assert_eq!(test, test2);
        assert!(test3.is_identity());
    }
    #[test]
    #[allow(non_snake_case)]
    fn cloudflare_tests() {
        let P1 = ProjectivePoint::ORDER * ProjectivePoint::generator();
        assert!(P1.is_identity());
        assert!(WeierstrassGroup::is_on_group(P1));
        let mut k = ProjectivePoint::random_scalar();
        let mut p = k * ProjectivePoint::generator();
        for _ in 0..10 {
            k = ProjectivePoint::random_scalar();
            p = k * p;
            assert!(WeierstrassGroup::is_on_group(p));
        }
        let r1 = ProjectivePoint::new_scalar(ProjectivePoint::ORDER - U256::from_u8(1));
        let q = r1 * p;
        let r = p + q;
        assert!(r.is_identity());
        let k1 = ProjectivePoint::random_scalar();
        let k2 = ProjectivePoint::random_scalar();
        let s = WeierstrassGroup::dblmul(&p, k1, q, k2);
        assert_eq!(s, k1 * p + k2 * q);
        let id = ProjectivePoint::identity();
        let b = id.to_bytes();
        let des_id = ProjectivePoint::from_slice(&b).unwrap();
        assert!(des_id.is_identity());
        assert_eq!(id, des_id);

        for _ in 0..10 {
            let sk = ProjectivePoint::random_scalar();
            let pt = sk * ProjectivePoint::generator();
            let bs = pt.to_bytes();
            let deser_p = ProjectivePoint::from_slice(&bs).unwrap();
            assert_eq!(pt, deser_p)
        }
    }
}
