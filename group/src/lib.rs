use std::{
    collections::HashMap,
    fmt::Debug,
    marker::PhantomData,
    ops::{Add, Mul, Neg, Sub},
};

use crypto_bigint::{AddMod, Integer, InvMod, MulMod, NegMod, SubMod, U256, U320};
use sha2::{digest::consts::U246, Digest};

pub trait ScalarElement<FieldElement, const N: usize> {
    const ZERO: FieldElement;
    const ONE: FieldElement;
    const N: usize = N;

    fn to_be_bytes(&self) -> [u8; N];
    fn from_slice(slice: &[u8]) -> Self
    where
        Self: Sized,
    {
        let mut bytes: [u8; N] = [0; N];
        if slice.len() >= Self::N {
            bytes.copy_from_slice(&slice[slice.len() - Self::N..]);
        } else {
            bytes[Self::N - slice.len()..].copy_from_slice(&slice);
        }
        Self::from_bytes(bytes)
    }
    fn from_bytes(bytes: [u8; N]) -> Self;
}

pub fn transform_field_element<
    F1: ScalarElement<F1, N1>,
    const N1: usize,
    F2: ScalarElement<F2, N2>,
    const N2: usize,
>(
    src: F1,
) -> F2 {
    F2::from_slice(&src.to_be_bytes())
}

impl ScalarElement<U320, 40> for U320 {
    const ZERO: U320 = U320::ZERO;

    const ONE: U320 = U320::ONE;

    fn to_be_bytes(&self) -> [u8; 40] {
        self.to_be_bytes()
    }

    fn from_bytes(slice: [u8; Self::N]) -> Self {
        U320::from_be_slice(&slice)
    }
}

impl ScalarElement<U256, 32> for U256 {
    const ZERO: U256 = U256::ZERO;

    const ONE: U256 = U256::ONE;

    fn to_be_bytes(&self) -> [u8; 32] {
        self.to_be_bytes()
    }

    fn from_bytes(slice: [u8; Self::N]) -> Self {
        U256::from_be_slice(&slice)
    }
}

pub trait Coords<FieldElement> {
    fn x(&self) -> FieldElement;
    fn y(&self) -> FieldElement;
}

pub trait Group<const N: usize>
where
    <Self as Group<N>>::FieldElement: InvMod
        + ScalarElement<<Self as Group<N>>::FieldElement, N>
        + Mul<Self, Output = Self>
        + Integer
        + PartialEq
        + Clone
        + Copy
        + Debug,

    Self: Sub<Output = Self>,
    Self: Add<Output = Self>,
    Self: Neg<Output = Self>,
    Self: Mul<<Self as Group<N>>::FieldElement, Output = Self>,
    Self: Clone + Copy + PartialEq + Debug + Sync + Send,
    <Self as Group<N>>::AffinePoint: Coords<Self::FieldElement>,
{
    type FieldElement;
    type NonZeroFieldElement;
    type AffinePoint;

    const ORDER: Self::FieldElement;
    const PRIME_MOD: Self::FieldElement;

    fn identity() -> Self;
    fn generator() -> Self;
    fn new_scalar(s: Self::FieldElement) -> Self::FieldElement;
    fn random_scalar() -> Self::FieldElement;
    fn is_on_group(point: Self) -> bool;
    fn size_point_bytes() -> usize;
    fn equal(&self, other: Self) -> bool;
    fn dblmul(&self, left: Self::FieldElement, point: Self, right: Self::FieldElement) -> Self;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
    fn hash_points<D: Digest>(pts: Vec<Self>) -> Self::FieldElement;
    fn to_affine(&self) -> Self::AffinePoint;
}

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
pub trait EdwardsGroup<const N: usize>: Group<N> {
    const a: Self::FieldElement;
    const d: Self::FieldElement;

    fn x(&self) -> Self::FieldElement;
    fn y(&self) -> Self::FieldElement;
    fn z(&self) -> Self::FieldElement;
    fn t(&self) -> Self::FieldElement;

    fn new(
        x: Self::FieldElement,
        y: Self::FieldElement,
        t: Self::FieldElement,
        z: Self::FieldElement,
    ) -> Self;

    fn equal(&self, other: Self) -> bool {
        let x0z1 = self.x().mul_mod(&other.z(), &Self::PRIME_MOD);
        let x1z0 = other.x().mul_mod(&self.z(), &Self::PRIME_MOD);
        let y0z1 = self.y().mul_mod(&other.z(), &Self::PRIME_MOD);
        let y1z0 = other.y().mul_mod(&self.z(), &Self::PRIME_MOD);
        x0z1 == x1z0 && y0z1 == y1z0
    }
    fn neg(&self) -> Self {
        let x = self.x().neg_mod(&Self::PRIME_MOD);
        let t = self.t().neg_mod(&Self::PRIME_MOD);
        Self::new(x, self.y(), t, self.z())
    }
    fn to_bytes(&self) -> Vec<u8>;

    fn to_affine(&self) -> Self::AffinePoint;
    fn is_on_group(pt: Self) -> bool {
        let x2 = pt.x().mul_mod(&pt.x(), &Self::PRIME_MOD);
        let y2 = pt.y().mul_mod(&pt.y(), &Self::PRIME_MOD);
        let t2 = pt.t().mul_mod(&pt.t(), &Self::PRIME_MOD);
        let z2 = pt.z().mul_mod(&pt.z(), &Self::PRIME_MOD);
        let l0 = Self::a
            .mul_mod(&x2, &Self::PRIME_MOD)
            .add_mod(&y2, &Self::PRIME_MOD);
        let r0 = Self::d
            .mul_mod(&t2, &Self::PRIME_MOD)
            .add_mod(&z2, &Self::PRIME_MOD);
        let l1 = pt.x().mul_mod(&pt.y(), &Self::PRIME_MOD);
        let r1 = pt.z().mul_mod(&pt.t(), &Self::PRIME_MOD);
        l0.sub_mod(&r0, &Self::PRIME_MOD) == Self::FieldElement::ZERO
            && l1.sub_mod(&r1, &Self::PRIME_MOD) == Self::FieldElement::ZERO
    }
    fn dbl(&self) -> Self {
        let other_a = self.x().mul_mod(&self.x(), &Self::PRIME_MOD);
        let B = self.y().mul_mod(&self.y(), &Self::PRIME_MOD);
        let CC = self.z().mul_mod(&self.z(), &Self::PRIME_MOD);
        let C = CC.add_mod(&CC, &Self::PRIME_MOD);
        let other_d = Self::a.mul_mod(&other_a, &Self::PRIME_MOD);
        let EE = self.x().add_mod(&self.y(), &Self::PRIME_MOD);
        let E = EE
            .mul_mod(&EE, &Self::PRIME_MOD)
            .sub_mod(&other_a, &Self::PRIME_MOD)
            .sub_mod(&B, &Self::PRIME_MOD);
        let G = other_d.add_mod(&B, &Self::PRIME_MOD);
        let F = G.sub_mod(&C, &Self::PRIME_MOD);
        let H = other_d.sub_mod(&B, &Self::PRIME_MOD);
        let x3 = E.mul_mod(&F, &Self::PRIME_MOD);
        let y3 = G.mul_mod(&H, &Self::PRIME_MOD);
        let t3 = E.mul_mod(&H, &Self::PRIME_MOD);
        let z3 = F.mul_mod(&G, &Self::PRIME_MOD);
        Self::new(x3, y3, t3, z3)
    }
    fn is_identity(&self) -> bool {
        self.x() == Self::FieldElement::ZERO
            && self.y() != Self::FieldElement::ZERO
            && self.t() == Self::FieldElement::ZERO
            && self.z() != Self::FieldElement::ZERO
            && self.z() == self.y()
    }
    fn dblmul(&self, left: Self::FieldElement, point: Self, right: Self::FieldElement) -> Self {
        let mut q = Self::identity();
        let k1 = left.to_be_bytes();
        let k2 = right.to_be_bytes();
        let mut curr = Self::identity();
        let mut map = HashMap::new();
        let mut curr2 = Self::identity();
        let mut map2 = HashMap::new();
        for i in 0..16 {
            map.insert(i, curr);
            curr = curr + *self;
            map2.insert(i, curr2);
            curr2 = curr2 + point;
        }
        for b in 0..N {
            let k1u = k1[b] / 16;
            let k1d = k1[b] % 16;
            let k2u = k2[b] / 16;
            let k2d = k2[b] % 16;
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.add(map[&k1u]);
            q = q.add(map2[&k2u]);

            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.add(map[&k1d]);
            q = q.add(map2[&k2d]);
        }
        q
    }
    fn add(&self, rhs: Self) -> Self {
        let other_a = self.x().mul_mod(&rhs.x(), &Self::PRIME_MOD);
        let B = self.y().mul_mod(&rhs.y(), &Self::PRIME_MOD);
        let C = Self::d
            .mul_mod(&self.t(), &Self::PRIME_MOD)
            .mul_mod(&rhs.t(), &Self::PRIME_MOD);
        let other_d = self.z().mul_mod(&rhs.z(), &Self::PRIME_MOD);
        let E1 = self.x().add_mod(&self.y(), &Self::PRIME_MOD);
        let E2 = rhs.x().add_mod(&rhs.y(), &Self::PRIME_MOD);
        let E = E1
            .mul_mod(&E2, &Self::PRIME_MOD)
            .sub_mod(&other_a, &Self::PRIME_MOD)
            .sub_mod(&B, &Self::PRIME_MOD);
        let F = other_d.sub_mod(&C, &Self::PRIME_MOD);
        let G = other_d.add_mod(&C, &Self::PRIME_MOD);
        let H = B.sub_mod(
            &Self::a.mul_mod(&other_a, &Self::PRIME_MOD),
            &Self::PRIME_MOD,
        );
        let x3 = E.mul_mod(&F, &Self::PRIME_MOD);
        let y3 = G.mul_mod(&H, &Self::PRIME_MOD);
        let t3 = E.mul_mod(&H, &Self::PRIME_MOD);
        let z3 = F.mul_mod(&G, &Self::PRIME_MOD);
        Self::new(x3, y3, t3, z3)
    }
    fn scalar_mul(&self, rhs: Self::FieldElement) -> Self {
        let mut q = Self::identity();
        let bytes = rhs.to_be_bytes();
        let mut curr = Self::identity();
        let mut map = HashMap::new();
        for i in 0..16 {
            map.insert(i, curr);
            curr = curr + *self;
        }
        for b in bytes {
            let upper = b / 16;
            let lower = b % 16;
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.add(map[&upper]);
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.add(map[&lower]);
        }
        q
    }
    fn hash_points<D: Digest>(pts: Vec<Self>) -> Self::FieldElement {
        let mut hasher = D::new();
        for p in pts {
            hasher.update(EdwardsGroup::to_bytes(&p));
        }
        let hash: Vec<u8> = hasher.finalize().to_vec();
        let mut scalar_bytes: [u8; N] = [0; N];
        if <D as Digest>::output_size() >= N {
            scalar_bytes.copy_from_slice(&hash[..N]);
        } else {
            let rest = N - <D as Digest>::output_size();
            scalar_bytes[rest..].copy_from_slice(hash.as_slice());
        }
        Self::new_scalar(Self::FieldElement::from_slice(&scalar_bytes))
    }
}

pub struct Hasher<D: Digest, G1, const N: usize>
where
    G1: Group<N>,
{
    data: D,
    _phantom: PhantomData<G1>,
}

impl<D: Digest, G1: Group<N>, const N: usize> Hasher<D, G1, N> {
    pub fn new() -> Self {
        Self {
            data: D::new(),
            _phantom: PhantomData,
        }
    }
    pub fn update<const N2: usize, G: Group<N2>>(&mut self, pt: G) {
        self.data.update(pt.to_bytes());
    }
    pub fn finalize(self) -> G1::FieldElement {
        let hash: Vec<u8> = self.data.finalize().to_vec();
        let mut scalar_bytes: [u8; N] = [0; N];
        if <D as Digest>::output_size() >= N {
            scalar_bytes.copy_from_slice(&hash[..N]);
        } else {
            let rest = N - <D as Digest>::output_size();
            scalar_bytes[rest..].copy_from_slice(hash.as_slice());
        }
        G1::new_scalar(G1::FieldElement::from_slice(&scalar_bytes))
    }
}

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
pub trait WeierstrassGroup<const N: usize>: Group<N> {
    const a: Self::FieldElement;
    const b: Self::FieldElement;

    fn x(&self) -> Self::FieldElement;
    fn y(&self) -> Self::FieldElement;
    fn z(&self) -> Self::FieldElement;

    fn new(x: Self::FieldElement, y: Self::FieldElement, z: Self::FieldElement) -> Self;

    fn equal(&self, other: Self) -> bool {
        let x0z1 = self.x().mul_mod(&other.z(), &Self::PRIME_MOD);
        let x1z0 = other.x().mul_mod(&self.z(), &Self::PRIME_MOD);
        let y0z1 = self.y().mul_mod(&other.z(), &Self::PRIME_MOD);
        let y1z0 = other.y().mul_mod(&self.z(), &Self::PRIME_MOD);
        x0z1 == x1z0 && y0z1 == y1z0
    }
    fn neg(&self) -> Self {
        let y = self.y().neg_mod(&Self::PRIME_MOD);
        Self::new(self.x(), y, self.z())
    }
    fn to_bytes(&self) -> Vec<u8>;

    fn fe2(x: Self::FieldElement) -> Self::FieldElement {
        x.mul_mod(&x, &Self::PRIME_MOD)
    }
    fn addfe(x: Self::FieldElement, y: Self::FieldElement) -> Self::FieldElement {
        x.add_mod(&y, &Self::PRIME_MOD)
    }
    fn subfe(x: Self::FieldElement, y: Self::FieldElement) -> Self::FieldElement {
        x.sub_mod(&y, &Self::PRIME_MOD)
    }
    fn mulfe(x: Self::FieldElement, y: Self::FieldElement) -> Self::FieldElement {
        x.mul_mod(&y, &Self::PRIME_MOD)
    }

    fn to_affine(&self) -> Self::AffinePoint;
    fn is_on_group(pt: Self) -> bool {
        let y2 = pt.y().mul_mod(&pt.y(), &Self::PRIME_MOD);
        let y2z = y2.mul_mod(&pt.z(), &Self::PRIME_MOD);
        let x3 = pt
            .x()
            .mul_mod(&pt.x(), &Self::PRIME_MOD)
            .mul_mod(&pt.x(), &Self::PRIME_MOD);
        let ax = Self::a.mul_mod(&pt.x(), &Self::PRIME_MOD);
        let z2 = pt.z().mul_mod(&pt.z(), &Self::PRIME_MOD);
        let axz2 = ax.mul_mod(&z2, &Self::PRIME_MOD);
        let z3 = z2.mul_mod(&pt.z(), &Self::PRIME_MOD);
        let bz3 = Self::b.mul_mod(&z3, &Self::PRIME_MOD);
        let t5 = y2z.sub_mod(
            &x3.add_mod(&axz2, &Self::PRIME_MOD)
                .add_mod(&bz3, &Self::PRIME_MOD),
            &Self::PRIME_MOD,
        );
        t5 == Self::FieldElement::ZERO
    }
    fn dbl(&self) -> Self {
        let (x, y, z) = (self.x(), self.y(), self.z());
        let b = Self::b;
        let t0 = Self::fe2(x);
        let t1 = Self::fe2(y);
        let t2 = Self::fe2(z);
        let t3 = Self::mulfe(x, y);
        let t3 = Self::addfe(t3, t3);
        let z3 = Self::mulfe(x, z);
        let z3 = Self::addfe(z3, z3);
        let y3 = Self::mulfe(b, t2);
        let y3 = Self::subfe(y3, z3);
        let x3 = Self::addfe(y3, y3);
        let y3 = Self::addfe(x3, y3);
        let x3 = Self::subfe(t1, y3);
        let y3 = Self::addfe(t1, y3);
        let y3 = Self::mulfe(x3, y3);
        let x3 = Self::mulfe(x3, t3);
        let t3 = Self::addfe(t2, t2);
        let t2 = Self::addfe(t2, t3);
        let z3 = Self::mulfe(b, z3);
        let z3 = Self::subfe(z3, t2);
        let z3 = Self::subfe(z3, t0);
        let t3 = Self::addfe(z3, z3);
        let z3 = Self::addfe(z3, t3);
        let t3 = Self::addfe(t0, t0);
        let t0 = Self::addfe(t3, t0);
        let t0 = Self::subfe(t0, t2);
        let t0 = Self::mulfe(t0, z3);
        let y3 = Self::addfe(y3, t0);
        let t0 = Self::mulfe(y, z);
        let t0 = Self::addfe(t0, t0);
        let z3 = Self::mulfe(t0, z3);
        let x3 = Self::subfe(x3, z3);
        let z3 = Self::mulfe(t0, t1);
        let z3 = Self::addfe(z3, z3);
        let z3 = Self::addfe(z3, z3);
        Self::new(x3, y3, z3)
    }
    fn is_identity(&self) -> bool {
        self.x() == Self::FieldElement::ZERO
            && self.y() != Self::FieldElement::ZERO
            && self.z() == Self::FieldElement::ZERO
    }
    fn dblmul(&self, left: Self::FieldElement, point: Self, right: Self::FieldElement) -> Self {
        let mut q = Self::identity();
        let k1 = left.to_be_bytes();
        let k2 = right.to_be_bytes();
        let mut curr = Self::identity();
        let mut map = HashMap::new();
        let mut curr2 = Self::identity();
        let mut map2 = HashMap::new();
        for i in 0..16 {
            map.insert(i, curr);
            curr = curr + *self;
            map2.insert(i, curr2);
            curr2 = curr2 + point;
        }
        for b in 0..N {
            let k1u = k1[b] / 16;
            let k1d = k1[b] % 16;
            let k2u = k2[b] / 16;
            let k2d = k2[b] % 16;
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.add(map[&k1u]);
            q = q.add(map2[&k2u]);

            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.add(map[&k1d]);
            q = q.add(map2[&k2d]);
        }
        q
    }
    fn add(&self, rhs: Self) -> Self {
        let (x1, y1, z1) = (self.x(), self.y(), self.z());
        let (x2, y2, z2) = (rhs.x(), rhs.y(), rhs.z());
        let (p, b) = (Self::PRIME_MOD, Self::b);

        let mut t0;
        let mut t1;
        let mut t2;
        let mut t3;
        let mut t4;
        let mut x3;
        let mut y3;
        let mut z3;

        t0 = Self::mulfe(x1, x2);
        t1 = Self::mulfe(y1, y2); //(y1 * y2) % p // 2.  t1 = y1 * y2
        t2 = Self::mulfe(z1, z2); // % p // 3.  t2 = z1 * z2
        t3 = Self::addfe(x1, y1); //% p // 4.  t3 = x1 + y1
        t4 = Self::addfe(x2, y2); // % p // 5.  t4 = x2 + y2
        t3 = Self::mulfe(t3, t4); // % p // 6.  t3 = t3 * t4
        t4 = Self::addfe(t0, t1); //% p // 7.  t4 = t0 + t1
        t3 = Self::subfe(t3, t4); //% p // 8.  t3 = t3 - t4
        t4 = Self::addfe(y1, z1); // % p // 9.  t4 = y1 + z1
        x3 = Self::addfe(y2, z2); // % p // 10. x3 = y2 + z2
        t4 = Self::mulfe(t4, x3); // % p // 11. t4 = t4 * x3
        x3 = Self::addfe(t1, t2); // % p // 12. x3 = t1 + t2
        t4 = Self::subfe(t4, x3); // % p // 13. t4 = t4 - x3
        x3 = Self::addfe(x1, z1); // % p // 14. x3 = x1 + z1
        y3 = Self::addfe(x2, z2); // % p // 15. y3 = x2 + z2
        x3 = Self::mulfe(x3, y3); // % p // 16. x3 = x3 * y3
        y3 = Self::addfe(t0, t2); // % p // 17. y3 = t0 + t2
        y3 = Self::subfe(x3, y3); // % p // 18. y3 = x3 - y3
        z3 = Self::mulfe(b, t2); // % p //  19. z3 = b* t2
        x3 = Self::subfe(y3, z3); // % p // 20. x3 = y3 - z3
        z3 = Self::addfe(x3, x3); // % p // 21. z3 = x3 + x3
        x3 = Self::addfe(x3, z3); // % p // 22. x3 = x3 + z3
        z3 = Self::subfe(t1, x3); // % p // 23. z3 = t1 - x3
        x3 = Self::addfe(t1, x3); // % p // 24. x3 = t1 + x3
        y3 = Self::mulfe(b, y3); // % p //  25. y3 = b* y3
        t1 = Self::addfe(t2, t2); // % p // 26. t1 = t2 + t2
        t2 = Self::addfe(t1, t2); // % p // 27. t2 = t1 + t2
        y3 = Self::subfe(y3, t2); // % p // 28. y3 = y3 - t2
        y3 = Self::subfe(y3, t0); // % p // 29. y3 = y3 - t0
        t1 = Self::addfe(y3, y3); // % p // 30. t1 = y3 + y3
        y3 = Self::addfe(t1, y3); // % p // 31. y3 = t1 + y3
        t1 = Self::addfe(t0, t0); // % p // 32. t1 = t0 + t0
        t0 = Self::addfe(t1, t0); // % p // 33. t0 = t1 + t0
        t0 = Self::subfe(t0, t2); // % p // 34. t0 = t0 - t2
        t1 = Self::mulfe(t4, y3); // % p // 35. t1 = t4 * y3
        t2 = Self::mulfe(t0, y3); // % p // 36. t2 = t0 * y3
        y3 = Self::mulfe(x3, z3); // % p // 37. y3 = x3 * z3
        y3 = Self::addfe(y3, t2); // % p // 38. y3 = y3 + t2
        x3 = Self::mulfe(t3, x3); // % p // 39. x3 = t3 * x3
        x3 = Self::subfe(x3, t1); // % p // 40. x3 = x3 - t1
        z3 = Self::mulfe(t4, z3); // % p // 41. z3 = t4 * z3
        t1 = Self::mulfe(t3, t0); // % p // 42. t1 = t3 * t0
        z3 = Self::addfe(z3, t1); // % p // 43. z3 = z3 + t1
        Self::new(x3, y3, z3)
    }
    fn scalar_mul(&self, rhs: Self::FieldElement) -> Self {
        let mut q = Self::identity();
        let bytes = rhs.to_be_bytes();
        let mut curr = Self::identity();
        let mut map = HashMap::new();
        for i in 0..16 {
            map.insert(i, curr);
            curr = curr + *self;
        }
        for b in bytes {
            let upper = b / 16;
            let lower = b % 16;
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.add(map[&upper]);
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.dbl();
            q = q.add(map[&lower]);
        }
        q
    }
    fn hash_points<D: Digest>(pts: Vec<Self>) -> Self::FieldElement {
        let mut hasher = D::new();
        for p in pts {
            hasher.update(WeierstrassGroup::to_bytes(&p));
        }
        let hash: Vec<u8> = hasher.finalize().to_vec();
        let bytes_to_use = N.min(<D as Digest>::output_size());
        let mut scalar_bytes: [u8; N] = [0; N];
        if <D as Digest>::output_size() >= N {
            scalar_bytes.copy_from_slice(&hash[..N]);
        } else {
            let rest = N - <D as Digest>::output_size();
            scalar_bytes[rest..].copy_from_slice(hash.as_slice());
        }
        Self::new_scalar(Self::FieldElement::from_slice(&scalar_bytes))
    }
}
