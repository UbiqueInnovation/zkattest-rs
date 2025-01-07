use std::io::Cursor;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto_bigint::Encoding;
use group::Group;
use p256::{
    ecdsa::{signature::SignerMut, Signature, SigningKey},
    elliptic_curve::{sec1::Coordinates, Field},
    EncodedPoint,
};
use proves::pedersen::{
    EqualityProof, MultiplicationProof, PedersenParams, PointAddProof, SignatureProofList,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tom256::U320;

fn zk_attest_proof(msg: Vec<u8>, mut kp: SigningKey) -> Vec<u8> {
    let pub_key = kp.verifying_key().to_sec1_bytes().to_vec();
    let sig: Signature = kp.sign(&msg);
    let msg_hash = Sha256::digest(&msg).to_vec();
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
    proof.serialize()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("small-size");
    group.bench_function("scalar multiplication [p256]", |b| {
        b.iter(|| {
            let a = p256_arithmetic::ProjectivePoint::random_scalar();
            a * p256_arithmetic::ProjectivePoint::generator()
        })
    });
    group.bench_function("scalar multiplication [tom256]", |b| {
        b.iter(|| {
            let a = tom256::ProjectivePoint::random_scalar();
            a * tom256::ProjectivePoint::generator()
        })
    });
    group.bench_function("point equality [proof]", |b| {
        b.iter(|| {
            let x = tom256::ProjectivePoint::random_scalar();
            let ped_param = PedersenParams::<tom256::ProjectivePoint, 40>::new();
            let c1 = ped_param.commit(x);
            let c2 = ped_param.commit(x);

            let proof = EqualityProof::prove(ped_param, x, c1, c2);
            proof.serialize()
        })
    });
    group.bench_function("point equality [verify]", |b| {
        let x = tom256::ProjectivePoint::random_scalar();
        let ped_param = PedersenParams::<tom256::ProjectivePoint, 40>::new();
        let c1 = ped_param.commit(x);
        let c2 = ped_param.commit(x);

        let proof = EqualityProof::prove(ped_param, x, c1, c2);
        let proof = proof.serialize();

        b.iter(|| {
            let mut p = Cursor::new(proof.clone());
            let eq = EqualityProof::deserialize(ped_param, &mut p).unwrap();
            eq.verify(c1.commitment, c2.commitment)
        })
    });
    group.bench_function("multiplication proof [proof]", |b| {
        b.iter(|| {
            let ped_param = PedersenParams::<tom256::ProjectivePoint, 40>::new();
            let x = tom256::ProjectivePoint::random_scalar();
            let y = tom256::ProjectivePoint::random_scalar();
            let cx = ped_param.commit(x);
            let cy = ped_param.commit(y);
            let z = x.mul_mod(&y, &tom256::ProjectivePoint::ORDER.to_nz().unwrap());
            let cz = ped_param.commit(z);
            let proof = MultiplicationProof::prove(ped_param, x, y, z, cx, cy, cz);
            proof.serialize()
        });
    });
    group.bench_function("multiplication proof [verify]", |b| {
        let ped_param = PedersenParams::<tom256::ProjectivePoint, 40>::new();
        let x = tom256::ProjectivePoint::random_scalar();
        let y = tom256::ProjectivePoint::random_scalar();
        let cx = ped_param.commit(x);
        let cy = ped_param.commit(y);
        let z = x.mul_mod(&y, &tom256::ProjectivePoint::ORDER.to_nz().unwrap());
        let cz = ped_param.commit(z);
        let proof = MultiplicationProof::prove(ped_param, x, y, z, cx, cy, cz);
        let proof = proof.serialize();
        b.iter(|| {
            let mut proof = Cursor::new(proof.clone());
            let deserialized_proof =
                MultiplicationProof::<tom256::ProjectivePoint, 40>::deserialize(
                    ped_param, &mut proof,
                )
                .unwrap();
            assert!(deserialized_proof.verify(cx.commitment, cy.commitment, cz.commitment));
        });
    });
    group.bench_function("point add [proof]", |b| {
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
        b.iter(|| {
            let proof =
                PointAddProof::prove(params, x1, y1, x2, y2, x3, p1x, p1y, p2x, p2y, p3x, p3y);
            proof.serialize()
        });
    });
    group.bench_function("point add [verify]", |b| {
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
        let proof = proof.serialize();
        let mut serialized_proof = Cursor::new(proof);
        let deserialized_proof = PointAddProof::<tom256::ProjectivePoint, 40>::deserialize(
            params,
            &mut serialized_proof,
        )
        .unwrap();
        b.iter(|| {
            deserialized_proof.verify(
                p1x.commitment,
                p1y.commitment,
                p2x.commitment,
                p2y.commitment,
                p3x.commitment,
                p3y.commitment,
            )
        });
    });
    group.sample_size(10);
    group.bench_function("zk_attest_proof", |b| {
        b.iter(|| {
            let kp = p256::ecdsa::SigningKey::random(&mut OsRng);
            zk_attest_proof(black_box(b"hallo").to_vec(), black_box(kp));
        })
    });
    let kp = p256::ecdsa::SigningKey::random(&mut OsRng);
    let proof = zk_attest_proof(b"hallo".to_vec(), kp);
    group.bench_function("zk_attest_verify", |b| {
        let p = proof.clone();
        b.iter(|| {
            let proof = SignatureProofList::<
                p256_arithmetic::ProjectivePoint,
                32,
                tom256::ProjectivePoint,
                40,
            >::deserialize(&mut Cursor::new(p.clone()))
            .unwrap();
            let msg_hash = Sha256::digest(b"hallo").to_vec();
            proof.verify_from_hash(&msg_hash)
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

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
