use ark_ec::pairing::Pairing;
use dleq::{DlEq, PairingCommitment, PairingPedersenParams};
use group::Group;
use pedersen::{PedersenParams, SignatureProofList};
use sha2::{Digest, Sha256};

pub mod dleq;
pub mod pedersen;
pub use group;
pub use p256_arithmetic;
pub use tom256;

pub fn device_binding<BbsGroup: Pairing>(
    signature: Vec<u8>,
    pub_key: Vec<u8>,
    msg: Vec<u8>,
    bbs_wittness_x: PairingCommitment<BbsGroup>,
    bbs_params_x: PairingPedersenParams<BbsGroup>,
    bbs_wittness_y: PairingCommitment<BbsGroup>,
    bbs_params_y: PairingPedersenParams<BbsGroup>,
) -> DeviceBinding<p256_arithmetic::ProjectivePoint, 32, tom256::ProjectivePoint, 40, BbsGroup> {
    let msg_hash = Sha256::digest(&msg).to_vec();
    let params_nist = PedersenParams::<p256_arithmetic::ProjectivePoint, 32>::new();
    let params_tom = PedersenParams::<tom256::ProjectivePoint, 40>::new();
    let (proof, c_x, c_y, x_coord, y_coord) = SignatureProofList::from_signature(
        params_nist,
        params_tom,
        &signature,
        &msg_hash,
        &pub_key,
        80,
    );

    let equality_x = DlEq::<180, 64, 8, 2, _, 40, _>::prove(
        params_tom,
        bbs_params_x,
        c_x,
        bbs_wittness_x,
        x_coord,
    );
    let equality_y = DlEq::<180, 64, 8, 2, _, 40, _>::prove(
        params_tom,
        bbs_params_y,
        c_y,
        bbs_wittness_y,
        y_coord,
    );
    // let mut proof_bytes = proof.serialize();
    // proof_bytes.extend(equality_x.serialize());
    // proof_bytes.extend(equality_y.serialize());
    // proof_bytes
    DeviceBinding {
        zk_attest: proof,
        eq_x: equality_x,
        eq_y: equality_y,
    }
}

pub struct DeviceBinding<
    G1: Group<N1>,
    const N1: usize,
    G2: Group<N2>,
    const N2: usize,
    BbsGroup: Pairing,
> {
    pub zk_attest: SignatureProofList<G1, N1, G2, N2>,
    pub eq_x: DlEq<180, 64, 8, 2, G2, N2, BbsGroup>,
    pub eq_y: DlEq<180, 64, 8, 2, G2, N2, BbsGroup>,
}

impl<G1: Group<N1>, const N1: usize, G2: Group<N2>, const N2: usize, BbsGroup: Pairing>
    DeviceBinding<G1, N1, G2, N2, BbsGroup>
{
    pub fn verify(&self, msg: Vec<u8>) -> bool {
        let msg_hash = Sha256::digest(&msg).to_vec();
        if !self.zk_attest.verify_from_hash(&msg_hash) {
            return false;
        }
        if !self.eq_x.verify(self.zk_attest.p_x, self.eq_x.c2) {
            return false;
        }
        if !self.eq_y.verify(self.zk_attest.p_y, self.eq_y.c2) {
            return false;
        }
        true
    }
}
