/* Copyright 2024 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.   
 */
use std::io::Cursor;

use p256::{
    ecdsa::{signature::SignerMut, Signature, SigningKey},
    elliptic_curve::rand_core::OsRng,
};
use proves::{
    p256_arithmetic,
    pedersen::{PedersenParams, SignatureProofList},
    tom256,
};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct Signer {
    signing: SigningKey,
}
#[wasm_bindgen]
impl Signer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            signing: SigningKey::random(&mut OsRng),
        }
    }
    pub fn public_key(&self) -> Vec<u8> {
        self.signing.verifying_key().to_sec1_bytes().to_vec()
    }
    pub fn sign(&mut self, msg: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing.sign(msg);
        signature.to_vec()
    }
    pub fn zk_attest(&mut self, msg: &[u8]) -> Vec<u8> {
        let pub_key = self.public_key();
        let signature = self.sign(msg);
        let params_nist = PedersenParams::<p256_arithmetic::ProjectivePoint, 32>::new();
        let msg_hash = Sha256::digest(&msg).to_vec();
        let params_tom = PedersenParams::<tom256::ProjectivePoint, 40>::new();
        console_log!("start proof");
        let proofs = SignatureProofList::from_signature(
            params_nist,
            params_tom,
            &signature,
            &msg_hash,
            &pub_key,
            80,
        );
        console_log!("finished proof");
        console_log!("serialize");
        proofs.0.serialize()
    }
}

#[wasm_bindgen]
pub fn verify_zkattest(proof: &[u8], msg: &[u8]) -> bool {
    let mut reader = Cursor::new(proof);
    console_log!("start deserialize");
    let p = SignatureProofList::<p256_arithmetic::ProjectivePoint,32, tom256::ProjectivePoint,40>::deserialize(&mut reader).unwrap();
    let msg_hash = Sha256::digest(&msg).to_vec();
    console_log!("finished, start verification");
    p.verify_from_hash(&msg_hash)
}

#[macro_export]
macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);
}
