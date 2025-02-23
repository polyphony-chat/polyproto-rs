use polyproto::key::PublicKey;
use polyproto::signature::Signature;

use crate::common::{self, Ed25519Signature};

#[test]
fn eq_algorithm_identifier_signature_publickey() {
    let private_key = common::gen_priv_key();
    let public_key = private_key.public_key.clone();
    assert_eq!(
        Ed25519Signature::algorithm_identifier(),
        public_key.algorithm_identifier()
    )
}
