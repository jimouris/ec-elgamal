use curve25519_dalek::Scalar;

use ec_elgamal::elgamal::{
    ElGamalCiphertext, elgamal_add, elgamal_decrypt, elgamal_encrypt, elgamal_keygen,
    elgamal_point_mul, elgamal_rerandomize, to_point,
};

#[test]
fn encrypt_decrypt() {
    let (sk, pk) = elgamal_keygen();

    // Basic encryption/decryption
    let message = to_point(Scalar::from(42u64));
    let ct = elgamal_encrypt(message, &pk);
    let decrypted = elgamal_decrypt(&ct, sk);
    assert_eq!(decrypted, message);
}

#[test]
fn encrypt_rerandomize_decrypt() {
    let (sk, pk) = elgamal_keygen();

    // Basic encryption/decryption
    let message = to_point(Scalar::from(42u64));
    let ct = elgamal_encrypt(message, &pk);
    let (new_ct, _) = elgamal_rerandomize(&ct, &pk);
    let decrypted = elgamal_decrypt(&new_ct, sk);
    assert_eq!(decrypted, message);
}

#[test]
fn serialize_deserialize() {
    let (_, pk) = elgamal_keygen();

    // Basic encryption/decryption
    let message = to_point(Scalar::from(42u64));
    let ct = elgamal_encrypt(message, &pk);

    // Serialization
    let serialized = ct.serialize();
    let deserialized = ElGamalCiphertext::deserialize(&serialized);
    assert_eq!(ct, deserialized);
}

#[test]
fn addition() {
    let (sk, pk) = elgamal_keygen();

    // Homomorphic addition
    let m1 = to_point(Scalar::from(10u64));
    let m2 = to_point(Scalar::from(20u64));
    let ct1 = elgamal_encrypt(m1, &pk);
    let ct2 = elgamal_encrypt(m2, &pk);
    let ct_sum = elgamal_add(&ct1, &ct2);
    let decrypted = elgamal_decrypt(&ct_sum, sk);
    assert_eq!(decrypted, m1 + m2);
}

#[test]
fn scalar_multiplication() {
    let (sk, pk) = elgamal_keygen();

    // Homomorphic addition
    let m1 = to_point(Scalar::from(10u64));
    let m2 = Scalar::from(2u64);
    let ct = elgamal_encrypt(m1, &pk);

    let ct_mul = elgamal_point_mul(&ct, &m2);

    let decrypted = elgamal_decrypt(&ct_mul, sk);
    assert_eq!(decrypted, m1 * m2);
}
