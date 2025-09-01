use curve25519_dalek::{Scalar, constants::RISTRETTO_BASEPOINT_TABLE};
// Update the import path if the elgamal module is in src/elgamal.rs or src/elgamal/mod.rs
use ec_elgamal::elgamal::{
    ElGamalCiphertext, elgamal_add, elgamal_decrypt, elgamal_encrypt,
    elgamal_encrypt_with_randomness, elgamal_keygen, elgamal_rerandomize, to_point,
};
use rand_core::OsRng;

#[test]
fn elgamal() {
    let (sk, pk) = elgamal_keygen();

    // Basic encryption/decryption
    let message = to_point(Scalar::from(42u64));
    let ct = elgamal_encrypt(message, &pk);
    let decrypted = elgamal_decrypt(&ct, sk);
    assert_eq!(decrypted, message);

    // Rerandomization
    let (new_ct, _) = elgamal_rerandomize(&ct, &pk);
    let decrypted = elgamal_decrypt(&new_ct, sk);
    assert_eq!(decrypted, message);

    // Serialization
    let serialized = ct.serialize();
    let deserialized = ElGamalCiphertext::deserialize(&serialized);
    assert_eq!(ct, deserialized);

    // Homomorphic addition
    let m1 = to_point(Scalar::from(10u64));
    let m2 = to_point(Scalar::from(20u64));
    let ct1 = elgamal_encrypt(m1, &pk);
    let ct2 = elgamal_encrypt(m2, &pk);
    let ct_sum = elgamal_add(&ct1, &ct2);
    let decrypted_sum = elgamal_decrypt(&ct_sum, sk);
    assert_eq!(decrypted_sum, m1 + m2);
}

#[test]
fn paras_elgamal_check() {
    // Server
    let (_, pk) = elgamal_keygen();
    let delta = Scalar::from(42u64);
    let gamma_prime = Scalar::random(&mut OsRng);
    let ct_prime =
        elgamal_encrypt_with_randomness(&delta * RISTRETTO_BASEPOINT_TABLE, &pk, gamma_prime);

    // Client
    let (ct, gamma) = elgamal_rerandomize(&ct_prime, &pk);

    // Server - Check - first way
    let ct_check = elgamal_encrypt_with_randomness(
        &delta * RISTRETTO_BASEPOINT_TABLE,
        &pk,
        gamma_prime + gamma,
    );
    assert_eq!(ct_check, ct);

    // Server - Check - second way
    let ct_zero =
        elgamal_encrypt_with_randomness(&Scalar::ZERO * RISTRETTO_BASEPOINT_TABLE, &pk, gamma);
    let ct_check = elgamal_add(&ct_prime, &ct_zero);
    assert_eq!(ct_check, ct);
}
