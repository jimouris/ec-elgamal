use curve25519_dalek::Scalar;
use ec_elgamal::elgamal::*;

fn main() {
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
