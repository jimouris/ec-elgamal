use curve25519_dalek::Scalar;
use ec_elgamal::elgamal::*;
use rayon::prelude::*;
use std::time::Instant;

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

    // Benchmark parameters
    let n_iterations = 100_000u64;
    let point_1 = to_point(Scalar::from(1u64));
    let point_2 = to_point(Scalar::from(2u64));
    let ct1 = elgamal_encrypt(point_1, &pk);
    let ct2 = elgamal_encrypt(point_2, &pk);
    let mut ct_sum = ElGamalCiphertext::zero();

    // ----- Sequential benchmarks -----

    // Point addition benchmark
    let start = Instant::now();
    for _ in 0..n_iterations {
        ct_sum = elgamal_add(&ct_sum, &ct1);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let elgamal_add_mean = elapsed_ns as f64 / n_iterations as f64;
    println!("Sequential:");
    println!(
        "\tTotal ElGamal ciphertext addition time for {} additions: {} ms",
        n_iterations,
        elapsed_ns / 1_000_000
    );
    println!(
        "\tMean ElGamal ciphertext addition time: {:.2} ns",
        elgamal_add_mean
    );
    // Scalar-point multiplication benchmark
    let start = Instant::now();
    for _ in 0..n_iterations {
        let _ = elgamal_point_mul(&ct1, &Scalar::from(2u64));
    }
    let elapsed_ms = start.elapsed().as_millis();
    let elgamal_mul_mean_us = elapsed_ms as f64 * 1_000f64 / n_iterations as f64;
    println!(
        "\tTotal ElGamal ciphertext multiplication time for {} multiplications: {} sec",
        n_iterations,
        elapsed_ms as f64 / 1_000f64
    );
    println!(
        "\tMean ElGamal ciphertext multiplication time: {:.2} μs",
        elgamal_mul_mean_us
    );

    // ----- Parallel benchmarks -----

    let start = Instant::now();
    (0..n_iterations).into_par_iter().for_each(|_| {
        let _ = elgamal_add(&ct1, &ct2);
    });
    let elapsed_ns = start.elapsed().as_nanos();
    let elgamal_add_mean = elapsed_ns as f64 / n_iterations as f64;
    println!("\nParallel:");
    println!(
        "\tTotal ElGamal ciphertext addition time for {} additions: {} ms",
        n_iterations,
        elapsed_ns / 1_000_000
    );
    println!(
        "\tMean ElGamal ciphertext addition time: {:.2} ns",
        elgamal_add_mean
    );

    let decrypted_sum = elgamal_decrypt(&ct_sum, sk);
    assert_eq!(decrypted_sum, to_point(Scalar::from(n_iterations)));
    // Scalar-point multiplication benchmark
    let start = Instant::now();
    (0..n_iterations).into_par_iter().for_each(|_| {
        let _ = elgamal_point_mul(&ct1, &Scalar::from(2u64));
    });
    let elapsed_ms = start.elapsed().as_millis();
    let elgamal_mul_mean_us = elapsed_ms as f64 * 1_000f64 / n_iterations as f64;
    println!(
        "\tTotal ElGamal ciphertext multiplication time for {} multiplications: {} sec",
        n_iterations,
        elapsed_ms as f64 / 1_000f64
    );
    println!(
        "\tMean ElGamal ciphertext multiplication time: {:.2} μs",
        elgamal_mul_mean_us
    );
}
