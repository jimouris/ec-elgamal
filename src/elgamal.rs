use curve25519_dalek::{
    RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_TABLE, ristretto::CompressedRistretto,
    traits::Identity,
};
use serde::{Deserialize, Serialize};

use rand_core::OsRng;

// Generate a random scalar (private key)
pub fn gen_scalar() -> Scalar {
    Scalar::random(&mut OsRng)
}

/// Convert a scalar into a RistrettoPoint by multiplying with the basepoint
pub fn to_point(scalar: Scalar) -> RistrettoPoint {
    &scalar * RISTRETTO_BASEPOINT_TABLE
}

/// Represents an ElGamal ciphertext: (c1, c2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    pub c1: RistrettoPoint,
    pub c2: RistrettoPoint,
}

impl ElGamalCiphertext {
    /// Returns a ciphertext with both points set to the identity (zero) point.
    pub fn zero() -> Self {
        ElGamalCiphertext {
            c1: RistrettoPoint::identity(),
            c2: RistrettoPoint::identity(),
        }
    }

    /// Serialize the ElGamal ciphertext to 64 bytes (2 * 32-byte compressed RistrettoPoints)
    pub fn serialize(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.c1.compress().to_bytes());
        out[32..].copy_from_slice(&self.c2.compress().to_bytes());
        out
    }

    /// Deserialize an ElGamal ciphertext from 64 bytes
    pub fn deserialize(elgamal_bytes: &[u8; 64]) -> Self {
        let c1 = CompressedRistretto::decompress(
            &CompressedRistretto::from_slice(&elgamal_bytes[..32]).unwrap(),
        )
        .unwrap();
        let c2 = CompressedRistretto::decompress(
            &CompressedRistretto::from_slice(&elgamal_bytes[32..]).unwrap(),
        )
        .unwrap();

        ElGamalCiphertext { c1, c2 }
    }
}

// Key generation
pub fn elgamal_keygen() -> (Scalar, RistrettoPoint) {
    let private_key = gen_scalar();
    let public_key = &private_key * RISTRETTO_BASEPOINT_TABLE;
    (private_key, public_key)
}

// ElGamal encryption
pub fn elgamal_encrypt(
    plaintext: RistrettoPoint,
    public_key: &RistrettoPoint,
) -> ElGamalCiphertext {
    elgamal_encrypt_with_randomness(plaintext, public_key, gen_scalar())
}

/// ElGamal encryption with externally provided randomness
pub fn elgamal_encrypt_with_randomness(
    plaintext: RistrettoPoint,
    public_key: &RistrettoPoint,
    randomness: Scalar,
) -> ElGamalCiphertext {
    let c1 = &randomness * RISTRETTO_BASEPOINT_TABLE;
    let c2 = plaintext + randomness * public_key;

    ElGamalCiphertext { c1, c2 }
}

// ElGamal decryption
pub fn elgamal_decrypt(ciphertext: &ElGamalCiphertext, private_key: Scalar) -> RistrettoPoint {
    ciphertext.c2 - (private_key * ciphertext.c1)
}

/// Homomorphic addition of two ElGamal ciphertexts:
/// Given ct1 = Enc(m1; r1) and ct2 = Enc(m2; r2),
/// returns ct_sum = Enc(m1 + m2; r1 + r2)
pub fn elgamal_add(ct1: &ElGamalCiphertext, ct2: &ElGamalCiphertext) -> ElGamalCiphertext {
    ElGamalCiphertext {
        c1: ct1.c1 + ct2.c1,
        c2: ct1.c2 + ct2.c2,
    }
}

/// Multiply an ElGamalCiphertext by a scalar (homomorphic scalar multiplication)
pub fn elgamal_point_mul(ct: &ElGamalCiphertext, scalar: &Scalar) -> ElGamalCiphertext {
    ElGamalCiphertext {
        c1: scalar * ct.c1,
        c2: scalar * ct.c2,
    }
}

/// Rerandomize an ElGamal ciphertext and return the new ciphertext and the randomness used
pub fn elgamal_rerandomize(
    ciphertext: &ElGamalCiphertext,
    public_key: &RistrettoPoint,
) -> (ElGamalCiphertext, Scalar) {
    let r = gen_scalar();
    let new_c1 = ciphertext.c1 + &r * RISTRETTO_BASEPOINT_TABLE;
    let new_c2 = ciphertext.c2 + r * public_key;

    (
        ElGamalCiphertext {
            c1: new_c1,
            c2: new_c2,
        },
        r,
    )
}
