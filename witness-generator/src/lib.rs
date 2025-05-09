//! Used for computing the witnesses needed for HTTP and JSON elements of Web Proof NIVC
//! hashchain-based circuits.
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

pub mod error;
pub mod http;
pub mod json;
#[cfg(test)] pub(crate) mod mock;

use std::collections::HashMap;

use client_side_prover::traits::{Engine, Group};
use ff::{Field, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use num_bigint::BigUint;
#[cfg(test)] use rstest::rstest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use self::error::WitnessGeneratorError;
#[cfg(test)] pub(crate) use self::mock::*;

pub type E = client_side_prover::provider::Bn256EngineKZG;
pub type G = <E as Engine>::GE;
pub type F = <G as Group>::Scalar;

/// Struct representing a byte or padding.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ByteOrPad {
  /// A byte.
  Byte(u8),
  /// Padding byte.
  /// substituted to `-1` for `Fr` field element and `0` for `u8` byte.
  Pad,
}

impl ByteOrPad {
  /// Converts a slice of bytes to a vector of `ByteOrPad` with padding.
  pub fn from_bytes_with_padding(bytes: &[u8], padding: usize) -> Vec<ByteOrPad> {
    let mut result = bytes.iter().map(|&b| Self::Byte(b)).collect::<Vec<_>>();
    result.extend(std::iter::repeat(Self::Pad).take(padding));
    result
  }

  pub fn pad_to_nearest_multiple(bytes: &[u8], multiple: usize) -> Vec<ByteOrPad> {
    let padding = if bytes.len() % multiple == 0 { 0 } else { multiple - (bytes.len() % multiple) };
    Self::from_bytes_with_padding(bytes, padding)
  }
}

impl From<u8> for ByteOrPad {
  fn from(b: u8) -> Self { Self::Byte(b) }
}

impl From<&u8> for ByteOrPad {
  fn from(b: &u8) -> Self { Self::Byte(*b) }
}

impl From<&ByteOrPad> for halo2curves::bn256::Fr {
  fn from(b: &ByteOrPad) -> Self {
    match b {
      ByteOrPad::Byte(b) => Self::from(u64::from(*b)),
      ByteOrPad::Pad => -Self::one(),
    }
  }
}

/// Converts a field element to a base10 string.
pub fn field_element_to_base10_string(fe: F) -> String {
  BigUint::from_bytes_le(&fe.to_bytes()).to_str_radix(10)
}

impl Serialize for ByteOrPad {
  /// converts to field element using `to_field_element` and then to base10 string
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where S: serde::Serializer {
    serializer.serialize_str(field_element_to_base10_string(self.into()).as_str())
  }
}

impl PartialEq<u8> for ByteOrPad {
  fn eq(&self, other: &u8) -> bool {
    match self {
      Self::Byte(b) => b == other,
      Self::Pad => false,
    }
  }
}

/// Packs a chunk of 16 bytes into a field element
///
/// **Note**: if the chunk is fully padded, it will be ignored
fn bytepack(bytes: &[ByteOrPad]) -> Option<F> {
  let mut output = F::ZERO;
  let mut is_padded_chunk = 0;
  for (idx, byte) in bytes.iter().enumerate() {
    let mut pow = F::ONE;
    match byte {
      ByteOrPad::Byte(byte) => {
        output += F::from(u64::from(*byte)) * {
          for _ in 0..(8 * idx) {
            pow *= F::from(2);
          }
          pow
        };
      },
      ByteOrPad::Pad => {
        is_padded_chunk += 1;
      },
    }
  }

  if is_padded_chunk == bytes.len() {
    None
  } else {
    Some(output)
  }
}

pub fn poseidon<const N: usize>(preimage: &[F]) -> F {
  let mut poseidon = Poseidon::<ark_bn254::Fr>::new_circom(N).unwrap();

  // Convert each field element to bytes and collect into a Vec
  let byte_arrays: Vec<[u8; 32]> = preimage.iter().map(F::to_bytes).collect();

  // Create slice of references to the bytes
  let byte_slices: Vec<&[u8]> = byte_arrays.iter().map(<[u8; 32]>::as_slice).collect();

  let hash: [u8; 32] = poseidon.hash_bytes_le(&byte_slices).unwrap();

  F::from_repr(hash).unwrap()
}

/// Hashes byte array padded with -1 with Poseidon
///
/// **Note**:
/// - any chunk of 16 bytes that is fully padded with -1 will be ignored
/// - check [`bytepack`] for more details
pub fn data_hasher(preimage: &[ByteOrPad], seed: F) -> F {
  // Pack the input bytes in chunks of 16 into field elements
  let packed_inputs = preimage.chunks(16).map(bytepack).collect::<Vec<Option<F>>>();

  // Iterate over the packed inputs and hash them with Poseidon
  let mut hash_val = seed;
  for packed_input in packed_inputs {
    if packed_input.is_none() {
      continue;
    }
    hash_val = poseidon::<2>(&[hash_val, packed_input.unwrap()]);
  }
  hash_val
}

pub fn polynomial_digest(bytes: &[u8], polynomial_input: F, counter: u64) -> F {
  let mut monomial = if counter == 0 { F::ONE } else { polynomial_input.pow([counter]) };
  let mut accumulated = F::ZERO;
  for byte in bytes {
    accumulated += F::from(u64::from(*byte)) * monomial;
    monomial *= polynomial_input;
  }
  accumulated
}

#[cfg(test)]
mod tests {

  use super::*;

  #[test]
  fn test_bytepack() {
    let pack0 = bytepack(&[0, 0, 0].into_iter().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>());
    assert_eq!(pack0, Some(F::from(0)));

    let pack1 = bytepack(&[1, 0, 0].into_iter().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>());
    assert_eq!(pack1, Some(F::from(1)));

    let pack2 = bytepack(&[0, 1, 0].into_iter().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>());
    assert_eq!(pack2, Some(F::from(256)));

    let pack3 = bytepack(&[0, 0, 1].into_iter().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>());
    assert_eq!(pack3, Some(F::from(65536)));

    let pack4 = bytepack(&[ByteOrPad::Pad; 3]);
    assert_eq!(pack4, None);
  }

  #[test]
  fn test_poseidon() {
    // let hash = poseidon_chainer(&[bytepack(&[0]), bytepack(&[0])]);
    let hash = poseidon::<2>(&[F::from(0), F::from(0)]);
    assert_eq!(hash.to_bytes(), [
      100, 72, 182, 70, 132, 238, 57, 168, 35, 213, 254, 95, 213, 36, 49, 220, 129, 228, 129, 123,
      242, 195, 234, 60, 171, 158, 35, 158, 251, 245, 152, 32
    ]);

    let hash = poseidon::<2>(&[F::from(69), F::from(420)]);
    assert_eq!(hash.to_bytes(), [
      10, 230, 247, 95, 9, 23, 36, 117, 25, 37, 98, 141, 178, 220, 241, 100, 187, 169, 126, 226,
      80, 175, 17, 100, 232, 1, 29, 0, 165, 144, 139, 2,
    ]);
  }

  #[test]
  fn test_data_hasher() {
    let hash = data_hasher(&[ByteOrPad::Byte(0); 16], F::ZERO);
    assert_eq!(
      hash,
      F::from_str_vartime(
        "14744269619966411208579211824598458697587494354926760081771325075741142829156"
      )
      .unwrap()
    );

    let hash = data_hasher(&[ByteOrPad::Pad; 16], F::ZERO);
    assert_eq!(hash, F::ZERO);

    let mut hash_input = [ByteOrPad::Byte(0); 16];
    hash_input[0] = ByteOrPad::Byte(1);
    let hash = data_hasher(hash_input.as_ref(), F::ZERO);
    assert_eq!(hash, poseidon::<2>([F::ZERO, F::ONE].as_ref()));

    hash_input = [ByteOrPad::Byte(0); 16];
    hash_input[15] = ByteOrPad::Byte(1);
    let hash = data_hasher(hash_input.as_ref(), F::ZERO);
    assert_eq!(
      hash,
      poseidon::<2>(
        [F::ZERO, F::from_str_vartime("1329227995784915872903807060280344576").unwrap()].as_ref()
      )
    );
  }

  #[test]
  fn test_polynomial_digest() {
    let bytes = [1, 2, 3, 4, 5];
    let digest_ctr_0 = polynomial_digest(&bytes, F::from(2), 0);
    assert_eq!(
      digest_ctr_0,
      F::from(1 + 2 * 2 + 3 * 2_u64.pow(2) + 4 * 2_u64.pow(3) + 5 * 2_u64.pow(4))
    );

    let digest_ctr_2 = polynomial_digest(&bytes, F::from(2), 2);
    assert_eq!(
      digest_ctr_2,
      F::from(
        2_u64.pow(2) + 2 * 2_u64.pow(3) + 3 * 2_u64.pow(4) + 4 * 2_u64.pow(5) + 5 * 2_u64.pow(6)
      )
    );
  }
}
