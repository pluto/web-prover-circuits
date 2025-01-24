//! Used for computing the witnesses needed for HTTP and JSON elements of Web Proof NIVC
//! hashchain-based circuits.

pub mod error;
pub mod http;
pub mod json;

use http::*;
use json::*;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use ff::{Field, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use serde_json::Value;
use std::collections::HashMap;

type StackAndTreeHashes = (Vec<[F; 2]>, Vec<[F; 2]>);

pub use error::WitnessGeneratorError;

use client_side_prover::traits::{Engine, Group};

pub type E = client_side_prover::provider::Bn256EngineKZG;
pub type G = <E as Engine>::GE;
pub type F = <G as Group>::Scalar;

#[cfg(test)]
pub(crate) fn mock_manifest() -> Manifest {
    let request = Request {
        method: "GET".to_string(),
        url: "spotify.com".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: HashMap::new(),
    };
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/json; charset=utf-8".to_string(),
    );
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    let body = ResponseBody {
        json: vec![
            JsonKey::String("data".to_string()),
            JsonKey::String("items".to_string()),
            JsonKey::Num(0),
            JsonKey::String("profile".to_string()),
            JsonKey::String("name".to_string()),
        ],
    };
    let response = Response {
        status: "200".to_string(),
        version: "HTTP/1.1".to_string(),
        message: "OK".to_string(),
        headers,
        body,
    };
    Manifest { request, response }
}

pub fn manifest_digest(
    manifest_response: &Response,
    ciphertext_digest: F,
    max_stack_height: usize,
) -> (F, F) {
    // TODO: This assumes the start line format here as well.
    // Then digest the start line using the ciphertext_digest as a random input
    let start_line_bytes = format!(
        "{} {} {}",
        &manifest_response.version, &manifest_response.status, &manifest_response.message
    );
    let start_line_digest = polynomial_digest(start_line_bytes.as_bytes(), ciphertext_digest);

    // Digest all the headers
    let header_bytes = headers_to_bytes(&manifest_response.headers);
    let headers_digest = header_bytes.map(|bytes| polynomial_digest(&bytes, ciphertext_digest));

    // Digest the JSON sequence
    let json_tree_hash = json_tree_hasher(
        ciphertext_digest,
        &manifest_response.body.json,
        max_stack_height,
    );
    let json_sequence_digest = compress_tree_hash(ciphertext_digest, json_tree_hash);

    // Put all the digests into a vec
    let mut all_digests = vec![];
    all_digests.push(json_sequence_digest);
    all_digests.push(start_line_digest);
    headers_digest.into_iter().for_each(|d| all_digests.push(d));

    // Iterate through the material and sum up poseidon hashes of each as to not mix polynomials
    let manifest_digest = ciphertext_digest
        + all_digests
            .into_iter()
            .map(|d| poseidon::<1>(&[d]))
            .sum::<F>();
    (ciphertext_digest, manifest_digest)
}

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
        let mut result = bytes
            .iter()
            .map(|&b| ByteOrPad::Byte(b))
            .collect::<Vec<_>>();
        result.extend(std::iter::repeat(ByteOrPad::Pad).take(padding));
        result
    }

    /// converts a slice of `ByteOrPad` to a vector of bytes. Converts `Pad` to `0`.
    pub fn as_bytes(bytes: &[ByteOrPad]) -> Vec<u8> {
        bytes
            .iter()
            .map(|b| match b {
                ByteOrPad::Byte(b) => *b,
                ByteOrPad::Pad => 0,
            })
            .collect()
    }
}

impl From<u8> for ByteOrPad {
    fn from(b: u8) -> Self {
        ByteOrPad::Byte(b)
    }
}

impl From<&u8> for ByteOrPad {
    fn from(b: &u8) -> Self {
        ByteOrPad::Byte(*b)
    }
}

impl From<&ByteOrPad> for halo2curves::bn256::Fr {
    fn from(b: &ByteOrPad) -> Self {
        match b {
            ByteOrPad::Byte(b) => halo2curves::bn256::Fr::from(*b as u64),
            ByteOrPad::Pad => -halo2curves::bn256::Fr::one(),
        }
    }
}

/// Converts a field element to a base10 string.
fn field_element_to_base10_string(fe: F) -> String {
    BigUint::from_bytes_le(&fe.to_bytes()).to_str_radix(10)
}

impl Serialize for ByteOrPad {
    /// converts to field element using `to_field_element` and then to base10 string
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(field_element_to_base10_string(self.into()).as_str())
    }
}

impl PartialEq<u8> for ByteOrPad {
    fn eq(&self, other: &u8) -> bool {
        match self {
            ByteOrPad::Byte(b) => b == other,
            ByteOrPad::Pad => false,
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
                output += F::from(*byte as u64) * {
                    for _ in 0..(8 * idx) {
                        pow *= F::from(2);
                    }
                    pow
                };
            }
            ByteOrPad::Pad => {
                is_padded_chunk += 1;
            }
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
pub fn data_hasher(preimage: &[ByteOrPad]) -> F {
    // Pack the input bytes in chunks of 16 into field elements
    let packed_inputs = preimage
        .chunks(16)
        .map(bytepack)
        .collect::<Vec<Option<F>>>();

    // Iterate over the packed inputs and hash them with Poseidon
    let mut hash_val = F::ZERO;
    for packed_input in packed_inputs {
        if packed_input.is_none() {
            continue;
        }
        hash_val = poseidon::<2>(&[hash_val, packed_input.unwrap()]);
    }
    hash_val
}

pub fn polynomial_digest(bytes: &[u8], polynomial_input: F) -> F {
    let mut monomial = F::ONE;
    let mut accumulated = F::ZERO;
    for byte in bytes {
        accumulated += F::from(u64::from(*byte)) * monomial;
        monomial *= polynomial_input;
    }
    accumulated
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use num_bigint::BigUint;

    use super::*;

    #[test]
    fn test_bytepack() {
        let pack0 = bytepack(
            &[0, 0, 0]
                .into_iter()
                .map(ByteOrPad::from)
                .collect::<Vec<ByteOrPad>>(),
        );
        assert_eq!(pack0, Some(F::from(0)));

        let pack1 = bytepack(
            &[1, 0, 0]
                .into_iter()
                .map(ByteOrPad::from)
                .collect::<Vec<ByteOrPad>>(),
        );
        assert_eq!(pack1, Some(F::from(1)));

        let pack2 = bytepack(
            &[0, 1, 0]
                .into_iter()
                .map(ByteOrPad::from)
                .collect::<Vec<ByteOrPad>>(),
        );
        assert_eq!(pack2, Some(F::from(256)));

        let pack3 = bytepack(
            &[0, 0, 1]
                .into_iter()
                .map(ByteOrPad::from)
                .collect::<Vec<ByteOrPad>>(),
        );
        assert_eq!(pack3, Some(F::from(65536)));

        let pack4 = bytepack(&[ByteOrPad::Pad; 3]);
        assert_eq!(pack4, None);
    }

    #[test]
    fn test_poseidon() {
        // let hash = poseidon_chainer(&[bytepack(&[0]), bytepack(&[0])]);
        let hash = poseidon::<2>(&[F::from(0), F::from(0)]);
        assert_eq!(
            hash.to_bytes(),
            [
                100, 72, 182, 70, 132, 238, 57, 168, 35, 213, 254, 95, 213, 36, 49, 220, 129, 228,
                129, 123, 242, 195, 234, 60, 171, 158, 35, 158, 251, 245, 152, 32
            ]
        );

        let hash = poseidon::<2>(&[F::from(69), F::from(420)]);
        assert_eq!(
            hash.to_bytes(),
            [
                10, 230, 247, 95, 9, 23, 36, 117, 25, 37, 98, 141, 178, 220, 241, 100, 187, 169,
                126, 226, 80, 175, 17, 100, 232, 1, 29, 0, 165, 144, 139, 2,
            ]
        );
    }

    #[test]
    fn test_data_hasher() {
        let hash = data_hasher(&[ByteOrPad::Byte(0); 16]);
        assert_eq!(
            hash,
            F::from_str_vartime(
                "14744269619966411208579211824598458697587494354926760081771325075741142829156"
            )
            .unwrap()
        );

        let hash = data_hasher(&[ByteOrPad::Pad; 16]);
        assert_eq!(hash, F::ZERO);

        let mut hash_input = [ByteOrPad::Byte(0); 16];
        hash_input[0] = ByteOrPad::Byte(1);
        let hash = data_hasher(hash_input.as_ref());
        assert_eq!(hash, poseidon::<2>([F::ZERO, F::ONE].as_ref()));

        hash_input = [ByteOrPad::Byte(0); 16];
        hash_input[15] = ByteOrPad::Byte(1);
        let hash = data_hasher(hash_input.as_ref());
        assert_eq!(
            hash,
            poseidon::<2>(
                [
                    F::ZERO,
                    F::from_str_vartime("1329227995784915872903807060280344576").unwrap()
                ]
                .as_ref()
            )
        );
    }

    // TODO: This test doesn't actually test anything at all. Fix that.
    // #[test]
    // fn test_initial_digest() {
    //     let test_ciphertext_padded = TEST_CIPHERTEXT
    //         .iter()
    //         .map(|x| ByteOrPad::Byte(*x))
    //         .collect::<Vec<ByteOrPad>>();
    //     let ciphertext_digest = data_hasher(&test_ciphertext_padded);
    //     let (ct_digest, manifest_digest) =
    //         response_initial_digest(&mock_manifest().response, ciphertext_digest, 5);
    //     println!("\nManifest Digest (decimal):");
    //     println!("  {}", BigUint::from_bytes_le(&manifest_digest.to_bytes()));

    //     assert_eq!(
    //         BigUint::from_bytes_le(&ct_digest.to_bytes()),
    //         BigUint::from_str(
    //             "5947802862726868637928743536818722886587721698845887498686185738472802646104"
    //         )
    //         .unwrap()
    //     );

    //     let (ct_digest, _manifest_digest) =
    //         request_initial_digest(&mock_manifest().request, ciphertext_digest);
    //     assert_eq!(
    //         BigUint::from_bytes_le(&ct_digest.to_bytes()),
    //         BigUint::from_str(
    //             "5947802862726868637928743536818722886587721698845887498686185738472802646104"
    //         )
    //         .unwrap()
    //     );
    // }
}
