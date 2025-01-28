use std::char::MAX;

use super::*;

pub mod parser;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonKey {
  /// Object key
  String(String),
  /// Array index
  Num(usize),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Location {
  #[default]
  None,
  ObjectKey,
  ObjectValue,
  ArrayIndex(usize),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Status {
  #[default]
  None,
  ParsingString(String),
  ParsingNumber(String),
}

#[derive(Clone, Debug)]
pub struct JsonMachine<const MAX_STACK_HEIGHT: usize> {
  pub polynomial_input: F,
  pub status:           Status,
  pub location:         [Location; MAX_STACK_HEIGHT],
  pub label_stack:      [(String, String); MAX_STACK_HEIGHT],
}

#[derive(Clone, Debug)]
pub struct RawJsonMachine<const MAX_STACK_HEIGHT: usize> {
  pub polynomial_input: F,
  pub stack:            [(F, F); MAX_STACK_HEIGHT],
  pub tree_hash:        [(F, F); MAX_STACK_HEIGHT],
}

impl<const MAX_STACK_HEIGHT: usize> RawJsonMachine<MAX_STACK_HEIGHT> {
  pub fn compress_tree_hash(self) -> F {
    let mut accumulated = F::ZERO;
    let mut monomial = F::ONE;
    // Note, since the target value will be a primitive type in `tree_hash[1]`, we don't actively
    // need to hash that position as we hash primitive target values separately
    for idx in 0..MAX_STACK_HEIGHT {
      accumulated += self.stack[idx].0 * monomial;
      monomial *= self.polynomial_input;
      accumulated += self.stack[idx].1 * monomial;
      monomial *= self.polynomial_input;
      accumulated += self.tree_hash[idx].0 * monomial;
      monomial *= self.polynomial_input;
    }
    accumulated
  }

  // TODO: Need to take into account if we enter into a value that is an object inside of object. So
  // need a bit more than just `JsonMaskType` maybe.
  pub fn from_chosen_sequence_and_input(
    polynomial_input: F,
    key_sequence: &[JsonKey],
  ) -> RawJsonMachine<MAX_STACK_HEIGHT> {
    // TODO: This should be an error
    assert!(key_sequence.len() <= MAX_STACK_HEIGHT);
    let mut stack = [(F::ZERO, F::ZERO); MAX_STACK_HEIGHT];
    let mut tree_hash = [(F::ZERO, F::ZERO); MAX_STACK_HEIGHT];
    for (idx, val_type) in key_sequence.iter().enumerate() {
      match val_type {
        JsonKey::String(string) => {
          stack[idx] = (F::ONE, F::ONE);
          let mut string_hash = F::ZERO;
          let mut monomial = F::ONE;
          for byte in string.as_bytes() {
            string_hash += monomial * F::from(u64::from(*byte));
            monomial *= polynomial_input;
          }
          tree_hash[idx] = (string_hash, F::ZERO);
        },
        JsonKey::Num(array_idx) => {
          tree_hash[idx] = (F::ZERO, F::ZERO);
          stack[idx] = (F::from(2), F::from(*array_idx as u64));
        },
      }
    }
    Self { polynomial_input, stack, tree_hash }
  }
}

// TODO: Fix all panics here
pub fn json_value_digest(
  plaintext: &[ByteOrPad],
  keys: &[JsonKey],
) -> Result<Vec<u8>, WitnessGeneratorError> {
  let pad_index = plaintext.iter().position(|&b| b == ByteOrPad::Pad).unwrap_or(plaintext.len());
  let mut json: Value = serde_json::from_slice(&ByteOrPad::as_bytes(&plaintext[..pad_index]))?;

  for key in keys {
    match key {
      JsonKey::String(string) => {
        if let Some(value) = json.get_mut(string) {
          json = value.take();
        } else {
          panic!()
          // return Err(ProofError::JsonKeyError(string.clone()));
        }
      },
      JsonKey::Num(idx) => {
        if let Some(value) = json.get_mut(*idx) {
          json = value.take();
        } else {
          panic!()
          // return Err(ProofError::JsonKeyError(idx.to_string()));
        }
      },
    }
  }

  let value = match json {
    Value::Number(num) => num.to_string(),
    Value::String(val) => val,
    _ => {
      panic!()
      // return Err(ProofError::JsonKeyError(
      //     "Value is not a string or number".to_string(),
      // ))
    },
  };

  Ok(value.as_bytes().to_vec())
}

impl Into<(F, F)> for Location {
  fn into(self) -> (F, F) {
    match self {
      Self::None => (F::ZERO, F::ZERO),
      Self::ObjectKey => (F::ONE, F::ZERO),
      Self::ObjectValue => (F::ONE, F::ONE),
      Self::ArrayIndex(idx) => (F::from(2), F::from(idx as u64)),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // TODO: This test doesn't actually test anything at all. Fix that.
  #[test]
  fn test_json_tree_hasher() {
    let key_sequence = [
      JsonKey::String(KEY_0.to_string()),
      JsonKey::String(KEY_1.to_string()),
      JsonKey::Num(0),
      JsonKey::String(KEY_2.to_string()),
      JsonKey::String(KEY_3.to_string()),
    ];

    let polynomial_input = poseidon::<2>(&[F::from(69), F::from(420)]);
    println!("polynomial_input: {:?}", BigUint::from_bytes_le(&polynomial_input.to_bytes()));
    let raw_json_machine =
      RawJsonMachine::<10>::from_chosen_sequence_and_input(polynomial_input, &key_sequence);

    println!("Stack (decimal):");
    for (i, pair) in raw_json_machine.stack.iter().enumerate() {
      let num1 = BigUint::from_bytes_le(&pair.0.to_bytes());
      let num2 = BigUint::from_bytes_le(&pair.1.to_bytes());
      println!("  {i}: [{num1}, {num2}]");
    }

    println!("\nTree hashes (decimal):");
    for (i, pair) in raw_json_machine.tree_hash.iter().enumerate() {
      let num1 = BigUint::from_bytes_le(&pair.0.to_bytes());
      let num2 = BigUint::from_bytes_le(&pair.1.to_bytes());
      println!("  {i}: [{num1}, {num2}]");
    }

    let digest = raw_json_machine.compress_tree_hash();
    println!("\nDigest (decimal):");
    println!("  {}", BigUint::from_bytes_le(&digest.to_bytes()));
  }

  #[test]
  fn test_json_value_digest() {
    let json = r#"{"data": {"items": [{"profile": {"name": "Taylor Swift"}}]}}"#;
    let json_bytes_padded = ByteOrPad::from_bytes_with_padding(json.as_bytes(), 1024);

    let keys = vec![
      JsonKey::String(KEY_0.to_string()),
      JsonKey::String(KEY_1.to_string()),
      JsonKey::Num(0),
      JsonKey::String(KEY_2.to_string()),
      JsonKey::String(KEY_3.to_string()),
    ];

    let value = json_value_digest(&json_bytes_padded, &keys).unwrap();
    assert_eq!(value, b"Taylor Swift");
  }
}
