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
  pub parsing_string:   F,
  pub parsing_number:   F,
  pub monomial:         F,
}

impl<const MAX_STACK_HEIGHT: usize> RawJsonMachine<MAX_STACK_HEIGHT> {
  pub fn initial_state() -> Self {
    Self {
      polynomial_input: F::ZERO,
      stack:            [(F::ZERO, F::ZERO); MAX_STACK_HEIGHT],
      tree_hash:        [(F::ZERO, F::ZERO); MAX_STACK_HEIGHT],
      parsing_string:   F::ZERO,
      parsing_number:   F::ZERO,
      monomial:         F::ZERO,
    }
  }

  pub fn compress_tree_hash(&self) -> F {
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

  pub fn from_chosen_sequence_and_input(
    polynomial_input: F,
    key_sequence: &[JsonKey],
  ) -> Result<RawJsonMachine<MAX_STACK_HEIGHT>, WitnessGeneratorError> {
    if key_sequence.len() > MAX_STACK_HEIGHT {
      return Err(WitnessGeneratorError::JsonKeyError("Key sequence too long".to_string()));
    }

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

    // TODO: This is wrong, we shouldn't really output this type here. This function is just to get
    // the tree hash type of stuff for a given json sequence and value
    Ok(Self {
      polynomial_input,
      stack,
      tree_hash,
      parsing_number: F::ZERO,
      parsing_string: F::ZERO,
      monomial: F::ZERO,
    })
  }

  pub fn flatten(&self) -> [F; MAX_STACK_HEIGHT * 4 + 3] {
    let mut output = [F::ZERO; MAX_STACK_HEIGHT * 4 + 3];
    for (idx, pair) in self.stack.iter().enumerate() {
      output[2 * idx] = pair.0;
      output[2 * idx + 1] = pair.1;
    }
    for (idx, pair) in self.tree_hash.iter().enumerate() {
      output[2 * idx + MAX_STACK_HEIGHT * 2] = pair.0;
      output[2 * idx + 1 + MAX_STACK_HEIGHT * 2] = pair.1;
    }
    output[MAX_STACK_HEIGHT * 4] = self.monomial;
    output[MAX_STACK_HEIGHT * 4 + 1] = self.parsing_string;
    output[MAX_STACK_HEIGHT * 4 + 2] = self.parsing_number;
    output
  }
}

pub fn json_value_digest<const MAX_STACK_HEIGHT: usize>(
  plaintext: &[u8],
  keys: &[JsonKey],
) -> Result<Vec<u8>, WitnessGeneratorError> {
  assert!(!keys.is_empty());
  assert!(keys.len() <= MAX_STACK_HEIGHT);
  assert!(plaintext.iter().all(|&b| b.is_ascii() && b > 0), "Input must be valid ASCII");

  let mut json: Value = serde_json::from_slice(plaintext)?;

  for key in keys {
    match key {
      JsonKey::String(string) =>
        if let Some(value) = json.get_mut(string) {
          json = value.take();
        } else {
          return Err(WitnessGeneratorError::JsonKeyError(string.clone()));
        },
      JsonKey::Num(idx) =>
        if let Some(value) = json.get_mut(*idx) {
          json = value.take();
        } else {
          return Err(WitnessGeneratorError::JsonKeyError(idx.to_string()));
        },
    }
  }

  let value = match json {
    Value::Number(num) => num.to_string(),
    Value::String(val) => val,
    _ =>
      return Err(WitnessGeneratorError::JsonKeyError(
        "Value is not a string or number".to_string(),
      )),
  };

  Ok(value.as_bytes().to_vec())
}

impl From<Location> for (F, F) {
  fn from(val: Location) -> Self {
    match val {
      Location::None => (F::ZERO, F::ZERO),
      Location::ObjectKey => (F::ONE, F::ZERO),
      Location::ObjectValue => (F::ONE, F::ONE),
      Location::ArrayIndex(idx) => (F::from(2), F::from(idx as u64)),
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
      RawJsonMachine::<10>::from_chosen_sequence_and_input(polynomial_input, &key_sequence)
        .unwrap();

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

    let keys = vec![
      JsonKey::String(KEY_0.to_string()),
      JsonKey::String(KEY_1.to_string()),
      JsonKey::Num(0),
      JsonKey::String(KEY_2.to_string()),
      JsonKey::String(KEY_3.to_string()),
    ];

    let value = json_value_digest::<5>(json.as_bytes(), &keys).unwrap();
    assert_eq!(value, b"Taylor Swift");
  }
}
