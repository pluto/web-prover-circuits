use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonKey {
  /// Object key
  String(String),
  /// Array index
  Num(usize),
}

// TODO: Need to take into account if we enter into a value that is an object inside of object. So
// need a bit more than just `JsonMaskType` maybe.
pub fn json_tree_hasher(
  polynomial_input: F,
  key_sequence: &[JsonKey],
  max_stack_height: usize,
) -> StackAndTreeHashes {
  assert!(key_sequence.len() <= max_stack_height); // TODO: This should be an error
  let mut stack = Vec::new();
  let mut tree_hashes = Vec::new();
  for val_type in key_sequence {
    match val_type {
      JsonKey::String(string) => {
        stack.push([F::ONE, F::ONE]);
        let mut string_hash = F::ZERO;
        let mut monomial = F::ONE;
        for byte in string.as_bytes() {
          string_hash += monomial * F::from(u64::from(*byte));
          monomial *= polynomial_input;
        }
        tree_hashes.push([string_hash, F::ZERO]);
      },
      JsonKey::Num(idx) => {
        tree_hashes.push([F::ZERO, F::ZERO]);
        stack.push([F::from(2), F::from(*idx as u64)]);
      },
    }
  }
  (stack, tree_hashes)
}

pub fn compress_tree_hash(polynomial_input: F, stack_and_tree_hashes: StackAndTreeHashes) -> F {
  assert!(stack_and_tree_hashes.0.len() == stack_and_tree_hashes.1.len()); // TODO: This should be an error
  let mut accumulated = F::ZERO;
  let mut monomial = F::ONE;
  for idx in 0..stack_and_tree_hashes.0.len() {
    accumulated += stack_and_tree_hashes.0[idx][0] * monomial;
    monomial *= polynomial_input;
    accumulated += stack_and_tree_hashes.0[idx][1] * monomial;
    monomial *= polynomial_input;
    accumulated += stack_and_tree_hashes.1[idx][0] * monomial;
    monomial *= polynomial_input;
  }
  accumulated
}

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

#[cfg(test)]
mod tests {
  use super::*;

  // TODO: This test doesn't actually test anything at all. Fix that.
  #[test]
  fn test_json_tree_hasher() {
    let key_sequence = vec![
      JsonKey::String(KEY_0.to_string()),
      JsonKey::String(KEY_1.to_string()),
      JsonKey::Num(0),
      JsonKey::String(KEY_2.to_string()),
      JsonKey::String(KEY_3.to_string()),
    ];

    let polynomial_input = poseidon::<2>(&[F::from(69), F::from(420)]);
    println!("polynomial_input: {:?}", BigUint::from_bytes_le(&polynomial_input.to_bytes()));
    let stack_and_tree_hashes = json_tree_hasher(polynomial_input, &key_sequence, 10);

    println!("Stack (decimal):");
    for (i, pair) in stack_and_tree_hashes.0.iter().enumerate() {
      let num1 = BigUint::from_bytes_le(&pair[0].to_bytes());
      let num2 = BigUint::from_bytes_le(&pair[1].to_bytes());
      println!("  {i}: [{num1}, {num2}]");
    }

    println!("\nTree hashes (decimal):");
    for (i, pair) in stack_and_tree_hashes.1.iter().enumerate() {
      let num1 = BigUint::from_bytes_le(&pair[0].to_bytes());
      let num2 = BigUint::from_bytes_le(&pair[1].to_bytes());
      println!("  {i}: [{num1}, {num2}]");
    }

    let digest = compress_tree_hash(polynomial_input, stack_and_tree_hashes);
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
