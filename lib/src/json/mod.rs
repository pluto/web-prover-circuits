use super::*;

pub mod parser;
#[cfg(test)] mod tests;

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
