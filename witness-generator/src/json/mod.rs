use super::*;

pub mod parser;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
  ParsingString((String, bool)),
  ParsingPrimitive(String),
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
  pub polynomial_input:  F,
  pub stack:             [(F, F); MAX_STACK_HEIGHT],
  pub tree_hash:         [(F, F); MAX_STACK_HEIGHT],
  pub parsing_string:    F,
  pub parsing_primitive: F,
  pub escaped:           F,
  pub monomial:          F,
}

impl<const MAX_STACK_HEIGHT: usize> RawJsonMachine<MAX_STACK_HEIGHT> {
  pub fn initial_state() -> Self {
    Self {
      polynomial_input:  F::ZERO,
      stack:             [(F::ZERO, F::ZERO); MAX_STACK_HEIGHT],
      tree_hash:         [(F::ZERO, F::ZERO); MAX_STACK_HEIGHT],
      parsing_string:    F::ZERO,
      parsing_primitive: F::ZERO,
      monomial:          F::ZERO,
      escaped:           F::ZERO,
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
      parsing_primitive: F::ZERO,
      parsing_string: F::ZERO,
      monomial: F::ZERO,
      escaped: F::ZERO,
    })
  }

  pub fn flatten(&self) -> [F; MAX_STACK_HEIGHT * 4 + 4] {
    let mut output = [F::ZERO; MAX_STACK_HEIGHT * 4 + 4];
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
    output[MAX_STACK_HEIGHT * 4 + 2] = self.parsing_primitive;
    output[MAX_STACK_HEIGHT * 4 + 3] = self.escaped;
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
    Value::Bool(val) => val.to_string(),
    val @ Value::Null => val.to_string(),
    _ =>
      return Err(WitnessGeneratorError::JsonKeyError(
        "Value is not a string or other primitive type".to_string(),
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
  const TEST_STACK_HEIGHT: usize = 10;

  fn string_hash(input: &str, polynomial_input: F) -> F {
    let mut string_hash = F::ZERO;
    let mut monomial = F::ONE;
    for byte in input.as_bytes() {
      string_hash += monomial * F::from(u64::from(*byte));
      monomial *= polynomial_input;
    }
    string_hash
  }

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

    let raw_json_machine =
      RawJsonMachine::<10>::from_chosen_sequence_and_input(polynomial_input, &key_sequence)
        .unwrap();

    println!("Stack (decimal):");
    assert_eq!(raw_json_machine.stack[0], (F::ONE, F::ONE));
    assert_eq!(raw_json_machine.stack[1], (F::ONE, F::ONE));
    assert_eq!(raw_json_machine.stack[2], (F::from(2), F::from(0)));
    assert_eq!(raw_json_machine.stack[3], (F::ONE, F::ONE));
    assert_eq!(raw_json_machine.stack[4], (F::ONE, F::ONE));

    println!("\nTree hashes (decimal):");
    assert_eq!(raw_json_machine.tree_hash[0], (string_hash(KEY_0, polynomial_input), F::ZERO));
    assert_eq!(raw_json_machine.tree_hash[1], (string_hash(KEY_1, polynomial_input), F::ZERO));
    assert_eq!(raw_json_machine.tree_hash[2], (F::ZERO, F::ZERO));
    assert_eq!(raw_json_machine.tree_hash[3], (string_hash(KEY_2, polynomial_input), F::ZERO));
    assert_eq!(raw_json_machine.tree_hash[4], (string_hash(KEY_3, polynomial_input), F::ZERO));

    // Test with empty sequence
    let result = RawJsonMachine::<TEST_STACK_HEIGHT>::from_chosen_sequence_and_input(
      F::from(7), // arbitrary polynomial input
      &[],
    );
    assert!(result.is_ok());
    let machine = result.unwrap();
    assert_eq!(machine.polynomial_input, F::from(7));
    assert!(machine.stack.iter().all(|&(a, b)| a == F::ZERO && b == F::ZERO));

    // Test with string key
    let sequence = vec![JsonKey::String("test".to_string())];
    let result =
      RawJsonMachine::<TEST_STACK_HEIGHT>::from_chosen_sequence_and_input(F::from(7), &sequence);
    assert!(result.is_ok());
    let machine = result.unwrap();
    assert_eq!(machine.stack[0], (F::ONE, F::ONE));
    // Verify string hash calculation
    let expected_hash = {
      let mut hash = F::ZERO;
      let mut monomial = F::ONE;
      for &byte in "test".as_bytes() {
        hash += monomial * F::from(u64::from(byte));
        monomial *= F::from(7);
      }
      hash
    };
    assert_eq!(machine.tree_hash[0].0, expected_hash);
    assert_eq!(machine.tree_hash[0].1, F::ZERO);

    // Test with array index
    let sequence = vec![JsonKey::Num(5)];
    let result =
      RawJsonMachine::<TEST_STACK_HEIGHT>::from_chosen_sequence_and_input(F::from(7), &sequence);
    assert!(result.is_ok());
    let machine = result.unwrap();
    assert_eq!(machine.stack[0], (F::from(2), F::from(5)));
    assert_eq!(machine.tree_hash[0], (F::ZERO, F::ZERO));

    // Test with mixed sequence
    let sequence = vec![
      JsonKey::String("outer".to_string()),
      JsonKey::Num(3),
      JsonKey::String("inner".to_string()),
    ];
    let result =
      RawJsonMachine::<TEST_STACK_HEIGHT>::from_chosen_sequence_and_input(F::from(7), &sequence);
    assert!(result.is_ok());
    let machine = result.unwrap();
    // Check outer string
    assert_eq!(machine.stack[0], (F::ONE, F::ONE));
    // Check array index
    assert_eq!(machine.stack[1], (F::from(2), F::from(3)));
    // Check inner string
    assert_eq!(machine.stack[2], (F::ONE, F::ONE));

    // Test stack overflow
    let long_sequence = (0..TEST_STACK_HEIGHT + 1).map(JsonKey::Num).collect::<Vec<_>>();
    let result = RawJsonMachine::<TEST_STACK_HEIGHT>::from_chosen_sequence_and_input(
      F::from(7),
      &long_sequence,
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), WitnessGeneratorError::JsonKeyError(_)));
  }

  #[test]
  fn test_compress_tree_hash() {
    // Test case 1: Empty machine (all zeros)
    let empty_machine = RawJsonMachine::<TEST_STACK_HEIGHT> {
      polynomial_input:  F::from(7),
      stack:             [(F::ZERO, F::ZERO); TEST_STACK_HEIGHT],
      tree_hash:         [(F::ZERO, F::ZERO); TEST_STACK_HEIGHT],
      parsing_primitive: F::ZERO,
      parsing_string:    F::ZERO,
      monomial:          F::ZERO,
      escaped:           F::ZERO,
    };
    assert_eq!(empty_machine.compress_tree_hash(), F::ZERO);

    // Test case 2: Single entry
    let mut single_entry_machine = empty_machine.clone();
    single_entry_machine.stack[0] = (F::ONE, F::from(2));
    single_entry_machine.tree_hash[0] = (F::from(3), F::ZERO);

    let expected_hash = {
      let p = F::from(7); // polynomial input
      F::ONE + F::from(2) * p + F::from(3) * (p * p)
    };
    assert_eq!(single_entry_machine.compress_tree_hash(), expected_hash);

    // Test case 3: Multiple entries
    let mut multi_entry_machine = empty_machine.clone();
    // Set some known values
    multi_entry_machine.stack[0] = (F::ONE, F::ONE); // First entry
    multi_entry_machine.stack[1] = (F::from(2), F::ZERO); // Second entry
    multi_entry_machine.tree_hash[0] = (F::from(5), F::ZERO);
    multi_entry_machine.tree_hash[1] = (F::from(7), F::ZERO);

    let expected_hash = {
      let p = F::from(7);
      let mut acc = F::ZERO;
      let mut mon = F::ONE;

      // First entry
      acc += F::ONE * mon; // stack[0].0
      mon *= p;
      acc += F::ONE * mon; // stack[0].1
      mon *= p;
      acc += F::from(5) * mon; // tree_hash[0].0
      mon *= p;

      // Second entry
      acc += F::from(2) * mon; // stack[1].0
      mon *= p;
      acc += F::ZERO * mon; // stack[1].1
      mon *= p;
      acc += F::from(7) * mon; // tree_hash[1].0
      mon *= p;

      // Remaining entries are zero
      for _ in 2..TEST_STACK_HEIGHT {
        mon *= p; // stack[i].0
        mon *= p; // stack[i].1
        mon *= p; // tree_hash[i].0
      }

      acc
    };
    assert_eq!(multi_entry_machine.compress_tree_hash(), expected_hash);

    // Test case 4: Verify polynomial input influence
    let mut machine1 = empty_machine.clone();
    let mut machine2 = empty_machine.clone();
    machine2.polynomial_input = F::from(11); // Different polynomial input

    // Set identical values but expect different hashes due to different polynomial inputs
    machine1.stack[0] = (F::ONE, F::ONE);
    machine1.tree_hash[0] = (F::from(3), F::ZERO);
    machine2.stack[0] = (F::ONE, F::ONE);
    machine2.tree_hash[0] = (F::from(3), F::ZERO);

    assert_ne!(machine1.compress_tree_hash(), machine2.compress_tree_hash());

    // Test case 5: Verify position sensitivity
    let mut pos1_machine = empty_machine.clone();
    let mut pos2_machine = empty_machine.clone();

    // Same values in different positions
    pos1_machine.stack[0] = (F::ONE, F::ZERO);
    pos2_machine.stack[1] = (F::ONE, F::ZERO);

    assert_ne!(pos1_machine.compress_tree_hash(), pos2_machine.compress_tree_hash());
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
