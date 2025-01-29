use super::*;

impl<const MAX_STACK_HEIGHT: usize> From<JsonMachine<MAX_STACK_HEIGHT>>
  for RawJsonMachine<MAX_STACK_HEIGHT>
{
  fn from(value: JsonMachine<MAX_STACK_HEIGHT>) -> Self {
    let mut stack = [(F::ZERO, F::ZERO); MAX_STACK_HEIGHT];
    let mut tree_hash = [(F::ZERO, F::ZERO); MAX_STACK_HEIGHT];
    for (idx, (location, labels)) in value.location.into_iter().zip(value.label_stack).enumerate() {
      stack[idx] = location.into();
      tree_hash[idx] = (
        polynomial_digest(labels.0.as_bytes(), value.polynomial_input, 0),
        polynomial_digest(labels.1.as_bytes(), value.polynomial_input, 0),
      );
    }

    Self { polynomial_input: value.polynomial_input, stack, tree_hash }
  }
}

impl<const MAX_STACK_HEIGHT: usize> JsonMachine<MAX_STACK_HEIGHT> {
  fn current_location(&self) -> Location {
    for i in 0..MAX_STACK_HEIGHT {
      if self.location[i] == Location::None {
        if i == 0 {
          return self.location[0];
        }
        return self.location[i - 1];
      }
    }
    self.location[MAX_STACK_HEIGHT - 1]
  }

  fn pointer(&self) -> usize {
    for i in 0..MAX_STACK_HEIGHT {
      if self.location[i] == Location::None {
        return i;
      }
    }
    MAX_STACK_HEIGHT
  }

  fn write_to_label_stack(&mut self) {
    match self.status.clone() {
      Status::ParsingNumber(str) | Status::ParsingString(str) => match self.current_location() {
        Location::ArrayIndex(_) | Location::ObjectValue =>
          self.label_stack[self.pointer() - 1].1 = str,
        Location::ObjectKey => {
          self.label_stack[self.pointer() - 1].0 = str;
          self.label_stack[self.pointer() - 1].1 = String::new();
        },
        Location::None => {},
      },
      Status::None => {},
    }
  }

  fn clear_label_stack(&mut self) {
    self.label_stack[self.pointer()] = (String::new(), String::new());
  }
}

impl<const MAX_STACK_HEIGHT: usize> Default for JsonMachine<MAX_STACK_HEIGHT> {
  fn default() -> Self {
    Self {
      polynomial_input: F::ONE,
      status:           Status::default(),
      location:         [Location::default(); MAX_STACK_HEIGHT],
      label_stack:      std::array::from_fn(|_| (String::new(), String::new())),
    }
  }
}

const START_BRACE: u8 = 123;
const END_BRACE: u8 = 125;
const START_BRACKET: u8 = 91;
const END_BRACKET: u8 = 93;
const COLON: u8 = 58;
const COMMA: u8 = 44;
const QUOTE: u8 = 34;
const NUMBER: [u8; 10] = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57];

// Tell clippy to eat shit
#[allow(clippy::too_many_lines)]
pub fn parse<const MAX_STACK_HEIGHT: usize>(
  bytes: &[u8],
  polynomial_input: F,
) -> Result<Vec<JsonMachine<MAX_STACK_HEIGHT>>, WitnessGeneratorError> {
  let mut machine = JsonMachine::<MAX_STACK_HEIGHT> {
    polynomial_input,
    status: Status::default(),
    location: [Location::default(); MAX_STACK_HEIGHT],
    label_stack: std::array::from_fn(|_| (String::new(), String::new())),
  };
  let mut output = vec![];
  // ctr used only for debuggin
  // let mut ctr = 0;
  for char in bytes {
    // Update the machine
    // dbg!(*char as char);
    match *char {
      START_BRACE => match (machine.clone().status, machine.current_location()) {
        (Status::None, Location::None | Location::ObjectValue | Location::ArrayIndex(_)) => {
          machine.location[machine.pointer()] = Location::ObjectKey;
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "Start brace in invalid position!".to_string(),
          )),
      },
      END_BRACE => match (machine.clone().status, machine.current_location()) {
        (Status::None, Location::ObjectValue) => {
          machine.location[machine.pointer() - 1] = Location::None;
          machine.clear_label_stack();
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "End brace in invalid position!".to_string(),
          )),
      },
      START_BRACKET => match (machine.clone().status, machine.current_location()) {
        (Status::None, Location::None | Location::ObjectValue | Location::ArrayIndex(_)) => {
          machine.location[machine.pointer()] = Location::ArrayIndex(0);
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "Start bracket in invalid position!".to_string(),
          )),
      },
      END_BRACKET => match (machine.clone().status, machine.current_location()) {
        (Status::None, Location::ArrayIndex(_)) => {
          machine.location[machine.pointer() - 1] = Location::None;
          machine.clear_label_stack();
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "End bracket in invalid position!".to_string(),
          )),
      },
      COLON => match (machine.clone().status, machine.current_location()) {
        (Status::None, Location::ObjectKey) => {
          machine.location[machine.pointer() - 1] = Location::ObjectValue;
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser("Colon in invalid position!".to_string())),
      },
      COMMA => match (machine.clone().status, machine.current_location()) {
        (Status::None | Status::ParsingNumber(_), Location::ObjectValue) => {
          machine.location[machine.pointer() - 1] = Location::ObjectKey;
        },
        (Status::None | Status::ParsingNumber(_), Location::ArrayIndex(idx)) => {
          machine.location[machine.pointer() - 1] = Location::ArrayIndex(idx + 1);
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser("Comma in invalid position!".to_string())),
      },
      QUOTE => match machine.status {
        Status::None => machine.status = Status::ParsingString(String::new()),
        Status::ParsingString(_) => {
          machine.status = Status::None;

          match machine.current_location() {
            // Clear off the second position if we finish a string while there
            Location::ArrayIndex(_) | Location::ObjectValue =>
              machine.label_stack[machine.pointer() - 1].1 = String::new(),
            _ => {},
          }
        },
        Status::ParsingNumber(_) =>
          return Err(WitnessGeneratorError::JsonParser(
            "Quote found while parsing number!".to_string(),
          )),
      },
      c if NUMBER.contains(&c) => match machine.clone().status {
        Status::None => machine.status = Status::ParsingNumber(String::from(c as char)),
        Status::ParsingNumber(mut str) => {
          str.push(*char as char);
          machine.status = Status::ParsingNumber(str);
        },
        Status::ParsingString(mut str) => {
          str.push(*char as char);
          machine.status = Status::ParsingString(str);
        },
      },

      _ => match machine.status.clone() {
        Status::ParsingNumber(_) => machine.status = Status::None,
        Status::ParsingString(mut str) => {
          str.push(*char as char);
          machine.status = Status::ParsingString(str);
        },
        Status::None => {},
      },
    }
    machine.write_to_label_stack();
    output.push(machine.clone());
    // let raw_state = RawJsonMachine::from(machine.clone());
    // let raw_stack = raw_state
    //   .stack
    //   .into_iter()
    //   .map(|f| (BigUint::from_bytes_le(&f.0.to_bytes()),
    // BigUint::from_bytes_le(&f.1.to_bytes())))   .collect::<Vec<(BigUint, BigUint)>>();
    // let raw_tree_hash = raw_state
    //   .tree_hash
    //   .into_iter()
    //   .map(|f| (BigUint::from_bytes_le(&f.0.to_bytes()),
    // BigUint::from_bytes_le(&f.1.to_bytes())))   .collect::<Vec<(BigUint, BigUint)>>();
    // Debuggin'
    // for (i, (a, b)) in raw_stack.iter().enumerate() {
    //   println!("state[{ctr:?}].stack[{:2}] = [{}][{}]", i, a, b);
    // }
    // for (i, (a, b)) in raw_tree_hash.iter().enumerate() {
    //   println!("state[{ctr:?}].tree_hash[{:2}] = [{}][{}]", i, a, b);
    // }
    // ctr += 1;
    // dbg!(&RawJsonMachine::from(machine.clone()));
  }
  Ok(output)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_pointer() {
    let mut machine = JsonMachine::<3>::default();
    assert_eq!(machine.pointer(), 0);
    machine.location[0] = Location::ObjectKey;
    assert_eq!(machine.pointer(), 1);
    machine.location[1] = Location::ObjectKey;
    assert_eq!(machine.pointer(), 2);
  }

  const SPOTIFY_EXAMPLE: &str = r#"{ "data" : { "items" : [ { "data" : "Artist" , "profile" : { "name" : "Taylor Swift" } } ] } }"#;

  #[test]
  fn test_json_parser_spotify() {
    // Use a super awesome random polynomial input
    let polynomial_input = poseidon::<2>(&[F::from(69), F::from(420)]);

    // Parse the json and cross my fingers
    let states = parse::<5>(SPOTIFY_EXAMPLE.as_bytes(), polynomial_input).unwrap();

    // We're looking for tswizzle and if we don't find her i will cry
    let key_sequence = [
      JsonKey::String(KEY_0.to_string()),
      JsonKey::String(KEY_1.to_string()),
      JsonKey::Num(0),
      JsonKey::String(KEY_2.to_string()),
      JsonKey::String(KEY_3.to_string()),
    ];
    let t_swizzle = polynomial_digest(b"Taylor Swift", polynomial_input, 0);

    let raw_json_state =
      RawJsonMachine::<5>::from_chosen_sequence_and_input(polynomial_input, &key_sequence);
    let contains = states
      .into_iter()
      .map(RawJsonMachine::from)
      .filter(|val| val.compress_tree_hash() == raw_json_state.compress_tree_hash());

    // Here's the moment of truth
    assert_eq!(
      contains
        .into_iter()
        .filter(|keys_found| {
          keys_found.tree_hash.iter().filter(|tree_hash| tree_hash.1 == t_swizzle).count() > 0
        })
        .count(),
      1
    );
  }

  #[rstest]
  #[case::array_only(r#"[ 42, { "a" : "b" } , [ 0 , 1 ] , "foobar"]"#)]
  #[case::value_array(
    r#"{ "k" : [ 420 , 69 , 4200 , 600 ] , "b" : [ "ab" , "ba" , "ccc" , "d" ] }"#
  )]
  #[case::value_array_object(r#"{ "a" : [ { "b" : [ 1 , 4 ] } , { "c" : "b" } ] }"#)]
  #[case::value_object(r#"{ "a" : { "d" : "e" , "e" : "c" } , "e" : { "f" : "a" , "e" : "2" } , "g" : { "h" : { "a" : "c" } } , "ab" : "foobar" , "bc" : 42 , "dc" : [ 0 , 1 , "a" ] }"#)]
  fn test_json_parser_valid(#[case] input: &str) {
    let polynomial_input = poseidon::<2>(&[F::from(69), F::from(420)]);
    let states = parse::<10>(input.as_bytes(), polynomial_input).unwrap();
    assert_eq!(states.last().unwrap().location, [Location::None; 10]);
    assert_eq!(
      states.last().unwrap().label_stack,
      std::array::from_fn(|_| (String::new(), String::new()))
    );
  }
}
