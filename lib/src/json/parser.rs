use super::*;

#[derive(Clone, Debug)]
pub struct JsonMachine<const MAX_STACK_HEIGHT: usize> {
  polynomial_input: F,
  status:           Status,
  location:         [Location; MAX_STACK_HEIGHT],
  label_stack:      [(String, String); MAX_STACK_HEIGHT],
}

#[derive(Clone, Debug)]
pub struct RawJsonMachine<const MAX_STACK_HEIGHT: usize> {
  stack:     [(F, F); MAX_STACK_HEIGHT],
  tree_hash: [(F, F); MAX_STACK_HEIGHT],
}

impl<const MAX_STACK_HEIGHT: usize> From<JsonMachine<MAX_STACK_HEIGHT>>
  for RawJsonMachine<MAX_STACK_HEIGHT>
{
  fn from(value: JsonMachine<MAX_STACK_HEIGHT>) -> Self {
    let mut stack = [(F::ZERO, F::ZERO); MAX_STACK_HEIGHT];
    let mut tree_hash = [(F::ZERO, F::ZERO); MAX_STACK_HEIGHT];
    for (idx, (location, labels)) in value.location.into_iter().zip(value.label_stack).enumerate() {
      stack[idx] = location.into();
      tree_hash[idx] = (
        polynomial_digest(&labels.0.as_bytes(), value.polynomial_input, 0),
        polynomial_digest(&labels.1.as_bytes(), value.polynomial_input, 0),
      );
    }

    RawJsonMachine { stack, tree_hash }
  }
}

impl<const MAX_STACK_HEIGHT: usize> JsonMachine<MAX_STACK_HEIGHT> {
  pub fn current_location(&self) -> Location {
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

  pub fn pointer(&self) -> usize {
    for i in 0..MAX_STACK_HEIGHT {
      if self.location[i] == Location::None {
        return i;
      }
    }
    MAX_STACK_HEIGHT
  }

  pub fn write_to_label_stack(&mut self) {
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

  pub fn clear_label_stack(&mut self) {
    self.label_stack[self.pointer()] = (String::new(), String::new());
  }

  pub fn produce_tree_hash(&self, polynomial_input: F) -> [(F, F); MAX_STACK_HEIGHT] {
    let mut result = [(F::ZERO, F::ZERO); MAX_STACK_HEIGHT];
    for (idx, (lhs, rhs)) in self.label_stack.iter().enumerate() {
      result[idx] = (
        polynomial_digest(lhs.as_bytes(), polynomial_input, 0),
        polynomial_digest(rhs.as_bytes(), polynomial_input, 0),
      );
    }
    result
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

const START_BRACE: u8 = 123;
const END_BRACE: u8 = 125;
const START_BRACKET: u8 = 91;
const END_BRACKET: u8 = 93;
const COLON: u8 = 58;
const COMMA: u8 = 44;
const QUOTE: u8 = 34;
const NUMBER: [u8; 10] = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57];

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
  for char in bytes {
    // Update the machine
    dbg!(*char as char);
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
        (Status::None, Location::ObjectValue) => {
          machine.location[machine.pointer() - 1] = Location::ObjectKey;
        },
        (Status::None, Location::ArrayIndex(idx)) => {
          machine.location[machine.pointer() - 1] = Location::ArrayIndex(idx + 1);
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser("Comma in invalid position!".to_string())),
      },
      QUOTE => match machine.status {
        Status::None => machine.status = Status::ParsingString(String::new()),
        Status::ParsingString(_) => machine.status = Status::None,
        Status::ParsingNumber(_) =>
          return Err(WitnessGeneratorError::JsonParser(
            "Quote found while parsing number!".to_string(),
          )),
      },
      c if NUMBER.contains(&c) => match machine.clone().status {
        Status::None => machine.status = Status::ParsingNumber(String::from(c as char)),
        Status::ParsingNumber(mut str) => {
          str.push(*char as char);
          machine.status = Status::ParsingString(str);
        },
        Status::ParsingString(mut str) => {
          str.push(*char as char);
          machine.status = Status::ParsingNumber(str);
        },
      },

      _ => match machine.status.clone() {
        Status::ParsingNumber(_) => machine.status = Status::None,
        Status::ParsingString(mut str) => {
          str.push(*char as char);
          machine.status = Status::ParsingString(str);
        },
        Status::None => output.push(machine.clone()),
      },
    }
    machine.write_to_label_stack();
    dbg!(&machine);
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

  #[test]
  fn test_json_parser() {
    let polynomial_input = poseidon::<2>(&[F::from(69), F::from(420)]);
    let states = parse::<10>(RESPONSE_BODY.as_bytes(), polynomial_input);
  }
}
