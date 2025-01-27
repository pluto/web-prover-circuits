use super::*;

#[derive(Clone, Debug)]
pub struct JsonMachine<const MAX_STACK_HEIGHT: usize> {
  // stack:    [[F; 2]; MAX_STACK_HEIGHT],
  //   tree_hash: [[F; 2]; MAX_STACK_HEIGHT],
  monomial: F,
  status:   Status,
  location: [Location; MAX_STACK_HEIGHT], /* TODO: Make this also an array at stack height and
                                           * maybe just make an
                                           * ".into()" to produce the actual stack */
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

  // pub fn top_of_stack(&self) -> [F; 2] {
  //   for i in (0..MAX_STACK_HEIGHT).rev() {
  //     if self.stack[i][0] == F::ZERO && self.stack[i][1] == F::ZERO {
  //       if i == 0 {
  //         return [F::ZERO, F::ZERO];
  //       }
  //       return [self.stack[0][i - 1], self.stack[1][i - 1]];
  //     }
  //   }
  //   [self.stack[0][MAX_STACK_HEIGHT - 1], self.stack[1][MAX_STACK_HEIGHT - 1]]
  // }

  pub fn pointer(&self) -> usize {
    for i in 0..MAX_STACK_HEIGHT {
      if self.location[i] == Location::None {
        return i;
      }
    }
    MAX_STACK_HEIGHT
  }
}

impl<const MAX_STACK_HEIGHT: usize> Default for JsonMachine<MAX_STACK_HEIGHT> {
  fn default() -> Self {
    Self {
      // stack:    [[F::default(); 2]; MAX_STACK_HEIGHT],
      //   tree_hash: [[F::default(); 2]; MAX_STACK_HEIGHT],
      monomial: F::default(),
      status:   Status::default(),
      location: [Location::default(); MAX_STACK_HEIGHT],
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Status {
  #[default]
  None,
  ParsingString,
  ParsingNumber,
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
  let mut machine = JsonMachine::<MAX_STACK_HEIGHT>::default();
  let mut output = vec![];
  for char in bytes {
    dbg!(*char as char);
    dbg!(&machine);
    match *char {
      START_BRACE => match (machine.status, machine.current_location()) {
        (Status::None, Location::None | Location::ObjectValue | Location::ArrayIndex(_)) => {
          machine.location[machine.pointer()] = Location::ObjectKey;
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "Start brace in invalid position!".to_string(),
          )),
      },
      END_BRACE => match (machine.status, machine.current_location()) {
        (Status::None, Location::ObjectValue) => {
          machine.location[machine.pointer() - 1] = Location::None;
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "End brace in invalid position!".to_string(),
          )),
      },
      START_BRACKET => match (machine.status, machine.current_location()) {
        (Status::None, Location::None | Location::ObjectValue | Location::ArrayIndex(_)) => {
          machine.location[machine.pointer()] = Location::ArrayIndex(0);
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "Start bracket in invalid position!".to_string(),
          )),
      },
      END_BRACKET => match (machine.status, machine.current_location()) {
        (Status::None, Location::ArrayIndex(_)) => {
          machine.location[machine.pointer() - 1] = Location::None;
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "End bracket in invalid position!".to_string(),
          )),
      },
      COLON => match (machine.status, machine.current_location()) {
        (Status::None, Location::ObjectKey) => {
          machine.location[machine.pointer() - 1] = Location::ObjectValue;
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser("Colon in invalid position!".to_string())),
      },
      COMMA => match (machine.status, machine.current_location()) {
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
        Status::None => machine.status = Status::ParsingString,
        Status::ParsingString => machine.status = Status::None,
        Status::ParsingNumber =>
          return Err(WitnessGeneratorError::JsonParser(
            "Quote found while parsing number!".to_string(),
          )),
      },
      c if NUMBER.contains(&c) =>
        if machine.status == Status::None {
          machine.status = Status::ParsingNumber;
        },
      _ => match machine.status {
        Status::ParsingNumber => machine.status = Status::None,
        _ => output.push(machine.clone()),
      },
    }
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
  fn test_json_parser() { parse::<10>(RESPONSE_BODY.as_bytes(), F::from(2)); }
}
