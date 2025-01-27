use super::*;

#[derive(Clone, Debug)]
pub struct JsonMachine<const MAX_STACK_HEIGHT: usize> {
  stack:    [[F; 2]; MAX_STACK_HEIGHT],
  //   tree_hash: [[F; 2]; MAX_STACK_HEIGHT],
  monomial: F,
  status:   Status,
  location: Location, /* TODO: Make this also an array at stack height and maybe just make an
                       * ".into()" to produce the actual stack */
}

impl<const MAX_STACK_HEIGHT: usize> JsonMachine<MAX_STACK_HEIGHT> {
  pub fn top_of_stack(&self) -> [F; 2] {
    for i in (0..MAX_STACK_HEIGHT).rev() {
      if self.stack[i][0] == F::ZERO && self.stack[i][1] == F::ZERO {
        if i == 0 {
          return [F::ZERO, F::ZERO];
        }
        return [self.stack[0][i - 1], self.stack[1][i - 1]];
      }
    }
    [self.stack[0][MAX_STACK_HEIGHT - 1], self.stack[1][MAX_STACK_HEIGHT - 1]]
  }

  pub fn pointer(&self) -> usize {
    dbg!(&self.stack);
    for i in 0..MAX_STACK_HEIGHT {
      if self.stack[i][0] == F::ZERO && self.stack[i][1] == F::ZERO {
        return i;
      }
    }
    MAX_STACK_HEIGHT
  }
}

impl<const MAX_STACK_HEIGHT: usize> Default for JsonMachine<MAX_STACK_HEIGHT> {
  fn default() -> Self {
    Self {
      stack:    [[F::default(); 2]; MAX_STACK_HEIGHT],
      //   tree_hash: [[F::default(); 2]; MAX_STACK_HEIGHT],
      monomial: F::default(),
      status:   Status::default(),
      location: Location::default(),
    }
  }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum Location {
  #[default]
  None,
  ObjectKey,
  ObjectValue,
  ArrayIndex(usize),
}

#[derive(Clone, Copy, Debug, Default)]
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

pub fn parse<const MAX_STACK_HEIGHT: usize>(
  bytes: &[u8],
  polynomial_input: F,
) -> Result<Vec<JsonMachine<MAX_STACK_HEIGHT>>, WitnessGeneratorError> {
  let mut machine = JsonMachine::<MAX_STACK_HEIGHT>::default();
  let mut output = vec![];
  for char in bytes {
    dbg!(&machine);
    match *char {
      START_BRACE => match (machine.status, machine.location) {
        (Status::None, Location::None | Location::ObjectValue | Location::ArrayIndex(_)) => {
          machine.location = Location::ObjectKey;
          machine.stack[machine.pointer()][..].copy_from_slice(&[F::ONE, F::ZERO]);
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "Start brace in invalid position!".to_string(),
          )),
      },
      END_BRACE => match (machine.status, machine.location) {
        (Status::None, Location::ObjectValue) => {
          // TODO: Return to "previous" location
          // machine.location = Location::ObjectKey;
          machine.stack[machine.pointer()][..].copy_from_slice(&[F::ZERO, F::ZERO]);
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "End brace in invalid position!".to_string(),
          )),
      },
      START_BRACKET => match (machine.status, machine.location) {
        (Status::None, Location::None | Location::ObjectValue | Location::ArrayIndex(_)) => {
          machine.location = Location::ArrayIndex(0);
          machine.stack[machine.pointer()][..].copy_from_slice(&[F::ONE + F::ONE, F::ZERO]);
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "Start bracket in invalid position!".to_string(),
          )),
      },
      END_BRACKET => match (machine.status, machine.location) {
        (Status::None, Location::ArrayIndex(_)) => {
          // TODO: Return to "previous" location
          // machine.location = Location::ArrayIndex(0);
          machine.stack[machine.pointer()][..].copy_from_slice(&[F::ZERO, F::ZERO]);
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser(
            "End bracket in invalid position!".to_string(),
          )),
      },
      COLON => match (machine.status, machine.location) {
        (Status::None, Location::ObjectKey) => {
          machine.location = Location::ObjectValue;
          machine.stack[machine.pointer()][..].copy_from_slice(&[F::ONE, F::ONE]);
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser("Colon in invalid position!".to_string())),
      },
      COMMA => match (machine.status, machine.location) {
        (Status::None, Location::ObjectValue) => {
          machine.location = Location::ObjectKey;
          machine.stack[machine.pointer()][..].copy_from_slice(&[F::ONE, F::ZERO]);
        },
        (Status::None, Location::ArrayIndex(idx)) => {
          machine.location = Location::ArrayIndex(idx + 1);
          machine.stack[machine.pointer()][..]
            .copy_from_slice(&[F::ONE, F::from((idx + 1) as u64)]);
        },
        _ =>
          return Err(WitnessGeneratorError::JsonParser("Comma in invalid position!".to_string())),
      },
      _ => {
        output.push(machine.clone());
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
    machine.stack[0][..].copy_from_slice(&[F::ONE, F::ONE]);
    assert_eq!(machine.pointer(), 1);
    machine.stack[1][..].copy_from_slice(&[F::ONE, F::ONE]);
    assert_eq!(machine.pointer(), 2);
  }

  #[test]
  fn test_json_parser() { parse::<10>(RESPONSE_BODY.as_bytes(), F::from(2)); }
}
