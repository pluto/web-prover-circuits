use super::*;

const SPACE: u8 = 32;
const CR: u8 = 13;
const LF: u8 = 10;
const COLON: u8 = 58;

pub fn parse(bytes: &[u8], polynomial_input: F) -> Result<Vec<HttpMachine>, WitnessGeneratorError> {
  let mut machine = HttpMachine {
    header_num: 0,
    status:     HttpStatus::ParsingStart(StartLineLocation::Beginning),
  };

  let mut output = vec![];
  for char in bytes {
    dbg!(*char as char);
    match (*char, machine.status) {
      (SPACE, HttpStatus::ParsingStart(loc)) => match loc {
        StartLineLocation::Beginning =>
          machine.status = HttpStatus::ParsingStart(StartLineLocation::Middle),
        StartLineLocation::Middle =>
          machine.status = HttpStatus::ParsingStart(StartLineLocation::End),
        StartLineLocation::End => {},
      },
      (
        CR,
        HttpStatus::ParsingStart(StartLineLocation::End)
        | HttpStatus::ParsingHeader(NameOrValue::Value),
      ) => machine.status = HttpStatus::LineStatus(LineStatus::CR),
      (CR, HttpStatus::LineStatus(LineStatus::CRLF)) =>
        machine.status = HttpStatus::LineStatus(LineStatus::CRLFCR),
      (LF, HttpStatus::LineStatus(LineStatus::CR)) =>
        machine.status = HttpStatus::LineStatus(LineStatus::CRLF),
      (LF, HttpStatus::LineStatus(LineStatus::CRLFCR)) => {
        machine.status = HttpStatus::ParsingBody;
        machine.header_num = 0;
      },
      (_, HttpStatus::LineStatus(LineStatus::CRLF)) => {
        machine.status = HttpStatus::ParsingHeader(NameOrValue::Name);
        machine.header_num += 1;
      },
      (COLON, HttpStatus::ParsingHeader(NameOrValue::Name)) =>
        machine.status = HttpStatus::ParsingHeader(NameOrValue::Value),
      _ => {},
    }
    output.push(machine);
    dbg!(machine);
  }
  Ok(output)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  pub fn test_parse_http() {
    // It's funny to me every time
    let polynomial_input = poseidon::<2>(&[F::from(69), F::from(420)]);
    let states = parse(&mock::RESPONSE_PLAINTEXT.as_bytes(), polynomial_input);
  }
}
