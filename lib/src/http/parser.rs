use super::*;

const SPACE: u8 = 32;
const CR: u8 = 13;
const LF: u8 = 10;
const COLON: u8 = 58;

pub fn parse(bytes: &[u8], polynomial_input: F) -> Result<Vec<HttpMachine>, WitnessGeneratorError> {
  let mut machine = HttpMachine {
    header_num:  0,
    status:      HttpStatus::ParsingStart(StartLineLocation::Beginning),
    line_digest: F::ZERO,
  };

  let mut output = vec![];
  let mut ctr = 0;
  let mut line_ctr = 0;
  for char in bytes {
    println!("-------------------------------------------------");
    println!("char: {:?}, {}", *char as char, *char);
    println!("-------------------------------------------------");
    match (*char, machine.status) {
      (SPACE, HttpStatus::ParsingStart(loc)) => {
        match loc {
          StartLineLocation::Beginning =>
            machine.status = HttpStatus::ParsingStart(StartLineLocation::Middle),
          StartLineLocation::Middle =>
            machine.status = HttpStatus::ParsingStart(StartLineLocation::End),
          StartLineLocation::End => {},
        };
        machine.line_digest += polynomial_input.pow([line_ctr]) * F::from(*char as u64);
        line_ctr += 1;
      },
      (
        CR,
        HttpStatus::ParsingStart(StartLineLocation::End)
        | HttpStatus::ParsingHeader(NameOrValue::Value),
      ) => {
        machine.status = HttpStatus::LineStatus(LineStatus::CR);
        line_ctr = 0;
        machine.line_digest = F::ZERO;
      },
      (CR, HttpStatus::LineStatus(LineStatus::CRLF)) => {
        machine.status = HttpStatus::LineStatus(LineStatus::CRLFCR);
        line_ctr = 0;
        machine.line_digest = F::ZERO;
      },
      (LF, HttpStatus::LineStatus(LineStatus::CR)) => {
        machine.status = HttpStatus::LineStatus(LineStatus::CRLF);
        line_ctr = 0;
        machine.line_digest = F::ZERO;
      },
      (LF, HttpStatus::LineStatus(LineStatus::CRLFCR)) => {
        machine.status = HttpStatus::ParsingBody;
        machine.header_num = 0;
        line_ctr = 0;
        machine.line_digest = F::ZERO;
      },
      (_, HttpStatus::LineStatus(LineStatus::CRLF)) => {
        machine.status = HttpStatus::ParsingHeader(NameOrValue::Name);
        machine.header_num += 1;
        machine.line_digest += polynomial_input.pow([line_ctr]) * F::from(*char as u64);
        line_ctr += 1;
      },
      (COLON, HttpStatus::ParsingHeader(NameOrValue::Name)) => {
        machine.status = HttpStatus::ParsingHeader(NameOrValue::Value);
        machine.line_digest += polynomial_input.pow([line_ctr]) * F::from(*char as u64);
        line_ctr += 1;
      },
      (_, HttpStatus::ParsingBody) => {},
      _ => {
        machine.line_digest += polynomial_input.pow([line_ctr]) * F::from(*char as u64);
        line_ctr += 1;
      },
    }
    output.push(machine);
    let raw_state = RawHttpMachine::from(machine.clone());

    println!(
      "state[ {ctr:?} ].parsing_start       = {:?}",
      BigUint::from_bytes_le(&raw_state.parsing_start.to_bytes())
    );
    println!(
      "state[ {ctr:?} ].parsing_header      = {:?}",
      BigUint::from_bytes_le(&raw_state.parsing_header.to_bytes())
    );
    println!(
      "state[ {ctr:?} ].parsing_field_name  = {:?}",
      BigUint::from_bytes_le(&raw_state.parsing_field_name.to_bytes())
    );
    println!(
      "state[ {ctr:?} ].parsing_field_value = {:?}",
      BigUint::from_bytes_le(&raw_state.parsing_field_value.to_bytes())
    );
    println!(
      "state[ {ctr:?} ].parsing_body        = {:?}",
      BigUint::from_bytes_le(&raw_state.parsing_body.to_bytes())
    );
    println!(
      "state[ {ctr:?} ].line_status         = {:?}",
      BigUint::from_bytes_le(&raw_state.line_status.to_bytes())
    );
    println!(
      "state[ {ctr:?} ].inner_main_digest   = {:?}",
      BigUint::from_bytes_le(&raw_state.line_digest.to_bytes())
    );
    println!("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    ctr += 1;
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
    let states = parse(&mock::RESPONSE_PLAINTEXT.as_bytes(), polynomial_input).unwrap();
    assert_eq!(states.len(), mock::RESPONSE_PLAINTEXT.len());

    let machine_state = RawHttpMachine::from(states.last().unwrap().clone());
    assert_eq!(machine_state.parsing_start, F::ZERO);
    assert_eq!(machine_state.parsing_header, F::ZERO);
    assert_eq!(machine_state.parsing_field_name, F::ZERO);
    assert_eq!(machine_state.parsing_field_value, F::ZERO);
    assert_eq!(machine_state.parsing_body, F::ONE);
    assert_eq!(machine_state.line_status, F::from(0));
    assert_eq!(machine_state.line_digest, F::from(0));
  }

  const HTTP_BYTES: [u8; 915] = [
    72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 67, 111, 110, 110, 101, 99,
    116, 105, 111, 110, 58, 32, 99, 108, 111, 115, 101, 13, 10, 67, 111, 110, 116, 101, 110, 116,
    45, 76, 101, 110, 103, 116, 104, 58, 32, 50, 50, 13, 10, 67, 97, 99, 104, 101, 45, 67, 111,
    110, 116, 114, 111, 108, 58, 32, 109, 97, 120, 45, 97, 103, 101, 61, 51, 48, 48, 13, 10, 67,
    111, 110, 116, 101, 110, 116, 45, 83, 101, 99, 117, 114, 105, 116, 121, 45, 80, 111, 108, 105,
    99, 121, 58, 32, 100, 101, 102, 97, 117, 108, 116, 45, 115, 114, 99, 32, 39, 110, 111, 110,
    101, 39, 59, 32, 115, 116, 121, 108, 101, 45, 115, 114, 99, 32, 39, 117, 110, 115, 97, 102,
    101, 45, 105, 110, 108, 105, 110, 101, 39, 59, 32, 115, 97, 110, 100, 98, 111, 120, 13, 10, 67,
    111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 58, 32, 116, 101, 120, 116, 47, 112, 108,
    97, 105, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13, 10, 69,
    84, 97, 103, 58, 32, 34, 101, 48, 101, 54, 53, 49, 48, 99, 49, 102, 99, 49, 51, 98, 51, 97, 54,
    51, 97, 99, 98, 99, 48, 54, 49, 53, 101, 101, 48, 55, 97, 52, 57, 53, 50, 56, 55, 51, 97, 56,
    100, 97, 55, 55, 48, 50, 55, 100, 48, 48, 52, 49, 50, 102, 99, 99, 102, 49, 97, 53, 99, 101,
    50, 57, 34, 13, 10, 83, 116, 114, 105, 99, 116, 45, 84, 114, 97, 110, 115, 112, 111, 114, 116,
    45, 83, 101, 99, 117, 114, 105, 116, 121, 58, 32, 109, 97, 120, 45, 97, 103, 101, 61, 51, 49,
    53, 51, 54, 48, 48, 48, 13, 10, 88, 45, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112,
    101, 45, 79, 112, 116, 105, 111, 110, 115, 58, 32, 110, 111, 115, 110, 105, 102, 102, 13, 10,
    88, 45, 70, 114, 97, 109, 101, 45, 79, 112, 116, 105, 111, 110, 115, 58, 32, 100, 101, 110,
    121, 13, 10, 88, 45, 88, 83, 83, 45, 80, 114, 111, 116, 101, 99, 116, 105, 111, 110, 58, 32,
    49, 59, 32, 109, 111, 100, 101, 61, 98, 108, 111, 99, 107, 13, 10, 88, 45, 71, 105, 116, 72,
    117, 98, 45, 82, 101, 113, 117, 101, 115, 116, 45, 73, 100, 58, 32, 55, 56, 51, 49, 58, 51, 50,
    55, 52, 49, 52, 58, 49, 50, 70, 57, 69, 54, 58, 49, 65, 51, 51, 67, 50, 58, 54, 55, 54, 52, 54,
    56, 70, 49, 13, 10, 65, 99, 99, 101, 112, 116, 45, 82, 97, 110, 103, 101, 115, 58, 32, 98, 121,
    116, 101, 115, 13, 10, 68, 97, 116, 101, 58, 32, 84, 104, 117, 44, 32, 49, 57, 32, 68, 101, 99,
    32, 50, 48, 50, 52, 32, 50, 49, 58, 51, 53, 58, 53, 57, 32, 71, 77, 84, 13, 10, 86, 105, 97,
    58, 32, 49, 46, 49, 32, 118, 97, 114, 110, 105, 115, 104, 13, 10, 88, 45, 83, 101, 114, 118,
    101, 100, 45, 66, 121, 58, 32, 99, 97, 99, 104, 101, 45, 104, 121, 100, 49, 49, 48, 48, 48, 51,
    52, 45, 72, 89, 68, 13, 10, 88, 45, 67, 97, 99, 104, 101, 58, 32, 72, 73, 84, 13, 10, 88, 45,
    67, 97, 99, 104, 101, 45, 72, 105, 116, 115, 58, 32, 48, 13, 10, 88, 45, 84, 105, 109, 101,
    114, 58, 32, 83, 49, 55, 51, 52, 54, 52, 52, 49, 54, 48, 46, 53, 54, 48, 57, 53, 51, 44, 86,
    83, 48, 44, 86, 69, 49, 13, 10, 86, 97, 114, 121, 58, 32, 65, 117, 116, 104, 111, 114, 105,
    122, 97, 116, 105, 111, 110, 44, 65, 99, 99, 101, 112, 116, 45, 69, 110, 99, 111, 100, 105,
    110, 103, 44, 79, 114, 105, 103, 105, 110, 13, 10, 65, 99, 99, 101, 115, 115, 45, 67, 111, 110,
    116, 114, 111, 108, 45, 65, 108, 108, 111, 119, 45, 79, 114, 105, 103, 105, 110, 58, 32, 42,
    13, 10, 67, 114, 111, 115, 115, 45, 79, 114, 105, 103, 105, 110, 45, 82, 101, 115, 111, 117,
    114, 99, 101, 45, 80, 111, 108, 105, 99, 121, 58, 32, 99, 114, 111, 115, 115, 45, 111, 114,
    105, 103, 105, 110, 13, 10, 88, 45, 70, 97, 115, 116, 108, 121, 45, 82, 101, 113, 117, 101,
    115, 116, 45, 73, 68, 58, 32, 50, 48, 97, 101, 102, 56, 55, 48, 50, 53, 102, 54, 56, 52, 98,
    101, 55, 54, 50, 53, 55, 102, 49, 53, 98, 102, 102, 53, 97, 55, 57, 50, 97, 99, 49, 53, 97, 97,
    100, 50, 13, 10, 69, 120, 112, 105, 114, 101, 115, 58, 32, 84, 104, 117, 44, 32, 49, 57, 32,
    68, 101, 99, 32, 50, 48, 50, 52, 32, 50, 49, 58, 52, 48, 58, 53, 57, 32, 71, 77, 84, 13, 10,
    83, 111, 117, 114, 99, 101, 45, 65, 103, 101, 58, 32, 49, 53, 51, 13, 10, 13, 10, 123, 10, 32,
    32, 34, 104, 101, 108, 108, 111, 34, 58, 32, 34, 119, 111, 114, 108, 100, 34, 10, 125,
  ];

  #[test]
  pub fn test_parse_http_complex() {
    // It's funny to me every time
    let polynomial_input = poseidon::<2>(&[F::from(69), F::from(420)]);
    let states = parse(&HTTP_BYTES, polynomial_input).unwrap();

    let machine_state = RawHttpMachine::from(states.last().unwrap().clone());
    assert_eq!(machine_state.parsing_start, F::ZERO);
    assert_eq!(machine_state.parsing_header, F::ZERO);
    assert_eq!(machine_state.parsing_field_name, F::ZERO);
    assert_eq!(machine_state.parsing_field_value, F::ZERO);
    assert_eq!(machine_state.parsing_body, F::ONE);
    assert_eq!(machine_state.line_status, F::from(0));
    assert_eq!(machine_state.line_digest, F::from(0));
  }
}
