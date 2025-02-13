use super::*;

const SPACE: u8 = 32;
const CR: u8 = 13;
const LF: u8 = 10;
const COLON: u8 = 58;

pub fn parse(bytes: &[u8], polynomial_input: F) -> Result<Vec<HttpMachine>, WitnessGeneratorError> {
  let mut machine = HttpMachine {
    header_num:    0,
    status:        HttpStatus::ParsingStart(StartLineLocation::Beginning),
    line_digest:   F::ZERO,
    line_monomial: F::ONE,
  };

  let mut output = vec![];
  let mut line_ctr = 0;
  for (_ctr, char) in bytes.iter().enumerate() {
    // println!("-------------------------------------------------");
    // println!("char: {:?}, {}", *char as char, *char);
    // println!("-------------------------------------------------");
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
    machine.line_monomial = if line_ctr == 0 { F::ZERO } else { polynomial_input.pow([line_ctr]) };
    output.push(machine);
    // let raw_state = RawHttpMachine::from(machine);

    // println!(
    //   "state[ {ctr:?} ].parsing_start       = {:?}",
    //   BigUint::from_bytes_le(&raw_state.parsing_start.to_bytes())
    // );
    // println!(
    //   "state[ {ctr:?} ].parsing_header      = {:?}",
    //   BigUint::from_bytes_le(&raw_state.parsing_header.to_bytes())
    // );
    // println!(
    //   "state[ {ctr:?} ].parsing_field_name  = {:?}",
    //   BigUint::from_bytes_le(&raw_state.parsing_field_name.to_bytes())
    // );
    // println!(
    //   "state[ {ctr:?} ].parsing_field_value = {:?}",
    //   BigUint::from_bytes_le(&raw_state.parsing_field_value.to_bytes())
    // );
    // println!(
    //   "state[ {ctr:?} ].parsing_body        = {:?}",
    //   BigUint::from_bytes_le(&raw_state.parsing_body.to_bytes())
    // );
    // println!(
    //   "state[ {ctr:?} ].line_status         = {:?}",
    //   BigUint::from_bytes_le(&raw_state.line_status.to_bytes())
    // );
    // println!(
    //   "state[ {ctr:?} ].inner_main_digest   = {:?}",
    //   BigUint::from_bytes_le(&raw_state.line_digest.to_bytes())
    // );
    // println!(
    //   "state[ {ctr:?} ].line_monomial       = {:?}",
    //   BigUint::from_bytes_le(&raw_state.line_monomial.to_bytes())
    // );
    // println!("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
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
    let states = parse(mock::RESPONSE_PLAINTEXT.as_bytes(), polynomial_input).unwrap();
    assert_eq!(states.len(), mock::RESPONSE_PLAINTEXT.len());

    let machine_state = RawHttpMachine::from(states.last().unwrap().to_owned());
    assert_eq!(machine_state.parsing_start, F::ZERO);
    assert_eq!(machine_state.parsing_header, F::ZERO);
    assert_eq!(machine_state.parsing_field_name, F::ZERO);
    assert_eq!(machine_state.parsing_field_value, F::ZERO);
    assert_eq!(machine_state.parsing_body, F::ONE);
    assert_eq!(machine_state.line_status, F::from(0));
    assert_eq!(machine_state.line_digest, F::from(0));
    assert_eq!(machine_state.line_monomial, F::from(0));
  }

  #[rstest]
  #[case::github("github_response")]
  #[case::reddit("reddit_request")]
  pub fn test_parse_http_complex(#[case] filename: &str) {
    // It's funny to me every time
    let polynomial_input = poseidon::<2>(&[F::from(69), F::from(420)]);

    let input = std::fs::read(format!("../examples/http/{}.http", filename)).unwrap();
    let states = parse(&input, polynomial_input).unwrap();

    let machine_state: [String; 8] = RawHttpMachine::from(states[511].to_owned()).into();
    dbg!(machine_state);

    let machine_state: [String; 8] = RawHttpMachine::from(states[1023].to_owned()).into();
    dbg!(machine_state);

    let machine_state = RawHttpMachine::from(states.last().unwrap().to_owned());
    assert_eq!(machine_state.parsing_start, F::ZERO);
    assert_eq!(machine_state.parsing_header, F::ZERO);
    assert_eq!(machine_state.parsing_field_name, F::ZERO);
    assert_eq!(machine_state.parsing_field_value, F::ZERO);
    assert_eq!(machine_state.parsing_body, F::ONE);
    assert_eq!(machine_state.line_status, F::from(0));
    assert_eq!(machine_state.line_digest, F::from(0));
    assert_eq!(machine_state.line_monomial, F::from(0));
  }
}
