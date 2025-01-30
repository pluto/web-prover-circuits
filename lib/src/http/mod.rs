use super::*;

pub mod parser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpMachine {
  pub header_num:  usize,
  pub status:      HttpStatus,
  pub line_digest: F,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawHttpMachine {
  pub parsing_start:       F,
  pub parsing_header:      F,
  pub parsing_field_name:  F,
  pub parsing_field_value: F,
  pub parsing_body:        F,
  pub line_status:         F,
  pub line_digest:         F,
}

impl From<HttpMachine> for RawHttpMachine {
  fn from(value: HttpMachine) -> Self {
    let mut raw_http_machine = RawHttpMachine::default();
    raw_http_machine.line_digest = value.line_digest;
    raw_http_machine.parsing_header = F::from(value.header_num as u64);
    match value.status {
      HttpStatus::ParsingStart(start_line_location) => match start_line_location {
        StartLineLocation::Beginning => raw_http_machine.parsing_start = F::ONE,
        StartLineLocation::Middle => raw_http_machine.parsing_start = F::from(2),
        StartLineLocation::End => raw_http_machine.parsing_start = F::from(3),
      },
      HttpStatus::ParsingHeader(name_or_value) => match name_or_value {
        NameOrValue::Name => {
          raw_http_machine.parsing_field_name = F::ONE;
          raw_http_machine.parsing_field_value = F::ZERO;
        },
        NameOrValue::Value => {
          raw_http_machine.parsing_field_name = F::ZERO;
          raw_http_machine.parsing_field_value = F::ONE;
        },
      },
      HttpStatus::ParsingBody => raw_http_machine.parsing_body = F::ONE,
      HttpStatus::LineStatus(line_status) => match line_status {
        LineStatus::CR => raw_http_machine.line_status = F::ONE,
        LineStatus::CRLF => raw_http_machine.line_status = F::from(2),
        LineStatus::CRLFCR => raw_http_machine.line_status = F::from(3),
      },
    }
    raw_http_machine
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpStatus {
  ParsingStart(StartLineLocation),
  ParsingHeader(NameOrValue),
  ParsingBody,
  LineStatus(LineStatus),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameOrValue {
  Name,
  Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartLineLocation {
  Beginning,
  Middle,
  End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineStatus {
  CR,
  CRLF,
  CRLFCR,
}

/// Manifest containing [`Request`] and [`Response`]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
  /// HTTP request lock items
  pub request:  Request,
  /// HTTP response lock items
  pub response: Response,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseBody {
  pub json: Vec<JsonKey>,
}

/// HTTP Response items required for circuits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
  /// HTTP response status
  pub status:  String,
  /// HTTP version
  #[serde(default = "default_version")]
  pub version: String,
  /// HTTP response message
  #[serde(default = "default_message")]
  pub message: String,
  /// HTTP headers to lock
  pub headers: HashMap<String, String>,
  /// HTTP body keys
  pub body:    ResponseBody,
}

/// HTTP Request items required for circuits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
  /// HTTP method (GET or POST)
  pub method:  String,
  /// HTTP request URL
  pub url:     String,
  /// HTTP version
  #[serde(default = "default_version")]
  pub version: String,
  /// Request headers to lock
  pub headers: HashMap<String, String>,
}

pub enum HttpMaskType {
  StartLine,
  Header(usize),
  Body,
}

/// Default HTTP version
pub fn default_version() -> String { "HTTP/1.1".to_string() }
/// Default HTTP message
pub fn default_message() -> String { "OK".to_string() }

// TODO: Note, HTTP does not require a `:` and space between the name and value of a header, so we
// will have to deal with this somehow, but for now I'm assuming there's a space
pub fn headers_to_bytes(headers: &HashMap<String, String>) -> impl Iterator<Item = Vec<u8>> + '_ {
  headers.iter().map(|(k, v)| format!("{}: {}", k.clone(), v.clone()).as_bytes().to_vec())
}

/// compute private inputs for the HTTP circuit.
/// # Arguments
/// - `plaintext`: the plaintext HTTP request/response padded with `-1` to nearest power of 2
/// - `mask_at`: the [`HttpMaskType`] of the HTTP request/response to mask
/// # Returns
/// - the masked HTTP request/response
pub fn compute_http_witness(plaintext: &[ByteOrPad], mask_at: HttpMaskType) -> Vec<ByteOrPad> {
  let mut result = Vec::new();
  match mask_at {
    HttpMaskType::StartLine => {
      // Find the first CRLF sequence
      for i in 0..plaintext.len().saturating_sub(1) {
        if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
          result = plaintext[..i].to_vec();
          break;
        }
      }
    },
    HttpMaskType::Header(idx) => {
      let mut current_header = 0;
      let mut start_pos = 0;

      // Skip the start line
      for i in 0..plaintext.len().saturating_sub(1) {
        if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
          start_pos = i + 2;
          break;
        }
      }

      // Find the specified header
      let mut header_start_pos = start_pos;
      for i in start_pos..plaintext.len().saturating_sub(1) {
        if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
          if current_header == idx {
            // Copy the header line (including CRLF)
            result = plaintext[header_start_pos..i].to_vec();
            break;
          }

          // Check for end of headers (double CRLF)
          if i + 3 < plaintext.len() && plaintext[i + 2] == b'\r' && plaintext[i + 3] == b'\n' {
            break;
          }

          current_header += 1;
          header_start_pos = i + 2;
        }
      }
    },
    HttpMaskType::Body => {
      // Find double CRLF that marks start of body
      for i in 0..plaintext.len().saturating_sub(3) {
        if plaintext[i] == b'\r'
          && plaintext[i + 1] == b'\n'
          && plaintext[i + 2] == b'\r'
          && plaintext[i + 3] == b'\n'
        {
          // Copy everything after the double CRLF
          let body_start = i + 4;
          if body_start < plaintext.len() {
            result = plaintext[body_start..].to_vec();
          }
          break;
        }
      }
    },
  }
  result
}

pub fn compute_http_header_witness(
  plaintext: &[ByteOrPad],
  name: &[u8],
) -> (usize, Vec<ByteOrPad>) {
  let mut result = Vec::new();

  let mut current_header = 0;
  let mut current_header_name = vec![];
  let mut start_pos = 0;

  // Skip the start line
  for i in 1..plaintext.len().saturating_sub(1) {
    if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
      start_pos = i + 2;
      break;
    }
  }

  // Find the specified header
  let mut header_start_pos = start_pos;
  for i in start_pos..plaintext.len().saturating_sub(1) {
    // find header name
    if plaintext[i] == b':' {
      current_header_name = plaintext[header_start_pos..i].to_vec();
    }
    // find next header line
    if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
      if current_header_name == name {
        // Copy the header line (including CRLF)
        result = plaintext[header_start_pos..i].to_vec();
        break;
      }

      // Check for end of headers (double CRLF)
      if i + 3 < plaintext.len() && plaintext[i + 2] == b'\r' && plaintext[i + 3] == b'\n' {
        break;
      }

      current_header += 1;
      header_start_pos = i + 2;
    }
  }

  (current_header, result)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_compute_http_witness_start_line() {
    let bytes = compute_http_witness(
      &RESPONSE_PLAINTEXT
        .as_bytes()
        .iter()
        .copied()
        .map(ByteOrPad::from)
        .collect::<Vec<ByteOrPad>>(),
      HttpMaskType::StartLine,
    );
    assert_eq!(ByteOrPad::as_bytes(&bytes), RESPONSE_START_LINE.as_bytes());
  }

  #[test]
  fn test_compute_http_witness_header_0() {
    let bytes = compute_http_witness(
      &RESPONSE_PLAINTEXT
        .as_bytes()
        .iter()
        .copied()
        .map(ByteOrPad::from)
        .collect::<Vec<ByteOrPad>>(),
      HttpMaskType::Header(0),
    );
    assert_eq!(ByteOrPad::as_bytes(&bytes), RESPONSE_HEADER_0.as_bytes());
  }

  #[test]
  fn test_compute_http_witness_header_1() {
    let bytes = compute_http_witness(
      &RESPONSE_PLAINTEXT
        .as_bytes()
        .iter()
        .copied()
        .map(ByteOrPad::from)
        .collect::<Vec<ByteOrPad>>(),
      HttpMaskType::Header(1),
    );
    assert_eq!(ByteOrPad::as_bytes(&bytes), RESPONSE_HEADER_1.as_bytes());
  }

  #[test]
  fn test_compute_http_witness_body() {
    let bytes = compute_http_witness(
      &RESPONSE_PLAINTEXT
        .as_bytes()
        .iter()
        .copied()
        .map(ByteOrPad::from)
        .collect::<Vec<ByteOrPad>>(),
      HttpMaskType::Body,
    );
    assert_eq!(ByteOrPad::as_bytes(&bytes), RESPONSE_BODY.as_bytes());
  }

  #[test]
  fn test_compute_http_witness_name() {
    let (index, bytes_from_name) = compute_http_header_witness(
      &RESPONSE_PLAINTEXT
        .as_bytes()
        .iter()
        .copied()
        .map(ByteOrPad::from)
        .collect::<Vec<ByteOrPad>>(),
      "Transfer-Encoding".as_bytes(),
    );
    let bytes_from_index = compute_http_witness(
      &RESPONSE_PLAINTEXT
        .as_bytes()
        .iter()
        .copied()
        .map(ByteOrPad::from)
        .collect::<Vec<ByteOrPad>>(),
      HttpMaskType::Header(2),
    );
    assert_eq!(bytes_from_index, bytes_from_name);
    assert_eq!(index, 2);
  }

  #[test]
  fn test_compute_http_witness_name_not_present() {
    let (_, bytes_from_name) = compute_http_header_witness(
      &RESPONSE_PLAINTEXT
        .as_bytes()
        .iter()
        .copied()
        .map(ByteOrPad::from)
        .collect::<Vec<ByteOrPad>>(),
      "pluto-rocks".as_bytes(),
    );
    assert!(bytes_from_name.is_empty());
  }
}
