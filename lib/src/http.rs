use super::*;

/// Manifest containing [`Request`] and [`Response`]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// HTTP request lock items
    pub request: Request,
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
    pub status: String,
    /// HTTP version
    #[serde(default = "default_version")]
    pub version: String,
    /// HTTP response message
    #[serde(default = "default_message")]
    pub message: String,
    /// HTTP headers to lock
    pub headers: HashMap<String, String>,
    /// HTTP body keys
    pub body: ResponseBody,
}

/// HTTP Request items required for circuits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// HTTP method (GET or POST)
    pub method: String,
    /// HTTP request URL
    pub url: String,
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
pub fn default_version() -> String {
    "HTTP/1.1".to_string()
}
/// Default HTTP message
pub fn default_message() -> String {
    "OK".to_string()
}

// TODO: Note, HTTP does not require a `:` and space between the name and value of a header, so we
// will have to deal with this somehow, but for now I'm assuming there's a space
pub fn headers_to_bytes(headers: &HashMap<String, String>) -> impl Iterator<Item = Vec<u8>> + '_ {
    headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k.clone(), v.clone()).as_bytes().to_vec())
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
        }
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
                    if i + 3 < plaintext.len()
                        && plaintext[i + 2] == b'\r'
                        && plaintext[i + 3] == b'\n'
                    {
                        break;
                    }

                    current_header += 1;
                    header_start_pos = i + 2;
                }
            }
        }
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
        }
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

    // TODO: Make these consts just strings and cast into bytes later.
    const TEST_HTTP_BYTES: &[u8] = &[
        72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 99, 111, 110, 116, 101,
        110, 116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111,
        110, 47, 106, 115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102,
        45, 56, 13, 10, 99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110,
        103, 58, 32, 103, 122, 105, 112, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69, 110,
        99, 111, 100, 105, 110, 103, 58, 32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13, 10, 123,
        13, 10, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32,
        32, 34, 105, 116, 101, 109, 115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34,
        100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34,
        58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34,
        110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116,
        34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13,
        10, 32, 32, 32, 125, 13, 10, 125,
    ];

    const TEST_CIPHERTEXT: [u8; 320] = [
        2, 125, 219, 141, 140, 93, 49, 129, 95, 178, 135, 109, 48, 36, 194, 46, 239, 155, 160, 70,
        208, 147, 37, 212, 17, 195, 149, 190, 38, 215, 23, 241, 84, 204, 167, 184, 179, 172, 187,
        145, 38, 75, 123, 96, 81, 6, 149, 36, 135, 227, 226, 254, 177, 90, 241, 159, 0, 230, 183,
        163, 210, 88, 133, 176, 9, 122, 225, 83, 171, 157, 185, 85, 122, 4, 110, 52, 2, 90, 36,
        189, 145, 63, 122, 75, 94, 21, 163, 24, 77, 85, 110, 90, 228, 157, 103, 41, 59, 128, 233,
        149, 57, 175, 121, 163, 185, 144, 162, 100, 17, 34, 9, 252, 162, 223, 59, 221, 106, 127,
        104, 11, 121, 129, 154, 49, 66, 220, 65, 130, 171, 165, 43, 8, 21, 248, 12, 214, 33, 6,
        109, 3, 144, 52, 124, 225, 206, 223, 213, 86, 186, 93, 170, 146, 141, 145, 140, 57, 152,
        226, 218, 57, 30, 4, 131, 161, 0, 248, 172, 49, 206, 181, 47, 231, 87, 72, 96, 139, 145,
        117, 45, 77, 134, 249, 71, 87, 178, 239, 30, 244, 156, 70, 118, 180, 176, 90, 92, 80, 221,
        177, 86, 120, 222, 223, 244, 109, 150, 226, 142, 97, 171, 210, 38, 117, 143, 163, 204, 25,
        223, 238, 209, 58, 59, 100, 1, 86, 241, 103, 152, 228, 37, 187, 79, 36, 136, 133, 171, 41,
        184, 145, 146, 45, 192, 173, 219, 146, 133, 12, 246, 190, 5, 54, 99, 155, 8, 198, 156, 174,
        99, 12, 210, 95, 5, 128, 166, 118, 50, 66, 26, 20, 3, 129, 232, 1, 192, 104, 23, 152, 212,
        94, 97, 138, 162, 90, 185, 108, 221, 211, 247, 184, 253, 15, 16, 24, 32, 240, 240, 3, 148,
        89, 30, 54, 161, 131, 230, 161, 217, 29, 229, 251, 33, 220, 230, 102, 131, 245, 27, 141,
        220, 67, 16, 26,
    ];

    const TEST_HTTP_START_LINE: &[u8] =
        &[72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75];

    const TEST_HTTP_HEADER_0: &[u8] = &[
        99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105,
        99, 97, 116, 105, 111, 110, 47, 106, 115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101,
        116, 61, 117, 116, 102, 45, 56,
    ];

    const TEST_HTTP_HEADER_1: &[u8] = &[
        99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103,
        122, 105, 112,
    ];

    const TEST_HTTP_BODY: &[u8] = &[
        123, 13, 10, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32,
        32, 32, 34, 105, 116, 101, 109, 115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111, 102, 105, 108, 101,
        34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102,
        116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93,
        13, 10, 32, 32, 32, 125, 13, 10, 125,
    ];

    #[test]
    fn test_compute_http_witness_start_line() {
        let bytes = compute_http_witness(
            &TEST_HTTP_BYTES
                .iter()
                .copied()
                .map(ByteOrPad::from)
                .collect::<Vec<ByteOrPad>>(),
            HttpMaskType::StartLine,
        );
        assert_eq!(ByteOrPad::as_bytes(&bytes), TEST_HTTP_START_LINE);
    }

    #[test]
    fn test_compute_http_witness_header_0() {
        let bytes = compute_http_witness(
            &TEST_HTTP_BYTES
                .iter()
                .copied()
                .map(ByteOrPad::from)
                .collect::<Vec<ByteOrPad>>(),
            HttpMaskType::Header(0),
        );
        assert_eq!(ByteOrPad::as_bytes(&bytes), TEST_HTTP_HEADER_0);
    }

    #[test]
    fn test_compute_http_witness_header_1() {
        let bytes = compute_http_witness(
            &TEST_HTTP_BYTES
                .iter()
                .copied()
                .map(ByteOrPad::from)
                .collect::<Vec<ByteOrPad>>(),
            HttpMaskType::Header(1),
        );
        assert_eq!(ByteOrPad::as_bytes(&bytes), TEST_HTTP_HEADER_1);
    }

    #[test]
    fn test_compute_http_witness_body() {
        let bytes = compute_http_witness(
            &TEST_HTTP_BYTES
                .iter()
                .copied()
                .map(ByteOrPad::from)
                .collect::<Vec<ByteOrPad>>(),
            HttpMaskType::Body,
        );
        assert_eq!(ByteOrPad::as_bytes(&bytes), TEST_HTTP_BODY);
    }

    #[test]
    fn test_compute_http_witness_name() {
        let (index, bytes_from_name) = compute_http_header_witness(
            &TEST_HTTP_BYTES
                .iter()
                .copied()
                .map(ByteOrPad::from)
                .collect::<Vec<ByteOrPad>>(),
            "Transfer-Encoding".as_bytes(),
        );
        let bytes_from_index = compute_http_witness(
            &TEST_HTTP_BYTES
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
            &TEST_HTTP_BYTES
                .iter()
                .copied()
                .map(ByteOrPad::from)
                .collect::<Vec<ByteOrPad>>(),
            "pluto-rocks".as_bytes(),
        );
        assert!(bytes_from_name.is_empty());
    }
}
