// TODO: Make these consts just strings and cast into bytes later.

pub(crate) const RESPONSE_PLAINTEXT: &str = "HTTP/1.1 200 OK\r
content-type: application/json; charset=utf-8\r
content-encoding: gzip\r
Transfer-Encoding: chunked\r\n\r
{\r
   \"data\": {\r
       \"items\": [\r
           {\r
               \"data\": \"Artist\",\r
               \"profile\": {\r
                \"name\": \"Taylor Swift\"\r
               }\r
           }\r
       ]\r
   }\r
}";

pub(crate) const RESPONSE_START_LINE: &str = "HTTP/1.1 200 OK";

pub(crate) const RESPONSE_HEADER_0: &str = "content-type: application/json; charset=utf-8";

pub(crate) const RESPONSE_HEADER_1: &str = "content-encoding: gzip";

pub(crate) const RESPONSE_BODY: &str = "{\r
   \"data\": {\r
       \"items\": [\r
           {\r
               \"data\": \"Artist\",\r
               \"profile\": {\r
                \"name\": \"Taylor Swift\"\r
               }\r
           }\r
       ]\r
   }\r
}";

pub(crate) const RESPONSE_CIPHERTEXT: [u8; 320] = [
  2, 125, 219, 141, 140, 93, 49, 129, 95, 178, 135, 109, 48, 36, 194, 46, 239, 155, 160, 70, 208,
  147, 37, 212, 17, 195, 149, 190, 38, 215, 23, 241, 84, 204, 167, 184, 179, 172, 187, 145, 38, 75,
  123, 96, 81, 6, 149, 36, 135, 227, 226, 254, 177, 90, 241, 159, 0, 230, 183, 163, 210, 88, 133,
  176, 9, 122, 225, 83, 171, 157, 185, 85, 122, 4, 110, 52, 2, 90, 36, 189, 145, 63, 122, 75, 94,
  21, 163, 24, 77, 85, 110, 90, 228, 157, 103, 41, 59, 128, 233, 149, 57, 175, 121, 163, 185, 144,
  162, 100, 17, 34, 9, 252, 162, 223, 59, 221, 106, 127, 104, 11, 121, 129, 154, 49, 66, 220, 65,
  130, 171, 165, 43, 8, 21, 248, 12, 214, 33, 6, 109, 3, 144, 52, 124, 225, 206, 223, 213, 86, 186,
  93, 170, 146, 141, 145, 140, 57, 152, 226, 218, 57, 30, 4, 131, 161, 0, 248, 172, 49, 206, 181,
  47, 231, 87, 72, 96, 139, 145, 117, 45, 77, 134, 249, 71, 87, 178, 239, 30, 244, 156, 70, 118,
  180, 176, 90, 92, 80, 221, 177, 86, 120, 222, 223, 244, 109, 150, 226, 142, 97, 171, 210, 38,
  117, 143, 163, 204, 25, 223, 238, 209, 58, 59, 100, 1, 86, 241, 103, 152, 228, 37, 187, 79, 36,
  136, 133, 171, 41, 184, 145, 146, 45, 192, 173, 219, 146, 133, 12, 246, 190, 5, 54, 99, 155, 8,
  198, 156, 174, 99, 12, 210, 95, 5, 128, 166, 118, 50, 66, 26, 20, 3, 129, 232, 1, 192, 104, 23,
  152, 212, 94, 97, 138, 162, 90, 185, 108, 221, 211, 247, 184, 253, 15, 16, 24, 32, 240, 240, 3,
  148, 89, 30, 54, 161, 131, 230, 161, 217, 29, 229, 251, 33, 220, 230, 102, 131, 245, 27, 141,
  220, 67, 16, 26,
];

pub(crate) const KEY_0: &str = "data";
pub(crate) const KEY_1: &str = "items";
pub(crate) const KEY_2: &str = "profile";
pub(crate) const KEY_3: &str = "name";

// use std::collections::HashMap;

// use crate::{
//   http::{Manifest, Request, Response, ResponseBody},
//   json::JsonKey,
// };

// #[cfg(test)]
// pub(crate) fn mock_manifest() -> Manifest {
//   let request = Request {
//     method:  "GET".to_string(),
//     url:     "spotify.com".to_string(),
//     version: "HTTP/1.1".to_string(),
//     headers: HashMap::new(),
//   };
//   let mut headers = HashMap::new();
//   headers.insert("content-type".to_string(), "application/json; charset=utf-8".to_string());
//   headers.insert("content-encoding".to_string(), "gzip".to_string());
//   let body = ResponseBody {
//     json: vec![
//       JsonKey::String("data".to_string()),
//       JsonKey::String("items".to_string()),
//       JsonKey::Num(0),
//       JsonKey::String("profile".to_string()),
//       JsonKey::String("name".to_string()),
//     ],
//   };
//   let response = Response {
//     status: "200".to_string(),
//     version: "HTTP/1.1".to_string(),
//     message: "OK".to_string(),
//     headers,
//     body,
//   };
//   Manifest { request, response }
// }
