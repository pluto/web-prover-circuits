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

pub(crate) const KEY_0: &str = "data";
pub(crate) const KEY_1: &str = "items";
pub(crate) const KEY_2: &str = "profile";
pub(crate) const KEY_3: &str = "name";
