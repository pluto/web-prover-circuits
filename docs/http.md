# HTTP Extractor

> [!WARNING] Deprecated docs
> These docs are out-of-date with current architecture which uses hash-based approach. Will be updated later. More details can be found in [circuits](../circuits/http/verification.circom)

HTTP is a more strict and well-defined specification that JSON, and thus, it's parser is a lot easier than JSON.

Proof generation for HTTP extractor is broken into:
- [Parser](../circuits/http/parser/machine.circom): state parser based on a stack machine
- [Interpreter](../circuits/http/interpreter.circom): interpretation of stack machine to represent different HTTP states.
- [Locker](../circuits/http/locker.circom): locks start line, headers in a HTTP file
- [codegen](../src/codegen/http.rs): generates locker circuit that locks start line, headers and extract response

## Parser

We follow [RFC 9112](https://httpwg.org/specs/rfc9112.html) to represent and understand HTTP state in the parser.

Parser is divided into two files:
- [Language](../circuits/json/parser/language.circom): HTTP language syntax
- [Machine](../circuits/json/parser/machine.circom): stack machine responsible for updating state

HTTP parser state consists of:
- `parsing_start`: flag that counts up to 3 for each value in the start line. Request has `[method, target, version]` and Response has `[version, status, message]`.
- `parsing_header`: flag + counter for each new header
- `parsing_field_name`: flag tracking if inside a field name
- `parsing_field_value`: flag tracking whether inside field value
- `parsing_body`: flag tracking if inside body
- `line_status`: flag counting double CRLF

We advise to go through detailed [tests](../circuits/test/http/locker.test.ts) to understand HTTP state parsing.

## Interpreter
Interpreter builds following high-level circuit to understand parser state:
- `inStartLine`: whether parser is inside start line
- `inStartMiddle`: whether parser is inside second value of start line
- `inStartEnd`: whether parser is inside last value of start line
- `MethodMatch`: matches a method at specified index
- `HeaderFieldNameValueMatch`: match a header field name and value
- `HeaderFieldNameMatch`: match a header field name

## Codegen
[Lockfile](../examples/http/lockfile/) needs to be supplied while generating the code through `pabuild` cli and should follow certain rules.

```json
{
    "version": "HTTP/1.1",
    "status": "200",
    "message": "OK",
    "headerName1": "Content-Type",
    "headerValue1": "application/json"
}
```

It should mention start line values depending on Request or Response file, and header field names and values to be matched.

Codegen generates a circom template to match lockfile values and extracts response body, if the lockfile is for response data.

## Extractor
Extracting response body is done by checking whether parser state is inside body and creating a mask to determine starting bytes. Shifting the body by starting byte index gives the response body.