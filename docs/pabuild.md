# `pabuild` CLI Tool
This repository contains a small Rust CLI tool called `pabuild`.

## Install `pabuild`
From the root of this repository, run:
```sh
cargo install --path .
```
to install the `pabuild` binary.
You can see a help menu with the subcommands by:
```sh
pabuild --help
```

## Witnessgen
To get the basic idea, run
```sh
pabuild witness --help
```
It can process and generate input JSON files to be used for parser/extractor circuits.

> [!NOTE]
> `circuit-name` need to be **same** for witness generator and codegen.

### Examples
**JSON Parsing:**
If we have a given JSON file we want to parse such as [`examples/json/test/example.json`](../examples/json/test/example.json) for the `json-parser` circuit (see [`circuits.json`](../circuits.json)), then we can:

```sh
pabuild witness parser json --input-file examples/json/test/example.json --circuit-name json-parser
```

Afterwards, you can run `npx circomkit compile json-parser` then `circomkit witness json-parser input`.

**HTTP Parsing:**
If we have a given HTTP request/response (as a file) we want to parse such as [`examples/http/get_request.http`](../examples/http/get_request.http) for the `http-parser` circuit (see `circuits.json`), then we can:

```sh
pabuild witness parser http --input-file examples/http/get_request.http --circuit-name http-parser
```

Afterwards, you can run `npx circomkit compile http-parser` then `circomkit witness http-parser input`.

**JSON Extractor:**
To extract a value out of a JSON, we need a lockfile that contains keys and value type.

```sh
pabuild witness extractor json --input-file examples/json/test/value_string.json --lockfile examples/json/lockfile/value_string.json --circuit-name value_string
```

**HTTP Extractor:**
To extract reponse from HTTP, a lockfile need to be given with start line (method, status, version) and headers to be matched. Example can be found in [examples/http/lockfile](../examples/http/lockfile/).

```sh
pabuild witness extractor http --input-file examples/http/get_response.http --lockfile examples/http/lockfile/response.lock.json --circuit-name get-response
```

## Codegen
Extractor circuit is generated using rust to handle arbitrary keys and array indices.

Run:
```sh
pabuild codegen --help
```
to get options:
```
Usage: pabuild codegen [OPTIONS] --circuit-name <CIRCUIT_NAME> --input-file <INPUT_FILE> --lockfile <LOCKFILE> <SUBCOMMAND>

Arguments:
  <SUBCOMMAND>  [possible values: json, http, extended]

Options:
      --circuit-name <CIRCUIT_NAME>  Name of the circuit (to be used in circomkit config)
      --input-file <INPUT_FILE>      Path to the JSON/HTTP file
      --lockfile <LOCKFILE>          Path to the lockfile
  -d, --debug                        Optional circuit debug logs
  -h, --help                         Print help
```
Takes 3 input arguments:
- `input-file`: input json/http file. Examples are located in [examples/json](../examples/json/test/).
- `lockfile`: keys and value type for extraction. Should contain only two keys:
  - `keys`: list of all the keys for the value to be extracted.
  - `value_type`: Currently only two value types are supported: `String`,`Number`.
- `circuit-name`: circuit filename to save. Located in [circuits/main](../circuits/main/). Prefixed with `json_`
- `debug`: Optional circuit debug logs.

### JSON Extraction

To test an end-to-end JSON extraction proof:
- Run codegen to generate circuits. Replace `value_string` with `circuit-name`.
   ```sh
   pabuild codegen json --circuit-name value_string --input-file examples/json/test/value_string.json --lockfile examples/json/lockfile/value_string.json -d
   ```

- codegen adds circuit config to [circuits.json](../circuits.json) for circomkit support. Compile circuits using `npx circomkit compile value_string`

- Generate witness:
   ```sh
   node build/value_string/value_string_js/generate_witness.js build/value_string/value_string_js/value_string.wasm inputs/value_string/inputs.json build/value_string/witness.wtns
   ```
   or generate using circomkit:
   ```bash
   npx circomkit witness value_string inputs
   ```

- create trusted setup, circomkit downloads the required trusted setup file. Download manually, if using `snarkjs`:
   ```bash
   npx circomkit setup value_string
   # OR
   snarkjs groth16 setup build/value_string/value_string.r1cs ptau/powersOfTau28_hez_final_14.ptau build/value_string/groth16_pkey.zkey

   snarkjs zkey contribute build/value_string/groth16_pkey.zkey build/value_string/groth16_pkey_1.zkey --name="random" -v

   snarkjs zkey beacon build/value_string/groth16_pkey_1.zkey build/value_string/groth16_pkey_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"

   snarkjs zkey verify build/value_string/value_string.r1cs ptau/powersOfTau28_hez_final_14.ptau build/value_string/groth16_pkey_final.zkey

   snarkjs zkey export verificationkey build/value_string/groth16_pkey_final.zkey build/value_string/groth16_vkey.json
   ```

- create proof:
   ```bash
   npx circomkit prove value_string inputs
   # OR
   snarkjs groth16 prove build/value_string/groth16_pkey_final.zkey build/value_string/witness.wtns build/value_string/groth16_proof.json inputs/value_string/inputs.json
   ```

- verify proof:
   ```bash
   npx circomkit verify value_string value_string
   # OR
   snarkjs groth16 verify build/value_string/groth16_vkey.json inputs/value_string/inputs.json build/value_string/groth16_proof.json
   ```

### HTTP Locking and Extraction

To test an end-to-end HTTP response extraction proof:
- Run codegen to generate circuits. Replace `get-response` with `circuit-name`.
   ```sh
   pabuild codegen http --circuit-name get-response --input-file examples/http/get_response.http --lockfile examples/http/lockfile/response.lock.json -d
   ```

- codegen adds circuit config to [circuits.json](../circuits.json) for circomkit support. Compile circuits using `npx circomkit compile get-response`

- Generate witness:
   ```sh
   node build/get-response/get-response_js/generate_witness.js build/get-response/get-response_js/get-response.wasm inputs/get-response/inputs.json build/get-response/witness.wtns
   ```
   or generate using circomkit:
   ```bash
   npx circomkit witness get-response inputs
   ```

- create trusted setup, circomkit downloads the required trusted setup file. Download manually, if using `snarkjs`:
   ```bash
   npx circomkit setup get-response
   # OR
   snarkjs groth16 setup build/get-response/get-response.r1cs ptau/powersOfTau28_hez_final_16.ptau build/get-response/groth16_pkey.zkey

   snarkjs zkey contribute build/get-response/groth16_pkey.zkey build/get-response/groth16_pkey_1.zkey --name="random" -v

   snarkjs zkey beacon build/get-response/groth16_pkey_1.zkey build/get-response/groth16_pkey_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"

   snarkjs zkey verify build/get-response/get-response.r1cs ptau/powersOfTau28_hez_final_16.ptau build/get-response/groth16_pkey_final.zkey

   snarkjs zkey export verificationkey build/get-response/groth16_pkey_final.zkey build/get-response/groth16_vkey.json
   ```

- create proof:
   ```bash
   npx circomkit prove get-response inputs
   # OR
   snarkjs groth16 prove build/get-response/groth16_pkey_final.zkey build/get-response/witness.wtns build/get-response/groth16_proof.json inputs/get-response/inputs.json
   ```

- verify proof:
   ```bash
   npx circomkit verify value_string value_string
   # OR
   snarkjs groth16 verify build/get-response/groth16_vkey.json inputs/get-response/inputs.json build/get-response/groth16_proof.json
   ```

### Extended HTTP + JSON extraction

`pabuild` allows to create a proof of arbitrary HTTP response.
- Locks start line, and headers for HTTP as specified in [lockfile](../examples/http/lockfile/spotify_extended.lock.json).
  - **NOTE**: `Accept-Encoding: identity` header is mandatory as pabuild doesn't support `gzip` encoding.
- extracts response body out
- create a JSON value extractor circuit based on keys in [lockfile](../examples/http/lockfile/spotify_extended.lock.json)
- extract the value out and create a proof

Steps to run an end-to-end proof is similar to HTTP/JSON extractor:
- Run codegen to generate circuits. Replace `value_string` with `circuit-name`.
   ```sh
   pabuild codegen extended --circuit-name spotify_top_artists --input-file examples/http/spotify_top_artists.json --lockfile examples/http/lockfile/spotify_extended.lock.json -d
   ```

- Refer to [HTTP extractor](#http-locking-and-extraction) for following steps:
   - generate witness
   - create trusted setup
   - create proof
   - verify proof