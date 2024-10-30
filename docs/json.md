# JSON extractor

Extractor module provides circuits to generate proofs of arbitrary values in a JSON file. To achieve this, proof generation is broken into following components:
- [parser](../circuits/json/parser/): state parser based on a stack machine
- [interpreter](../circuits/json/interpreter.circom): high-level interpretation of JSON state
- [codegen](../src/bin/codegen.rs): extractor circuit generation
- [extractor](../circuits/main/extractor.circom): extracting value for a specific key inside a JSON

## Parser
Parser is divided into three files:
- [Language](../circuits/json/parser/language.circom): JSON language syntax
- [Parser](../circuits/json/parser/parser.circom): initialises the parser and parse individual bytes
- [Machine](../circuits/json/parser/machine.circom): stack machine responsible for updating state

State of JSON parser consists of:
- `stack` with a maximum `MAX_STACK_HEIGHT` argument
- `parsing_string`
- `parsing_number`

Let's take a simple [example](../examples/json/test/value_string.json): `{ "k": "v" }`. Parser initialises the stack with `[0, 0]` and starts iterating through each byte one-by-one.

1. `0`: detects `START_BRACKET: {`. so, we're inside a key and updates stack to `[1, 0]`
2. `3`: detects a `QUOTE:"` and toggles `parsing_string` to `1`
3. `4`: detects another `QUOTE` and toggles `parsing_string` back to `0`
4. `5`: detects `COLON` and updates stack to `[1, 1]` which means we're now inside a value
5. `7`: detects a `QUOTE` again and toggles `parsing_string` which is toggled back on `9`
6. `11`: detects `CLOSING_BRACKET: }` and resets stack back to `[0, 0]`

```
State[ 0 ].byte =  123
State[ 0 ].stack[ 0 ]     = [ 1 ][ 0 ]
State[ 0 ].parsing_string =  0
State[ 0 ].parsing_number =  0
mask 0
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
State[ 1 ].byte =  32
State[ 1 ].stack[ 0 ]     = [ 1 ][ 0 ]
State[ 1 ].parsing_string =  0
State[ 1 ].parsing_number =  0
mask 0
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
State[ 2 ].byte =  34
State[ 2 ].stack[ 0 ]     = [ 1 ][ 0 ]
State[ 2 ].parsing_string =  1
State[ 2 ].parsing_number =  0
mask 0
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
State[ 3 ].byte =  107
State[ 3 ].stack[ 0 ]     = [ 1 ][ 0 ]
State[ 3 ].parsing_string =  1
State[ 3 ].parsing_number =  0
mask 0
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
State[ 4 ].byte =  34
State[ 4 ].stack[ 0 ]     = [ 1 ][ 0 ]
State[ 4 ].parsing_string =  0
State[ 4 ].parsing_number =  0
mask 0
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
State[ 5 ].byte =  58
State[ 5 ].stack[ 0 ]     = [ 1 ][ 1 ]
State[ 5 ].parsing_string =  0
State[ 5 ].parsing_number =  0
mask 0
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
State[ 6 ].byte =  32
State[ 6 ].stack[ 0 ]     = [ 1 ][ 1 ]
State[ 6 ].parsing_string =  0
State[ 6 ].parsing_number =  0
mask 0
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
State[ 7 ].byte =  34
State[ 7 ].stack[ 0 ]     = [ 1 ][ 1 ]
State[ 7 ].parsing_string =  1
State[ 7 ].parsing_number =  0
mask 34
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
State[ 8 ].byte =  118
State[ 8 ].stack[ 0 ]     = [ 1 ][ 1 ]
State[ 8 ].parsing_string =  1
State[ 8 ].parsing_number =  0
mask 118
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
State[ 9 ].byte =  34
State[ 9 ].stack[ 0 ]     = [ 1 ][ 1 ]
State[ 9 ].parsing_string =  0
State[ 9 ].parsing_number =  0
mask 0
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
State[ 10 ].byte =  32
State[ 10 ].stack[ 0 ]     = [ 1 ][ 1 ]
State[ 10 ].parsing_string =  0
State[ 10 ].parsing_number =  0
mask 0
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
State[ 11 ].stack[ 0 ]     = [ 0 ][ 0 ]
State[ 11 ].parsing_string =  0
State[ 11 ].parsing_number =  0
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
value_starting_index 7
value[ 0 ]= 118
```

Logic for parser:
- Iterate through each byte.
- Determine current byte token, and form instruction.
  - determine what is the current byte in signals: start brace, end brace, start bracket, end bracket, colon, comma, number, quote, other (whitespace)
  - create an instruction by multiplying arrays together
- form a state mask based on current state
- multiply instruction and mask together to calculate whether reading or writing value to stack.
- rewrite stack using new instruction
  - stack[0] can change when pushing (read start brace or bracket) / popping (read end brace or bracket)
  - stack[1] can change when readColon / readComma

Let's deep dive into interpreter and extractor.

## Interpreter
Interpreter builds high-level circuits on top of stack to understand state better. It provides following templates:
- `InsideKey`
- `InsideValueAtTop` & `InsideValue`
- `InsideArrayIndexAtTop` & `InsideArrayIndex`
- `NextKVPair` & `NextKVPairAtDepth`
- `KeyMatch` & `KeyMatchAtDepth`

## Codegen
To handle arbitrary depth JSON key, we need to generate circuits on-the-fly using some metadata.

```json
{
    "keys": [
        "a"
    ],
    "value_type": "string"
}
```

Each new key in `keys` is associated with depth in parser stack, i.e. key `a` has depth `0`, and the value type of `a` is a `string`.
Using this, a rust program generates circuit that can extract any key at depth 0 (and not just key `a`) whose value type is a string.

## Extractor
To extract a key at specific depth and value type, we provide

arguments:
- `DATA_BYTES`: data length in bytes
- `MAX_STACK_HEIGHT`: maximum stack height possible during parsing of `data`. Equal to maximum open brackets `{, [` in data.
- `keyLen{i}`: ith key length in bytes, if key is a string
- `index{i}`: ith key array index
- `depth{i}`: ith key's stack depth
- `maxValueLen`: maximum value length

inputs:
- `data`: data in bytes array of `DATA_BYTES` length
- `key{i}`: key i in bytes array of `keyLen{i}` length

output:
- `value`: value of the specified key

Extractor performs following operations:
- parse data byte-by-byte using parser
- use interpreter to gather more information on current state, i.e. whether we're parsing key or value
- if `parsing_key`, then it matches each key in `is_key{i}_match` signal
- if `parsing_value`, then it checks whether we're inside correct values at each depth, i.e.
  - if the key looks like `a.0.b.0` then, value of stack at depth `0` should be `[1, 1]`, and depth `1` should be `[2, 0]`, and so on.
- if the key matches, then we need to propogate this result to the value of that key.
  - We use interpreter's `NextKVPair` template to determine when we start parsing next key pair again in `is_next_pair_at_depth{i}`
- In previous example,
  - key match (`byte = 107`) happened at state 3. so we toggle `is_key1_match_for_value[3]` true.
  - At state 4, `is_key1_match[4]` will return false, but, since we're not parsing next key pair again, we want `is_key1_match_for_value[4]=true` as well.
  - So, we just use previous index's `is_key1_match_for_value` value, i.e. `is_key1_match_for_value[4] = is_key1_match_for_value[3] * is_next_pair[4]`
  - as soon as we hit next pair, we toggle this bit again to 0, and wait for key match again.
- To extract the value, we create a `mask` around that value.
  - `mask[i] = data[i] * parsing_value[i] * is_value_match[i]`, i.e. we're inside the correct value and the key matched for this value.
- Then, we just shift `data` by `value_starting_bytes` to the left and truncate `data` length to `maxValueLen`.

We encourage you to look at [tests](../circuits/test/json/), if you need deeper understanding of [examples](../examples/json/test/).