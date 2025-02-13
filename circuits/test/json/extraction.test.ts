import { poseidon1, poseidon2 } from "poseidon-lite";
import { circomkit, WitnessTester, readJSONInputFile, strToBytes, JsonMaskType, jsonTreeHasher, compressTreeHash, PolynomialDigest, modAdd, PUBLIC_IO_VARIABLES, modPow } from "../common";
import { assert } from "chai";
import { nearestMultiplePad } from "../common";

const DATA_BYTES = 512;
const MAX_STACK_HEIGHT = 12;
const mock_ct_digest = poseidon2([69, 420]);

describe("JSON Extraction", () => {
    let hash_parser: WitnessTester<["step_in", "ciphertext_digest", "data", "sequence_digest", "value_digest", "state"]>;

    before(async () => {
        hash_parser = await circomkit.WitnessTester(`Parser`, {
            file: "json/extraction",
            template: "JSONExtraction",
            params: [DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_VARIABLES],
        });
    });

    it(`input: array_only`, async () => {
        let filename = "array_only";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let input_padded = input.concat(Array(DATA_BYTES - input.length).fill(-1));

        // Test `42` in 0th slot
        let targetValue = strToBytes("42");
        let keySequence: JsonMaskType[] = [
            { type: "ArrayIndex", value: 0 },
        ];
        let [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        let sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        let sequence_digest_hashed = poseidon1([sequence_digest]);

        let value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));

        let data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));

        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
        let state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));

        let step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];

        let json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> First subtest passed.");

        // Test `"b"` in 1st slot object
        targetValue = strToBytes("b");
        keySequence = [
            { type: "ArrayIndex", value: 1 },
            { type: "Object", value: strToBytes("a") },
        ];
        [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        sequence_digest_hashed = poseidon1([sequence_digest]);
        value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];;

        json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> Second subtest passed.");
    });

    it(`input: value_array`, async () => {
        let filename = "value_array";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let input_padded = input.concat(Array(DATA_BYTES - input.length).fill(-1));

        // Test `420` in "k"'s 0th slot
        let targetValue = strToBytes("420");
        let keySequence: JsonMaskType[] = [
            { type: "Object", value: strToBytes("k") },
            { type: "ArrayIndex", value: 0 },
        ];
        let [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        let sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        let sequence_digest_hashed = poseidon1([sequence_digest]);
        let data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));

        let value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
        let state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));
        let step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];

        let json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> First subtest passed.");

        // Test `"d"` in "b"'s 3rd slot
        targetValue = strToBytes("d");
        keySequence = [
            { type: "Object", value: strToBytes("b") },
            { type: "ArrayIndex", value: 3 },
        ];
        [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        sequence_digest_hashed = poseidon1([sequence_digest]);
        value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];
        json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> Second subtest passed.");
    });

    it(`input: value_array_object`, async () => {
        let filename = "value_array_object";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let input_padded = input.concat(Array(DATA_BYTES - input.length).fill(-1));

        const KEY0 = strToBytes("a");
        const KEY1 = strToBytes("b");
        const targetValue = strToBytes("4");

        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
            { type: "ArrayIndex", value: 0 },
            { type: "Object", value: KEY1 },
            { type: "ArrayIndex", value: 1 },
        ];

        const [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        const sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        const sequence_digest_hashed = poseidon1([sequence_digest]);
        const data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));
        const value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
        const state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));
        const step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];

        let json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
    });

    it(`input: string escape`, async () => {
        let filename = "string_escape";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let input_padded = input.concat(Array(DATA_BYTES - input.length).fill(-1));

        const KEY0 = strToBytes("a");
        const targetValue = strToBytes("\"b\"");
        console.log(targetValue);

        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
        ];

        const [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, 10);
        const sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        const sequence_digest_hashed = poseidon1([sequence_digest]);
        const data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));

        const value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
        let state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));
        const step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];

        let json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
    });

    it(`input: primitives`, async () => {
        let filename = "primitives";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let input_padded = input.concat(Array(DATA_BYTES - input.length).fill(-1));

        // Test `null` in "null" key
        let targetValue = strToBytes("null");
        let keySequence: JsonMaskType[] = [
            { type: "Object", value: strToBytes("null") },
        ];
        let [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        console.log(treeHashes);
        let sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        let sequence_digest_hashed = poseidon1([sequence_digest]);

        let value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));

        let data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));

        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
        let state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));

        let step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];

        let json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> First subtest passed.");

        // Test `"false"` in "false" key
        targetValue = strToBytes("false");
        keySequence = [
            { type: "Object", value: strToBytes("false") },
        ];
        [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        sequence_digest_hashed = poseidon1([sequence_digest]);
        value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];;

        json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> Second subtest passed.");

        // Test `true` in "true" key
        targetValue = strToBytes("true");
        keySequence = [
            { type: "Object", value: strToBytes("true") },
        ];
        [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        sequence_digest_hashed = poseidon1([sequence_digest]);
        value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];;

        json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> Third subtest passed.");

        // Test `2.0E-1` in "num1" key
        targetValue = strToBytes("2.0E-1");
        keySequence = [
            { type: "Object", value: strToBytes("num1") },
        ];
        [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        sequence_digest_hashed = poseidon1([sequence_digest]);
        value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];;

        json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> Fourth subtest passed.");

        // Test `2.0e+1` in "num1" key
        targetValue = strToBytes("2.0e+1");
        keySequence = [
            { type: "Object", value: strToBytes("num2") },
        ];
        [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        sequence_digest_hashed = poseidon1([sequence_digest]);
        value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];;

        json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> Fourth subtest passed.");
    });

    it(`input: primitives_array`, async () => {
        let filename = "primitives_array";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let input_padded = input.concat(Array(DATA_BYTES - input.length).fill(-1));

        // Test `null` in pos 0
        let targetValue = strToBytes("null");
        let keySequence: JsonMaskType[] = [
            { type: "ArrayIndex", value: 0 },
        ];
        let [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        console.log(treeHashes);
        let sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        let sequence_digest_hashed = poseidon1([sequence_digest]);

        let value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));

        let data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));

        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
        let state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));

        let step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];

        let json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> First subtest passed.");

        // Test `false` in pos 1
        targetValue = strToBytes("false");
        keySequence = [
            { type: "ArrayIndex", value: 1 },
        ];
        [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        sequence_digest_hashed = poseidon1([sequence_digest]);
        value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];;

        json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> Second subtest passed.");

        // Test `true` pos 2
        targetValue = strToBytes("true");
        keySequence = [
            { type: "ArrayIndex", value: 2 },
        ];
        [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        sequence_digest_hashed = poseidon1([sequence_digest]);
        value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];;

        json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> Third subtest passed.");

        // Test `2.0E-1` in pos3
        targetValue = strToBytes("2.0E-1");
        keySequence = [
            { type: "ArrayIndex", value: 3 },
        ];
        [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        sequence_digest_hashed = poseidon1([sequence_digest]);
        value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];;

        json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> Fourth subtest passed.");

        // Test `2.0e+1` in pos 4
        targetValue = strToBytes("2.0e+1");
        keySequence = [
            { type: "ArrayIndex", value: 4 },
        ];
        [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        sequence_digest_hashed = poseidon1([sequence_digest]);
        value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];;

        json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> Fourth subtest passed.");
    });

    it(`input: empty`, async () => {
        let filename = "empty";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let input_padded = input.concat(Array(DATA_BYTES - input.length).fill(-1));

        // Test `{}` in "empty" key
        let keySequence: JsonMaskType[] = [
            { type: "Object", value: strToBytes("empty") },
        ];
        let [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        console.log(treeHashes);
        let sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        let sequence_digest_hashed = poseidon1([sequence_digest]);

        let value_digest = BigInt(0);

        let data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));

        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
        let state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));

        let step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];

        let json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> First subtest passed.");

        // Test `[]` in "arr" key
        keySequence = [
            { type: "Object", value: strToBytes("arr") },
        ];
        [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        sequence_digest_hashed = poseidon1([sequence_digest]);
        value_digest = BigInt(0);
        step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];;

        json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
        console.log("> Second subtest passed.");
    });

    it(`input: spotify`, async () => {
        let filename = "spotify";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let input_padded = nearestMultiplePad(input, DATA_BYTES);

        const KEY0 = strToBytes("data");
        const KEY1 = strToBytes("me");
        const KEY2 = strToBytes("profile");
        const KEY3 = strToBytes("topArtists");
        const KEY4 = strToBytes("items");
        const KEY5 = strToBytes("data");
        const KEY6 = strToBytes("profile");
        const KEY7 = strToBytes("name");
        const targetValue = strToBytes("Pink Floyd");

        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
            { type: "Object", value: KEY1 },
            { type: "Object", value: KEY2 },
            { type: "Object", value: KEY3 },
            { type: "Object", value: KEY4 },
            { type: "ArrayIndex", value: 0 },
            { type: "Object", value: KEY5 },
            { type: "Object", value: KEY6 },
            { type: "Object", value: KEY7 },
        ];

        const [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, 10);
        const sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        const sequence_digest_hashed = poseidon1([sequence_digest]);
        const data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));

        const value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
        let state2 = [
            BigInt("1"), BigInt("1"),
            BigInt("1"), BigInt("1"),
            BigInt("1"), BigInt("1"),
            BigInt("1"), BigInt("1"),
            BigInt("1"), BigInt("1"),
            BigInt("2"), BigInt("0"),
            BigInt("1"), BigInt("1"),
            BigInt("1"), BigInt("1"),
            BigInt("1"), BigInt("1"),
            BigInt("1"), BigInt("1"),
            BigInt("2"), BigInt("2"),
            BigInt("1"), BigInt("0"),
            BigInt("21114443489864049154001762655191180301122514770016290267650674674192767465697"), BigInt("0"),
            BigInt("6831575284631332314047141597015456944409870082618779346385457763507373982298"), BigInt("0"),
            BigInt("11807992475950612596410595977851585466077166903715611787715431816169278988645"), BigInt("0"),
            BigInt("6780061509483589239421291947946885432473743248352401215903845935894912933796"), BigInt("0"),
            BigInt("8399802325731199225013812405787143556786329551153905411468626346744193582661"), BigInt("0"),
            BigInt("0"), BigInt("0"),
            BigInt("21114443489864049154001762655191180301122514770016290267650674674192767465697"), BigInt("0"),
            BigInt("20657103927053063591983067049524250022245139000924954731087186169764759392836"), BigInt("0"),
            BigInt("18211997483052406977396736902181255088105290584316186088813516197303012472272"), BigInt("0"),
            BigInt("10946756681378220817082917740365178789699667719578097414130696820612396982453"), BigInt("0"),
            BigInt("0"), BigInt("0"),
            BigInt("9014008244201113686655702455526978210634317473911009575747281709319350724249"), BigInt("0"),
            BigInt("3259012130809677133330262640542695849256518265822971433624635410535031074847"), BigInt("1"),
            BigInt("0"), BigInt("0"),
        ];
        let state3 = [BigInt("1"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("2"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("2"), BigInt("2"),
        BigInt("1"), BigInt("1"),
        BigInt("21114443489864049154001762655191180301122514770016290267650674674192767465697"), BigInt("0"),
        BigInt("6831575284631332314047141597015456944409870082618779346385457763507373982298"), BigInt("0"),
        BigInt("11807992475950612596410595977851585466077166903715611787715431816169278988645"), BigInt("0"),
        BigInt("6780061509483589239421291947946885432473743248352401215903845935894912933796"), BigInt("0"),
        BigInt("8399802325731199225013812405787143556786329551153905411468626346744193582661"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("21114443489864049154001762655191180301122514770016290267650674674192767465697"), BigInt("0"),
        BigInt("20657103927053063591983067049524250022245139000924954731087186169764759392836"), BigInt("0"),
        BigInt("18211997483052406977396736902181255088105290584316186088813516197303012472272"), BigInt("0"),
        BigInt("10946756681378220817082917740365178789699667719578097414130696820612396982453"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("1670561198430172148681353801331385832385430133942816907683484425076474887655"), BigInt("16572438045525961943251465619605168041221082178875908327386397278381398802869"),
        BigInt("17071743095618934420079457007323118272072062312285404774051893513653887087610"), BigInt("1"),
        BigInt("0"), BigInt("0"),];
        let state4 = [BigInt("1"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("1"), BigInt("1"),
        BigInt("2"), BigInt("3"),
        BigInt("1"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("21114443489864049154001762655191180301122514770016290267650674674192767465697"), BigInt("0"),
        BigInt("6831575284631332314047141597015456944409870082618779346385457763507373982298"), BigInt("0"),
        BigInt("11807992475950612596410595977851585466077166903715611787715431816169278988645"), BigInt("0"),
        BigInt("6780061509483589239421291947946885432473743248352401215903845935894912933796"), BigInt("0"),
        BigInt("8399802325731199225013812405787143556786329551153905411468626346744193582661"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("21114443489864049154001762655191180301122514770016290267650674674192767465697"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("0"), BigInt("0"),
        BigInt("16831674487885313515168509902646763923398513124794098473399128205752230500967"), BigInt("1"),
        BigInt("0"), BigInt("0"),];
        let states = [state, state2, state3, state4];
        let state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));
        const step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];

        let jsonCircuitCount = Math.ceil(input.length / DATA_BYTES);
        let jsonExtractionStepIn = step_in;
        let jsonExtractionStepOut: bigint[] = [];

        for (let i = 0; i < jsonCircuitCount; i++) {
            let stepOut = await hash_parser.compute({
                data: input_padded.slice(i * DATA_BYTES, (i + 1) * DATA_BYTES),
                ciphertext_digest: mock_ct_digest,
                sequence_digest,
                value_digest,
                step_in: jsonExtractionStepIn,
                state: states[i],
            }, ["step_out"]);
            jsonExtractionStepOut = (stepOut.step_out as bigint[]);

            jsonExtractionStepIn = jsonExtractionStepOut;
        }

        assert.deepEqual(jsonExtractionStepOut[0], value_digest);
        assert.deepEqual(jsonExtractionStepOut[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual(jsonExtractionStepOut[9], sequence_digest_hashed);
    });

    it(`split input: reddit`, async () => {
        let filename = "reddit";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let [input1, input2] = [input.slice(0, DATA_BYTES), input.slice(DATA_BYTES, DATA_BYTES * 2)];

        const KEY0 = strToBytes("data");
        const KEY1 = strToBytes("redditorInfoByName");
        const KEY2 = strToBytes("karma");
        const KEY3 = strToBytes("fromAwardsReceived");
        const targetValue = strToBytes("470");

        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
            { type: "Object", value: KEY1 },
            { type: "ArrayIndex", value: 1 },
            { type: "Object", value: KEY2 },
            { type: "Object", value: KEY3 },
        ];

        const [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, MAX_STACK_HEIGHT);
        const sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        const sequence_digest_hashed = poseidon1([sequence_digest]);
        const data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));
        let split_data_digest = PolynomialDigest(input1, mock_ct_digest, BigInt(0));

        const value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
        let state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));
        let step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];

        let json_extraction_step_out = await hash_parser.compute({
            data: input1,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        let json_step_out = json_extraction_step_out.step_out as bigint[];
        assert.deepEqual(json_step_out[0], modAdd(data_digest - split_data_digest, BigInt(0)));
        assert.deepEqual(json_step_out[7], modPow(mock_ct_digest, BigInt(DATA_BYTES)));
        assert.deepEqual(json_step_out[9], sequence_digest_hashed);

        state = [
            1, 1,
            1, 1,
            2, 1,
            1, 1,
            1, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            BigInt("21114443489864049154001762655191180301122514770016290267650674674192767465697"), 0,
            BigInt("5598430990202924133535403001375485211379346439428387975269023087121609504266"), 0,
            BigInt("0"), 0,
            BigInt("4215832829314030653029106205864494290655121331068956006579751774144816160308"), 0,
            BigInt("5246441899134905677385878544168914162812821659359814307393023359653386558866"), 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            BigInt("4867204701236088702941544733654106581221207892466505318353687073841230613376"), 1, 0, 0
        ];
        state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));
        assert.deepEqual(state_digest, json_step_out[8]);

        let input2_digest = PolynomialDigest(input2, mock_ct_digest, BigInt(DATA_BYTES));
        json_extraction_step_out = await hash_parser.compute({
            data: input2.concat(Array(DATA_BYTES - input2.length).fill(-1)),
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in: json_step_out,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], modAdd(data_digest - split_data_digest - input2_digest, value_digest));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
    });

    it(`input: venmo`, async () => {
        let filename = "venmo";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let input_padded = input.concat(Array(DATA_BYTES - input.length).fill(-1));


        const KEY0 = strToBytes("data");
        const KEY1 = strToBytes("profile");
        const KEY2 = strToBytes("identity");
        const KEY3 = strToBytes("balance");
        const KEY4 = strToBytes("userBalance");
        const KEY5 = strToBytes("value");
        const targetValue = strToBytes("523.69");

        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
            { type: "Object", value: KEY1 },
            { type: "Object", value: KEY2 },
            { type: "Object", value: KEY3 },
            { type: "Object", value: KEY4 },
            { type: "Object", value: KEY5 },
        ];

        const [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, 10);
        const sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        const sequence_digest_hashed = poseidon1([sequence_digest]);
        const data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));

        const value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
        let state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));
        const step_in = [data_digest, 0, 0, 0, 0, 0, 0, 1, state_digest, sequence_digest_hashed, 0];

        let json_extraction_step_out = await hash_parser.compute({
            data: input_padded,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(input.length)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);
    });
})