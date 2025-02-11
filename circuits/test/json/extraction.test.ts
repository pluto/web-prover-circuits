import { poseidon1, poseidon2 } from "poseidon-lite";
import { circomkit, WitnessTester, readJSONInputFile, strToBytes, JsonMaskType, jsonTreeHasher, compressTreeHash, PolynomialDigest, modAdd, PUBLIC_IO_VARIABLES, modPow } from "../common";
import { assert } from "chai";

const DATA_BYTES = 320;
const MAX_STACK_HEIGHT = 6;

describe("JSON Extraction", () => {
    let hash_parser: WitnessTester<["step_in", "ciphertext_digest", "data", "sequence_digest", "value_digest", "state"]>;
    const mock_ct_digest = poseidon2([69, 420]);

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

        let state = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);
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
        let state = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);
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
        let state = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);
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

    it(`input: spotify`, async () => {
        let filename = "spotify";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let input_padded = input.concat(Array(DATA_BYTES - input.length).fill(-1));

        const KEY0 = strToBytes("data");
        const KEY1 = strToBytes("items");
        const KEY2 = strToBytes("profile");
        const KEY3 = strToBytes("name");
        const targetValue = strToBytes("Taylor Swift");

        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
            { type: "Object", value: KEY1 },
            { type: "ArrayIndex", value: 0 },
            { type: "Object", value: KEY2 },
            { type: "Object", value: KEY3 },
        ];

        const [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, 10);
        const sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        const sequence_digest_hashed = poseidon1([sequence_digest]);
        const data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));

        const value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        let state = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);
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

    it(`split input: reddit`, async () => {
        let filename = "reddit";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        let [input1, input2, input3] = [input.slice(0, DATA_BYTES), input.slice(DATA_BYTES, DATA_BYTES * 2), input.slice(DATA_BYTES * 2)];
        input3 = input3.concat(Array(DATA_BYTES - input3.length).fill(-1));

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
        let state = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);
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
            2, 0,
            1, 1,
            1, 1,
            BigInt("21114443489864049154001762655191180301122514770016290267650674674192767465697"), 0,
            BigInt("5598430990202924133535403001375485211379346439428387975269023087121609504266"), 0,
            BigInt("0"), 0,
            BigInt("4215832829314030653029106205864494290655121331068956006579751774144816160308"), 0,
            BigInt("10193689792027765875739665277472584711579103240499433210836208365265070585573"), 51,
            1, 0, 1
        ];
        state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));
        assert.deepEqual(state_digest, json_step_out[8]);

        let input2_digest = PolynomialDigest(input2, mock_ct_digest, BigInt(DATA_BYTES));
        json_extraction_step_out = await hash_parser.compute({
            data: input2,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in: json_step_out,
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], modAdd(data_digest - split_data_digest - input2_digest, value_digest));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[7], modPow(mock_ct_digest, BigInt(DATA_BYTES * 2)));
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[9], sequence_digest_hashed);

        state = [
            1, 1,
            1, 1,
            2, 1,
            1, 1,
            1, 1,
            BigInt("21114443489864049154001762655191180301122514770016290267650674674192767465697"), 0,
            BigInt("5598430990202924133535403001375485211379346439428387975269023087121609504266"), 0,
            BigInt("0"), 0,
            BigInt("4215832829314030653029106205864494290655121331068956006579751774144816160308"), 0,
            BigInt("10193689792027765875739665277472584711579103240499433210836208365265070585573"), 0,
            0, 0, 0
        ];
        state_digest = PolynomialDigest(state, mock_ct_digest, BigInt(0));
        assert.deepEqual(state_digest, (json_extraction_step_out.step_out as BigInt[])[8]);

        json_extraction_step_out = await hash_parser.compute({
            data: input3,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in: json_extraction_step_out.step_out as bigint[],
            state,
        }, ["step_out"]);
        assert.deepEqual((json_extraction_step_out.step_out as BigInt[])[0], value_digest);
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
        let state = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);
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