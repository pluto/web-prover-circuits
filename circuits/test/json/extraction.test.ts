import { poseidon1, poseidon2 } from "poseidon-lite";
import { circomkit, WitnessTester, readJSONInputFile, strToBytes, JsonMaskType, jsonTreeHasher, compressTreeHash, PolynomialDigest, modAdd } from "../common";

describe("JSON Extraction", () => {
    let hash_parser: WitnessTester<["step_in", "ciphertext_digest", "data", "sequence_digest", "value_digest"]>;
    const mock_ct_digest = poseidon2([69, 420]);

    it(`input: array_only`, async () => {
        let filename = "array_only";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        const MAX_STACK_HEIGHT = 3;

        hash_parser = await circomkit.WitnessTester(`Parser`, {
            file: "json/extraction",
            template: "JSONExtraction",
            params: [input.length, MAX_STACK_HEIGHT],
        });

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
        let data_digest_hashed = poseidon1([data_digest]);
        let step_in = modAdd(sequence_digest_hashed, data_digest_hashed);

        await hash_parser.expectPass({
            data: input,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in
        });
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
        step_in = modAdd(sequence_digest_hashed, data_digest_hashed);

        await hash_parser.expectPass({
            data: input,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in
        });
        console.log("> Second subtest passed.");
    });

    it(`input: value_array`, async () => {
        let filename = "value_array";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        const MAX_STACK_HEIGHT = 3;

        hash_parser = await circomkit.WitnessTester(`Parser`, {
            file: "json/extraction",
            template: "JSONExtraction",
            params: [input.length, MAX_STACK_HEIGHT],
        });

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
        let data_digest_hashed = poseidon1([data_digest]);
        let value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        let step_in = modAdd(sequence_digest_hashed, data_digest_hashed);

        await hash_parser.expectPass({
            data: input,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in
        });
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
        step_in = modAdd(sequence_digest_hashed, data_digest_hashed);
        await hash_parser.expectPass({
            data: input,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in
        });
        console.log("> Second subtest passed.");
    });

    it(`input: value_array_object`, async () => {
        let filename = "value_array_object";
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, []);
        hash_parser = await circomkit.WitnessTester(`Parser`, {
            file: "json/extraction",
            template: "JSONExtraction",
            params: [input.length, 5],
        });

        const KEY0 = strToBytes("a");
        const KEY1 = strToBytes("b");
        const targetValue = strToBytes("4");

        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
            { type: "ArrayIndex", value: 0 },
            { type: "Object", value: KEY1 },
            { type: "ArrayIndex", value: 1 },
        ];

        const [stack, treeHashes] = jsonTreeHasher(mock_ct_digest, keySequence, 10);
        const sequence_digest = compressTreeHash(mock_ct_digest, [stack, treeHashes]);
        const sequence_digest_hashed = poseidon1([sequence_digest]);
        const data_digest = PolynomialDigest(input, mock_ct_digest, BigInt(0));
        const data_digest_hashed = poseidon1([data_digest]);
        const value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        const step_in = modAdd(sequence_digest_hashed, data_digest_hashed);

        await hash_parser.expectPass({
            data: input,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in
        });
    });

    it(`input: spotify`, async () => {
        let filename = "spotify";
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, []);
        hash_parser = await circomkit.WitnessTester(`Parser`, {
            file: "json/extraction",
            template: "JSONExtraction",
            params: [input.length, 5],
        });

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
        const data_digest_hashed = poseidon1([data_digest]);
        const value_digest = PolynomialDigest(targetValue, mock_ct_digest, BigInt(0));
        const step_in = modAdd(sequence_digest_hashed, data_digest_hashed);

        await hash_parser.expectPass({
            data: input,
            ciphertext_digest: mock_ct_digest,
            sequence_digest,
            value_digest,
            step_in
        });
    });
})