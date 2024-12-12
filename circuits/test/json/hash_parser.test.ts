import { poseidon1, poseidon2 } from "poseidon-lite";
import { circomkit, WitnessTester, readJSONInputFile, strToBytes, JsonMaskType, jsonTreeHasher, compressTreeHash } from "../common";

describe("Hash Parser", () => {
    let hash_parser: WitnessTester<["data", "polynomial_input", "sequence_digest", "step_in"]>;

    it(`input: array_only`, async () => {
        let filename = "array_only";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);
        const MAX_STACK_HEIGHT = 3;

        hash_parser = await circomkit.WitnessTester(`Parser`, {
            file: "json/extraction",
            template: "JSONExtraction",
            params: [input.length, MAX_STACK_HEIGHT],
        });
        console.log("#constraints:", await hash_parser.getConstraintCount());

        // Test `42` in 0th slot
        let polynomial_input = poseidon2([69, 420]);
        let targetValue = strToBytes("42");
        let keySequence: JsonMaskType[] = [
            { type: "ArrayIndex", value: 0 },
        ];
        let [stack, treeHashes] = jsonTreeHasher(polynomial_input, keySequence, targetValue, MAX_STACK_HEIGHT);
        let sequence_digest = compressTreeHash(polynomial_input, [stack, treeHashes]);
        let sequence_digest_hash = poseidon1([sequence_digest]);
        await hash_parser.expectPass({
            data: input,
            polynomial_input,
            sequence_digest,
            step_in: sequence_digest_hash
        });
        console.log("> First subtest passed.");

        // Test `"b"` in 1st slot object
        polynomial_input = poseidon2([69, 420]);
        targetValue = strToBytes("b");
        keySequence = [
            { type: "ArrayIndex", value: 1 },
            { type: "Object", value: strToBytes("a") },
        ];
        [stack, treeHashes] = jsonTreeHasher(polynomial_input, keySequence, targetValue, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(polynomial_input, [stack, treeHashes]);
        sequence_digest_hash = poseidon1([sequence_digest]);
        await hash_parser.expectPass({
            data: input,
            polynomial_input,
            sequence_digest,
            step_in: sequence_digest_hash
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
        console.log("#constraints:", await hash_parser.getConstraintCount());

        // Test `420` in "k"'s 0th slot
        let polynomial_input = poseidon2([69, 420]);
        let targetValue = strToBytes("420");
        let keySequence: JsonMaskType[] = [
            { type: "Object", value: strToBytes("k") },
            { type: "ArrayIndex", value: 0 },
        ];
        let [stack, treeHashes] = jsonTreeHasher(polynomial_input, keySequence, targetValue, MAX_STACK_HEIGHT);
        let sequence_digest = compressTreeHash(polynomial_input, [stack, treeHashes]);
        let sequence_digest_hash = poseidon1([sequence_digest]);
        await hash_parser.expectPass({
            data: input,
            polynomial_input,
            sequence_digest,
            step_in: sequence_digest_hash
        });
        console.log("> First subtest passed.");

        // Test `"d"` in "b"'s 3rd slot
        polynomial_input = poseidon2([69, 420]);
        targetValue = strToBytes("d");
        keySequence = [
            { type: "Object", value: strToBytes("b") },
            { type: "ArrayIndex", value: 3 },
        ];
        [stack, treeHashes] = jsonTreeHasher(polynomial_input, keySequence, targetValue, MAX_STACK_HEIGHT);
        sequence_digest = compressTreeHash(polynomial_input, [stack, treeHashes]);
        sequence_digest_hash = poseidon1([sequence_digest]);
        await hash_parser.expectPass({
            data: input,
            polynomial_input,
            sequence_digest,
            step_in: sequence_digest_hash
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
        console.log("#constraints:", await hash_parser.getConstraintCount());

        const polynomial_input = poseidon2([69, 420]);
        const KEY0 = strToBytes("a");
        const KEY1 = strToBytes("b");
        const targetValue = strToBytes("4");

        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
            { type: "ArrayIndex", value: 0 },
            { type: "Object", value: KEY1 },
            { type: "ArrayIndex", value: 1 },
        ];

        const [stack, treeHashes] = jsonTreeHasher(polynomial_input, keySequence, targetValue, 10);
        const sequence_digest = compressTreeHash(polynomial_input, [stack, treeHashes]);
        const sequence_digest_hash = poseidon1([sequence_digest]);

        await hash_parser.expectPass({
            data: input,
            polynomial_input,
            sequence_digest,
            step_in: sequence_digest_hash
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
        console.log("#constraints:", await hash_parser.getConstraintCount());

        const polynomial_input = poseidon2([69, 420]);
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

        const [stack, treeHashes] = jsonTreeHasher(polynomial_input, keySequence, targetValue, 10);
        const sequence_digest = compressTreeHash(polynomial_input, [stack, treeHashes]);
        const sequence_digest_hash = poseidon1([sequence_digest]);

        await hash_parser.expectPass({
            data: input,
            polynomial_input,
            sequence_digest,
            step_in: sequence_digest_hash
        });
    });
})