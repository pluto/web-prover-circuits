import { poseidon2 } from "poseidon-lite";
import { circomkit, WitnessTester, readJSONInputFile, strToBytes, JsonMaskType, jsonTreeHasher, compressTreeHash } from "../../common";

describe("Hash Parser", () => {
    let hash_parser: WitnessTester<["data", "polynomial_input", "sequence_digest"]>;

    // it(`input: array_only`, async () => {
    //     let filename = "array_only";
    //     let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);

    //     hash_parser = await circomkit.WitnessTester(`Parser`, {
    //         file: "json/parser/hash_parser",
    //         template: "ParserHasher",
    //         params: [input.length, 3],
    //     });
    //     console.log("#constraints:", await hash_parser.getConstraintCount());

    //     await hash_parser.expectPass({
    //         data: input,
    //         polynomial_input: 2,
    //         sequence_digest: 1, // TODO: This isn't useful
    //     });
    // });

    // it(`input: value_array.json`, async () => {
    //     let filename = "value_array";
    //     let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, []);
    //     console.log(JSON.stringify(input));

    //     circuit = await circomkit.WitnessTester(`Parser`, {
    //         file: "json/parser/hash_parser",
    //         template: "ParserHasher",
    //         params: [input.length, 4],
    //     });
    //     console.log("#constraints:", await circuit.getConstraintCount());

    //     await circuit.expectPass({
    //         data: input
    //     });
    // });

    // it(`input: value_array_object.json`, async () => {
    //     let filename = "value_array_object";
    //     let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, []);

    //     circuit = await circomkit.WitnessTester(`Parser`, {
    //         file: "json/parser/hash_parser",
    //         template: "ParserHasher",
    //         params: [input.length, 7],
    //     });
    //     console.log("#constraints:", await circuit.getConstraintCount());

    //     await circuit.expectPass({
    //         data: input
    //     });
    // });


    it(`spotify_input`, async () => {
        let filename = "spotify";
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, []);
        hash_parser = await circomkit.WitnessTester(`Parser`, {
            file: "json/parser/hash_parser",
            template: "ParserHasher",
            params: [input.length, 5],
        });
        console.log("#constraints:", await hash_parser.getConstraintCount());

        let polynomial_input = poseidon2([69, 420]);
        console.log("polynomial_input: ", polynomial_input);

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
        const compressed = compressTreeHash(polynomial_input, [stack, treeHashes]);

        await hash_parser.expectPass({
            data: input,
            polynomial_input,
            sequence_digest: compressed,
        });
    });
})