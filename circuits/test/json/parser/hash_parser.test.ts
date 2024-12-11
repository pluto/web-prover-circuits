import { circomkit, WitnessTester, readJSONInputFile } from "../../common";

describe("Hash Parser", () => {
    let hash_parser: WitnessTester<["data", "polynomial_input", "sequence_digest"]>;

    it(`input: array_only`, async () => {
        let filename = "array_only";
        let [input, _keyUnicode, _output] = readJSONInputFile(`${filename}.json`, []);

        hash_parser = await circomkit.WitnessTester(`Parser`, {
            file: "json/parser/hash_parser",
            template: "ParserHasher",
            params: [input.length, 3],
        });
        console.log("#constraints:", await hash_parser.getConstraintCount());

        await hash_parser.expectPass({
            data: input,
            polynomial_input: 2,
            sequence_digest: 1, // TODO: This isn't useful
        });
    });

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


    // it(`spotify_input`, async () => {
    //     let filename = "spotify";
    //     let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, []);
    //     hash_parser = await circomkit.WitnessTester(`Parser`, {
    //         file: "json/parser/hash_parser",
    //         template: "ParserHasher",
    //         params: [input.length, 5],
    //     });
    //     console.log("#constraints:", await hash_parser.getConstraintCount());

    //     await hash_parser.expectPass({
    //         data: input,
    //         polynomial_input: 1,
    //         sequence_digest: 234435029355,
    //     });
    // });
})