import { circomkit, WitnessTester, readJSONInputFile } from "../common";

describe("JSON Parser", () => {
    let circuit: WitnessTester<["data"]>;

    it(`array only input`, async () => {
        let filename = "array_only";
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, []);

        circuit = await circomkit.WitnessTester(`Parser`, {
            file: "json/parser",
            template: "Parser",
            params: [input.length, 2],
        });

        await circuit.expectPass({
            data: input
        });
    });

    it(`object input`, async () => {
        let filename = "value_object";
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, []);

        circuit = await circomkit.WitnessTester(`Parser`, {
            file: "json/parser",
            template: "Parser",
            params: [input.length, 3],
        });

        await circuit.expectPass({
            data: input
        });
    });

    it(`string_escape input`, async () => {
        let filename = "string_escape";
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, []);

        circuit = await circomkit.WitnessTester(`Parser`, {
            file: "json/parser",
            template: "Parser",
            params: [input.length, 3],
        });

        await circuit.expectPass({
            data: input
        });
    });
})