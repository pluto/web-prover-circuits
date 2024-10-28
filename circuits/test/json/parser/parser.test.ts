import { circomkit, WitnessTester, generateDescription, readJSONInputFile } from "../../common";

describe("json-parser", () => {
    let circuit: WitnessTester<["data"]>;

    it(`array only input`, async () => {
        let filename = "array_only";
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, [0]);

        circuit = await circomkit.WitnessTester(`Parser`, {
            file: "json/parser/parser",
            template: "Parser",
            params: [input.length, 2],
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        await circuit.expectPass({
            data: input
        });
    });

    it(`object input`, async () => {
        let filename = "value_object";
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, ["a"]);

        circuit = await circomkit.WitnessTester(`Parser`, {
            file: "json/parser/parser",
            template: "Parser",
            params: [input.length, 3],
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        await circuit.expectPass({
            data: input
        });
    });
})