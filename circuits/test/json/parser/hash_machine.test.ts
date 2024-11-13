import { circomkit, WitnessTester, generateDescription, readJSONInputFile } from "../../common";
import { PoseidonModular } from "../../common/poseidon";

describe("hash_machine", () => {
    let circuit: WitnessTester<["data"]>;

    it(`array only input`, async () => {
        let filename = "array_only";
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, [0]);

        circuit = await circomkit.WitnessTester(`Parser`, {
            file: "json/parser/hash_parser",
            template: "ParserHasher",
            params: [input.length, 3],
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        await circuit.expectPass({
            data: input
        });
    });

    console.log("[0,0] hash: ", PoseidonModular([0, 0]));
    console.log("[2,0] hash: ", PoseidonModular([2, 0]));
    console.log("[2,1] hash: ", PoseidonModular([2, 1]));
    console.log("[1,0] hash: ", PoseidonModular([1, 0]));
    // [0,0] hash:  14744269619966411208579211824598458697587494354926760081771325075741142829156n
    // [2,0] hash:  17525667638260400994329361135304146970274213890416440938331684485841550124768n
    // [2,1] hash:  9708419728795563670286566418307042748092204899363634976546883453490873071450n
    // [1,0] hash:  18423194802802147121294641945063302532319431080857859605204660473644265519999n

    // TODO: Check that the hash of the packedState.in getting the next_state_hash is correct, the stack hashes are correct.

    // it(`example input`, async () => {
    //     let filename = "example";
    //     let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, ["a"]);

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



})