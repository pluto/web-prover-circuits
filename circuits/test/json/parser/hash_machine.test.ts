import { circomkit, WitnessTester, generateDescription, readJSONInputFile } from "../../common";
import { PoseidonModular } from "../../common/poseidon";

describe("hash_machine", () => {
    let circuit: WitnessTester<["data"]>;

    it(`array_only_input`, async () => {
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

    // Numbers for the 42 read in 0th index
    console.log("[0,\"4\"] hash: ", PoseidonModular([0, 52]));
    console.log("[prev,\"2\"] hash: ", PoseidonModular([BigInt("10851631763548351427431043290272583122934382613350600043660274710013149244741"), 50]));

    // Number for the "a"
    console.log("[0,\"a\"] hash: ", PoseidonModular([0, 97]));
    // Numbers for the "b" read inside object in 1st index
    console.log("[0,\"b\"] hash: ", PoseidonModular([0, 98]));

    // console.log("[2,0] hash: ", PoseidonModular([2, 0]));
    // console.log("[2,1] hash: ", PoseidonModular([2, 1]));
    // console.log("[1,0] hash: ", PoseidonModular([1, 0]));
    // [0,0] hash:  14744269619966411208579211824598458697587494354926760081771325075741142829156n
    // [2,0] hash:  17525667638260400994329361135304146970274213890416440938331684485841550124768n
    // [2,1] hash:  9708419728795563670286566418307042748092204899363634976546883453490873071450n
    // [1,0] hash:  18423194802802147121294641945063302532319431080857859605204660473644265519999n

    // TODO: Check that the hash of the packedState.in getting the next_state_hash is correct, the stack hashes are correct.

    // it(`example_input`, async () => {
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


    it(`spotify_input`, async () => {
        let filename = "spotify";
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, ["data"]);
        console.log(input);
        circuit = await circomkit.WitnessTester(`Parser`, {
            file: "json/parser/hash_parser",
            template: "ParserHasher",
            params: [input.length, 7],
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        await circuit.expectPass({
            data: input
        });
    });
})