import { circomkit, WitnessTester } from "../common";
import witness from "../../../inputs/search/witness.json";

describe("SubstringMatchWithIndex", () => {
    let circuit: WitnessTester<["data", "key", "start"], ["out"]>;

    before(async () => {
        circuit = await circomkit.WitnessTester(`SubstringSearch`, {
            file: "utils/search",
            template: "SubstringMatchWithIndex",
            params: [787, 10],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("data = witness.json:data, key = witness.json:key, r = hash(key+data)", async () => {
        await circuit.expectPass(
            {
                data: witness["data"],
                key: witness["key"],
                start: 6
            },
            { out: 1 },
        );
    });

    it("data = witness.json:data, key = witness.json:key, r = hash(key+data),  output false", async () => {
        await circuit.expectPass(
            {
                data: witness["data"],
                key: witness["key"],
                start: 98
            },
            { out: 0 }
        );
    });
});
