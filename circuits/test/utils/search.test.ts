import { circomkit, toByte, WitnessTester } from "../common";

const data = toByte("Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum");
const key = toByte("Ipsum");

describe("SubstringMatchWithIndex", () => {
    let circuit: WitnessTester<["data", "key", "start"], ["out"]>;

    before(async () => {
        circuit = await circomkit.WitnessTester(`SubstringSearch`, {
            file: "utils/search",
            template: "SubstringMatchWithIndex",
            params: [data.length, key.length],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("data = witness.json:data, key = witness.json:key, r = hash(key+data)", async () => {
        await circuit.expectPass(
            {
                data: data,
                key: key,
                start: 6
            },
            { out: 1 },
        );
    });

    it("data = witness.json:data, key = witness.json:key, r = hash(key+data),  output false", async () => {
        await circuit.expectPass(
            {
                data: data,
                key: key,
                start: 98
            },
            { out: 0 }
        );
    });
});
