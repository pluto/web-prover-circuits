import { circomkit, WitnessTester } from "../common";

describe("ASCII", () => {
    let circuit: WitnessTester<["in"], ["out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`ASCII`, {
            file: "utils/bytes",
            template: "ASCII",
            params: [13],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("(valid) witness: in = b\"Hello, world!\"", async () => {
        await circuit.expectPass(
            { in: [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33] },
        );
    });

    it("(invalid) witness: in = [256, ...]", async () => {
        await circuit.expectFail(
            { in: [256, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33] }
        );
    });
});