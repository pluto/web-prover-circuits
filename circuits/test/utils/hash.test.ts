import { circomkit, WitnessTester } from "../common";
import { PoseidonModular } from "../common/poseidon";

describe("hash", () => {
    describe("PoseidonModular_16", () => {
        let circuit: WitnessTester<["in"], ["out"]>;

        before(async () => {
            circuit = await circomkit.WitnessTester(`PoseidonModular`, {
                file: "utils/hash",
                template: "PoseidonModular",
                params: [16],
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        it("witness: in = [16*random]", async () => {
            const input = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));
            const hash = PoseidonModular(input);

            await circuit.expectPass(
                { in: input },
                { out: hash }
            );
        });
    });

    describe("PoseidonModular_379", () => {
        let circuit: WitnessTester<["in"], ["out"]>;

        before(async () => {
            circuit = await circomkit.WitnessTester(`PoseidonModular`, {
                file: "utils/hash",
                template: "PoseidonModular",
                params: [379],
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        it("witness: in = [379*random]", async () => {
            const input = Array.from({ length: 379 }, () => Math.floor(Math.random() * 256));
            const hash = PoseidonModular(input);

            await circuit.expectPass(
                { in: input },
                { out: hash }
            );
        });
    });
});