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

    describe("PoseidonChainer", () => {
        let circuit: WitnessTester<["in"], ["out"]>;

        before(async () => {
            circuit = await circomkit.WitnessTester(`PoseidonChainer`, {
                file: "utils/hash",
                template: "PoseidonChainer",
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        it("witness: in = [69,420]", async () => {
            const input = [69, 420];
            const hash = PoseidonModular(input);
            await circuit.expectPass(
                { in: input },
                { out: hash }
            );
        });
    });

    describe("DataHasher", () => {
        let circuit: WitnessTester<["in"], ["out"]>;

        before(async () => {
            circuit = await circomkit.WitnessTester(`DataHasher`, {
                file: "utils/hash",
                template: "DataHasher",
                params: [16],
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        it("witness: in = [0,...x16]", async () => {
            const input = Array(16).fill(0);
            const hash = PoseidonModular([0, 0]);
            await circuit.expectPass(
                { in: input },
                { out: hash }
            );
        });

        it("witness: in = [1,0,...x15]", async () => {
            let input = Array(16).fill(0);
            input[0] = 1;
            const hash = PoseidonModular([0, 1]);
            await circuit.expectPass(
                { in: input },
                { out: hash }
            );
        });

        it("witness: in = [0,0,...x15,1]", async () => {
            let input = Array(16).fill(0);
            input[15] = 1;
            const hash = PoseidonModular([0, "1329227995784915872903807060280344576"]);
            await circuit.expectPass(
                { in: input },
                { out: hash }
            );
        });

    });
});