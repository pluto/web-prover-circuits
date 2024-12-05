import assert from "assert";
import { circomkit, WitnessTester } from "../common";
import { DataHasher, PoseidonModular } from "../common/poseidon";

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

        let all_zero_hash = BigInt("14744269619966411208579211824598458697587494354926760081771325075741142829156");
        it("witness: in = [0,...x16]", async () => {
            const input = Array(16).fill(0);
            await circuit.expectPass(
                { in: input },
                { out: all_zero_hash }
            );
        });
        // Check that TS version of DataHasher also is correct
        assert.deepEqual(DataHasher(Array(16).fill(0)), all_zero_hash);

        it("witness: in = [-1,...x16]", async () => {
            const input = Array(16).fill(-1);
            await circuit.expectPass(
                { in: input },
                { out: 0 }
            );
        });
        // Check that TS version of DataHasher also is correct
        assert.deepEqual(DataHasher(Array(16).fill(-1)), 0);

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

    const TEST_HTTP_BYTES = [
        72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 99, 111, 110, 116, 101, 110,
        116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106,
        115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13, 10, 99,
        111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122, 105,
        112, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69, 110, 99, 111, 100, 105, 110, 103, 58,
        32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13, 10, 123, 13, 10, 32, 32, 32, 34, 100, 97, 116,
        97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109, 115, 34, 58, 32,
        91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115,
        116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114,
        111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119,
        105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13,
        10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13,
        10, 32, 32, 32, 125, 13, 10, 125]

    const http_start_line = [72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10];
    const padded_http_start_line = http_start_line.concat(Array(320 - http_start_line.length).fill(-1));

    describe("DataHasherHTTP", () => {
        let circuit: WitnessTester<["in"], ["out"]>;
        let circuit_small: WitnessTester<["in"], ["out"]>;

        before(async () => {
            circuit = await circomkit.WitnessTester(`DataHasher`, {
                file: "utils/hash",
                template: "DataHasher",
                params: [320],
            });
            console.log("#constraints:", await circuit.getConstraintCount());

            circuit_small = await circomkit.WitnessTester(`DataHasher`, {
                file: "utils/hash",
                template: "DataHasher",
                params: [32],
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        it("witness: HTTP bytes", async () => {
            let hash = DataHasher(TEST_HTTP_BYTES);
            assert.deepEqual(String(hash), "2195365663909569734943279727560535141179588918483111718403427949138562480675");
            await circuit.expectPass({ in: TEST_HTTP_BYTES }, { out: "2195365663909569734943279727560535141179588918483111718403427949138562480675" });
        });

        let padded_hash = DataHasher(padded_http_start_line);
        it("witness: padded HTTP start line", async () => {
            await circuit.expectPass({ in: padded_http_start_line }, { out: padded_hash });
        });

        let hash = DataHasher(http_start_line);
        it("witness: unpadded HTTP start line", async () => {
            await circuit_small.expectPass({ in: http_start_line.concat(Array(32 - http_start_line.length).fill(-1)) }, { out: hash });
        });
    });
});
