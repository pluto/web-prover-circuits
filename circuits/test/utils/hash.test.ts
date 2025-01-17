import assert from "assert";
import { circomkit, http_response_plaintext, http_start_line, PolynomialDigest, WitnessTester } from "../common";
import { DataHasher, PoseidonModular } from "../common/poseidon";
import { poseidon1 } from "poseidon-lite";


describe("DataHasher", () => {
    let circuit: WitnessTester<["in"], ["out"]>;

    before(async () => {
        circuit = await circomkit.WitnessTester(`DataHasher`, {
            file: "utils/hash",
            template: "DataHasher",
            params: [16],
        });
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

        circuit_small = await circomkit.WitnessTester(`DataHasher`, {
            file: "utils/hash",
            template: "DataHasher",
            params: [32],
        });
    });

    it("witness: HTTP bytes", async () => {
        let hash = DataHasher(http_response_plaintext);
        assert.deepEqual(String(hash), "2195365663909569734943279727560535141179588918483111718403427949138562480675");
        await circuit.expectPass({ in: http_response_plaintext }, { out: "2195365663909569734943279727560535141179588918483111718403427949138562480675" });
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

describe("PolynomialDigest", () => {
    let circuit: WitnessTester<["bytes", "polynomial_input"], ["digest"]>;

    before(async () => {
        circuit = await circomkit.WitnessTester(`PolynomialDigest`, {
            file: "utils/hash",
            template: "PolynomialDigest",
            params: [4],
        });
    });

    it("witness: bytes = [0,0,0,0], polynomial_input = 1", async () => {
        const bytes = [0, 0, 0, 0];
        const polynomial_input = 0;

        await circuit.expectPass(
            { bytes, polynomial_input },
            { digest: 0 }
        );
    });

    it("witness: bytes = [1,2,3,4], polynomial_input = 7", async () => {
        const bytes = [1, 2, 3, 4];
        const polynomial_input = 7;

        await circuit.expectPass(
            { bytes, polynomial_input },
            { digest: 1 + 2 * 7 + 3 * 7 ** 2 + 4 * 7 ** 3 }
        );
    });

    it("witness: bytes = [4*random], polynomial_input = random", async () => {
        const bytes = Array.from({ length: 4 }, () => Math.floor(Math.random() * 256));
        const polynomial_input = poseidon1([BigInt(Math.floor(Math.random() * 694206942069420))]);
        const digest = PolynomialDigest(bytes, polynomial_input, BigInt(0));

        await circuit.expectPass(
            { bytes, polynomial_input },
            { digest }
        );
    });

});

describe("PolynomialDigestWithCounter", () => {
    let circuit: WitnessTester<["bytes", "polynomial_input", "counter"], ["digest"]>;

    before(async () => {
        circuit = await circomkit.WitnessTester(`PolynomialDigestWithCounter`, {
            file: "utils/hash",
            template: "PolynomialDigestWithCounter",
            params: [4],
        });
    });

    it("witness: bytes = [1,2,3,4], polynomial_input = 7, counter = 0", async () => {
        const bytes = [1, 2, 3, 4];
        const polynomial_input = 7;

        await circuit.expectPass(
            { bytes, polynomial_input, counter: 0 },
            { digest: 1 + 2 * 7 + 3 * 7 ** 2 + 4 * 7 ** 3 }
        );
    });

    it("witness: bytes = [1,2,3,4], polynomial_input = 7, counter = 2", async () => {
        const bytes = [1, 2, 3, 4];
        const polynomial_input = 7;

        await circuit.expectPass(
            { bytes, polynomial_input, counter: 2 },
            { digest: 1 * 7 ** 2 + 2 * 7 ** 3 + 3 * 7 ** 4 + 4 * 7 ** 5 }
        );
    });
});