import { circomkit, WitnessTester } from "../common";

import witness from "../../../inputs/search/witness.json";
import { PoseidonModular } from "../common/poseidon";

describe("search", () => {
    describe("SubstringSearch", () => {
        let circuit: WitnessTester<["data", "key", "random_num"], ["position"]>;

        it("key at first position", async () => {
            const data = [10, 8, 9, 4, 11, 9, 1, 2];
            const key = [10, 8, 9, 4];
            const concatenatedInput = key.concat(data);
            const hashResult = PoseidonModular(concatenatedInput);

            circuit = await circomkit.WitnessTester(`SubstringSearch`, {
                file: "utils/search",
                template: "SubstringSearch",
                params: [data.length, key.length],
            });

            await circuit.expectPass(
                { data: data, key: key, random_num: hashResult },
                { position: 0 },
            );
        });

        it("key at last position", async () => {
            const data = [11, 9, 1, 2, 10, 8, 9, 4];
            const key = [10, 8, 9, 4];
            const concatenatedInput = key.concat(data);
            const hashResult = PoseidonModular(concatenatedInput);

            circuit = await circomkit.WitnessTester(`SubstringSearch`, {
                file: "utils/search",
                template: "SubstringSearch",
                params: [data.length, key.length],
            });

            await circuit.expectPass(
                { data: data, key: key, random_num: hashResult },
                { position: 4 },
            );
        });

        /// highlights the importance of appropriate calculation of random number for linear matching.
        /// `1` as used here leads to passing constraints because [1, 0] matches with [0, 1]
        /// because both have equal linear combination sum.
        it("(INVALID `r=1` value) random_num input passes for different position, correct key position: 2", async () => {
            const data = [0, 0, 1, 0, 0];
            const key = [1, 0];

            circuit = await circomkit.WitnessTester(`SubstringSearch`, {
                file: "utils/search",
                template: "SubstringSearch",
                params: [data.length, key.length],
            });

            await circuit.expectPass(
                { data: data, key: key, random_num: 1 },
                { position: 1 },
            );
        });

        it("data = witness.json:data, key = witness.json:key, r = hash(data+key)", async () => {
            const concatenatedInput = witness["key"].concat(witness["data"]);
            const hashResult = PoseidonModular(concatenatedInput);

            circuit = await circomkit.WitnessTester(`SubstringSearch`, {
                file: "utils/search",
                template: "SubstringSearch",
                params: [witness["data"].length, witness["key"].length],
            });
            console.log("#constraints:", await circuit.getConstraintCount());

            await circuit.expectPass(
                { data: witness["data"], key: witness["key"], random_num: hashResult },
                { position: 6 }
            );
        });
    });

    describe("SubstringMatchWithHasher", () => {
        let circuit: WitnessTester<["data", "key", "r", "start"], ["out"]>;

        before(async () => {
            circuit = await circomkit.WitnessTester(`SubstringSearch`, {
                file: "utils/search",
                template: "SubstringMatchWithHasher",
                params: [787, 10],
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        it("data = witness.json:data, key = witness.json:key, r = hash(key+data)", async () => {
            await circuit.expectPass(
                {
                    data: witness["data"],
                    key: witness["key"],
                    r: PoseidonModular(witness["key"].concat(witness["data"])),
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
                    r: PoseidonModular(witness["key"].concat(witness["data"])),
                    start: 98
                },
                { out: 0 }
            );
        });
    });

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

    describe("SubstringMatchWithIndexPadded", () => {
        let circuit: WitnessTester<["data", "key", "keyLen", "start"], ["out"]>;
        let maxKeyLen = 30;

        before(async () => {
            circuit = await circomkit.WitnessTester(`SubstringSearch`, {
                file: "utils/search",
                template: "SubstringMatchWithIndexPadded",
                params: [787, maxKeyLen],
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        it("data = witness.json:data, key = witness.json:key, r = hash(key+data)", async () => {
            let key = witness["key"];
            let pad_key = key.concat(Array(maxKeyLen - key.length).fill(0));
            await circuit.expectPass(
                {
                    data: witness["data"],
                    key: pad_key,
                    keyLen: witness["key"].length,
                    start: 6
                },
                { out: 1 },
            );
        });

        it("data = witness.json:data, key = witness.json:key, r = hash(key+data),  output false", async () => {
            let key = witness["key"];
            let pad_key = key.concat(Array(maxKeyLen - key.length).fill(0));
            await circuit.expectPass(
                {
                    data: witness["data"],
                    key: pad_key,
                    keyLen: witness["key"].length,
                    start: 98
                },
                { out: 0 }
            );
        });
    });

    describe("SubstringMatch", () => {
        let circuit: WitnessTester<["data", "key"], ["position"]>;

        before(async () => {
            circuit = await circomkit.WitnessTester(`SubstringSearch`, {
                file: "utils/search",
                template: "SubstringMatch",
                params: [787, 10],
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        it("data = witness.json:data, key = witness.json:key", async () => {
            await circuit.expectPass(
                { data: witness["data"], key: witness["key"] },
                { position: 6 },
            );
        });

        it("data = witness.json:data, key = invalid key byte", async () => {
            await circuit.expectFail(
                { data: witness["data"], key: witness["key"].concat(257) },
            );
        });

        it("data = witness.json:data, key = wrong key", async () => {
            await circuit.expectFail(
                { data: witness["data"], key: witness["key"].concat(0) },
            );
        });
    });
});