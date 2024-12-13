import { circomkit, WitnessTester } from "../common";

describe("SwitchArray", () => {
    let circuit: WitnessTester<["case", "branches", "vals"], ["match", "out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`SwitchArray`, {
            file: "utils/operators",
            template: "SwitchArray",
            params: [3, 2],
        });
    });

    it("witness: case = 0, branches = [0, 1, 2], vals = [[69,0], [420,1], [1337,2]]", async () => {
        await circuit.expectPass(
            { case: 0, branches: [0, 1, 2], vals: [[69, 0], [420, 1], [1337, 2]] },
            { match: 1, out: [69, 0] },
        );
    });

    it("witness: case = 1, branches = [0, 1, 2], vals = [[69,0], [420,1], [1337,2]]", async () => {
        await circuit.expectPass(
            { case: 1, branches: [0, 1, 2], vals: [[69, 0], [420, 1], [1337, 2]] },
            { match: 1, out: [420, 1] },
        );
    });

    it("witness: case = 2, branches = [0, 1, 2], vals = [[69,0], [420,1], [1337,2]]", async () => {
        await circuit.expectPass(
            { case: 2, branches: [0, 1, 2], vals: [[69, 0], [420, 1], [1337, 2]] },
            { match: 1, out: [1337, 2] },
        );
    });

    it("witness: case = 3, branches = [0, 1, 2], vals = [[69,0], [420,1], [1337,2]]", async () => {
        await circuit.expectPass(
            { case: 3, branches: [0, 1, 2], vals: [[69, 0], [420, 1], [1337, 2]] },
            { match: 0, out: [0, 0] }
        );
    });

    it("witness: case = 420, branches = [69, 420, 1337], vals = [[10,3], [20,5], [30,7]]", async () => {
        await circuit.expectPass(
            { case: 420, branches: [69, 420, 1337], vals: [[10, 3], [20, 5], [30, 7]] },
            { match: 1, out: [20, 5] }
        );
    });

    it("witness: case = 0, branches = [69, 420, 1337], vals = [[10,3], [20,5], [30,7]]", async () => {
        await circuit.expectPass(
            { case: 0, branches: [69, 420, 1337], vals: [[10, 3], [20, 5], [30, 7]] },
            { match: 0, out: [0, 0] }
        );
    });

});

describe("Switch", () => {
    let circuit: WitnessTester<["case", "branches", "vals"], ["match", "out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`Switch`, {
            file: "utils/operators",
            template: "Switch",
            params: [3],
        });
    });

    it("witness: case = 0, branches = [0, 1, 2], vals = [69, 420, 1337]", async () => {
        await circuit.expectPass(
            { case: 0, branches: [0, 1, 2], vals: [69, 420, 1337] },
            { match: 1, out: 69 },
        );
    });

    it("witness: case = 1, branches = [0, 1, 2], vals = [69, 420, 1337]", async () => {
        await circuit.expectPass(
            { case: 1, branches: [0, 1, 2], vals: [69, 420, 1337] },
            { match: 1, out: 420 },
        );
    });

    it("witness: case = 2, branches = [0, 1, 2], vals = [69, 420, 1337]", async () => {
        await circuit.expectPass(
            { case: 2, branches: [0, 1, 2], vals: [69, 420, 1337] },
            { match: 1, out: 1337 },
        );
    });

    it("witness: case = 3, branches = [0, 1, 2], vals = [69, 420, 1337]", async () => {
        await circuit.expectPass(
            { case: 3, branches: [0, 1, 2], vals: [69, 420, 1337] },
            { match: 0, out: 0 },
        );
    });


});

describe("InRange", () => {
    let circuit: WitnessTester<["in", "range"], ["out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`InRange`, {
            file: "utils/operators",
            template: "InRange",
            params: [8],
        });
    });

    it("witness: in = 1, range = [0,2]", async () => {
        await circuit.expectPass(
            { in: 1, range: [0, 2] },
            { out: 1 }
        );
    });

    it("witness: in = 69, range = [128,255]", async () => {
        await circuit.expectPass(
            { in: 69, range: [128, 255] },
            { out: 0 }
        );
    });

    it("witness: in = 200, range = [128,255]", async () => {
        await circuit.expectPass(
            { in: 1, range: [0, 2] },
            { out: 1 }
        );
    });
});