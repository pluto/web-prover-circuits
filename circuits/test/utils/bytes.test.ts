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

describe("BytePack", () => {
    let circuit: WitnessTester<["lower", "upper"], ["out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`DoubleBytePackArray`, {
            file: "utils/bytes",
            template: "DoubleBytePackArray",
            params: [1],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("witness: lower = 0, upper = 1", async () => {
        await circuit.expectPass(
            { lower: [0], upper: [1] }, { out: [256] }
        );
    });

    it("witness: lower = 1, upper = 1", async () => {
        await circuit.expectPass(
            { lower: [1], upper: [1] }, { out: [257] }
        );
    });

    it("witness: lower = 1, upper = 0", async () => {
        await circuit.expectPass(
            { lower: [1], upper: [0] }, { out: [1] }
        );
    });
});

describe("BytePack2", () => {
    let circuit: WitnessTester<["lower", "upper"], ["out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`DoubleBytePackArray`, {
            file: "utils/bytes",
            template: "DoubleBytePackArray",
            params: [2],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });
    it("witness: lower = [1,0], upper = [0,1]", async () => {
        await circuit.expectPass(
            { lower: [1, 0], upper: [0, 1] }, { out: [1, 256] }
        );
    });
});

describe("ByteUnpack", () => {
    let circuit: WitnessTester<["in"], ["lower", "upper"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`UnpackDoubleByteArray`, {
            file: "utils/bytes",
            template: "UnpackDoubleByteArray",
            params: [1],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("witness: in = 256", async () => {
        await circuit.expectPass(
            { in: [256] }, { lower: [0], upper: [1] }
        );
    });

    it("witness: in = 257", async () => {
        await circuit.expectPass(
            { in: [257] }, { lower: [1], upper: [1] }
        );
    });

    it("witness: in = 1", async () => {
        await circuit.expectPass(
            { in: [1] }, { lower: [1], upper: [] }
        );
    });
});

describe("ByteUnpack2", () => {
    let circuit: WitnessTester<["in"], ["lower", "upper"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`UnpackDoubleByteArray`, {
            file: "utils/bytes",
            template: "UnpackDoubleByteArray",
            params: [2],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("witness: in = [1,256]", async () => {
        await circuit.expectPass(
            { in: [1, 256] }, { lower: [1, 0], upper: [0, 1] }
        );
    });

});



// Generic version
describe("GenericBytePack2", () => {
    let circuit: WitnessTester<["in"], ["out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`GenericBytePackArray`, {
            file: "utils/bytes",
            template: "GenericBytePackArray",
            params: [2, 3],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });
    it("witness: lower = [1,0,0], upper = [0,1,0]", async () => {
        await circuit.expectPass(
            { in: [[1, 0, 0], [0, 1, 0]] }, { out: [1, 256] }
        );
    });
    it("witness: lower = [1,0,0], upper = [0,0,1]", async () => {
        await circuit.expectPass(
            { in: [[1, 0, 0], [0, 0, 1]] }, { out: [1, 65536] }
        );
    });
});

describe("GenericByteUnpack2", () => {
    let circuit: WitnessTester<["in"], ["out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`GenericByteUnpackArray`, {
            file: "utils/bytes",
            template: "GenericByteUnpackArray",
            params: [2, 3],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("witness: in = [1,256]", async () => {
        await circuit.expectPass(
            { in: [1, 256] }, { out: [[1, 0, 0], [0, 1, 0]] }
        );
    });

    it("witness: in = [1,256]", async () => {
        await circuit.expectPass(
            { in: [1, 65536] }, { out: [[1, 0, 0], [0, 0, 1]] }
        );
    });
});
