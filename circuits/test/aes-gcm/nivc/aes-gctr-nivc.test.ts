import { assert } from "chai";
import { WitnessTester } from "circomkit";
import { circomkit } from "../../common";

describe("aes-gctr-nivc", () => {
    let circuit_one_block: WitnessTester<["key", "iv", "plainText", "aad", "step_in"], ["step_out"]>;


    const DATA_BYTES_0 = 16;
    const TOTAL_BYTES_ACROSS_NIVC_0 = 2 * DATA_BYTES_0 + 4;

    it("all correct for self generated single zero pt block case", async () => {
        circuit_one_block = await circomkit.WitnessTester("aes-gcm-fold", {
            file: "aes-gcm/nivc/aes-gctr-nivc",
            template: "AESGCTRFOLD",
            params: [DATA_BYTES_0], // input len is 16 bytes
        });

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let plainText = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let aad = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let ct = [0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78];

        const counter = [0x00, 0x00, 0x00, 0x01];
        const step_in = new Array(TOTAL_BYTES_ACROSS_NIVC_0).fill(0x00);
        counter.forEach((value, index) => {
            step_in[2 * DATA_BYTES_0 + index] = value;
        });

        let expected = plainText.concat(ct).concat([0x00, 0x00, 0x00, 0x02]);
        expected = expected.concat(new Array(TOTAL_BYTES_ACROSS_NIVC_0 - expected.length).fill(0));
        const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: plainText, aad: aad, step_in: step_in }, ["step_out"])
        assert.deepEqual(witness.step_out, expected.map(BigInt));
    });

    it("all correct for self generated single non zero pt block", async () => {
        circuit_one_block = await circomkit.WitnessTester("aes-gcm-fold", {
            file: "aes-gcm/nivc/aes-gctr-nivc",
            template: "AESGCTRFOLD",
            params: [DATA_BYTES_0], // input len is 16 bytes
        });

        let key = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];
        let plainText = [0x74, 0x65, 0x73, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30];
        let iv = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];
        let aad = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let ct = [0x29, 0x29, 0xd2, 0xbb, 0x1a, 0xe9, 0x48, 0x04, 0x40, 0x2b, 0x8e, 0x77, 0x6e, 0x0d, 0x33, 0x56];

        const counter = [0x00, 0x00, 0x00, 0x01];
        const step_in = new Array(TOTAL_BYTES_ACROSS_NIVC_0).fill(0x00);
        counter.forEach((value, index) => {
            step_in[2 * DATA_BYTES_0 + index] = value;
        });

        let expected = plainText.concat(ct).concat([0x00, 0x00, 0x00, 0x02]);
        expected = expected.concat(new Array(TOTAL_BYTES_ACROSS_NIVC_0 - expected.length).fill(0));

        const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: plainText, aad: aad, step_in: step_in }, ["step_out"])
        assert.deepEqual(witness.step_out, expected.map(BigInt));
    });

    const DATA_BYTES_1 = 32;
    const TOTAL_BYTES_ACROSS_NIVC_1 = DATA_BYTES_1 * 2 + 4;


    let zero_block = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let key = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];
    let plainText1 = [0x74, 0x65, 0x73, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30];
    let plainText2 = [0x74, 0x65, 0x73, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30];
    let iv = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];
    let aad = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let ct_part1 = [0x29, 0x29, 0xd2, 0xbb, 0x1a, 0xe9, 0x48, 0x04, 0x40, 0x2b, 0x8e, 0x77, 0x6e, 0x0d, 0x33, 0x56];
    let ct_part2 = [0x26, 0x75, 0x65, 0x30, 0x71, 0x3e, 0x4c, 0x06, 0x5a, 0xf1, 0xd3, 0xc4, 0xf5, 0x6e, 0x02, 0x04];

    it("all correct for self generated two block case first fold", async () => {
        circuit_one_block = await circomkit.WitnessTester("aes-gcm-fold", {
            file: "aes-gcm/nivc/aes-gctr-nivc",
            template: "AESGCTRFOLD",
            params: [DATA_BYTES_1], // input len is 32 bytes
        });

        const counter = [0x00, 0x00, 0x00, 0x01];
        const step_in = new Array(TOTAL_BYTES_ACROSS_NIVC_1).fill(0x00);
        counter.forEach((value, index) => {
            step_in[2 * DATA_BYTES_1 + index] = value;
        });
        let expected = plainText1.concat(zero_block).concat(ct_part1).concat(zero_block).concat([0x00, 0x00, 0x00, 0x02]);
        expected = expected.concat(new Array(TOTAL_BYTES_ACROSS_NIVC_1 - expected.length).fill(0));

        const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: plainText1, aad: aad, step_in: step_in }, ["step_out"])
        assert.deepEqual(witness.step_out, expected.map(BigInt));
    });

    it("all correct for self generated two block case second fold", async () => {
        circuit_one_block = await circomkit.WitnessTester("aes-gcm-fold", {
            file: "aes-gcm/nivc/aes-gctr-nivc",
            template: "AESGCTRFOLD",
            params: [DATA_BYTES_1], // input len is 32 bytes
        });

        const counter = [0x00, 0x00, 0x00, 0x02];
        let step_in = plainText1.concat(zero_block).concat(ct_part1).concat(zero_block).concat(counter);
        step_in = step_in.concat(new Array(TOTAL_BYTES_ACROSS_NIVC_1 - step_in.length).fill(0));

        let expected = plainText1.concat(plainText2).concat(ct_part1).concat(ct_part2).concat([0x00, 0x00, 0x00, 0x03]);
        expected = expected.concat(new Array(TOTAL_BYTES_ACROSS_NIVC_1 - expected.length).fill(0));

        const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: plainText2, aad: aad, step_in: step_in }, ["step_out"])
        assert.deepEqual(witness.step_out, expected.map(BigInt));
    });
});