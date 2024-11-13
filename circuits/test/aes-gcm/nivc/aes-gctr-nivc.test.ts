import { assert } from "chai";
import { WitnessTester } from "circomkit";
import { circomkit } from "../../common";
import { PoseidonModular } from "../../common/poseidon";

function bytesToBigInt(bytes: number[] | Uint8Array): bigint {
    let result = BigInt(0);

    for (let i = 0; i < 16; i++) {
        result += BigInt(bytes[i]) * BigInt(2 ** (8 * i));
    }

    return result;
}

describe("aes-gctr-nivc", () => {
    let circuit_one_block: WitnessTester<["key", "iv", "plainText", "aad", "ctr", "cipherText", "step_in"], ["step_out"]>;


    // it("all correct for self generated single zero pt block case", async () => {
    //     circuit_one_block = await circomkit.WitnessTester("aes-gcm-fold", {
    //         file: "aes-gcm/nivc/aes-gctr-nivc",
    //         template: "AESGCTRFOLD",
    //         params: [1]
    //     });

    //     let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    //     let plainText = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    //     let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    //     let aad = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    //     let ct = [0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78];

    //     const ctr = [0x00, 0x00, 0x00, 0x01];
    //     const step_in = 0;

    //     const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: plainText, aad: aad, ctr: ctr, cipherText: ct, step_in: step_in }, ["step_out"])
    //     assert.deepEqual(witness.step_out, PoseidonModular([step_in, bytesToBigInt(plainText)]));
    // });

    // it("all correct for self generated single non zero pt block", async () => {
    //     circuit_one_block = await circomkit.WitnessTester("aes-gcm-fold", {
    //         file: "aes-gcm/nivc/aes-gctr-nivc",
    //         template: "AESGCTRFOLD",
    //         params: [1]
    //     });

    //     let key = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];
    //     let plainText = [0x74, 0x65, 0x73, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30];
    //     let iv = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];
    //     let aad = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    //     let ct = [0x29, 0x29, 0xd2, 0xbb, 0x1a, 0xe9, 0x48, 0x04, 0x40, 0x2b, 0x8e, 0x77, 0x6e, 0x0d, 0x33, 0x56];

    //     const ctr = [0x00, 0x00, 0x00, 0x01];
    //     const step_in = 0;

    //     const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: plainText, aad: aad, ctr: ctr, cipherText: ct, step_in: step_in }, ["step_out"])
    //     assert.deepEqual(witness.step_out, PoseidonModular([step_in, bytesToBigInt(plainText)]));
    // });

    let key = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];
    let plainText1 = [0x74, 0x65, 0x73, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30];
    let plainText2 = [0x74, 0x65, 0x73, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30];
    let iv = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];
    let aad = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let ct_part1 = [0x29, 0x29, 0xd2, 0xbb, 0x1a, 0xe9, 0x48, 0x04, 0x40, 0x2b, 0x8e, 0x77, 0x6e, 0x0d, 0x33, 0x56];
    let ct_part2 = [0x26, 0x75, 0x65, 0x30, 0x71, 0x3e, 0x4c, 0x06, 0x5a, 0xf1, 0xd3, 0xc4, 0xf5, 0x6e, 0x02, 0x04];

    // it("all correct for self generated two block case first fold", async () => {
    //     circuit_one_block = await circomkit.WitnessTester("aes-gcm-fold", {
    //         file: "aes-gcm/nivc/aes-gctr-nivc",
    //         template: "AESGCTRFOLD",
    //         params: [1]
    //     });

    //     const ctr = [0x00, 0x00, 0x00, 0x01];
    //     const step_in = 0;

    //     const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: plainText1, aad: aad, ctr: ctr, cipherText: ct_part1, step_in: step_in }, ["step_out"])
    //     assert.deepEqual(witness.step_out, PoseidonModular([step_in, bytesToBigInt(plainText1)]));
    // });

    // it("all correct for self generated two block case second fold", async () => {
    //     circuit_one_block = await circomkit.WitnessTester("aes-gcm-fold", {
    //         file: "aes-gcm/nivc/aes-gctr-nivc",
    //         template: "AESGCTRFOLD",
    //         params: [1]
    //     });

    //     const ctr_0 = [0x00, 0x00, 0x00, 0x01];
    //     const ctr_1 = [0x00, 0x00, 0x00, 0x02];
    //     const step_in_0 = 0;

    //     const witness_0 = await circuit_one_block.compute({ key: key, iv: iv, plainText: plainText1, aad: aad, ctr: ctr_0, cipherText: ct_part1, step_in: step_in_0 }, ["step_out"])
    //     const witness_1 = await circuit_one_block.compute({ key: key, iv: iv, plainText: plainText2, aad: aad, ctr: ctr_1, cipherText: ct_part2, step_in: witness_0.step_out }, ["step_out"])
    //     assert.deepEqual(witness_1.step_out, PoseidonModular([BigInt(witness_0.step_out.toString()), bytesToBigInt(plainText2)]));
    // });

    let circuit_two_block: WitnessTester<["key", "iv", "plainText", "aad", "ctr", "cipherText", "step_in"], ["step_out"]>;
    it("all correct for two folds at once", async () => {
        circuit_two_block = await circomkit.WitnessTester("aes-gcm-fold", {
            file: "aes-gcm/nivc/aes-gctr-nivc",
            template: "AESGCTRFOLD",
            params: [2]
        });

        const ctr_0 = [0x00, 0x00, 0x00, 0x01];
        const step_in_0 = 0;

        const witness = await circuit_two_block.compute({ key: key, iv: iv, aad: aad, ctr: ctr_0, plainText: [plainText1, plainText2], cipherText: [ct_part1, ct_part2], step_in: step_in_0 }, ["step_out"])
        let hash_0 = PoseidonModular([step_in_0, bytesToBigInt(plainText1)]);
        assert.deepEqual(witness.step_out, PoseidonModular([hash_0, bytesToBigInt(plainText2)]));
    });
});