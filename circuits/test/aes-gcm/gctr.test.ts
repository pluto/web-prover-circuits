import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { assert } from "chai";

describe("GCTR", () => {
    let circuit: WitnessTester<["plainText", "initialCounterBlock", "key"], ["cipherText"]>;
    it("should encrypt the plaintext", async () => {
        circuit = await circomkit.WitnessTester(`GCTR`, {
            file: "aes-gcm/gctr",
            template: "GCTR",
            params: [16],
        });

        // GOOD TEST CASE.
        const key = [0xca, 0xaa, 0x3f, 0x6f, 0xd3, 0x18, 0x22, 0xed, 0x2d, 0x21, 0x25, 0xf2, 0x25, 0xb0, 0x16, 0x9f];
        const column_wise_icb = [0x7f, 0x48, 0x12, 0x00, 0x6d, 0x3e, 0xfa, 0x00, 0x90, 0x8c, 0x55, 0x00, 0x41, 0x14, 0x2a, 0x02];
        const pt = [0x84, 0xc9, 0x07, 0xb1, 0x1a, 0xe3, 0xb7, 0x9f, 0xc4, 0x45, 0x1d, 0x1b, 0xf1, 0x7f, 0x4a, 0x99];
        const ct = [0xfd, 0xb4, 0xaa, 0xfa, 0x35, 0x19, 0xd3, 0xc0, 0x55, 0xbe, 0x8b, 0x34, 0x77, 0x64, 0xea, 0x33];

        const witness = await circuit.compute({ key: key, initialCounterBlock: column_wise_icb, plainText: pt }, ["cipherText"])

        assert.deepEqual(witness.cipherText, hexBytesToBigInt(ct))
    });
});

function hexBytesToBigInt(hexBytes: number[]): any[] {
    return hexBytes.map(byte => {
      let n = BigInt(byte);
      return n;
    });
  }