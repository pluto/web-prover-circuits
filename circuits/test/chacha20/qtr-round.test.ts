import { WitnessTester } from "circomkit";
import { circomkit, hexToBits, bitsToHex } from "../common";
import { assert } from "chai";

describe("qtr-round", () => {
    let circuit: WitnessTester<["in"], ["out"]>;
    it("should perform qtr-round", async () => {
        circuit = await circomkit.WitnessTester(`QR`, {
            file: "chacha20/chacha-qr",
            template: "QR",
        });

        // Test case from RCF https://www.rfc-editor.org/rfc/rfc7539.html#section-2.1
        let input = [ 
            hexToBits("0x11111111"),
            hexToBits("0x01020304"),
            hexToBits("0x9b8d6f43"),
            hexToBits("0x01234567")
        ];
        let expected = [ 
            hexToBits("0xea2a92f4"), 
            hexToBits("0xcb1cf8ce"), 
            hexToBits("0x4581472e"), 
            hexToBits("0x5881c4bb")
        ];
        const witness = await circuit.expectPass({ in: input }, { out: expected });
    });
});