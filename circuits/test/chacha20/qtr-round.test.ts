import { WitnessTester } from "circomkit";
import { circomkit, hexToBits, bitsToHex } from "../common";
import { assert } from "chai";

describe("chacha20", () => {
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

    describe("full-round", () => {
        let circuit: WitnessTester<["in"], ["out"]>;
        it("should perform qtr-round", async () => {
            circuit = await circomkit.WitnessTester(`QR`, {
                file: "chacha20/chacha-round",
                template: "Round",
            });
            // Test case from RCF https://www.rfc-editor.org/rfc/rfc7539.html#section-2.1
            let input = [ 
                hexToBits("61707865"),  hexToBits("3320646e"),  hexToBits("79622d32"),  hexToBits("6b206574"),
                hexToBits("03020100"),  hexToBits("07060504"),  hexToBits("0b0a0908"),  hexToBits("0f0e0d0c"),
                hexToBits("13121110"),  hexToBits("17161514"),  hexToBits("1b1a1918"),  hexToBits("1f1e1d1c"),
                hexToBits("00000001"),  hexToBits("09000000"),  hexToBits("4a000000"),  hexToBits("00000000")
            ];
            let expected = [ 
                hexToBits("e4e7f110"),  hexToBits("15593bd1"),  hexToBits("1fdd0f50"),  hexToBits("c47120a3"),
                hexToBits("c7f4d1c7"),  hexToBits("0368c033"),  hexToBits("9aaa2204"),  hexToBits("4e6cd4c3"),
                hexToBits("466482d2"),  hexToBits("09aa9f07"),  hexToBits("05d7c214"),  hexToBits("a2028bd9"),
                hexToBits("d19c12b5"),  hexToBits("b94e16de"),  hexToBits("e883d0cb"),  hexToBits("4e3c50a2")
            ];
            const witness = await circuit.expectPass({ in: input }, { out: expected });
        });
    });
});