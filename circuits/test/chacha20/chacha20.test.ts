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

    // this is failing right now
    describe("2 block test", () => {
        let circuit: WitnessTester<["key", "nonce", "counter", "in"], ["out"]>;
        it("should perform encryption", async () => {
            circuit = await circomkit.WitnessTester(`ChaCha20`, {
                file: "chacha20/chacha20",
                template: "ChaCha20",
                params: [16] // number of 32-bit words in the key, 512 / 32 = 16
            });
            // Test case from RCF https://www.rfc-editor.org/rfc/rfc7539.html#section-2.4.2
            let keyBytes = [
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b,
                0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13,
                0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f
            ];
            let nonceBytes = [
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x4a,
                0x00, 0x00, 0x00, 0x00
            ]; 

            let counter = 1;
            let plaintextBytes =[
                0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
                0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
                0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
                0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
            ];

            
            let ciphertextBytes = [
                0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
                0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
                0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
                0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8
            ];
            const ketBits = hexArrayToBits(keyBytes)
            const nonceBits = hexArrayToBits(nonceBytes)
            const ciphertextBits = BytesToInput(ciphertextBytes)
            const plaintextBits = BytesToInput(plaintextBytes)
            const counterBits = uintArray32ToBits([counter])[0]
			let w = await circuit.calculateWitness({
				key: ketBits,
				nonce: nonceBits,
				counter: counterBits,
				in: plaintextBits,
			});
            console.log(w.toLocaleString())
        });
    });
});

export function BytesToInput(bytes: number[]): number[] {
    const output: number[][] = [];
    let counter = 1;
    let bits: number[] = [];
    for (const byte of bytes) {
        for (let i = 7; i >= 0; i--) {
            bits.push((byte >> i) & 1);
        }
        if (counter % 4 == 0) {
            output.push(bits);
            bits = [];
        }

    }
    return bits;
}
export function hexArrayToBits(bytes: number[]): number[] {
    const bits: number[] = [];
    for (const byte of bytes) {
        for (let i = 7; i >= 0; i--) {
            bits.push((byte >> i) & 1);
        }
    }
    return bits;
}

export function uintArray32ToBits(uintArray: Uint32Array | number[]) {
	const bits: number[][] = []
	for (let i = 0; i < uintArray.length; i++) {
		const uint = uintArray[i]
		bits.push(numToBitsNumerical(uint))
	}

	return bits
}
function numToBitsNumerical(num: number, bitCount = 32) {
	const bits: number[] = []
	for(let i = 2 ** (bitCount - 1);i >= 1;i /= 2) {
		const bit = num >= i ? 1 : 0
		bits.push(bit)
		num -= bit * i
	}

	return bits
}