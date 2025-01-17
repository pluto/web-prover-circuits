import { WitnessTester } from "circomkit";
import { circomkit, PolynomialDigest, toByte, toUint32Array, uintArray32ToBits, modAdd } from "../common";
import { DataHasher } from "../common/poseidon";
import { assert } from "chai";

describe("Plaintext Authentication", () => {
    let circuit: WitnessTester<["key", "nonce", "counter", "plaintext", "plaintext_index_counter", "ciphertext_digest", "step_in"], ["step_out"]>;
    describe("16 block test", () => {
        it("should perform encryption", async () => {
            circuit = await circomkit.WitnessTester(`PlaintextAuthentication`, {
                file: "chacha20/authentication",
                template: "PlaintextAuthentication",
                params: [64] // number of bytes for plaintext
            });
            // Test case from RCF https://www.rfc-editor.org/rfc/rfc7539.html#section-2.4.2
            // the input encoding here is not the most intuitive. inputs are serialized as little endian.
            // i.e. "e4e7f110" is serialized as "10 f1 e7 e4". So the way i am reading in inputs is
            // to ensure that every 32 bit word is byte reversed before being turned into bits.
            // i think this should be easy when we compute witness in rust.
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

            let nonceBytes =
                [
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x4a,
                    0x00, 0x00, 0x00, 0x00
                ];
            let plaintextBytes =
                [
                    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
                    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
                    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
                    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
                ];
            let ciphertextBytes =
                [
                    0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
                    0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
                    0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
                    0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8
                ];
            const counterBits = uintArray32ToBits([1])[0];
            let ciphertext_digest = DataHasher(ciphertextBytes);
            let w = await circuit.compute({
                key: toInput(Buffer.from(keyBytes)),
                nonce: toInput(Buffer.from(nonceBytes)),
                counter: counterBits,
                plaintext: plaintextBytes,
                plaintext_index_counter: 0,
                ciphertext_digest: ciphertext_digest,
                step_in: 0
            }, (["step_out"]));

            // Output
            let plaintext_digest = PolynomialDigest(plaintextBytes, ciphertext_digest, BigInt(0));
            let output = modAdd(plaintext_digest - ciphertext_digest, BigInt(0));
            assert.deepEqual(w.step_out, output);
        });
    });

    describe("padded plaintext", () => {
        it("should perform encryption", async () => {
            circuit = await circomkit.WitnessTester(`PlaintextAuthentication`, {
                file: "chacha20/authentication",
                template: "PlaintextAuthentication",
                params: [128] // number of bytes in plaintext
            });
            // Test case from RCF https://www.rfc-editor.org/rfc/rfc7539.html#section-2.4.2
            // the input encoding here is not the most intuitive. inputs are serialized as little endian.
            // i.e. "e4e7f110" is serialized as "10 f1 e7 e4". So the way i am reading in inputs is
            // to ensure that every 32 bit word is byte reversed before being turned into bits.
            // i think this should be easy when we compute witness in rust.
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

            let nonceBytes =
                [
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x4a,
                    0x00, 0x00, 0x00, 0x00
                ];
            let plaintextBytes =
                toByte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip ");

            let ciphertextBytes =
                [
                    0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
                    0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
                    0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
                    0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
                    0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08
                ];
            let totalLength = 128;
            let paddedPlaintextBytes = plaintextBytes.concat(Array(totalLength - plaintextBytes.length).fill(-1));
            const counterBits = uintArray32ToBits([1])[0];
            let ciphertext_digest = DataHasher(ciphertextBytes);
            let w = await circuit.compute({
                key: toInput(Buffer.from(keyBytes)),
                nonce: toInput(Buffer.from(nonceBytes)),
                counter: counterBits,
                plaintext: paddedPlaintextBytes,
                step_in: 0,
                plaintext_index_counter: 0,
                ciphertext_digest: ciphertext_digest,
            }, (["step_out"]));

            let plaintext_digest = PolynomialDigest(plaintextBytes, ciphertext_digest, BigInt(0));
            let output = modAdd(plaintext_digest - ciphertext_digest, BigInt(0));
            assert.deepEqual(w.step_out, output);
        });
    });
});


export function toInput(bytes: Buffer) {
    return uintArray32ToBits(toUint32Array(bytes))
}

export function fromInput(bits: number[]) {
    const uint32Array = new Uint32Array(bits.length / 32);
    for (let i = 0; i < uint32Array.length; i++) {
        uint32Array[i] = parseInt(bits.slice(i * 32, (i + 1) * 32).join(''), 2);
    }
    const buffer = Buffer.alloc(uint32Array.length * 4);
    for (let i = 0; i < uint32Array.length; i++) {
        buffer.writeUInt32LE(uint32Array[i], i * 4);
    }
    return buffer;
}
