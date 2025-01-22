import 'mocha';
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { Circomkit, WitnessTester } from "circomkit";

export const circomkit = new Circomkit({
    verbose: false,
});

export { WitnessTester };

function stringifyValue(value: any): string {
    if (Array.isArray(value)) {
        return `[${value.map(stringifyValue).join(', ')}]`;
    }
    if (typeof value === 'object' && value !== null) {
        return `{${Object.entries(value).map(([k, v]) => `${k}: ${stringifyValue(v)}`).join(', ')}}`;
    }
    return String(value);
}

export function generateDescription(input: any): string {
    return Object.entries(input)
        .map(([key, value]) => `${key} = ${stringifyValue(value)}`)
        .join(", ");
}

export function readJSONInputFile(filename: string, key: any[]): [number[], number[][], number[]] {
    const valueStringPath = join(__dirname, "..", "..", "..", "examples", "json", filename);

    let input: number[] = [];
    let output: number[] = [];

    let data = filename;
    if (existsSync(valueStringPath)) {
        data = readFileSync(valueStringPath, 'utf-8');
    }

    let keyUnicode: number[][] = [];
    for (let i = 0; i < key.length; i++) {
        keyUnicode[i] = [];
        let key_string = key[i].toString();
        for (let j = 0; j < key_string.length; j++) {
            keyUnicode[i].push(key_string.charCodeAt(j));
        }
    }

    const byteArray = [];
    for (let i = 0; i < data.length; i++) {
        byteArray.push(data.charCodeAt(i));
    }
    input = byteArray;

    let jsonFile = JSON.parse(data);
    let value = key.reduce((acc, key) => acc && acc[key], jsonFile);
    value = value.toString();
    for (let i = 0; i < value.length; i++) {
        output.push(value.charCodeAt(i));
    }

    return [input, keyUnicode, output];
}

import fs from 'fs';
import { DataHasher } from './poseidon';
import { poseidon1 } from 'poseidon-lite';

export function readJsonFile<T>(filePath: string): T {
    // Read the file synchronously
    const fileContents = fs.readFileSync(filePath, 'utf-8');

    // Parse the JSON content
    const jsonData = JSON.parse(fileContents, (key, value) => {
        // Check if the value is a string that ends with 'n' (for BigInt)
        if (typeof value === 'string' && value.endsWith('n')) {
            // Convert it back to a BigInt
            return BigInt(value.slice(0, -1));
        }
        return value;
    });

    return jsonData as T;
}

export function toByte(data: string): number[] {
    const byteArray = [];
    for (let i = 0; i < data.length; i++) {
        byteArray.push(data.charCodeAt(i));
    }
    return byteArray
}

export function hexToBytes(hex: any) {
    return hex.match(/.{1,2}/g).map((byte: any) => parseInt(byte, 16));
}

export function hexBytesToBigInt(hexBytes: number[]): any[] {
    return hexBytes.map(byte => {
        let n = BigInt(byte);
        return n;
    });
}

export function hexToBits(hex: string): number[] {
    if (hex.startsWith('0x')) {
        hex = hex.slice(2);
    }
    const bits: number[] = [];
    for (let i = 0; i < hex.length; i++) {
        const nibble = parseInt(hex[i], 16);
        for (let j = 3; j >= 0; j--) {
            bits.push((nibble >> j) & 1);
        }
    }
    return bits;
}

export function bitsToHex(bits: number[]): string {
    let hex = '';
    for (let i = 0; i < bits.length; i += 4) {
        let nibble = 0;
        for (let j = 0; j < 4; j++) {
            nibble = (nibble << 1) | (bits[i + j] || 0);
        }
        hex += nibble.toString(16);
    }
    return hex;
}

export function bitsToBytes(bits: number[]): number[] {
    const bytes: number[] = [];
    for (let i = 0; i < bits.length; i += 8) {
        let byte = 0;
        for (let j = 0; j < 8; j++) {
            byte = (byte << 1) | (bits[i + j] || 0);
        }
        bytes.push(byte);
    }
    return bytes;
}

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

export function binaryStringToHex(binaryString: string): string {
    let hex = '';
    for (let i = 0; i < binaryString.length; i += 4) {
        const chunk = binaryString.slice(i, i + 4);
        const hexDigit = parseInt(chunk, 2).toString(16);
        hex += hexDigit;
    }
    return hex;
}

/**
 * Converts a Uint8Array to an array of bits.
 * BE order.
 */
export function uint8ArrayToBitsBE(buff: Uint8Array | number[]) {
    const res: number[] = []
    for (let i = 0; i < buff.length; i++) {
        for (let j = 0; j < 8; j++) {
            if ((buff[i] >> 7 - j) & 1) {
                res.push(1);
            } else {
                res.push(0);
            }
        }
    }
    return res;
}

export function toUint32Array(buf: Uint8Array) {
    const arr = new Uint32Array(buf.length / 4)
    const arrView = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
    for (let i = 0; i < arr.length; i++) {
        arr[i] = arrView.getUint32(i * 4, true)
    }
    return arr
}

/**
 * Converts a Uint32Array to an array of bits.
 * LE order.
 */
export function uintArray32ToBits(uintArray: Uint32Array | number[]) {
    const bits: number[][] = []
    for (let i = 0; i < uintArray.length; i++) {
        const uint = uintArray[i]
        bits.push(numToBitsNumerical(uint))
    }

    return bits
}

export function numToBitsNumerical(num: number, bitCount = 32) {
    const bits: number[] = []
    for (let i = 2 ** (bitCount - 1); i >= 1; i /= 2) {
        const bit = num >= i ? 1 : 0
        bits.push(bit)
        num -= bit * i
    }

    return bits
}

export function bytesToBigInt(bytes: number[] | Uint8Array): bigint {
    let result = BigInt(0);

    for (let i = 0; i < 16; i++) {
        result += BigInt(bytes[i]) * BigInt(2 ** (8 * i));
    }

    return result;
}

const prime = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
export function PolynomialDigest(coeffs: number[], input: bigint, counter: bigint): bigint {
    let result = BigInt(0);
    // input ** counter
    let power = BigInt(1);
    for (let i = 0; i < counter; i++) {
        power = (power * input) % prime;
    }

    for (let i = 0; i < coeffs.length; i++) {
        result = (result + BigInt(coeffs[i]) * power) % prime;
        power = (power * input) % prime;
    }

    return result;
}

// HTTP/1.1 200 OK
// content-type: application/json; charset=utf-8
// content-encoding: gzip
// Transfer-Encoding: chunked
//
// {
//    "data": {
//        "items": [
//            {
//                "data": "Artist",
//                "profile": {
//                    "name": "Taylor Swift"
//                }
//            }
//        ]
//    }
// }

// 320 bytes in the HTTP response
export const http_response_plaintext = [
    72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 99, 111, 110, 116, 101, 110,
    116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106,
    115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13, 10, 99,
    111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122, 105,
    112, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69, 110, 99, 111, 100, 105, 110, 103, 58,
    32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13, 10, 123, 13, 10, 32, 32, 32, 34, 100, 97, 116,
    97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109, 115, 34, 58, 32,
    91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115,
    116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114,
    111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119,
    105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13,
    10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13,
    10, 32, 32, 32, 125, 13, 10, 125,
];

export const http_response_ciphertext = [
    2, 125, 219, 141, 140, 93, 49, 129, 95, 178, 135, 109, 48, 36, 194, 46, 239, 155, 160, 70, 208,
    147, 37, 212, 17, 195, 149, 190, 38, 215, 23, 241, 84, 204, 167, 184, 179, 172, 187, 145, 38, 75,
    123, 96, 81, 6, 149, 36, 135, 227, 226, 254, 177, 90, 241, 159, 0, 230, 183, 163, 210, 88, 133,
    176, 9, 122, 225, 83, 171, 157, 185, 85, 122, 4, 110, 52, 2, 90, 36, 189, 145, 63, 122, 75, 94,
    21, 163, 24, 77, 85, 110, 90, 228, 157, 103, 41, 59, 128, 233, 149, 57, 175, 121, 163, 185, 144,
    162, 100, 17, 34, 9, 252, 162, 223, 59, 221, 106, 127, 104, 11, 121, 129, 154, 49, 66, 220, 65,
    130, 171, 165, 43, 8, 21, 248, 12, 214, 33, 6, 109, 3, 144, 52, 124, 225, 206, 223, 213, 86, 186,
    93, 170, 146, 141, 145, 140, 57, 152, 226, 218, 57, 30, 4, 131, 161, 0, 248, 172, 49, 206, 181,
    47, 231, 87, 72, 96, 139, 145, 117, 45, 77, 134, 249, 71, 87, 178, 239, 30, 244, 156, 70, 118,
    180, 176, 90, 92, 80, 221, 177, 86, 120, 222, 223, 244, 109, 150, 226, 142, 97, 171, 210, 38,
    117, 143, 163, 204, 25, 223, 238, 209, 58, 59, 100, 1, 86, 241, 103, 152, 228, 37, 187, 79, 36,
    136, 133, 171, 41, 184, 145, 146, 45, 192, 173, 219, 146, 133, 12, 246, 190, 5, 54, 99, 155, 8,
    198, 156, 174, 99, 12, 210, 95, 5, 128, 166, 118, 50, 66, 26, 20, 3, 129, 232, 1, 192, 104, 23,
    152, 212, 94, 97, 138, 162, 90, 185, 108, 221, 211, 247, 184, 253, 15, 16, 24, 32, 240, 240, 3,
    148, 89, 30, 54, 161, 131, 230, 161, 217, 29, 229, 251, 33, 220, 230, 102, 131, 245, 27, 141,
    220, 67, 16, 26,
];

export const http_response_ciphertext_dup = [
    66, 0, 57, 150, 208, 144, 184, 250, 244, 106, 253, 118, 105, 7, 189, 139, 78, 36, 126, 180, 79, 153, 22, 237, 62, 182, 186, 218, 239, 75, 35, 97, 231, 115, 106, 144, 4, 226, 80, 116, 121, 35, 136, 75, 89, 30, 78, 124, 59, 165, 121, 235, 65, 63, 174, 154, 143, 75, 78, 33, 20, 38, 21, 133, 42, 97, 147, 38, 195, 192, 90, 33, 165, 244, 196, 97, 167, 218, 2, 114, 7, 50, 34, 109, 211, 202, 30, 101, 196, 146, 61, 67, 166, 66, 255, 90, 38, 74, 162, 187, 173, 9, 149, 98, 16, 65, 79, 186, 61, 110, 193, 228, 163, 82, 238, 26, 30, 105, 206, 69, 2, 102, 238, 165, 47, 159, 39, 5, 197, 150, 0, 69, 51, 234, 132, 22, 219, 250, 22, 69, 111, 87, 123, 211, 13, 88, 46, 215, 6, 12, 107, 65, 69, 9, 235, 217, 180, 167, 132, 204
];

export const http_start_line = [72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75];

export const http_header_0 = [
    99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97,
    116, 105, 111, 110, 47, 106, 115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117,
    116, 102, 45, 56,
];

export const http_header_1 = [
    99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122,
    105, 112,
];
export const http_body = [
    123, 13, 10, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32,
    32, 34, 105, 116, 101, 109, 115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116,
    97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32,
    34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125,
    13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13, 10, 32, 32, 32, 125, 13, 10, 125,
];

export function strToBytes(str: string): number[] {
    return Array.from(str.split('').map(c => c.charCodeAt(0)));
}

// Enum equivalent for JsonMaskType
export type JsonMaskType =
    | { type: "Object", value: number[] }  // Changed from Uint8Array to number[]
    | { type: "ArrayIndex", value: number };

// Constants for the field arithmetic
const PRIME = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const ONE = BigInt(1);
const ZERO = BigInt(0);

export function modAdd(a: bigint, b: bigint): bigint {
    return ((a + b) % PRIME + PRIME) % PRIME;
}

function modMul(a: bigint, b: bigint): bigint {
    return (a * b) % PRIME;
}

export function jsonTreeHasher(
    polynomialInput: bigint,
    keySequence: JsonMaskType[],
    maxStackHeight: number
): [Array<[bigint, bigint]>, Array<bigint>] {
    if (keySequence.length > maxStackHeight) {
        throw new Error("Key sequence length exceeds max stack height");
    }

    const stack: Array<[bigint, bigint]> = [];
    const treeHashes: Array<bigint> = [];

    for (const valType of keySequence) {
        if (valType.type === "Object") {
            stack.push([ONE, ONE]);
            let stringHash = ZERO;
            let monomial = ONE;

            for (const byte of valType.value) {
                stringHash = modAdd(stringHash, modMul(monomial, BigInt(byte)));
                monomial = modMul(monomial, polynomialInput);
            }
            treeHashes.push(stringHash);
        } else { // ArrayIndex
            treeHashes.push(ZERO);
            stack.push([BigInt(2), BigInt(valType.value)]);
        }
    }

    return [stack, treeHashes];
}

export function compressTreeHash(
    polynomialInput: bigint,
    stackAndTreeHashes: [Array<[bigint, bigint]>, Array<bigint>]
): bigint {
    const [stack, treeHashes] = stackAndTreeHashes;

    if (stack.length !== treeHashes.length) {
        throw new Error("Stack and tree hashes must have the same length");
    }

    let accumulated = ZERO;
    let monomial = ONE;

    for (let idx = 0; idx < stack.length; idx++) {
        accumulated = modAdd(accumulated, modMul(stack[idx][0], monomial));
        monomial = modMul(monomial, polynomialInput);

        accumulated = modAdd(accumulated, modMul(stack[idx][1], monomial));
        monomial = modMul(monomial, polynomialInput);

        accumulated = modAdd(accumulated, modMul(treeHashes[idx], monomial));
        monomial = modMul(monomial, polynomialInput);
    }

    return accumulated;
}

interface ManifestResponse {
    version: string;
    status: string;
    message: string;
    headers: Record<string, string[]>;
    body: {
        json: JsonMaskType[];
    };
}

export interface Manifest {
    response: ManifestResponse;
}

function headersToBytes(headers: Record<string, string[]>): number[][] {
    const result: number[][] = [];

    for (const [key, values] of Object.entries(headers)) {
        for (const value of values) {
            // In HTTP/1.1, headers are formatted as "key: value"
            const headerLine = `${key}: ${value}`;
            result.push(strToBytes(headerLine));
        }
    }

    return result;
}

export function InitialDigest(
    manifest: Manifest,
    ciphertexts: number[][],
    maxStackHeight: number
): [bigint, bigint] {
    let ciphertextDigests: bigint[] = [];
    // Create a digest of the ciphertext itself
    ciphertexts.forEach(ciphertext => {
        const ciphertextDigest = DataHasher(ciphertext);
        ciphertextDigests.push(ciphertextDigest);
    });

    let ciphertextDigest = ciphertextDigests.reduce((a, b) => a + b, BigInt(0));

    // Digest the start line using the ciphertext_digest as a random input
    const startLineBytes = strToBytes(
        `${manifest.response.version} ${manifest.response.status} ${manifest.response.message}`
    );
    const startLineDigest = PolynomialDigest(startLineBytes, ciphertextDigest, BigInt(0));

    // Digest all the headers
    const headerBytes = headersToBytes(manifest.response.headers);
    const headersDigest = headerBytes.map(bytes =>
        PolynomialDigest(bytes, ciphertextDigest, BigInt(0))
    );

    // Digest the JSON sequence
    const jsonTreeHash = jsonTreeHasher(
        ciphertextDigest,
        manifest.response.body.json,
        maxStackHeight
    );
    const jsonSequenceDigest = compressTreeHash(ciphertextDigest, jsonTreeHash);

    // Put all the digests into an array
    const allDigests: bigint[] = [jsonSequenceDigest, startLineDigest, ...headersDigest];

    // Calculate manifest digest
    const manifestDigest = modAdd(
        ciphertextDigest,
        allDigests.map(d => poseidon1([d])).reduce((a, b) => modAdd(a, b), ZERO)
    );

    return [ciphertextDigest, manifestDigest];
}

export function MockManifest(): Manifest {
    const headers: Record<string, string[]> = {
        "content-type": ["application/json; charset=utf-8"],
        "content-encoding": ["gzip"]
    };

    const jsonSequence: JsonMaskType[] = [
        { type: "Object", value: strToBytes("data") },
        { type: "Object", value: strToBytes("items") },
        { type: "ArrayIndex", value: 0 },
        { type: "Object", value: strToBytes("profile") },
        { type: "Object", value: strToBytes("name") }
    ];

    return {
        response: {
            status: "200",
            version: "HTTP/1.1",
            message: "OK",
            headers: headers,
            body: {
                json: jsonSequence
            }
        }
    };
}