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
    const valueStringPath = join(__dirname, "..", "..", "..", "examples", "json", "test", filename);

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
			if ((buff[i] >> 7-j) & 1) {
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
	for(let i = 0;i < arr.length;i++) {
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
	for(let i = 2 ** (bitCount - 1);i >= 1;i /= 2) {
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