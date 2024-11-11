import { assert } from "chai";
import { circomkit, WitnessTester, toByte } from "../common";
import { PoseidonModular } from "../common/poseidon";

export function dataHasher(input: number[]): bigint {
    if (input.length % 16 !== 0) {
        throw new Error("DATA_BYTES must be divisible by 16");
    }

    let hashes: bigint[] = [BigInt(0)];  // Initialize first hash as 0

    for (let i = 0; i < Math.floor(input.length / 16); i++) {
        let packedInput = BigInt(0);

        // Pack 16 bytes into a single number
        for (let j = 0; j < 16; j++) {
            packedInput += BigInt(input[16 * i + j]) * BigInt(2 ** (8 * j));
        }

        // Compute next hash using previous hash and packed input
        hashes.push(PoseidonModular([hashes[i], packedInput]));
    }

    // Return the last hash
    return hashes[Math.floor(input.length / 16)];
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
const http_response_plaintext = [
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
    10, 32, 32, 32, 125, 13, 10, 125];

const http_response_ciphertext = [
    75, 220, 142, 158, 79, 135, 141, 163, 211, 26, 242, 137, 81, 253, 181, 117,
    253, 246, 197, 197, 61, 46, 55, 87, 218, 137, 240, 143, 241, 177, 225, 129,
    80, 114, 125, 72, 45, 18, 224, 179, 79, 231, 153, 198, 163, 252, 197, 219,
    233, 46, 202, 120, 99, 253, 76, 9, 70, 11, 200, 218, 228, 251, 133, 248,
    233, 177, 19, 241, 205, 128, 65, 76, 10, 31, 71, 198, 177, 78, 108, 246,
    175, 152, 42, 97, 255, 182, 157, 245, 123, 95, 130, 101, 129, 138, 236, 146,
    47, 22, 22, 13, 125, 1, 109, 158, 189, 131, 44, 43, 203, 118, 79, 181,
    86, 33, 235, 186, 75, 20, 7, 147, 102, 75, 90, 222, 255, 140, 94, 52,
    191, 145, 192, 71, 239, 245, 247, 175, 117, 136, 173, 235, 250, 189, 74, 155,
    103, 25, 164, 187, 22, 26, 39, 37, 113, 248, 170, 146, 73, 75, 45, 208,
    125, 49, 101, 11, 120, 215, 93, 160, 14, 147, 129, 181, 150, 59, 167, 197,
    230, 122, 77, 245, 247, 215, 136, 98, 1, 180, 213, 30, 214, 88, 83, 42,
    33, 112, 61, 4, 197, 75, 134, 149, 22, 228, 24, 95, 131, 35, 44, 181,
    135, 31, 173, 36, 23, 192, 177, 127, 156, 199, 167, 212, 66, 235, 194, 102,
    61, 144, 121, 59, 187, 179, 212, 34, 117, 47, 96, 3, 169, 73, 204, 88,
    36, 48, 158, 220, 237, 198, 180, 105, 7, 188, 109, 24, 201, 217, 186, 191,
    232, 63, 93, 153, 118, 214, 157, 167, 15, 216, 191, 152, 41, 106, 24, 127,
    8, 144, 78, 218, 133, 125, 89, 97, 10, 246, 8, 244, 112, 169, 190, 206,
    14, 217, 109, 147, 130, 61, 214, 237, 143, 77, 14, 14, 70, 56, 94, 97,
    207, 214, 106, 249, 37, 7, 186, 95, 174, 146, 203, 148, 173, 172, 13, 113
];
const http_body = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 123, 13, 10, 32, 32, 32, 34,
    100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109,
    115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114,
    116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111,
    114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32,
    32, 32, 93, 13, 10, 32, 32, 32, 125, 13, 10, 125,
]
const lengthDiff = http_response_plaintext.length - http_body.length;

// Create an array of zeros with the length difference
const padding = new Array(lengthDiff).fill(0);

// Concatenate the padding with http_body
const padded_http_body = [...padding, ...http_body];

const http_response_hash = dataHasher(http_response_plaintext);
const http_body_mask_hash = dataHasher(padded_http_body);


const json_key0_mask = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109, 115, 34, 58, 32, 91,
    13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116,
    34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111,
    102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105,
    102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13, 0,
    0, 0, 0, 0, 0, 0, 0,
];
const json_key0_mask_hash = dataHasher(json_key0_mask);

const json_key1_mask = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 91, 13, 10, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34,
    58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97,
    109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const json_key1_mask_hash = dataHasher(json_key1_mask);

const json_arr_mask = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100,
    97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13,
    10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34,
    58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const json_arr_mask_hash = dataHasher(json_arr_mask);

const json_key2_mask = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110,
    97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const json_key2_mask_hash = dataHasher(json_key2_mask);

const json_key3_mask = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34,
    84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
];
const json_key3_mask_hash = dataHasher(json_key3_mask);

describe("NIVC_FULL", async () => {
    let aesCircuit: WitnessTester<["key", "iv", "aad", "ctr", "plainText", "cipherText", "step_in"], ["step_out"]>;
    let httpParseAndLockStartLineCircuit: WitnessTester<["step_in", "data", "beginning", "beginning_length", "middle", "middle_length", "final", "final_length"], ["step_out"]>;
    let lockHeaderCircuit: WitnessTester<["step_in", "data", "header", "headerNameLength", "value", "headerValueLength"], ["step_out"]>;
    let bodyMaskCircuit: WitnessTester<["step_in", "data"], ["step_out"]>;
    let json_mask_object_circuit: WitnessTester<["step_in", "data", "key", "keyLen"], ["step_out"]>;
    let json_mask_arr_circuit: WitnessTester<["step_in", "data", "index"], ["step_out"]>;
    let extract_value_circuit: WitnessTester<["step_in", "data"], ["step_out"]>;

    const DATA_BYTES = 320;
    const MAX_STACK_HEIGHT = 5;

    const MAX_HEADER_NAME_LENGTH = 20;
    const MAX_HEADER_VALUE_LENGTH = 35;
    const MAX_BEGINNING_LENGTH = 10;
    const MAX_MIDDLE_LENGTH = 30;
    const MAX_FINAL_LENGTH = 10;

    const beginning = [72, 84, 84, 80, 47, 49, 46, 49]; // HTTP/1.1
    const middle = [50, 48, 48]; // 200
    const final = [79, 75]; // OK

    const MAX_KEY_LENGTH = 8;
    // TODO (Sambhav): max value length has to be divisible to 16
    const MAX_VALUE_LENGTH = 32;

    before(async () => {
        aesCircuit = await circomkit.WitnessTester("AESGCTRFOLD", {
            file: "aes-gcm/nivc/aes-gctr-nivc",
            template: "AESGCTRFOLD",
        });
        console.log("#constraints (AES-GCTR):", await aesCircuit.getConstraintCount());

        httpParseAndLockStartLineCircuit = await circomkit.WitnessTester(`ParseAndLockStartLine`, {
            file: "http/nivc/parse_and_lock_start_line",
            template: "ParseAndLockStartLine",
            params: [DATA_BYTES, MAX_BEGINNING_LENGTH, MAX_MIDDLE_LENGTH, MAX_FINAL_LENGTH],
        });
        console.log("#constraints (HTTP-PARSE-AND-LOCK-START-LINE):", await httpParseAndLockStartLineCircuit.getConstraintCount());

        lockHeaderCircuit = await circomkit.WitnessTester(`LockHeader`, {
            file: "http/nivc/lock_header",
            template: "LockHeader",
            params: [DATA_BYTES, MAX_HEADER_NAME_LENGTH, MAX_HEADER_VALUE_LENGTH],
        });
        console.log("#constraints (HTTP-LOCK-HEADER):", await lockHeaderCircuit.getConstraintCount());

        bodyMaskCircuit = await circomkit.WitnessTester(`BodyMask`, {
            file: "http/nivc/body_mask",
            template: "HTTPMaskBodyNIVC",
            params: [DATA_BYTES],
        });
        console.log("#constraints (HTTP-BODY-MASK):", await bodyMaskCircuit.getConstraintCount());

        json_mask_object_circuit = await circomkit.WitnessTester(`JsonMaskObjectNIVC`, {
            file: "json/nivc/masker",
            template: "JsonMaskObjectNIVC",
            params: [DATA_BYTES, MAX_STACK_HEIGHT, MAX_KEY_LENGTH],
        });
        console.log("#constraints (JSON-MASK-OBJECT):", await json_mask_object_circuit.getConstraintCount());

        json_mask_arr_circuit = await circomkit.WitnessTester(`JsonMaskArrayIndexNIVC`, {
            file: "json/nivc/masker",
            template: "JsonMaskArrayIndexNIVC",
            params: [DATA_BYTES, MAX_STACK_HEIGHT],
        });
        console.log("#constraints (JSON-MASK-ARRAY-INDEX):", await json_mask_arr_circuit.getConstraintCount());

        extract_value_circuit = await circomkit.WitnessTester(`JsonMaskExtractFinal`, {
            file: "json/nivc/extractor",
            template: "MaskExtractFinal",
            params: [DATA_BYTES, MAX_VALUE_LENGTH],
        });
        console.log("#constraints (JSON-MASK-EXTRACT-FINAL):", await extract_value_circuit.getConstraintCount());
    });


    let headerName = toByte("content-type")
    let headerValue = toByte("application/json; charset=utf-8");

    let headerNamePadded = headerName.concat(Array(MAX_HEADER_NAME_LENGTH - headerName.length).fill(0));
    let headerValuePadded = headerValue.concat(Array(MAX_HEADER_VALUE_LENGTH - headerValue.length).fill(0));
    let beginningPadded = beginning.concat(Array(MAX_BEGINNING_LENGTH - beginning.length).fill(0));
    let middlePadded = middle.concat(Array(MAX_MIDDLE_LENGTH - middle.length).fill(0));
    let finalPadded = final.concat(Array(MAX_FINAL_LENGTH - final.length).fill(0));
    it("NIVC_CHAIN", async () => {
        // Run AES chain
        let ctr = [0x00, 0x00, 0x00, 0x01];
        const init_nivc_input = 0;

        let pt = http_response_plaintext.slice(0, 16);
        let ct = http_response_ciphertext.slice(0, 16);
        let aes_gcm = await aesCircuit.compute({ key: Array(16).fill(0), iv: Array(12).fill(0), ctr: ctr, plainText: pt, aad: Array(16).fill(0), cipherText: ct, step_in: init_nivc_input }, ["step_out"]);
        let i = 0;
        console.log("AES `step_out[", i, "]`: ", aes_gcm.step_out);
        for (i = 1; i < (DATA_BYTES / 16); i++) {
            ctr[3] += 1; // This will work since we don't run a test that overlows a byte
            let pt = http_response_plaintext.slice(i * 16, i * 16 + 16);
            let ct = http_response_ciphertext.slice(i * 16, i * 16 + 16);
            aes_gcm = await aesCircuit.compute({ key: Array(16).fill(0), iv: Array(12).fill(0), ctr: ctr, plainText: pt, aad: Array(16).fill(0), cipherText: ct, step_in: aes_gcm.step_out }, ["step_out"]);
            console.log("AES `step_out[", i, "]`: ", aes_gcm.step_out);
        }
        assert.deepEqual(http_response_hash, aes_gcm.step_out);

        // Lock the start line
        let parseAndLockStartLine = await httpParseAndLockStartLineCircuit.compute({ step_in: aes_gcm.step_out, data: http_response_plaintext, beginning: beginningPadded, beginning_length: beginning.length, middle: middlePadded, middle_length: middle.length, final: finalPadded, final_length: final.length }, ["step_out"]);
        console.log("Start Line `step_out`: ", parseAndLockStartLine.step_out);

        // Lock a header
        let lockHeader = await lockHeaderCircuit.compute({ step_in: parseAndLockStartLine.step_out, data: http_response_plaintext, header: headerNamePadded, headerNameLength: headerName.length, value: headerValuePadded, headerValueLength: headerValue.length }, ["step_out"]);
        console.log("Lock Header `step_out`: ", lockHeader.step_out);

        // Mask the body
        // let bodyMask = await bodyMaskCircuit.compute({ step_in: lockHeader.step_out, data: http_response_plaintext }, ["step_out"]);
        let bodyMask = await bodyMaskCircuit.compute({ step_in: http_response_hash, data: http_response_plaintext }, ["step_out"]);
        console.log("Body Mask `step_out`: ", bodyMask.step_out);
        assert.deepEqual(bodyMask.step_out, http_body_mask_hash);

        let key0 = [100, 97, 116, 97, 0, 0, 0, 0]; // "data"
        let key0Len = 4;
        let key1 = [105, 116, 101, 109, 115, 0, 0, 0]; // "items"
        let key1Len = 5;
        let key2 = [112, 114, 111, 102, 105, 108, 101, 0]; // "profile"
        let key2Len = 7;
        let key3 = [110, 97, 109, 101, 0, 0, 0, 0]; // "name"
        let key3Len = 4;

        // let value = toByte("\"Taylor Swift\"");

        let json_extract_key0 = await json_mask_object_circuit.compute({ step_in: bodyMask.step_out, data: http_body, key: key0, keyLen: key0Len }, ["step_out"]);
        console.log("JSON Extract key0 `step_out`:", json_extract_key0.step_out);
        assert.deepEqual(json_extract_key0.step_out, json_key0_mask_hash);

        let json_extract_key1 = await json_mask_object_circuit.compute({ step_in: json_extract_key0.step_out, data: json_key0_mask, key: key1, keyLen: key1Len }, ["step_out"]);
        assert.deepEqual(json_extract_key1.step_out, json_key1_mask_hash);
        console.log("JSON Extract key1 `step_out`:", json_extract_key1.step_out);

        let json_extract_arr = await json_mask_arr_circuit.compute({ step_in: json_extract_key1.step_out, data: json_key1_mask, index: 0 }, ["step_out"]);
        assert.deepEqual(json_extract_arr.step_out, json_arr_mask_hash);
        console.log("JSON Extract arr `step_out`:", json_extract_arr.step_out);

        let json_extract_key2 = await json_mask_object_circuit.compute({ step_in: json_extract_arr.step_out, data: json_arr_mask, key: key2, keyLen: key2Len }, ["step_out"]);
        assert.deepEqual(json_extract_key2.step_out, json_key2_mask_hash);
        console.log("JSON Extract key2 `step_out`:", json_extract_key2.step_out);

        let json_extract_key3 = await json_mask_object_circuit.compute({ step_in: json_extract_key2.step_out, data: json_key2_mask, key: key3, keyLen: key3Len }, ["step_out"]);
        assert.deepEqual(json_extract_key3.step_out, json_key3_mask_hash);
        console.log("JSON Extract key3 `step_out`:", json_extract_key3.step_out);

        // TODO (autoparallel): we need to rethink extraction here.
        let finalOutput = toByte("\"Taylor Swift\"");
        let finalOutputPadded = finalOutput.concat(Array(Math.max(0, MAX_VALUE_LENGTH - finalOutput.length)).fill(0));
        let final_value_hash = dataHasher(finalOutputPadded);
        // await extract_value_circuit.expectPass({ step_in: json_extract_key3.step_out, data: json_key3_mask }, { step_out: final_value_hash });
        let extractValue = await extract_value_circuit.compute({ step_in: json_extract_key3.step_out, data: json_key3_mask }, ["step_out"]);
        console.log("finalValue", extractValue.step_out);
        assert.deepEqual(extractValue.step_out, final_value_hash);
    });
});