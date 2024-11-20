import { assert } from "chai";
import { circomkit, WitnessTester, toByte, uintArray32ToBits, toUint32Array } from "../common";
import { DataHasher } from "../common/poseidon";
import { toInput } from "../chacha20/chacha20-nivc.test";
import { buffer } from "stream/consumers";

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

const chacha20_http_response_ciphertext = [
    2,125,219,141,140,93,49,129,95,178,135,109,48,36,194,46,239,155,160,70,208,147,37,212,17,195,149,
    190,38,215,23,241,84,204,167,184,179,172,187,145,38,75,123,96,81,6,149,36,135,227,226,254,177,90,
    241,159,0,230,183,163,210,88,133,176,9,122,225,83,171,157,185,85,122,4,110,52,2,90,36,189,145,63,
    122,75,94,21,163,24,77,85,110,90,228,157,103,41,59,128,233,149,57,175,121,163,185,144,162,100,17,
    34,9,252,162,223,59,221,106,127,104,11,121,129,154,49,66,220,65,130,171,165,43,8,21,248,12,214,33,
    6,109,3,144,52,124,225,206,223,213,86,186,93,170,146,141,145,140,57,152,226,218,57,30,4,131,161,0,
    248,172,49,206,181,47,231,87,72,96,139,145,117,45,77,134,249,71,87,178,239,30,244,156,70,118,180,
    176,90,92,80,221,177,86,120,222,223,244,109,150,226,142,97,171,210,38,117,143,163,204,25,223,238,
    209,58,59,100,1,86,241,103,152,228,37,187,79,36,136,133,171,41,184,145,146,45,192,173,219,146,133,
    12,246,190,5,54,99,155,8,198,156,174,99,12,210,95,5,128,166,118,50,66,26,20,3,129,232,1,192,104,
    23,152,212,94,97,138,162,90,185,108,221,211,247,184,253,15,16,24,32,240,240,3,148,89,30,54,161,
    131,230,161,217,29,229,251,33,220,230,102,131,245,27,141,220,67,16,26
];

const aes_http_response_ciphertext = [
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
]

const http_start_line = [
    72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
];

const http_header_0 = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 111, 110, 116, 101, 110, 116, 45, 116,
    121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115, 111,
    110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13, 10, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

const http_header_1 = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122,
    105, 112, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const http_body = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 13, 10, 32, 32, 32, 34,
    100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109,
    115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114,
    116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111,
    114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32,
    32, 32, 93, 13, 10, 32, 32, 32, 125, 13, 10, 125,
];
const lengthDiff = http_response_plaintext.length - http_body.length;

// Create an array of zeros with the length difference
const padding = new Array(lengthDiff).fill(0);

// Concatenate the padding with http_body
const padded_http_body = [...padding, ...http_body];

const http_response_hash = DataHasher(http_response_plaintext);
const http_start_line_hash = DataHasher(http_start_line);
const http_header_0_hash = DataHasher(http_header_0);
const http_header_1_hash = DataHasher(http_header_1);
const http_body_mask_hash = DataHasher(padded_http_body);


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
const json_key0_mask_hash = DataHasher(json_key0_mask);

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
const json_key1_mask_hash = DataHasher(json_key1_mask);

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
const json_arr_mask_hash = DataHasher(json_arr_mask);

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
const json_key2_mask_hash = DataHasher(json_key2_mask);

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
const json_key3_mask_hash = DataHasher(json_key3_mask);

describe("NIVC_FULL", async () => {
    let aesCircuit: WitnessTester<["key", "iv", "aad", "ctr", "plainText", "cipherText", "step_in"], ["step_out"]>;
    let chacha20Circuit: WitnessTester<["key", "nonce", "counter", "plainText", "cipherText", "step_in"], ["step_out"]>;
    let httpCircuit: WitnessTester<["step_in", "data", "start_line_hash", "header_hashes", "body_hash"], ["step_out"]>;
    let json_mask_object_circuit: WitnessTester<["step_in", "data", "key", "keyLen"], ["step_out"]>;
    let json_mask_arr_circuit: WitnessTester<["step_in", "data", "index"], ["step_out"]>;
    let extract_value_circuit: WitnessTester<["step_in", "data"], ["step_out"]>;

    const MAX_NUMBER_OF_HEADERS = 2;

    const DATA_BYTES = 320;
    const MAX_STACK_HEIGHT = 5;

    const MAX_KEY_LENGTH = 8;
    const MAX_VALUE_LENGTH = 32;

    before(async () => {
        aesCircuit = await circomkit.WitnessTester("AESGCTRFOLD", {
            file: "aes-gcm/nivc/aes-gctr-nivc",
            template: "AESGCTRFOLD",
            params: [1]
        });
        console.log("#constraints (AES):", await aesCircuit.getConstraintCount());

        chacha20Circuit = await circomkit.WitnessTester("CHACHA20", {
            file: "chacha20/nivc/chacha20_nivc",
            template: "ChaCha20_NIVC",
            params: [80] // 80 * 32 = 2560 bits / 8 = 320 bytes
        });
        console.log("#constraints (CHACHA20):", await chacha20Circuit.getConstraintCount());

        httpCircuit = await circomkit.WitnessTester(`HttpNIVC`, {
            file: "http/nivc/http_nivc",
            template: "HttpNIVC",
            params: [DATA_BYTES, MAX_NUMBER_OF_HEADERS],
        });
        console.log("#constraints (HttpNIVC):", await httpCircuit.getConstraintCount());

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

    it("NIVC_CHAIN", async () => {
        const init_nivc_input = 0;

        // This tests both AES and ChaCha20 right now but we will only one in practice.
        // Run AES chain
        let ctr = [0x00, 0x00, 0x00, 0x01];
        let pt = http_response_plaintext.slice(0, 16);
        let ct = aes_http_response_ciphertext.slice(0, 16);
        let aes_gcm = await aesCircuit.compute({ key: Array(16).fill(0), iv: Array(12).fill(0), ctr: ctr, plainText: pt, aad: Array(16).fill(0), cipherText: ct, step_in: init_nivc_input }, ["step_out"]);
        let i = 0;
        console.log("AES `step_out[", i, "]`: ", aes_gcm.step_out);
        for (i = 1; i < (DATA_BYTES / 16); i++) {
            ctr[3] += 1; // This will work since we don't run a test that overlows a byte
            let pt = http_response_plaintext.slice(i * 16, i * 16 + 16);
            let ct = aes_http_response_ciphertext.slice(i * 16, i * 16 + 16);
            aes_gcm = await aesCircuit.compute({ key: Array(16).fill(0), iv: Array(12).fill(0), ctr: ctr, plainText: pt, aad: Array(16).fill(0), cipherText: ct, step_in: aes_gcm.step_out }, ["step_out"]);
            console.log("AES `step_out[", i, "]`: ", aes_gcm.step_out);
        }
        assert.deepEqual(http_response_hash, aes_gcm.step_out);

        // Run ChaCha20
        const counterBits = uintArray32ToBits([1])[0]
        const ptIn = toInput(Buffer.from(http_response_plaintext));
        const ctIn = toInput(Buffer.from(chacha20_http_response_ciphertext));
        const keyIn = toInput(Buffer.from(Array(32).fill(0)));
        const nonceIn = toInput(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00]));
        let chacha20 = await chacha20Circuit.compute({ key: keyIn, nonce: nonceIn, counter: counterBits, plainText: ptIn, cipherText: ctIn, step_in: init_nivc_input }, ["step_out"]);
        console.log("ChaCha20 `step_out`:", chacha20.step_out);
        assert.deepEqual(http_response_hash, chacha20.step_out);

        assert.deepEqual(chacha20.step_out, aes_gcm.step_out);

        let http = await httpCircuit.compute({ step_in: chacha20.step_out, data: http_response_plaintext, start_line_hash: http_start_line_hash, header_hashes: [http_header_0_hash, http_header_1_hash], body_hash: http_body_mask_hash }, ["step_out"]);
        console.log("HttpNIVC `step_out`:", http.step_out);

        let key0 = [100, 97, 116, 97, 0, 0, 0, 0]; // "data"
        let key0Len = 4;
        let key1 = [105, 116, 101, 109, 115, 0, 0, 0]; // "items"
        let key1Len = 5;
        let key2 = [112, 114, 111, 102, 105, 108, 101, 0]; // "profile"
        let key2Len = 7;
        let key3 = [110, 97, 109, 101, 0, 0, 0, 0]; // "name"
        let key3Len = 4;

        let json_extract_key0 = await json_mask_object_circuit.compute({ step_in: http.step_out, data: http_body, key: key0, keyLen: key0Len }, ["step_out"]);
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
        let final_value_hash = DataHasher(finalOutputPadded);
        let extractValue = await extract_value_circuit.compute({ step_in: json_extract_key3.step_out, data: json_key3_mask }, ["step_out"]);
        console.log("finalValue", extractValue.step_out);
        assert.deepEqual(extractValue.step_out, final_value_hash);
    });
});


describe("NIVC_FULL_2", async () => {
    let aesCircuit: WitnessTester<["key", "iv", "aad", "ctr", "plainText", "cipherText", "step_in"], ["step_out"]>;
    let chacha20Circuit: WitnessTester<["key", "nonce", "counter", "plainText", "cipherText", "step_in"], ["step_out"]>;
    let httpCircuit: WitnessTester<["step_in", "data", "start_line_hash", "header_hashes", "body_hash"], ["step_out"]>;
    let json_mask_object_circuit: WitnessTester<["step_in", "data", "key", "keyLen"], ["step_out"]>;
    let json_mask_arr_circuit: WitnessTester<["step_in", "data", "index"], ["step_out"]>;
    let extract_value_circuit: WitnessTester<["step_in", "data"], ["step_out"]>;

    const MAX_NUMBER_OF_HEADERS = 2;

    const DATA_BYTES = 320;
    const MAX_STACK_HEIGHT = 5;

    const MAX_KEY_LENGTH = 8;
    const MAX_VALUE_LENGTH = 32;

    before(async () => {
        aesCircuit = await circomkit.WitnessTester("AESGCTRFOLD", {
            file: "aes-gcm/nivc/aes-gctr-nivc",
            template: "AESGCTRFOLD",
            params: [2]
        });
        console.log("#constraints (AES):", await aesCircuit.getConstraintCount());

        chacha20Circuit = await circomkit.WitnessTester("CHACHA20", {
            file: "chacha20/nivc/chacha20_nivc",
            template: "ChaCha20_NIVC",
            params: [80] // 80 * 32 = 2560 bits / 8 = 320 bytes
        });
        console.log("#constraints (CHACHA20):", await chacha20Circuit.getConstraintCount());

        httpCircuit = await circomkit.WitnessTester(`HttpNIVC`, {
            file: "http/nivc/http_nivc",
            template: "HttpNIVC",
            params: [DATA_BYTES, MAX_NUMBER_OF_HEADERS],
        });
        console.log("#constraints (HttpNIVC):", await httpCircuit.getConstraintCount());

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

    it("NIVC_CHAIN_2", async () => {
        const init_nivc_input = 0;

        // Run AES chain
        let ctr = [0x00, 0x00, 0x00, 0x01];
        let pt = [http_response_plaintext.slice(0, 16), http_response_plaintext.slice(16, 32)];
        let ct = [aes_http_response_ciphertext.slice(0, 16), aes_http_response_ciphertext.slice(16, 32)];
        let aes_gcm = await aesCircuit.compute({ key: Array(16).fill(0), iv: Array(12).fill(0), ctr: ctr, plainText: pt, aad: Array(16).fill(0), cipherText: ct, step_in: init_nivc_input }, ["step_out"]);
        let i = 0;
        console.log("AES `step_out[", i, "]`: ", aes_gcm.step_out);
        for (i = 1; i < (DATA_BYTES / (16 * 2)); i++) {
            ctr[3] += 2; // This will work since we don't run a test that overlows a byte
            let pt = [http_response_plaintext.slice(i * 32, i * 32 + 16), http_response_plaintext.slice(i * 32 + 16, i * 32 + 32)];
            let ct = [aes_http_response_ciphertext.slice(i * 32, i * 32 + 16), aes_http_response_ciphertext.slice(i * 32 + 16, i * 32 + 32)];
            aes_gcm = await aesCircuit.compute({ key: Array(16).fill(0), iv: Array(12).fill(0), ctr: ctr, plainText: pt, aad: Array(16).fill(0), cipherText: ct, step_in: aes_gcm.step_out }, ["step_out"]);
            console.log("AES `step_out[", i, "]`: ", aes_gcm.step_out);
        }
        assert.deepEqual(http_response_hash, aes_gcm.step_out);

        // Run ChaCha20
        const counterBits = uintArray32ToBits([1])[0]
        const ptIn = toInput(Buffer.from(http_response_plaintext));
        const ctIn = toInput(Buffer.from(chacha20_http_response_ciphertext));
        const keyIn = toInput(Buffer.from(Array(32).fill(0)));
        const nonceIn = toInput(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00]));

        let chacha20 = await chacha20Circuit.compute({ key: keyIn, nonce: nonceIn, counter: counterBits, plainText: ptIn, cipherText: ctIn, step_in: init_nivc_input }, ["step_out"]);
        console.log("ChaCha20 `step_out`:", chacha20.step_out);
        assert.deepEqual(http_response_hash, chacha20.step_out);

        assert.deepEqual(chacha20.step_out, aes_gcm.step_out);

        let http = await httpCircuit.compute({ step_in: chacha20.step_out, data: http_response_plaintext, start_line_hash: http_start_line_hash, header_hashes: [http_header_0_hash, http_header_1_hash], body_hash: http_body_mask_hash }, ["step_out"]);
        console.log("HttpNIVC `step_out`:", http.step_out);

        let key0 = [100, 97, 116, 97, 0, 0, 0, 0]; // "data"
        let key0Len = 4;
        let key1 = [105, 116, 101, 109, 115, 0, 0, 0]; // "items"
        let key1Len = 5;
        let key2 = [112, 114, 111, 102, 105, 108, 101, 0]; // "profile"
        let key2Len = 7;
        let key3 = [110, 97, 109, 101, 0, 0, 0, 0]; // "name"
        let key3Len = 4;

        let json_extract_key0 = await json_mask_object_circuit.compute({ step_in: http.step_out, data: http_body, key: key0, keyLen: key0Len }, ["step_out"]);
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
        let final_value_hash = DataHasher(finalOutputPadded);
        let extractValue = await extract_value_circuit.compute({ step_in: json_extract_key3.step_out, data: json_key3_mask }, ["step_out"]);
        console.log("finalValue", extractValue.step_out);
        assert.deepEqual(extractValue.step_out, final_value_hash);
    });
});




