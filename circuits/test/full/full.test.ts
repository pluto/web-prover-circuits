import { assert } from "chai";
import { circomkit, WitnessTester, toByte, uintArray32ToBits, http_response_plaintext, chacha20_http_response_ciphertext, http_start_line, http_header_0, http_header_1, http_body, PolynomialDigest } from "../common";
import { DataHasher } from "../common/poseidon";
import { toInput } from "../chacha20/chacha20-nivc.test";

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

// Concatenate the padding with http_body
const http_response_hash = DataHasher(http_response_plaintext);
const start_line_digest = PolynomialDigest(http_start_line, http_response_hash);
const header_0_digest = PolynomialDigest(http_header_0, http_response_hash);
const header_1_digest = PolynomialDigest(http_header_1, http_response_hash);

// TODO: The consts below can probably be gotten rid of soon, needed for relic JSON
const padded_http_body = [
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

describe("Example NIVC Proof", async () => {
    let PlaintextAuthentication: WitnessTester<["key", "nonce", "counter", "plainText", "step_in"], ["step_out"]>;
    let HTTPVerification: WitnessTester<["step_in", "data", "main_digests"], ["step_out"]>;

    const MAX_NUMBER_OF_HEADERS = 2;
    const DATA_BYTES = 320;
    const MAX_STACK_HEIGHT = 5;
    const MAX_KEY_LENGTH = 8;
    const MAX_VALUE_LENGTH = 32;

    before(async () => {
        PlaintextAuthentication = await circomkit.WitnessTester("CHACHA20", {
            file: "chacha20/nivc/chacha20_nivc",
            template: "ChaCha20_NIVC",
            params: [320]
        });
        console.log("#constraints (PlaintextAuthentication):", await PlaintextAuthentication.getConstraintCount());

        HTTPVerification = await circomkit.WitnessTester(`HttpNIVC`, {
            file: "http/verification",
            template: "HTTPVerification",
            params: [DATA_BYTES, MAX_NUMBER_OF_HEADERS],
        });
        console.log("#constraints (HTTPVerification):", await HTTPVerification.getConstraintCount());

    });

    it("Spotify Example", async () => {
        const init_nivc_input = DataHasher(chacha20_http_response_ciphertext);
        // Run ChaCha20
        const counterBits = uintArray32ToBits([1])[0]
        const keyIn = toInput(Buffer.from(Array(32).fill(0)));
        const nonceIn = toInput(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00]));
        let chacha20 = await PlaintextAuthentication.compute({ key: keyIn, nonce: nonceIn, counter: counterBits, plainText: http_response_plaintext, step_in: init_nivc_input }, ["step_out"]);
        console.log("ChaCha20 `step_out`:", chacha20.step_out);
        assert.deepEqual(http_response_hash, chacha20.step_out);

        let http = await HTTPVerification.compute({
            step_in: chacha20.step_out,
            data: http_response_plaintext,
            main_digests: [start_line_digest, header_0_digest, header_1_digest],
        }, ["step_out"]);
        console.log("HttpNIVC `step_out`:", http.step_out);

        let key0 = [100, 97, 116, 97, 0, 0, 0, 0]; // "data"
        let key0Len = 4;
        let key1 = [105, 116, 101, 109, 115, 0, 0, 0]; // "items"
        let key1Len = 5;
        let key2 = [112, 114, 111, 102, 105, 108, 101, 0]; // "profile"
        let key2Len = 7;
        let key3 = [110, 97, 109, 101, 0, 0, 0, 0]; // "name"
        let key3Len = 4;
        // (autoparallel) This next line gives me an aneurysm
        let http_step_out = (http.step_out as number[])[0];
        // let json_extract_key0 = await json_mask_object_circuit.compute({ step_in: http_step_out, data: padded_http_body, key: key0, keyLen: key0Len }, ["step_out"]);
        // console.log("JSON Extract key0 `step_out`:", json_extract_key0.step_out);
        // assert.deepEqual(json_extract_key0.step_out, json_key0_mask_hash);

        // let json_extract_key1 = await json_mask_object_circuit.compute({ step_in: json_extract_key0.step_out, data: json_key0_mask, key: key1, keyLen: key1Len }, ["step_out"]);
        // assert.deepEqual(json_extract_key1.step_out, json_key1_mask_hash);
        // console.log("JSON Extract key1 `step_out`:", json_extract_key1.step_out);

        // let json_extract_arr = await json_mask_arr_circuit.compute({ step_in: json_extract_key1.step_out, data: json_key1_mask, index: 0 }, ["step_out"]);
        // assert.deepEqual(json_extract_arr.step_out, json_arr_mask_hash);
        // console.log("JSON Extract arr `step_out`:", json_extract_arr.step_out);

        // let json_extract_key2 = await json_mask_object_circuit.compute({ step_in: json_extract_arr.step_out, data: json_arr_mask, key: key2, keyLen: key2Len }, ["step_out"]);
        // assert.deepEqual(json_extract_key2.step_out, json_key2_mask_hash);
        // console.log("JSON Extract key2 `step_out`:", json_extract_key2.step_out);

        // let json_extract_key3 = await json_mask_object_circuit.compute({ step_in: json_extract_key2.step_out, data: json_key2_mask, key: key3, keyLen: key3Len }, ["step_out"]);
        // assert.deepEqual(json_extract_key3.step_out, json_key3_mask_hash);
        // console.log("JSON Extract key3 `step_out`:", json_extract_key3.step_out);

        // // TODO (autoparallel): we need to rethink extraction here.
        // let finalOutput = toByte("\"Taylor Swift\"");
        // let finalOutputPadded = finalOutput.concat(Array(Math.max(0, MAX_VALUE_LENGTH - finalOutput.length)).fill(0));
        // let final_value_hash = DataHasher(finalOutputPadded);
        // let extractValue = await extract_value_circuit.compute({ step_in: json_extract_key3.step_out, data: json_key3_mask }, ["step_out"]);
        // console.log("finalValue", extractValue.step_out);
        // assert.deepEqual(extractValue.step_out, final_value_hash);
    });
});
