import { assert } from "chai";
import { circomkit, WitnessTester, uintArray32ToBits, http_response_plaintext, http_response_ciphertext, http_start_line, http_header_0, http_header_1, http_body, PolynomialDigest, strToBytes, JsonMaskType, jsonTreeHasher, compressTreeHash, modAdd, InitialDigest, MockManifest, http_response_ciphertext_dup, PUBLIC_IO_VARIABLES, modPow } from "../common";
import { test_case, TestCaseManifest } from "./testCase.test";

import { toInput } from "../chacha20/authentication.test";
import { poseidon1 } from "poseidon-lite";
import { DataHasher } from "../common/poseidon";

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

const DATA_BYTES = 1024;
const MAX_NUMBER_OF_HEADERS = 25;
const MAX_STACK_HEIGHT = 10;

// These `check_*` are currently from Rust to ensure we have parity
const check_ciphertext_digest = BigInt("5947802862726868637928743536818722886587721698845887498686185738472802646104");
const check_ciphertext_digest_dup = BigInt(
    "9719560477146706366275627147615553588605800736547946825367443581777188004918"
);
const check_init_nivc_input = BigInt("10288873638660630335427615297930270928433661836597941144520949467184902553219");

function to_nonce(iv: Uint8Array, seq: number): Uint8Array {
    let nonce = new Uint8Array(12);
    nonce.fill(0);

    //   nonce[4..].copy_from_slice(&seq.to_be_bytes());
    const seqBytes = new Uint8Array(new BigUint64Array([BigInt(seq)]).buffer).reverse();
    nonce.set(seqBytes, 4);

    nonce.forEach((_, i) => {
        nonce[i] ^= iv[i];
    });

    return nonce;
}

describe("Example NIVC Proof", async () => {
    let PlaintextAuthentication: WitnessTester<["step_in", "plaintext", "key", "nonce", "counter", "ciphertext_digest"], ["step_out"]>;
    let HTTPVerification: WitnessTester<["step_in", "ciphertext_digest", "machine_state", "data", "main_digests"], ["step_out"]>;
    let JSONExtraction: WitnessTester<["step_in", "ciphertext_digest", "data", "sequence_digest", "value_digest", "state"], ["step_out"]>;

    before(async () => {
        PlaintextAuthentication = await circomkit.WitnessTester("PlaintextAuthentication", {
            file: "chacha20/authentication",
            template: "PlaintextAuthentication",
            params: [DATA_BYTES, PUBLIC_IO_VARIABLES]
        });

        HTTPVerification = await circomkit.WitnessTester("HTTPVerification", {
            file: "http/verification",
            template: "HTTPVerification",
            params: [DATA_BYTES, MAX_NUMBER_OF_HEADERS, PUBLIC_IO_VARIABLES],
        });

        JSONExtraction = await circomkit.WitnessTester(`JSONExtraction`, {
            file: "json/extraction",
            template: "JSONExtraction",
            params: [DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_VARIABLES],
        });
    });

    it("Spotify Example", async () => {
        // Run PlaintextAuthentication

        let http_response_padded = http_response_plaintext.concat(Array(DATA_BYTES - http_response_plaintext.length).fill(-1));
        let http_response_0_padded = http_response_plaintext.concat(Array(DATA_BYTES - http_start_line.length).fill(0));
        let ciphertext_padded = http_response_ciphertext.concat(Array(DATA_BYTES - http_response_ciphertext.length).fill(-1));


        const [ciphertext_digest, init_nivc_input] = InitialDigest(MockManifest(), [ciphertext_padded], MAX_STACK_HEIGHT);
        assert.deepEqual(ciphertext_digest, check_ciphertext_digest);

        const counterBits = uintArray32ToBits([1])[0]
        const keyIn = toInput(Buffer.from(Array(32).fill(0)));
        const nonceIn = toInput(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00]));
        let plaintext_authentication = await PlaintextAuthentication.compute({
            step_in: init_nivc_input,
            plaintext: http_response_padded,
            key: keyIn,
            nonce: nonceIn,
            counter: counterBits,
            ciphertext_digest,
        }, ["step_out"]);
        let plaintext_authentication_step_out = plaintext_authentication.step_out as bigint[];

        const plaintext_digest = PolynomialDigest(http_response_0_padded, ciphertext_digest, BigInt(0));
        const correct_plaintext_authentication_step_out = modAdd(init_nivc_input[0] - ciphertext_digest, plaintext_digest);
        assert.deepEqual(plaintext_authentication_step_out[0], correct_plaintext_authentication_step_out);
        assert.deepEqual(plaintext_authentication_step_out[1], modPow(ciphertext_digest, BigInt(http_response_plaintext.length)));

        // Run HTTPVerification
        let machine_state = Array(8).fill(0);
        machine_state[0] = 1; // Sets the parsing start to 1

        const start_line_digest = PolynomialDigest(http_start_line, ciphertext_digest, BigInt(0));
        const header_0_digest = PolynomialDigest(http_header_0, ciphertext_digest, BigInt(0));
        const header_1_digest = PolynomialDigest(http_header_1, ciphertext_digest, BigInt(0));

        let main_digests = Array(MAX_NUMBER_OF_HEADERS + 1).fill(0);
        main_digests[0] = start_line_digest;
        main_digests[1] = header_0_digest;
        main_digests[2] = header_1_digest;

        let http_verification = await HTTPVerification.compute({
            step_in: plaintext_authentication_step_out,
            ciphertext_digest,
            data: http_response_padded,
            main_digests,
            machine_state,
        }, ["step_out"]);

        let http_verification_step_out = http_verification.step_out as bigint[];
        http_verification_step_out = http_verification_step_out.slice(0, PUBLIC_IO_VARIABLES);
        let body_digest = PolynomialDigest(http_body, ciphertext_digest, BigInt(0));

        const start_line_digest_digest_hashed = poseidon1([start_line_digest]);
        const header_0_digest_hashed = poseidon1([header_0_digest]);
        const header_1_digest_hashed = poseidon1([header_1_digest]);

        assert.deepEqual(http_verification_step_out[0], modAdd(correct_plaintext_authentication_step_out - plaintext_digest, body_digest));
        assert.deepEqual(http_verification_step_out[2], modPow(ciphertext_digest, BigInt(http_response_plaintext.length)));
        assert.deepEqual(http_verification_step_out[4], modAdd(start_line_digest_digest_hashed, header_0_digest_hashed + header_1_digest_hashed));
        assert.deepEqual(http_verification_step_out[5], BigInt(0));

        // Run JSONExtraction
        const KEY0 = strToBytes("data");
        const KEY1 = strToBytes("items");
        const KEY2 = strToBytes("profile");
        const KEY3 = strToBytes("name");
        const targetValue = strToBytes("Taylor Swift");
        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
            { type: "Object", value: KEY1 },
            { type: "ArrayIndex", value: 0 },
            { type: "Object", value: KEY2 },
            { type: "Object", value: KEY3 },
        ];

        let state = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);

        const padded_http_body = http_body.concat(Array(DATA_BYTES - http_body.length).fill(-1));
        const [stack, treeHashes] = jsonTreeHasher(ciphertext_digest, keySequence, MAX_STACK_HEIGHT);
        const sequence_digest = compressTreeHash(ciphertext_digest, [stack, treeHashes]);
        const value_digest = PolynomialDigest(targetValue, ciphertext_digest, BigInt(0));

        let json_extraction = await JSONExtraction.compute({
            step_in: http_verification_step_out,
            ciphertext_digest,
            data: padded_http_body,
            value_digest,
            sequence_digest,
            state,
        }, ["step_out"]);
        let json_extraction_step_out = json_extraction.step_out as bigint[];
        assert.deepEqual(json_extraction_step_out[0], value_digest);
        assert.deepEqual(json_extraction_step_out[7], modPow(ciphertext_digest, BigInt(http_body.length)));
        assert.deepEqual(json_extraction_step_out[9], poseidon1([sequence_digest]));
    });

    it("multiple ciphertext packets", async () => {
        // Run PlaintextAuthentication

        assert.deepEqual(http_response_ciphertext.length / 2, http_response_ciphertext_dup.length);

        let [http_response_plaintext_1, http_response_plaintext_2] = [http_response_plaintext.slice(0, http_response_plaintext.length / 2), http_response_plaintext.slice(http_response_plaintext.length / 2)];
        let http_response_ciphertext_1 = http_response_ciphertext.slice(0, http_response_ciphertext.length / 2);
        let http_response_ciphertext_2 = http_response_ciphertext_dup;

        let http_response_padded = http_response_plaintext.concat(Array(DATA_BYTES - http_response_plaintext.length).fill(-1));
        let http_response1_padded = http_response_plaintext_1.concat(Array(DATA_BYTES - http_response_plaintext_1.length).fill(-1));
        let http_response1_0_padded = http_response_plaintext_1.concat(Array(DATA_BYTES - http_response_plaintext_1.length).fill(0));
        let http_response2_padded = http_response_plaintext_2.concat(Array(DATA_BYTES - http_response_plaintext_2.length).fill(-1));
        let http_response2_0_padded = http_response_plaintext_2.concat(Array(DATA_BYTES - http_response_plaintext_2.length).fill(0));
        let ciphertext1_padded = http_response_ciphertext_1.concat(Array(DATA_BYTES - http_response_ciphertext_1.length).fill(-1));
        let ciphertext2_padded = http_response_ciphertext_2.concat(Array(DATA_BYTES - http_response_ciphertext_2.length).fill(-1));

        const [ciphertext_digest, init_nivc_input] = InitialDigest(MockManifest(), [ciphertext1_padded, ciphertext2_padded], MAX_STACK_HEIGHT);

        let pt11Digest = PolynomialDigest(http_response1_0_padded, ciphertext_digest, BigInt(0));
        let pt21Digest = PolynomialDigest(http_response2_0_padded, ciphertext_digest, BigInt(http_response_plaintext_1.length));
        let ptDigest = PolynomialDigest(http_response_plaintext, ciphertext_digest, BigInt(0));
        assert.deepEqual(modAdd(pt11Digest, pt21Digest), ptDigest);

        const counterBits = uintArray32ToBits([1])[0];
        const keyIn = toInput(Buffer.from(Array(32).fill(0)));
        const nonceIn = toInput(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00]));
        let plaintext_authentication1 = await PlaintextAuthentication.compute({
            step_in: init_nivc_input,
            plaintext: http_response1_padded,
            key: keyIn,
            nonce: nonceIn,
            counter: counterBits,
            ciphertext_digest,
        }, ["step_out"]);
        let plaintext_authentication1_step_out = plaintext_authentication1.step_out as bigint[];

        let pt1Digest = PolynomialDigest(http_response1_0_padded, ciphertext_digest, BigInt(0));
        let ct1Digest = DataHasher(ciphertext1_padded, BigInt(0));
        assert.deepEqual(plaintext_authentication1_step_out[0], modAdd(init_nivc_input[0] - ct1Digest, pt1Digest));

        const nonceIn2 = toInput(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x01]));
        let plaintext_authentication2 = await PlaintextAuthentication.compute({
            step_in: plaintext_authentication1_step_out,
            plaintext: http_response2_padded,
            key: keyIn,
            nonce: nonceIn2,
            counter: counterBits,
            ciphertext_digest,
        }, ["step_out"]);
        let plaintext_authentication2_step_out = plaintext_authentication2.step_out as bigint[];
        assert.deepEqual(plaintext_authentication2_step_out[0], modAdd(init_nivc_input[0], ptDigest - ciphertext_digest));

        // Run HTTPVerification
        let machine_state = Array(8).fill(0);
        machine_state[0] = 1; // Sets the parsing start to 1

        const start_line_digest = PolynomialDigest(http_start_line, ciphertext_digest, BigInt(0));
        const header_0_digest = PolynomialDigest(http_header_0, ciphertext_digest, BigInt(0));
        const header_1_digest = PolynomialDigest(http_header_1, ciphertext_digest, BigInt(0));

        let main_digests = Array(MAX_NUMBER_OF_HEADERS + 1).fill(0);
        main_digests[0] = start_line_digest;
        main_digests[1] = header_0_digest;
        main_digests[2] = header_1_digest;

        let http_verification = await HTTPVerification.compute({
            step_in: plaintext_authentication2_step_out,
            ciphertext_digest,
            data: http_response_padded,
            main_digests,
            machine_state,
        }, ["step_out"]);

        let http_verification_step_out = http_verification.step_out as bigint[];
        http_verification_step_out = http_verification_step_out.slice(0, PUBLIC_IO_VARIABLES);
        let bodyDigest = PolynomialDigest(http_body, ciphertext_digest, BigInt(0));
        const start_line_digest_digest_hashed = poseidon1([start_line_digest]);
        const header_0_digest_hashed = poseidon1([header_0_digest]);
        const header_1_digest_hashed = poseidon1([header_1_digest]);

        assert.deepEqual(http_verification_step_out[0], modAdd(plaintext_authentication2_step_out[0] - ptDigest, bodyDigest));
        assert.deepEqual(http_verification_step_out[2], modPow(ciphertext_digest, BigInt(http_response_plaintext.length)));
        assert.deepEqual(http_verification_step_out[4], modAdd(start_line_digest_digest_hashed, header_0_digest_hashed + header_1_digest_hashed));
        assert.deepEqual(http_verification_step_out[5], BigInt(0));

        // Run JSONExtraction
        const KEY0 = strToBytes("data");
        const KEY1 = strToBytes("items");
        const KEY2 = strToBytes("profile");
        const KEY3 = strToBytes("name");
        const targetValue = strToBytes("Taylor Swift");
        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
            { type: "Object", value: KEY1 },
            { type: "ArrayIndex", value: 0 },
            { type: "Object", value: KEY2 },
            { type: "Object", value: KEY3 },
        ];

        const padded_http_body = http_body.concat(Array(DATA_BYTES - http_body.length).fill(-1));
        let state = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);
        const [stack, treeHashes] = jsonTreeHasher(ciphertext_digest, keySequence, MAX_STACK_HEIGHT);
        const sequence_digest = compressTreeHash(ciphertext_digest, [stack, treeHashes]);
        const value_digest = PolynomialDigest(targetValue, ciphertext_digest, BigInt(0));

        let json_extraction = await JSONExtraction.compute({
            step_in: http_verification_step_out,
            ciphertext_digest,
            data: padded_http_body,
            value_digest,
            sequence_digest,
            state,
        }, ["step_out"]);

        let json_extraction_step_out = json_extraction.step_out as bigint[];
        assert.deepEqual(json_extraction_step_out[0], value_digest);
        assert.deepEqual(json_extraction_step_out[7], modPow(ciphertext_digest, BigInt(http_body.length)));
        assert.deepEqual(json_extraction_step_out[9], poseidon1([sequence_digest]));
    });

    it("github example", async () => {

        let http_response_plaintext = test_case.plaintext;
        let http_response_ciphertext = test_case.ciphertext;
        let key = test_case.key;
        let iv = test_case.iv;
        let manifest = TestCaseManifest();

        let http_response_combined = http_response_plaintext[0].concat(http_response_plaintext[1]);
        let http_response_padded = http_response_combined.concat(Array(DATA_BYTES - http_response_combined.length).fill(-1));

        let http_response1_padded = http_response_plaintext[0].concat(Array(DATA_BYTES - http_response_plaintext[0].length).fill(-1));
        let http_response1_0_padded = http_response_plaintext[0].concat(Array(DATA_BYTES - http_response_plaintext[0].length).fill(0));
        let http_response2_padded = http_response_plaintext[1].concat(Array(DATA_BYTES - http_response_plaintext[1].length).fill(-1));
        let http_response2_0_padded = http_response_plaintext[1].concat(Array(DATA_BYTES - http_response_plaintext[1].length).fill(0));
        let ciphertext1_padded = http_response_ciphertext[0].concat(Array(DATA_BYTES - http_response_ciphertext[0].length).fill(-1));
        let ciphertext2_padded = http_response_ciphertext[1].concat(Array(DATA_BYTES - http_response_ciphertext[1].length).fill(-1));

        const [ciphertext_digest, init_nivc_input] = InitialDigest(manifest, [ciphertext1_padded, ciphertext2_padded], MAX_STACK_HEIGHT);

        let ptDigest = PolynomialDigest(http_response_combined, ciphertext_digest, BigInt(0));

        const counterBits = uintArray32ToBits([1])[0];
        const keyIn = toInput(Buffer.from(key));
        let nonce1 = to_nonce(Uint8Array.from(iv), 1);
        const nonceIn = toInput(Buffer.from(nonce1));
        let plaintext_authentication1 = await PlaintextAuthentication.compute({
            step_in: init_nivc_input,
            plaintext: http_response1_padded,
            key: keyIn,
            nonce: nonceIn,
            counter: counterBits,
            ciphertext_digest,
        }, ["step_out"]);
        let plaintext_authentication1_step_out = plaintext_authentication1.step_out as bigint[];

        let pt1Digest = PolynomialDigest(http_response1_0_padded, ciphertext_digest, BigInt(0));
        let ct1Digest = DataHasher(ciphertext1_padded, BigInt(0));
        assert.deepEqual(plaintext_authentication1_step_out[0], modAdd(init_nivc_input[0] - ct1Digest, pt1Digest));

        let nonce2 = to_nonce(Uint8Array.from(iv), 2);
        const nonceIn2 = toInput(Buffer.from(nonce2));
        let plaintext_authentication2 = await PlaintextAuthentication.compute({
            step_in: plaintext_authentication1.step_out,
            plaintext: http_response2_padded,
            key: keyIn,
            nonce: nonceIn2,
            counter: counterBits,
            ciphertext_digest,
        }, ["step_out"]);
        let plaintext_authentication2_step_out = plaintext_authentication2.step_out as bigint[];
        assert.deepEqual(plaintext_authentication2_step_out[0], modAdd(init_nivc_input[0], ptDigest - ciphertext_digest));

        // Run HTTPVerification
        const start_line_digest = PolynomialDigest(http_start_line, ciphertext_digest, BigInt(0));
        let header_0 = test_case.header_0;
        const header_0_digest = PolynomialDigest(header_0, ciphertext_digest, BigInt(0));

        let main_digests = Array(MAX_NUMBER_OF_HEADERS + 1).fill(0);
        main_digests[0] = start_line_digest;
        main_digests[1] = header_0_digest;
        let machine_state = Array(8).fill(0);
        machine_state[0] = 1; // Sets the parsing start to 1

        let http_verification1 = await HTTPVerification.compute({
            step_in: plaintext_authentication2_step_out,
            ciphertext_digest,
            data: http_response1_padded,
            main_digests,
            machine_state,
        }, ["step_out"]);
        let http_verification1_step_out = (http_verification1.step_out as bigint[]).slice(0, PUBLIC_IO_VARIABLES);
        assert.deepEqual(http_verification1_step_out[0], modAdd(init_nivc_input[0] - ciphertext_digest, ptDigest - pt1Digest));
        assert.deepEqual(http_verification1_step_out[5], BigInt(0)); // all matched
        assert.deepEqual(http_verification1_step_out[6], BigInt(0)); // body doesn't start yet

        machine_state = [0, 0, 0, 0, 1, 0, 0, 0];
        let bodyDigest = PolynomialDigest(http_response2_0_padded, ciphertext_digest, BigInt(0));
        console.log("bodyDigest", bodyDigest);

        let http_verification2 = await HTTPVerification.compute({
            step_in: http_verification1_step_out,
            ciphertext_digest,
            data: http_response2_padded,
            main_digests,
            machine_state,
        }, ["step_out"]);
        let http_verification2_step_out = (http_verification2.step_out as bigint[]).slice(0, PUBLIC_IO_VARIABLES);
        assert.deepEqual(http_verification2_step_out[0], modAdd(init_nivc_input[0] - ciphertext_digest, bodyDigest));
        assert.deepEqual(http_verification2_step_out[5], BigInt(0)); // all matched
        assert.deepEqual(http_verification2_step_out[6], BigInt(http_response_plaintext[1].length)); // body doesn't start yet

        // Run JSONExtraction
        const KEY0 = strToBytes("hello");
        const targetValue = strToBytes("world");
        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
        ];

        let state = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);

        const [stack, treeHashes] = jsonTreeHasher(ciphertext_digest, keySequence, MAX_STACK_HEIGHT);
        const sequence_digest = compressTreeHash(ciphertext_digest, [stack, treeHashes]);
        const value_digest = PolynomialDigest(targetValue, ciphertext_digest, BigInt(0));

        let json_extraction = await JSONExtraction.compute({
            step_in: http_verification2_step_out,
            ciphertext_digest,
            data: http_response2_padded,
            value_digest,
            sequence_digest,
            state,
        }, ["step_out"]);
        let json_extraction_step_out = json_extraction.step_out as bigint[];
        assert.deepEqual(json_extraction_step_out[0], value_digest);
        assert.deepEqual(json_extraction_step_out[7], modPow(ciphertext_digest, BigInt(http_response_plaintext[1].length)));
        assert.deepEqual(json_extraction_step_out[9], poseidon1([sequence_digest]));
    });

    // TODO: add a 3 iteration test
    it("3 iterations", async () => {
    });
});
