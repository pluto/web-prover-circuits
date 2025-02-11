import { assert } from "chai";
import { circomkit, WitnessTester, uintArray32ToBits, http_response_plaintext, http_response_ciphertext, http_start_line, http_header_0, http_header_1, http_body, PolynomialDigest, strToBytes, JsonMaskType, jsonTreeHasher, compressTreeHash, modAdd, InitialDigest, MockManifest, http_response_ciphertext_dup, PUBLIC_IO_VARIABLES, modPow, CombinedInitialDigest, findBodyIndex } from "../common";
import { CombinedTestCaseManifest, reddit_test_case, RedditTestCaseManifest, test_case, test_case_combined, TestCaseManifest } from "./testCase.test";
import { to_nonce as toNonce } from "../common/chacha";
import { toInput } from "../chacha20/authentication.test";
import { poseidon1 } from "poseidon-lite";
import { DataHasher } from "../common/poseidon";
import { defaultHttpMachineState } from "../common/http";

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
        let [machine_state, machine_state_digest] = defaultHttpMachineState(ciphertext_digest);

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

        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);

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
        let [machine_state, machine_state_digest] = defaultHttpMachineState(ciphertext_digest);

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
        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
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
        let nonce1 = toNonce(Uint8Array.from(iv), 1);
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

        let nonce2 = toNonce(Uint8Array.from(iv), 2);
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
        let [machine_state, machine_state_digest] = defaultHttpMachineState(ciphertext_digest);

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
        assert.deepEqual(http_verification2_step_out[6], modPow(ciphertext_digest, BigInt(http_response_plaintext[1].length - 1))); // body doesn't start yet

        // Run JSONExtraction
        const KEY0 = strToBytes("hello");
        const targetValue = strToBytes("world");
        const keySequence: JsonMaskType[] = [
            { type: "Object", value: KEY0 },
        ];

        let state = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);

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

    it("combined request and response", async () => {
        let request = test_case_combined.request;
        let response = test_case_combined.response;
        let manifest = CombinedTestCaseManifest();

        let requestCiphertextPadded: number[][] = [];
        request.ciphertext.forEach((ciphertext) => {
            requestCiphertextPadded.push(ciphertext.concat(Array(DATA_BYTES - ciphertext.length).fill(-1)));
        });
        let responseCiphertextPadded: number[][] = [];
        response.ciphertext.forEach((ciphertext) => {
            responseCiphertextPadded.push(ciphertext.concat(Array(DATA_BYTES - ciphertext.length).fill(-1)));
        });

        const [ciphertext_digest, init_nivc_input, allDigests] = CombinedInitialDigest(manifest, requestCiphertextPadded, responseCiphertextPadded, MAX_STACK_HEIGHT);

        let request_plaintext_packets_length = request.plaintext.length;
        let prevCtDigest = BigInt(0);
        let ptLengthSoFar = 0;
        let plaintextAuthenticationStepIn: bigint[] = init_nivc_input;
        let plaintextAuthenticationStepOut: bigint[] = [];
        for (var i = 0; i < request_plaintext_packets_length; i++) {
            let plaintext = request.plaintext[i];
            let plaintextPadded = plaintext.concat(Array(DATA_BYTES - plaintext.length).fill(-1));
            let ciphertext = request.ciphertext[i];

            const counterBits = uintArray32ToBits([1])[0];
            const keyIn = toInput(Buffer.from(request.key));
            let nonce = toNonce(Uint8Array.from(request.iv), i);
            const nonceIn = toInput(Buffer.from(nonce));
            let plaintextAuthentication = await PlaintextAuthentication.compute({
                step_in: plaintextAuthenticationStepIn,
                plaintext: plaintextPadded,
                key: keyIn,
                nonce: nonceIn,
                counter: counterBits,
                ciphertext_digest,
            }, ["step_out"]);
            plaintextAuthenticationStepOut = plaintextAuthentication.step_out as bigint[];

            let ptLength = ptLengthSoFar + plaintext.length;
            assert.deepEqual(plaintextAuthenticationStepOut[1], modPow(ciphertext_digest, BigInt(ptLength)));

            let ptDigest = PolynomialDigest(plaintext, ciphertext_digest, BigInt(ptLengthSoFar));
            prevCtDigest = DataHasher(ciphertext, prevCtDigest);
            let expectedGlobalVariable = modAdd(plaintextAuthenticationStepIn[0] - prevCtDigest, ptDigest, plaintextAuthenticationStepIn[10]);
            assert.deepEqual(plaintextAuthenticationStepOut[0], expectedGlobalVariable);

            plaintextAuthenticationStepIn = plaintextAuthenticationStepOut;
            ptLengthSoFar = ptLength;
        }

        let requestPlaintextCombined: number[] = [];
        request.plaintext.forEach((plaintext) => {
            requestPlaintextCombined = requestPlaintextCombined.concat(plaintext);
        });
        let ciphertextCombined: number[] = [];
        request.ciphertext.forEach((ciphertext) => {
            ciphertextCombined = ciphertextCombined.concat(ciphertext);
        });
        let circuitCount = Math.ceil(requestPlaintextCombined.length / DATA_BYTES);

        let plaintextDigest = PolynomialDigest(requestPlaintextCombined, ciphertext_digest, BigInt(0));

        let requestCiphertextDigest = BigInt(0);
        request.ciphertext.forEach((ciphertext) => {
            requestCiphertextDigest = DataHasher(ciphertext, requestCiphertextDigest);
        });

        assert.deepEqual(plaintextAuthenticationStepOut[0], modAdd(init_nivc_input[0] - requestCiphertextDigest, plaintextDigest));

        // Run HTTPVerification
        let [machineState, machine_state_digest] = defaultHttpMachineState(ciphertext_digest);
        let machineState2 = [0, 0, 0, 0, 1, 0, 0, 0];
        let machineStates = [machineState, machineState2];
        let prevBodyCounter = BigInt(0);

        let httpVerificationStepIn: bigint[] = plaintextAuthenticationStepOut;
        let httpVerificationStepOut: bigint[] = [];
        let mainDigests = allDigests.concat(Array(MAX_NUMBER_OF_HEADERS + 1 - allDigests.length).fill(0));
        for (var i = 0; i < circuitCount; i++) {
            let plaintext = requestPlaintextCombined.slice(i * DATA_BYTES, (i + 1) * DATA_BYTES);
            let plaintextPadded = plaintext.concat(Array(DATA_BYTES - plaintext.length).fill(-1));

            let httpVerification = await HTTPVerification.compute({
                step_in: httpVerificationStepIn,
                ciphertext_digest,
                data: plaintextPadded,
                main_digests: mainDigests,
                machine_state: machineStates[i],
            }, ["step_out"]);
            httpVerificationStepOut = (httpVerification.step_out as bigint[]).slice(0, PUBLIC_IO_VARIABLES);

            let bodyIndex = findBodyIndex(plaintext);
            if (bodyIndex < 0) {
                bodyIndex = 0;
            }

            let bodyDigest = PolynomialDigest(plaintext.slice(bodyIndex), ciphertext_digest, prevBodyCounter);
            let ptDigest = PolynomialDigest(plaintext, ciphertext_digest, BigInt(i * DATA_BYTES));
            assert.deepEqual(httpVerificationStepOut[0], modAdd(httpVerificationStepIn[0] - ptDigest, bodyDigest));

            prevBodyCounter += BigInt(plaintext.length - bodyIndex);
            httpVerificationStepIn = httpVerificationStepOut;
        }

        let allDigestHashed = BigInt(0);
        allDigests.forEach((digest) => {
            if (digest === BigInt(0)) {
                return;
            }
            allDigestHashed = modAdd(allDigestHashed, poseidon1([digest]));
        });

        let bodyIndex = requestPlaintextCombined.length - Number(prevBodyCounter);
        let requestBody = requestPlaintextCombined.slice(bodyIndex);

        let requestBodyDigest = PolynomialDigest(requestBody, ciphertext_digest, BigInt(0));
        assert.deepEqual(httpVerificationStepOut[0], modAdd(plaintextAuthenticationStepOut[0] - plaintextDigest, requestBodyDigest));
        assert.deepEqual(httpVerificationStepOut[2], modPow(ciphertext_digest, BigInt(requestPlaintextCombined.length)));
        assert.deepEqual(httpVerificationStepOut[4], allDigestHashed);
        assert.deepEqual(httpVerificationStepOut[5], BigInt(1 + Object.keys(manifest.response.headers).length));

        // request JSON
        let requestJsonCircuitCount = Math.ceil(requestBody.length / DATA_BYTES);

        // const requestTargetValue = strToBytes("0");

        let requestJsonInitialState = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);
        const requestJsonState = [requestJsonInitialState, requestJsonInitialState];

        // TODO: request sequence digest is same as response sequence digest
        const [responseStack, responseTreeHashes] = jsonTreeHasher(ciphertext_digest, manifest.response.body.json, MAX_STACK_HEIGHT);
        const response_sequence_digest = compressTreeHash(ciphertext_digest, [responseStack, responseTreeHashes]);
        const response_sequence_digest_hashed = poseidon1([response_sequence_digest]);
        const request_value_digest = BigInt(0);
        const request_sequence_digest = response_sequence_digest;

        let requestJsonExtractionStepIn: bigint[] = httpVerificationStepOut;
        let requestJsonExtractionStepOut: bigint[] = [];
        let requestBodyPtLengthSoFar = BigInt(0);
        for (var i = 0; i < requestJsonCircuitCount; i++) {
            let plaintext = requestBody.slice(i * DATA_BYTES, (i + 1) * DATA_BYTES);
            let plaintextPadded = plaintext.concat(Array(DATA_BYTES - plaintext.length).fill(-1));

            let jsonExtraction = await JSONExtraction.compute({
                step_in: requestJsonExtractionStepIn,
                ciphertext_digest,
                data: plaintextPadded,
                value_digest: request_value_digest,
                sequence_digest: request_sequence_digest,
                state: requestJsonState[i],
            }, ["step_out"]);
            requestJsonExtractionStepOut = jsonExtraction.step_out as bigint[];

            let plaintextDigest = PolynomialDigest(plaintext, ciphertext_digest, BigInt(i * DATA_BYTES));

            // console.log("plaintextDigest", plaintextDigest);
            assert.deepEqual(requestJsonExtractionStepOut[0], modAdd(requestJsonExtractionStepIn[0] - plaintextDigest, request_value_digest));
            assert.deepEqual(requestJsonExtractionStepOut[7], modPow(ciphertext_digest, BigInt(plaintext.length) + requestBodyPtLengthSoFar));
            assert.deepEqual(requestJsonExtractionStepOut[9], response_sequence_digest_hashed);

            requestBodyPtLengthSoFar += BigInt(plaintext.length);
            requestJsonExtractionStepIn = requestJsonExtractionStepOut;
        }

        // Run response plaintext authentication
        let response_plaintext_packets_length = response.plaintext.length;
        let prevResponseCtDigest = prevCtDigest;
        let responsePtLengthSoFar = ptLengthSoFar;
        let responsePlaintextAuthenticationStepIn: bigint[] = requestJsonExtractionStepOut;
        let responsePlaintextAuthenticationStepOut: bigint[] = [];
        for (var i = 0; i < response_plaintext_packets_length; i++) {
            let plaintext = response.plaintext[i];
            let plaintextPadded = plaintext.concat(Array(DATA_BYTES - plaintext.length).fill(-1));
            let ciphertext = response.ciphertext[i];
            assert.deepEqual(ciphertext.length, plaintext.length);

            const counterBits = uintArray32ToBits([1])[0];
            const keyIn = toInput(Buffer.from(response.key));
            let nonce = toNonce(Uint8Array.from(response.iv), i + request_plaintext_packets_length);
            const nonceIn = toInput(Buffer.from(nonce));
            let plaintextAuthentication = await PlaintextAuthentication.compute({
                step_in: responsePlaintextAuthenticationStepIn,
                plaintext: plaintextPadded,
                key: keyIn,
                nonce: nonceIn,
                counter: counterBits,
                ciphertext_digest,
            }, ["step_out"]);
            responsePlaintextAuthenticationStepOut = plaintextAuthentication.step_out as bigint[];

            let responsePtLength = responsePtLengthSoFar + plaintext.length;
            assert.deepEqual(responsePlaintextAuthenticationStepOut[1], modPow(ciphertext_digest, BigInt(responsePtLength)));

            let ptDigest = PolynomialDigest(plaintext, ciphertext_digest, BigInt(responsePtLengthSoFar));
            // console.log("ptDigest", ptDigest);
            prevResponseCtDigest = DataHasher(ciphertext, prevResponseCtDigest);
            // console.log("prevResponseCtDigest", prevResponseCtDigest);
            let expectedGlobalVariable = modAdd(responsePlaintextAuthenticationStepIn[0] - prevResponseCtDigest, ptDigest, responsePlaintextAuthenticationStepIn[10]);
            assert.deepEqual(responsePlaintextAuthenticationStepOut[0], expectedGlobalVariable);

            responsePlaintextAuthenticationStepIn = responsePlaintextAuthenticationStepOut;
            responsePtLengthSoFar = responsePtLength;
        }

        let responsePlaintextCombined: number[] = [];
        response.plaintext.forEach((plaintext) => {
            responsePlaintextCombined = responsePlaintextCombined.concat(plaintext);
        });
        let responseCiphertextCombined: number[] = [];
        response.ciphertext.forEach((ciphertext) => {
            responseCiphertextCombined = responseCiphertextCombined.concat(ciphertext);
        });
        let responseCircuitCount = Math.ceil(responsePlaintextCombined.length / DATA_BYTES);

        let responsePlaintextDigest = PolynomialDigest(responsePlaintextCombined, ciphertext_digest, BigInt(ptLengthSoFar));
        // console.log("responsePlaintextDigest", responsePlaintextDigest);

        let responseCiphertextDigest = prevCtDigest;
        response.ciphertext.forEach((ciphertext) => {
            responseCiphertextDigest = DataHasher(ciphertext, responseCiphertextDigest);
        });

        // Imp: request body digest need to be added here because of no request json circuit
        assert.deepEqual(responsePlaintextAuthenticationStepOut[0], modAdd(init_nivc_input[0] - prevResponseCtDigest, responsePlaintextDigest));

        // Run response HTTPVerification
        // Run HTTPVerification
        let [responseMachineState, _machine_state_digest] = defaultHttpMachineState(ciphertext_digest);
        let responseMachineState2 = [0, 0, 0, 0, 1, 0, 0, 0];
        let responseMachineState3 = [0, 0, 0, 0, 1, 0, 0, 0];
        let responseMachineStates = [responseMachineState, responseMachineState2, responseMachineState3];
        let prevResponseBodyCounter = BigInt(0);

        let responseHttpVerificationStepIn: bigint[] = responsePlaintextAuthenticationStepOut;
        let responseHttpVerificationStepOut: bigint[] = [];
        let responseMainDigests = mainDigests;
        for (var i = 0; i < responseCircuitCount; i++) {
            let plaintext = responsePlaintextCombined.slice(i * DATA_BYTES, (i + 1) * DATA_BYTES);
            let plaintextPadded = plaintext.concat(Array(DATA_BYTES - plaintext.length).fill(-1));

            let httpVerification = await HTTPVerification.compute({
                step_in: responseHttpVerificationStepIn,
                ciphertext_digest,
                data: plaintextPadded,
                main_digests: responseMainDigests,
                machine_state: responseMachineStates[i],
            }, ["step_out"]);
            responseHttpVerificationStepOut = (httpVerification.step_out as bigint[]).slice(0, PUBLIC_IO_VARIABLES);

            let bodyIndex = findBodyIndex(plaintext);
            if (bodyIndex < 0) {
                bodyIndex = 0;
            }
            let bodyDigest = PolynomialDigest(plaintext.slice(bodyIndex), ciphertext_digest, prevResponseBodyCounter);

            let ptDigest = PolynomialDigest(plaintext, ciphertext_digest, BigInt(i * DATA_BYTES + requestPlaintextCombined.length));

            // console.log("ptDigest", ptDigest);
            // console.log("bodyDigest", bodyDigest);

            assert.deepEqual(responseHttpVerificationStepOut[0], modAdd(responseHttpVerificationStepIn[0] - ptDigest, bodyDigest));

            prevResponseBodyCounter += BigInt(plaintext.length - bodyIndex); responseHttpVerificationStepIn = responseHttpVerificationStepOut;
        }

        let allResponseDigestHashed = allDigestHashed;

        // console.log("prevBodyCounter", prevResponseBodyCounter);

        let responseBodyIndex = responsePlaintextCombined.length - Number(prevResponseBodyCounter);
        let responseBodyDigest = PolynomialDigest(responsePlaintextCombined.slice(responseBodyIndex), ciphertext_digest, BigInt(0));
        assert.deepEqual(responseHttpVerificationStepOut[0], modAdd(responsePlaintextAuthenticationStepOut[0] - responsePlaintextDigest, responseBodyDigest));
        assert.deepEqual(responseHttpVerificationStepOut[2], modPow(ciphertext_digest, BigInt(requestPlaintextCombined.length + responsePlaintextCombined.length)));
        assert.deepEqual(responseHttpVerificationStepOut[4], allResponseDigestHashed);
        assert.deepEqual(responseHttpVerificationStepOut[5], BigInt(0));
        assert.deepEqual(responseHttpVerificationStepOut[6], modPow(ciphertext_digest, prevResponseBodyCounter - BigInt(1)));


        // Run response JSONExtraction
        let responseBody = responsePlaintextCombined.slice(responseBodyIndex);
        let responseJsonCircuitCount = Math.ceil(responseBody.length / DATA_BYTES);

        const targetValue = strToBytes("ord_67890");

        let initialState = Array(MAX_STACK_HEIGHT * 4 + 4).fill(0);
        let jsonState1: (bigint | number)[] = [
            1, 1,
            1, 1,
            1, 1,
            2, 1,
            1, 1,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            BigInt("2643355577121413363110676254722607428821847098722801093693738497454795754952"), 0,
            BigInt("206065045562833791004615579767579121827659506182906579294001675726221001604"), 0,
            BigInt("14813998612245502664604545737576797700378064010241101195875139875508571252941"), 0,
            0, 0,
            BigInt("5850828916669081089813287565658471500935406094393239671510986256315522569528"), 80,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            1, 1, 0, 0
        ];
        assert.deepEqual(jsonState1.length, MAX_STACK_HEIGHT * 4 + 4);
        let state = [initialState, jsonState1];

        const [stack, treeHashes] = jsonTreeHasher(ciphertext_digest, manifest.response.body.json, MAX_STACK_HEIGHT);
        const sequence_digest = compressTreeHash(ciphertext_digest, [stack, treeHashes]);
        const sequence_digest_hashed = poseidon1([sequence_digest]);
        const value_digest = PolynomialDigest(targetValue, ciphertext_digest, BigInt(0));

        let responseJsonExtractionStepIn: bigint[] = responseHttpVerificationStepOut;
        let responseJsonExtractionStepOut: bigint[] = [];
        let responseBodyPtLengthSoFar = BigInt(0);
        for (var i = 0; i < responseJsonCircuitCount; i++) {
            let plaintext = responseBody.slice(i * DATA_BYTES, (i + 1) * DATA_BYTES);
            let plaintextPadded = plaintext.concat(Array(DATA_BYTES - plaintext.length).fill(-1));

            let responseJsonExtraction = await JSONExtraction.compute({
                step_in: responseJsonExtractionStepIn,
                ciphertext_digest,
                data: plaintextPadded,
                value_digest,
                sequence_digest,
                state: state[i],
            }, ["step_out"]);
            responseJsonExtractionStepOut = responseJsonExtraction.step_out as bigint[];

            let plaintextDigest = PolynomialDigest(plaintext, ciphertext_digest, BigInt(i * DATA_BYTES));

            let valueDigest = value_digest;
            if (i === responseJsonCircuitCount - 1) {
                valueDigest = BigInt(0);
            }

            // console.log("plaintextDigest", plaintextDigest);
            assert.deepEqual(responseJsonExtractionStepOut[0], modAdd(responseJsonExtractionStepIn[0] - plaintextDigest, valueDigest));
            assert.deepEqual(responseJsonExtractionStepOut[7], modPow(ciphertext_digest, BigInt(plaintext.length) + responseBodyPtLengthSoFar));
            assert.deepEqual(responseJsonExtractionStepOut[9], sequence_digest_hashed);

            responseBodyPtLengthSoFar += BigInt(plaintext.length);
            responseJsonExtractionStepIn = responseJsonExtractionStepOut;
        }

        assert.deepEqual(responseJsonExtractionStepOut[0], value_digest);
        assert.deepEqual(responseJsonExtractionStepOut[1], modPow(ciphertext_digest, BigInt(requestPlaintextCombined.length + responsePlaintextCombined.length)));
        assert.deepEqual(responseJsonExtractionStepOut[2], modPow(ciphertext_digest, BigInt(requestPlaintextCombined.length + responsePlaintextCombined.length)));

        assert.deepEqual(responseJsonExtractionStepOut[4], init_nivc_input[4]); // all http digest unchanged
        assert.deepEqual(responseJsonExtractionStepOut[5], BigInt(0)); // all http matched
        assert.deepEqual(responseJsonExtractionStepOut[6], modPow(ciphertext_digest, prevResponseBodyCounter - BigInt(1))); // response body length
        assert.deepEqual(responseJsonExtractionStepOut[7], modPow(ciphertext_digest, BigInt(prevResponseBodyCounter))); // response body ciphertext digest pow counter
        assert.deepEqual(responseJsonExtractionStepOut[8], BigInt(0)); // final json state
        assert.deepEqual(responseJsonExtractionStepOut[9], sequence_digest_hashed); // sequence digest

    });
});

describe("512B circuit", function () {
    let PlaintextAuthentication: WitnessTester<["step_in", "plaintext", "key", "nonce", "counter", "ciphertext_digest"], ["step_out"]>;
    let HTTPVerification: WitnessTester<["step_in", "ciphertext_digest", "machine_state", "data", "main_digests"], ["step_out"]>;
    let JSONExtraction: WitnessTester<["step_in", "ciphertext_digest", "data", "sequence_digest", "value_digest", "state"], ["step_out"]>;

    it("request and response 512B", async () => {
        let DATA_BYTES = 512;

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

        let request = reddit_test_case.request;
        let response = reddit_test_case.response;
        let manifest = RedditTestCaseManifest();

        function nearestMultiplePad(input: number[], multiple: number): number[] {
            let length = input.length;
            let remainder = length % multiple;
            if (remainder === 0) {
                return input;
            }
            return input.concat(Array(multiple - remainder).fill(-1));
        }

        async function testPlaintextAuthenticationCircuit(plaintext: number[][], ciphertext: number[][], key: number[], iv: number[], seq: number, ciphertext_digest: bigint, plaintextDigest: bigint, plaintextLengthSoFar: number, prevCiphertextDigest: bigint, stepIn: bigint[], init_nivc_input: bigint[]): Promise<[bigint[], number, bigint]> {
            let plaintext_packets_length = plaintext.length;
            let prevCtDigest = prevCiphertextDigest;
            let ptLengthSoFar = plaintextLengthSoFar;
            let plaintextAuthenticationStepIn: bigint[] = stepIn;
            let plaintextAuthenticationStepOut: bigint[] = [];
            for (var i = 0; i < plaintext_packets_length; i++) {
                let plaintext_chunk = plaintext[i];
                let plaintextPadded = nearestMultiplePad(plaintext_chunk, DATA_BYTES);
                assert.deepEqual(plaintextPadded.length % DATA_BYTES, 0);
                let ciphertext_chunk = ciphertext[i];

                const keyIn = toInput(Buffer.from(key));
                let nonce = toNonce(Uint8Array.from(iv), i + seq);
                const nonceIn = toInput(Buffer.from(nonce));
                let intermediateStepIn = plaintextAuthenticationStepIn;
                for (var j = 0; j < plaintextPadded.length / DATA_BYTES; j++) {
                    const counterBits = uintArray32ToBits([j * (DATA_BYTES / 64) + 1])[0];
                    const plaintextBytes = plaintextPadded.slice(j * DATA_BYTES, (j + 1) * DATA_BYTES);
                    let plaintextAuthentication = await PlaintextAuthentication.compute({
                        step_in: intermediateStepIn,
                        plaintext: plaintextBytes,
                        key: keyIn,
                        nonce: nonceIn,
                        counter: counterBits,
                        ciphertext_digest,
                    }, ["step_out"]);
                    plaintextAuthenticationStepOut = plaintextAuthentication.step_out as bigint[];
                    intermediateStepIn = plaintextAuthenticationStepOut;
                }

                let ptLength = ptLengthSoFar + plaintext_chunk.length;

                assert.deepEqual(plaintextAuthenticationStepOut[1], modPow(ciphertext_digest, BigInt(ptLength)));

                let ptDigest = PolynomialDigest(plaintext_chunk, ciphertext_digest, BigInt(ptLengthSoFar));
                prevCtDigest = DataHasher(ciphertext_chunk, prevCtDigest);
                let expectedGlobalVariable = modAdd(plaintextAuthenticationStepIn[0] - prevCtDigest, ptDigest, plaintextAuthenticationStepIn[10]);
                assert.deepEqual(plaintextAuthenticationStepOut[0], expectedGlobalVariable);

                plaintextAuthenticationStepIn = plaintextAuthenticationStepOut;
                ptLengthSoFar = ptLength;
            }

            // console.log("plaintextDigest", plaintextDigest);

            let intermediateCiphertextDigest = prevCiphertextDigest;
            ciphertext.forEach((ciphertext) => {
                intermediateCiphertextDigest = DataHasher(ciphertext, intermediateCiphertextDigest);
            });
            // console.log("requestCiphertextDigest", requestCiphertextDigest);

            assert.deepEqual(plaintextAuthenticationStepOut[0], modAdd(init_nivc_input[0] - intermediateCiphertextDigest, plaintextDigest));

            return [plaintextAuthenticationStepOut, ptLengthSoFar, prevCtDigest];
        }

        async function testHttpVerificationCircuit(plaintextInput: number[], machineStates: (bigint | number)[][], mainDigests: bigint[], mainDigestsHashed: bigint, ciphertext_digest: bigint, plaintextDigest: bigint, stepIn: bigint[], plaintextLengthSoFar: number, headersToMatch: number): Promise<[bigint[], number[]]> {
            let circuitCount = Math.ceil(plaintextInput.length / DATA_BYTES);

            let inputBodyIndex = findBodyIndex(plaintextInput);
            let bodyChunk = Math.floor(inputBodyIndex / DATA_BYTES);
            assert.deepEqual(inputBodyIndex >= 0, true);
            let prevBodyCounter = BigInt(0);

            let httpVerificationStepIn: bigint[] = stepIn;
            let httpVerificationStepOut: bigint[] = [];
            for (var i = 0; i < circuitCount; i++) {
                let plaintext = plaintextInput.slice(i * DATA_BYTES, (i + 1) * DATA_BYTES);
                let plaintextPadded = plaintext.concat(Array(DATA_BYTES - plaintext.length).fill(-1));

                let httpVerification = await HTTPVerification.compute({
                    step_in: httpVerificationStepIn,
                    ciphertext_digest,
                    data: plaintextPadded,
                    main_digests: mainDigests,
                    machine_state: machineStates[i],
                }, ["step_out"]);
                httpVerificationStepOut = (httpVerification.step_out as bigint[]).slice(0, PUBLIC_IO_VARIABLES);

                let bodyDigest = BigInt(0);
                if (i == bodyChunk) {
                    let bodyIndex = inputBodyIndex % DATA_BYTES;
                    bodyDigest = PolynomialDigest(plaintext.slice(bodyIndex), ciphertext_digest, prevBodyCounter);
                    prevBodyCounter += BigInt(plaintext.length - bodyIndex);
                } else if (i > bodyChunk) {
                    bodyDigest = PolynomialDigest(plaintext, ciphertext_digest, prevBodyCounter);
                    prevBodyCounter += BigInt(plaintext.length);
                }

                let ptDigest = PolynomialDigest(plaintext, ciphertext_digest, BigInt(i * DATA_BYTES + plaintextLengthSoFar));
                // console.log("ptDigest", ptDigest);
                // console.log("bodyDigest", bodyDigest);
                assert.deepEqual(httpVerificationStepOut[0], modAdd(httpVerificationStepIn[0] - ptDigest, bodyDigest));

                httpVerificationStepIn = httpVerificationStepOut;
            }

            // console.log("prevBodyCounter", prevBodyCounter);

            let bodyIndex = plaintextInput.length - Number(prevBodyCounter);
            let body = plaintextInput.slice(bodyIndex);
            let bodyDigest = PolynomialDigest(body, ciphertext_digest, BigInt(0));
            assert.deepEqual(httpVerificationStepOut[0], modAdd(stepIn[0] - plaintextDigest, bodyDigest));
            assert.deepEqual(httpVerificationStepOut[2], modPow(ciphertext_digest, BigInt(plaintextInput.length + plaintextLengthSoFar)));
            assert.deepEqual(httpVerificationStepOut[4], mainDigestsHashed);
            assert.deepEqual(httpVerificationStepOut[5], stepIn[5] - BigInt(1 + headersToMatch));
            assert.deepEqual(httpVerificationStepOut[6], modPow(ciphertext_digest, prevBodyCounter - BigInt(1)));

            return [httpVerificationStepOut, body];
        }

        async function testJsonExtractionCircuit(body: number[], jsonStates: (number | bigint)[][], ciphertext_digest: bigint, value_digest: bigint, sequence_digest: bigint, stepIn: bigint[], valueChunk: number): Promise<[bigint[]]> {

            let jsonCircuitCount = Math.ceil(body.length / DATA_BYTES);

            let jsonExtractionStepIn: bigint[] = stepIn;
            let jsonExtractionStepOut: bigint[] = [];
            let bodyPtLengthSoFar = BigInt(0);

            for (var i = 0; i < jsonCircuitCount; i++) {
                let plaintext = body.slice(i * DATA_BYTES, (i + 1) * DATA_BYTES);
                let plaintextPadded = plaintext.concat(Array(DATA_BYTES - plaintext.length).fill(-1));

                let jsonExtraction = await JSONExtraction.compute({
                    step_in: jsonExtractionStepIn,
                    ciphertext_digest,
                    data: plaintextPadded,
                    value_digest: value_digest,
                    sequence_digest: sequence_digest,
                    state: jsonStates[i],
                }, ["step_out"]);
                jsonExtractionStepOut = jsonExtraction.step_out as bigint[];

                let valueDigest = value_digest;
                // TODO: hardcoded chunk
                if (i !== valueChunk) {
                    valueDigest = BigInt(0);
                }

                let plaintextDigest = PolynomialDigest(plaintext, ciphertext_digest, BigInt(i * DATA_BYTES));

                // console.log("plaintextDigest", plaintextDigest);
                assert.deepEqual(jsonExtractionStepOut[0], modAdd(jsonExtractionStepIn[0] - plaintextDigest, valueDigest));
                assert.deepEqual(jsonExtractionStepOut[7], modPow(ciphertext_digest, BigInt(plaintext.length) + bodyPtLengthSoFar));

                const sequence_digest_hashed = poseidon1([sequence_digest]);

                assert.deepEqual(jsonExtractionStepOut[0], modAdd(jsonExtractionStepIn[0] - plaintextDigest, valueDigest));
                assert.deepEqual(jsonExtractionStepOut[7], modPow(ciphertext_digest, BigInt(plaintext.length) + bodyPtLengthSoFar));
                assert.deepEqual(jsonExtractionStepOut[9], sequence_digest_hashed);

                bodyPtLengthSoFar += BigInt(plaintext.length);
                jsonExtractionStepIn = jsonExtractionStepOut;
            }

            return [jsonExtractionStepOut];
        }

        let requestCiphertextPadded: number[][] = [];
        request.ciphertext.forEach((ciphertext) => {
            requestCiphertextPadded.push(nearestMultiplePad(ciphertext, DATA_BYTES));
        });
        let responseCiphertextPadded: number[][] = [];
        response.ciphertext.forEach((ciphertext) => {
            responseCiphertextPadded.push(nearestMultiplePad(ciphertext, DATA_BYTES));
        });

        const [ciphertext_digest, init_nivc_input, allDigests] = CombinedInitialDigest(manifest, requestCiphertextPadded, responseCiphertextPadded, MAX_STACK_HEIGHT);

        let allDigestHashed = BigInt(0);
        allDigests.forEach((digest) => {
            if (digest === BigInt(0)) {
                return;
            }
            allDigestHashed = modAdd(allDigestHashed, poseidon1([digest]));
        });

        let requestPlaintextCombined: number[] = [];
        request.plaintext.forEach((plaintext) => {
            requestPlaintextCombined = requestPlaintextCombined.concat(plaintext);
        });

        let plaintextDigest = PolynomialDigest(requestPlaintextCombined, ciphertext_digest, BigInt(0));

        let [plaintextAuthenticationStepOut, ptLengthSoFar, prevCtDigest] = await testPlaintextAuthenticationCircuit(request.plaintext, request.ciphertext, request.key, request.iv, 0, ciphertext_digest, plaintextDigest, 0, BigInt(0), init_nivc_input, init_nivc_input);

        // Run HTTPVerification
        let machineState = Array(8).fill(0);
        machineState[0] = 1; // Sets the parsing start to 1
        machineState[7] = 1; // Sets the line monomial to 1
        let machineState2 = [0, 1, 0, 1, 0, 0, BigInt("21218358746262359245418567448753136091059684497465157067353670822841323691631"), BigInt("294712404858167615526411343770145012334003503108076178326684318832309721698")];
        let machineState3 = [0, 1, 0, 1, 0, 0, BigInt("919717730919706340110590210863304851669750368287633403333916997274010222649"), BigInt("7642534564124920286762396311812311563644921918815497734336392450908097866647")];
        let machineState4 = [0, 4, 0, 1, 0, 0, BigInt("16594509912132658633548398623473606113450450173523979681205586149623756925187"), BigInt("16036748119288573677512357943907797080397539423131796229203687601802883963153")];
        let machineStates = [machineState, machineState2, machineState3, machineState4];
        let mainDigests = allDigests.concat(Array(MAX_NUMBER_OF_HEADERS + 1 - allDigests.length).fill(0));

        let [httpVerificationStepOut, requestBody] = await testHttpVerificationCircuit(requestPlaintextCombined, machineStates, mainDigests, allDigestHashed, ciphertext_digest, plaintextDigest, plaintextAuthenticationStepOut, 0, Object.keys(manifest.request.headers).length);

        // request JSON

        const requestJsonInitialState = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);
        const requestJsonState1 = [
            1, 1,
            1, 1,
            1, 1,
            1, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            BigInt("2643355577121413363110676254722607428821847098722801093693738497454795754952"), 0,
            BigInt("5338721428392130291562574457634287478392987374506234693051178164715124780330"), 0,
            BigInt("19916492378103830709606695188381054612894951701170877230665125653610477584013"), 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0, 0
        ]
        const requestJsonState = [requestJsonInitialState, requestJsonState1];

        // TODO: request sequence digest is same as response sequence digest
        const [responseStack, responseTreeHashes] = jsonTreeHasher(ciphertext_digest, manifest.response.body.json, MAX_STACK_HEIGHT);
        const response_sequence_digest = compressTreeHash(ciphertext_digest, [responseStack, responseTreeHashes]);
        const request_value_digest = BigInt(0);
        const request_sequence_digest = response_sequence_digest;

        let [requestJsonExtractionStepOut] = await testJsonExtractionCircuit(requestBody, requestJsonState, ciphertext_digest, request_value_digest, request_sequence_digest, httpVerificationStepOut, 0);

        // Run response plaintext authentication
        let responsePlaintextCombined: number[] = [];
        response.plaintext.forEach((plaintext) => {
            responsePlaintextCombined = responsePlaintextCombined.concat(plaintext);
        });
        let responseCiphertextCombined: number[] = [];
        response.ciphertext.forEach((ciphertext) => {
            responseCiphertextCombined = responseCiphertextCombined.concat(ciphertext);
        });

        let responsePlaintextDigest = PolynomialDigest(responsePlaintextCombined, ciphertext_digest, BigInt(ptLengthSoFar));

        let [responsePlaintextAuthenticationStepOut, _responsePtLengthSoFar, _prevResponseCtDigest] = await testPlaintextAuthenticationCircuit(response.plaintext, response.ciphertext, response.key, response.iv, request.plaintext.length, ciphertext_digest, responsePlaintextDigest, ptLengthSoFar, prevCtDigest, requestJsonExtractionStepOut, init_nivc_input);

        // Run response HTTPVerification
        let responseMachineState = Array(8).fill(0);
        responseMachineState[0] = 1; // Sets the parsing start to 1
        responseMachineState[7] = 1; // Sets the line monomial to 1
        let responseMachineState2 = [0, 9, 0, 1, 0, 0, BigInt("20848396831015299078329888517201682120737434055968454964874253181566312587385"), BigInt("1127223840863862515198557295097962421105629773323840607111166584919676172461")];
        let responseMachineState3 = [0, 19, 0, 1, 0, 0, BigInt("13322495516355679604764199542756975746572852905948014148501917822450065381679"), BigInt("10666397918167336865867404922425055437141132122568687218975061476458388639027")];
        let responseMachineState4 = [0, 20, 0, 1, 0, 0, BigInt("12649825720393973615332758021959071459516676448706888536678587392957962764752"), BigInt("10155970281253632756670188800306451161176708763321775993434680795768541541484")];
        let responseMachineStates = [responseMachineState, responseMachineState2, responseMachineState3, responseMachineState4, responseMachineState4];

        let [responseHttpVerificationStepOut, responseBody] = await testHttpVerificationCircuit(responsePlaintextCombined, responseMachineStates, mainDigests, allDigestHashed, ciphertext_digest, responsePlaintextDigest, responsePlaintextAuthenticationStepOut, requestPlaintextCombined.length, Object.keys(manifest.response.headers).length);

        // Run response JSONExtraction
        // let responseBody = responsePlaintextCombined.slice(responseBodyIndex);
        let responseJsonCircuitCount = Math.ceil(responseBody.length / DATA_BYTES);


        let initialState = Array(MAX_STACK_HEIGHT * 4 + 3).fill(0);
        let jsonState1: (bigint | number)[] = [
            1, 1,
            1, 1,
            1, 1,
            2, 0,
            1, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            BigInt("2643355577121413363110676254722607428821847098722801093693738497454795754952"), 0,
            BigInt("206065045562833791004615579767579121827659506182906579294001675726221001604"), 0,
            BigInt("14813998612245502664604545737576797700378064010241101195875139875508571252941"), 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0, 0
        ];
        let jsonState2: (bigint | number)[] = [
            1, 1,
            1, 1,
            1, 1,
            2, 1,
            1, 1,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            BigInt("2643355577121413363110676254722607428821847098722801093693738497454795754952"), 0,
            BigInt("206065045562833791004615579767579121827659506182906579294001675726221001604"), 0,
            BigInt("14813998612245502664604545737576797700378064010241101195875139875508571252941"), 0,
            0, 0,
            BigInt("5850828916669081089813287565658471500935406094393239671510986256315522569528"), 80,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            1, 1, 0
        ];
        let jsonState3: (bigint | number)[] = [
            1, 1,
            1, 1,
            1, 1,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            BigInt("2643355577121413363110676254722607428821847098722801093693738497454795754952"), 0,
            BigInt("13093332208950235817341618792150663087469278585959802820674195585858448270816"), 0,
            BigInt("15070811010757240845867067014313790945176888278588877578774386329096200063291"), 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
            0, 1, 0
        ];
        assert.deepEqual(jsonState1.length, MAX_STACK_HEIGHT * 4 + 3);
        let jsonStates = [initialState, jsonState1, jsonState2, jsonState3];

        const [stack, treeHashes] = jsonTreeHasher(ciphertext_digest, manifest.response.body.json, MAX_STACK_HEIGHT);
        const sequence_digest = compressTreeHash(ciphertext_digest, [stack, treeHashes]);
        const sequence_digest_hashed = poseidon1([sequence_digest]);
        const targetValue = strToBytes("1789.0");
        const response_value_digest = PolynomialDigest(targetValue, ciphertext_digest, BigInt(0));

        let [responseJsonExtractionStepOut] = await testJsonExtractionCircuit(responseBody, jsonStates, ciphertext_digest, response_value_digest, sequence_digest, responseHttpVerificationStepOut, 0);

        assert.deepEqual(responseJsonExtractionStepOut[0], response_value_digest);
        assert.deepEqual(responseJsonExtractionStepOut[1], modPow(ciphertext_digest, BigInt(requestPlaintextCombined.length + responsePlaintextCombined.length)));
        assert.deepEqual(responseJsonExtractionStepOut[2], modPow(ciphertext_digest, BigInt(requestPlaintextCombined.length + responsePlaintextCombined.length)));

        assert.deepEqual(responseJsonExtractionStepOut[4], init_nivc_input[4]); // all http digest unchanged
        assert.deepEqual(responseJsonExtractionStepOut[5], BigInt(0)); // all http matched
        assert.deepEqual(responseJsonExtractionStepOut[6], modPow(ciphertext_digest, BigInt(responseBody.length) - BigInt(1))); // response body length
        assert.deepEqual(responseJsonExtractionStepOut[7], modPow(ciphertext_digest, BigInt(responseBody.length))); // response body ciphertext digest pow counter
        assert.deepEqual(responseJsonExtractionStepOut[8], BigInt(0)); // final json state
        assert.deepEqual(responseJsonExtractionStepOut[9], sequence_digest_hashed); // sequence digest

    });
});