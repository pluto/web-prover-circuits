import { assert } from "chai";
import { circomkit, WitnessTester, toByte, uintArray32ToBits, http_response_plaintext, http_response_ciphertext, http_start_line, http_header_0, http_header_1, http_body, PolynomialDigest, strToBytes, JsonMaskType, jsonTreeHasher, compressTreeHash, modAdd, InitialDigest, MockManifest } from "../common";
import { DataHasher } from "../common/poseidon";
import { toInput } from "../chacha20/chacha20-nivc.test";
import { poseidon1 } from "poseidon-lite";

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

const DATA_BYTES = 320;
const MAX_NUMBER_OF_HEADERS = 2;
const MAX_STACK_HEIGHT = 5;

// These `check_*` are currently from Rust
const check_ciphertext_digest = BigInt("5947802862726868637928743536818722886587721698845887498686185738472802646104");
const check_init_nivc_input = BigInt("1004047589511714647691705222985203827421588749970619269541141824992822853087");

const [ciphertext_digest, init_nivc_input] = InitialDigest(MockManifest(), http_response_ciphertext, strToBytes("Taylor Swift"), MAX_STACK_HEIGHT);
assert.deepEqual(ciphertext_digest, check_ciphertext_digest);
assert.deepEqual(init_nivc_input, check_init_nivc_input);

describe("Example NIVC Proof", async () => {
    let PlaintextAuthentication: WitnessTester<["step_in", "plainText", "key", "nonce", "counter"], ["step_out"]>;
    let HTTPVerification: WitnessTester<["step_in", "ciphertext_digest", "data", "main_digests"], ["step_out"]>;
    let JSONExtraction: WitnessTester<["step_in", "ciphertext_digest", "data", "sequence_digest"], ["step_out"]>;

    before(async () => {
        PlaintextAuthentication = await circomkit.WitnessTester("PlaintextAuthentication", {
            file: "chacha20/nivc/chacha20_nivc",
            template: "ChaCha20_NIVC",
            params: [DATA_BYTES]
        });
        console.log("#constraints (PlaintextAuthentication):", await PlaintextAuthentication.getConstraintCount());

        HTTPVerification = await circomkit.WitnessTester("HTTPVerification", {
            file: "http/verification",
            template: "HTTPVerification",
            params: [DATA_BYTES, MAX_NUMBER_OF_HEADERS],
        });
        console.log("#constraints (HTTPVerification):", await HTTPVerification.getConstraintCount());

        JSONExtraction = await circomkit.WitnessTester(`JSONExtraction`, {
            file: "json/extraction",
            template: "JSONExtraction",
            params: [DATA_BYTES, MAX_STACK_HEIGHT],
        });
        console.log("#constraints (JSONExtraction):", await JSONExtraction.getConstraintCount());
    });

    it("Spotify Example", async () => {
        // Run PlaintextAuthentication
        const counterBits = uintArray32ToBits([1])[0]
        const keyIn = toInput(Buffer.from(Array(32).fill(0)));
        const nonceIn = toInput(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00]));
        let plaintext_authentication = await PlaintextAuthentication.compute({
            step_in: init_nivc_input,
            plainText: http_response_plaintext,
            key: keyIn,
            nonce: nonceIn,
            counter: counterBits,
        }, ["step_out"]);
        console.log("Plaintext Authentication `step_out`:", plaintext_authentication.step_out);
        const http_response_plaintext_digest = PolynomialDigest(http_response_plaintext, ciphertext_digest);
        const http_response_plaintext_digest_hashed = poseidon1([http_response_plaintext_digest]);
        const correct_plaintext_authentication_step_out = modAdd(init_nivc_input - ciphertext_digest, http_response_plaintext_digest_hashed);
        assert.deepEqual(plaintext_authentication.step_out, correct_plaintext_authentication_step_out);

        // Run HTTPVerification
        const start_line_digest = PolynomialDigest(http_start_line, ciphertext_digest);
        const header_0_digest = PolynomialDigest(http_header_0, ciphertext_digest);
        const header_1_digest = PolynomialDigest(http_header_1, ciphertext_digest);
        const padded_http_body = http_body.concat(Array(320 - http_body.length).fill(-1));
        let step_in = BigInt(plaintext_authentication.step_out.toString(10));
        console.log("http_step_in: ", step_in);
        let http_verification = await HTTPVerification.compute({
            step_in,
            ciphertext_digest,
            data: http_response_plaintext,
            main_digests: [start_line_digest, header_0_digest, header_1_digest],
        }, ["step_out"]);
        // (autoparallel) This next line gives me an aneurysm
        let http_verification_step_out = BigInt((http_verification.step_out as number[])[0]);
        console.log("HTTP Verification `step_out`:", http_verification_step_out);
        const body_digest_hashed = poseidon1([PolynomialDigest(http_body, ciphertext_digest)]);
        const start_line_digest_digest_hashed = poseidon1([start_line_digest]);
        const header_0_digest_hashed = poseidon1([header_0_digest]);
        const header_1_digest_hashed = poseidon1([header_1_digest]);
        const correct_http_verification_step_out = modAdd(step_in - start_line_digest_digest_hashed - header_0_digest_hashed - header_1_digest_hashed - http_response_plaintext_digest_hashed, body_digest_hashed);
        assert.deepEqual(http_verification_step_out, correct_http_verification_step_out);

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

        const [stack, treeHashes] = jsonTreeHasher(ciphertext_digest, keySequence, targetValue, MAX_STACK_HEIGHT);
        const sequence_digest = compressTreeHash(ciphertext_digest, [stack, treeHashes]);

        const sequence_digest_hashed = poseidon1([sequence_digest]);
        console.log("sequence_digest_hashed = ", sequence_digest_hashed);

        let json_extraction = await JSONExtraction.compute({
            step_in: http_verification_step_out,
            ciphertext_digest,
            data: padded_http_body,
            sequence_digest,
        }, ["step_out"]);


    });
});
