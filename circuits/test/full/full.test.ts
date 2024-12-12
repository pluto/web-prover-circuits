import { assert } from "chai";
import { circomkit, WitnessTester, toByte, uintArray32ToBits, http_response_plaintext, chacha20_http_response_ciphertext, http_start_line, http_header_0, http_header_1, http_body, PolynomialDigest, strToBytes, JsonMaskType, jsonTreeHasher, compressTreeHash } from "../common";
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

// TODO: These are currently from Rust
const ciphertext_digest = BigInt(5947802862726868637928743536818722886587721698845887498686185738472802646104);
const init_nivc_input = BigInt(10058086791493234040243189470127050054517868204788786183557972712972489301322);
const start_line_digest = PolynomialDigest(http_start_line, ciphertext_digest);
const header_0_digest = PolynomialDigest(http_header_0, ciphertext_digest);
const header_1_digest = PolynomialDigest(http_header_1, ciphertext_digest);
const padded_http_body = http_body.concat(Array(320 - http_body.length).fill(-1));

describe("Example NIVC Proof", async () => {
    let PlaintextAuthentication: WitnessTester<["step_in", "plainText", "key", "nonce", "counter"], ["step_out"]>;
    let HTTPVerification: WitnessTester<["step_in", "ciphertext_digest", "data", "main_digests"], ["step_out"]>;
    let JSONExtraction: WitnessTester<["step_in", "ciphertext_digest", "data", "sequence_digest"], ["step_out"]>;

    const MAX_NUMBER_OF_HEADERS = 2;
    const DATA_BYTES = 320;
    const MAX_STACK_HEIGHT = 5;
    const MAX_KEY_LENGTH = 8;
    const MAX_VALUE_LENGTH = 32;

    before(async () => {
        PlaintextAuthentication = await circomkit.WitnessTester("PlaintextAuthentication", {
            file: "chacha20/nivc/chacha20_nivc",
            template: "ChaCha20_NIVC",
            params: [320]
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
            params: [DATA_BYTES, MAX_NUMBER_OF_HEADERS],
        });
        console.log("#constraints (JSONExtraction):", await JSONExtraction.getConstraintCount());
    });

    it("Spotify Example", async () => {
        // Run ChaCha20
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
        console.log("PlaintextAuthentication `step_out`:", plaintext_authentication.step_out);

        let http_verification = await HTTPVerification.compute({
            step_in: plaintext_authentication.step_out,
            ciphertext_digest,
            data: http_response_plaintext,
            main_digests: [start_line_digest, header_0_digest, header_1_digest],
        }, ["step_out"]);
        // (autoparallel) This next line gives me an aneurysm
        let http_verification_step_out = (http_verification.step_out as number[])[0];
        console.log("HttpNIVC `step_out`:", http_verification_step_out);

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

        const [stack, treeHashes] = jsonTreeHasher(ciphertext_digest, keySequence, targetValue, 10);
        const sequence_digest = compressTreeHash(ciphertext_digest, [stack, treeHashes]);
        const sequence_digest_hash = poseidon1([sequence_digest]);
        let json_extraction = await JSONExtraction.compute({
            step_in: plaintext_authentication.step_out,
            ciphertext_digest,
            data: padded_http_body,
            sequence_digest,
        }, ["step_out"]);

    });
});
