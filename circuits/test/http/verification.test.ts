import { circomkit, WitnessTester, PolynomialDigest, http_response_plaintext, http_start_line, http_header_0, http_header_1, http_body } from "../common";
import { assert } from "chai";
import { DataHasher } from "../common/poseidon";
import { poseidon2 } from "poseidon-lite";

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

const DATA_BYTES = 320;
const MAX_NUMBER_OF_HEADERS = 2;

describe("HTTP Verfication", async () => {
    let HTTPVerification: WitnessTester<["step_in", "data", "main_digests"], ["step_out"]>;
    before(async () => {
        HTTPVerification = await circomkit.WitnessTester("http_nivc", {
            file: "http/verification",
            template: "HTTPVerification",
            params: [DATA_BYTES, MAX_NUMBER_OF_HEADERS]
        });
    });

    it("witness: http_response_plaintext, no header", async () => {
        // Get all the hashes we need
        let plaintext_hash = DataHasher(http_response_plaintext);

        // Compute the HTTP info digest
        let main_digest = PolynomialDigest(http_start_line, plaintext_hash);
        let body_digest = PolynomialDigest(http_body, plaintext_hash);
        let step_out = poseidon2([body_digest, plaintext_hash]);

        // Run the HTTP circuit
        // POTENTIAL BUG: I didn't get this to work with `expectPass` as it didn't compute `step_out` that way???
        let http_nivc_compute = await HTTPVerification.compute({
            step_in: plaintext_hash,
            data: http_response_plaintext,
            main_digests: [main_digest].concat(Array(2).fill(0)),
        }, ["step_out"]);
        // I fucking hate circomkit
        assert.deepEqual((http_nivc_compute.step_out as BigInt[])[0], step_out);
    });

    it("witness: http_response_plaintext, one header", async () => {
        // Get all the hashes we need
        let plaintext_hash = DataHasher(http_response_plaintext);

        // Compute the HTTP info digest
        let start_line_digest = PolynomialDigest(http_start_line, plaintext_hash);
        let header_0_digest = PolynomialDigest(http_header_0, plaintext_hash);
        let body_digest = PolynomialDigest(http_body, plaintext_hash);
        let step_out = poseidon2([body_digest, plaintext_hash]);

        // Run the HTTP circuit
        // POTENTIAL BUG: I didn't get this to work with `expectPass` as it didn't compute `step_out` that way???
        let http_nivc_compute = await HTTPVerification.compute({
            step_in: plaintext_hash,
            data: http_response_plaintext,
            main_digests: [start_line_digest, header_0_digest].concat(Array(1).fill(0)),
        }, ["step_out"]);
        // I fucking hate circomkit
        assert.deepEqual((http_nivc_compute.step_out as BigInt[])[0], step_out);
    });

    it("witness: http_response_plaintext, two headers", async () => {
        // Get all the hashes we need
        let plaintext_hash = DataHasher(http_response_plaintext);

        // Compute the HTTP info digest
        let start_line_digest = PolynomialDigest(http_start_line, plaintext_hash);
        let header_0_digest = PolynomialDigest(http_header_0, plaintext_hash);
        let header_1_digest = PolynomialDigest(http_header_1, plaintext_hash);
        let body_digest = PolynomialDigest(http_body, plaintext_hash);
        let step_out = poseidon2([body_digest, plaintext_hash]);

        // Run the HTTP circuit
        // POTENTIAL BUG: I didn't get this to work with `expectPass` as it didn't compute `step_out` that way???
        let http_nivc_compute = await HTTPVerification.compute({
            step_in: plaintext_hash,
            data: http_response_plaintext,
            main_digests: [start_line_digest, header_0_digest, header_1_digest],
        }, ["step_out"]);
        // I fucking hate circomkit
        assert.deepEqual((http_nivc_compute.step_out as BigInt[])[0], step_out);
    });

    it("witness: http_response_plaintext, two headers, order does not matter", async () => {
        // Get all the hashes we need
        let plaintext_hash = DataHasher(http_response_plaintext);

        // Compute the HTTP info digest
        let start_line_digest = PolynomialDigest(http_start_line, plaintext_hash);
        let header_0_digest = PolynomialDigest(http_header_0, plaintext_hash);
        let header_1_digest = PolynomialDigest(http_header_1, plaintext_hash);
        let body_digest = PolynomialDigest(http_body, plaintext_hash);
        let step_out = poseidon2([body_digest, plaintext_hash]);

        // Run the HTTP circuit
        // POTENTIAL BUG: I didn't get this to work with `expectPass` as it didn't compute `step_out` that way???
        let http_nivc_compute = await HTTPVerification.compute({
            step_in: plaintext_hash,
            data: http_response_plaintext,
            main_digests: [header_1_digest, start_line_digest, header_0_digest],
        }, ["step_out"]);
        // I fucking hate circomkit
        assert.deepEqual((http_nivc_compute.step_out as BigInt[])[0], step_out);
    });
});