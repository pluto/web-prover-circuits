import { circomkit, WitnessTester, PolynomialDigest, http_response_plaintext, http_start_line, http_header_0, http_header_1, http_body, modAdd, PUBLIC_IO_VARIABLES } from "../common";
import { assert } from "chai";
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

const DATA_BYTES = 320;
const MAX_NUMBER_OF_HEADERS = 2;

describe("HTTP Verification", async () => {
    let HTTPVerification: WitnessTester<["step_in", "data", "machine_state", "main_digests", "ciphertext_digest"], ["step_out"]>;
    before(async () => {
        HTTPVerification = await circomkit.WitnessTester("http_nivc", {
            file: "http/verification",
            template: "HTTPVerification",
            params: [DATA_BYTES, MAX_NUMBER_OF_HEADERS, PUBLIC_IO_VARIABLES]
        });
    });
    const mock_ct_digest = poseidon1([69]);

    // Used across tests
    let machine_state = Array(6).fill(0);
    machine_state[0] = 1; // Sets the parsing start to 1
    let step_in = Array(PUBLIC_IO_VARIABLES).fill(0);
    step_in[3] = 1; // This would be the PD of the machine state given 1 is in the x^0 coeff

    // Get all the hashes we need
    let plaintext_digest = PolynomialDigest(http_response_plaintext, mock_ct_digest, BigInt(0));

    // Compute the HTTP info digest
    let start_line_digest = PolynomialDigest(http_start_line, mock_ct_digest, BigInt(0));
    let start_line_digest_hashed = poseidon1([start_line_digest]);
    let header_0_digest = PolynomialDigest(http_header_0, mock_ct_digest, BigInt(0));
    let header_0_digest_hashed = poseidon1([header_0_digest]);
    let header_1_digest = PolynomialDigest(http_header_1, mock_ct_digest, BigInt(0));
    let header_1_digest_hashed = poseidon1([header_1_digest]);
    let body_digest = PolynomialDigest(http_body, mock_ct_digest, BigInt(0));
    let output_difference = modAdd(-plaintext_digest, BigInt(0)); // TODO: need to add body_digest

    it("witness: http_response_plaintext, no header", async () => {
        // For this specific test, we need these registers set
        step_in[4] = start_line_digest_hashed;
        step_in[5] = 1; // Total number of matches to expect (sl)

        // Run the HTTP circuit
        // POTENTIAL BUG: I didn't get this to work with `expectPass` as it didn't compute `step_out` that way???
        let http_nivc_compute = await HTTPVerification.compute({
            step_in,  // This doesn't really matter for this test
            data: http_response_plaintext,
            machine_state,
            main_digests: [start_line_digest].concat(Array(2).fill(0)),
            ciphertext_digest: mock_ct_digest
        }, ["step_out"]);
        // I fucking hate circomkit
        assert.deepEqual((http_nivc_compute.step_out as BigInt[])[0], output_difference);
    });

    it("witness: http_response_plaintext, one header", async () => {
        // For this specific test, we need these registers set
        step_in[4] = start_line_digest_hashed + header_0_digest_hashed;
        step_in[5] = 2; // Total number of matches to expect (sl, h0)

        // Run the HTTP circuit
        // POTENTIAL BUG: I didn't get this to work with `expectPass` as it didn't compute `step_out` that way???
        let http_nivc_compute = await HTTPVerification.compute({
            step_in,  // This doesn't really matter for this test
            data: http_response_plaintext,
            machine_state,
            main_digests: [start_line_digest, header_0_digest].concat(Array(1).fill(0)),
            ciphertext_digest: mock_ct_digest
        }, ["step_out"]);
        // I fucking hate circomkit
        assert.deepEqual((http_nivc_compute.step_out as BigInt[])[0], output_difference);
    });

    it("witness: http_response_plaintext, two headers", async () => {
        // For this specific test, we need these registers set
        step_in[4] = start_line_digest_hashed + header_0_digest_hashed + header_1_digest_hashed;
        step_in[5] = 3; // Total number of matches to expect (sl, h0, h1)

        // Run the HTTP circuit
        // POTENTIAL BUG: I didn't get this to work with `expectPass` as it didn't compute `step_out` that way???
        let http_nivc_compute = await HTTPVerification.compute({
            step_in,  // This doesn't really matter for this test
            data: http_response_plaintext,
            machine_state,
            main_digests: [start_line_digest, header_0_digest, header_1_digest],
            ciphertext_digest: mock_ct_digest
        }, ["step_out"]);
        // I fucking hate circomkit
        assert.deepEqual((http_nivc_compute.step_out as BigInt[])[0], output_difference);
    });

    it("witness: http_response_plaintext, two headers, order does not matter", async () => {
        // For this specific test, we need these registers set
        step_in[4] = start_line_digest_hashed + header_0_digest_hashed + header_1_digest_hashed;
        step_in[5] = 3; // Total number of matches to expect (sl, h0, h1)

        // Run the HTTP circuit
        // POTENTIAL BUG: I didn't get this to work with `expectPass` as it didn't compute `step_out` that way???
        let http_nivc_compute = await HTTPVerification.compute({
            step_in,  // This doesn't really matter for this test
            data: http_response_plaintext,
            machine_state,
            main_digests: [header_1_digest, start_line_digest, header_0_digest],
            ciphertext_digest: mock_ct_digest
        }, ["step_out"]);
        // I fucking hate circomkit
        // TODO: need to check more of the assertions
        assert.deepEqual((http_nivc_compute.step_out as BigInt[])[0], output_difference);
    });
});