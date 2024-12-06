import { circomkit, WitnessTester, toByte } from "../common";
import { assert } from "chai";
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
let TEST_HTTP = [
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

const TEST_HTTP_START_LINE = [
    72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75
];

const TEST_HTTP_HEADER_0 = [
    99, 111, 110, 116, 101, 110, 116, 45, 116,
    121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115, 111,
    110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56
];

const TEST_HTTP_HEADER_1 = [
    99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122,
    105, 112
];

const TEST_HTTP_BODY = [
    123, 13, 10, 32, 32, 32, 34,
    100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109,
    115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65,
    114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121,
    108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32,
    32, 32, 32, 32, 32, 32, 93, 13, 10, 32, 32, 32, 125, 13, 10, 125,
];

const DATA_BYTES = 320;
const MAX_NUMBER_OF_HEADERS = 2;

function PolynomialDigest(coeffs: number[], input: bigint): bigint {
    const prime = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

    let result = BigInt(0);
    let power = BigInt(1);

    for (let i = 0; i < coeffs.length; i++) {
        result = (result + BigInt(coeffs[i]) * power) % prime;
        power = (power * input) % prime;
    }

    return result;
}

describe("HTTP Verfication", async () => {
    let HTTPVerification: WitnessTester<["step_in", "data", "which_headers", "main_digest", "body_digest"], ["step_out"]>;
    before(async () => {
        HTTPVerification = await circomkit.WitnessTester("http_nivc", {
            file: "http/verification",
            template: "HTTPVerification",
            params: [DATA_BYTES, MAX_NUMBER_OF_HEADERS]
        });
    });

    it("witness: TEST_HTTP, no header", async () => {
        // Get all the hashes we need
        let plaintext_hash = DataHasher(TEST_HTTP);
        // Compute the HTTP info digest
        // let start_line_digest = PolynomialDigest(TEST_HTTP_START_LINE, plaintext_hash);
        let main_digest = PolynomialDigest(TEST_HTTP_START_LINE, BigInt(2)); // TODO: For debugging purposes
        console.log("start_line_digest = ", main_digest);

        // let body_digest = PolynomialDigest(TEST_HTTP_BODY, plaintext_hash);
        let body_digest = PolynomialDigest(TEST_HTTP_BODY, BigInt(2)); // TODO: For debugging purposes

        // Run the HTTP circuit
        // POTENTIAL BUG: I didn't get this to work with `expectPass` as it didn't compute `step_out` that way???
        let http_nivc_compute = await HTTPVerification.compute({
            step_in: plaintext_hash,
            data: TEST_HTTP,
            which_headers: [0, 0],
            main_digest,
            body_digest: body_digest,
        }, ["step_out"]);
        // TODO: Readd this
        // assert.deepEqual(http_nivc_compute.step_out, body_digest);


    });

    // it("witness: TEST_HTTP, single header", async () => {
    //     // Get all the hashes we need
    //     // Get the data hash
    //     let plaintext_hash = DataHasher(TEST_HTTP);
    //     // Compute the HTTP info digest
    //     // let start_line_digest = PolynomialDigest(TEST_HTTP_START_LINE, plaintext_hash);
    //     let start_line_digest = PolynomialDigest(TEST_HTTP_START_LINE, BigInt(2)); // For debugging purposes
    //     console.log("start_line_digest = ", start_line_digest);
    //     let header_0_digest = PolynomialDigest(TEST_HTTP_HEADER_0, plaintext_hash);
    //     let body_digest = PolynomialDigest(TEST_HTTP_BODY, plaintext_hash);

    //     // Run the HTTP circuit
    //     // POTENTIAL BUG: I didn't get this to work with `expectPass` as it didn't compute `step_out` that way???
    //     let http_nivc_compute = await HTTPVerification.compute({
    //         step_in: plaintext_hash,
    //         data: TEST_HTTP,
    //         start_line_digest,
    //         which_headers: [1, 0],
    //         headers_digest: header_0_digest,
    //         body_digest: body_digest,
    //     }, ["step_out"]);
    //     // TODO: Readd this
    //     // assert.deepEqual(http_nivc_compute.step_out, body_digest);


    // });

    // it("witness: TEST_HTTP, two headers", async () => {
    //     // Get all the hashes we need
    //     // Get the data hash
    //     let data_hash = await dataHasher.compute({ in: TEST_HTTP }, ["out"]);
    //     // Get the start line hash
    //     let start_line_hash = await dataHasher.compute({ in: TEST_HTTP_START_LINE }, ["out"])
    //     // Get the header hashes
    //     let header_0_hash = await dataHasher.compute({ in: TEST_HTTP_HEADER_0 }, ["out"]);
    //     let header_1_hash = await dataHasher.compute({ in: TEST_HTTP_HEADER_1 }, ["out"]);
    //     // Get the body hash
    //     let body_hash = await dataHasher.compute({ in: TEST_HTTP_BODY }, ["out"]);

    //     // Run the HTTP circuit
    //     // POTENTIAL BUG: I didn't get this to work with `expectPass` as it didn't compute `step_out` that way???
    //     let http_nivc_compute = await httpNivc.compute({
    //         step_in: data_hash.out,
    //         data: TEST_HTTP,
    //         start_line_hash: start_line_hash.out,
    //         header_hashes: [header_0_hash.out, header_1_hash.out],
    //         body_hash: body_hash.out,
    //     }, ["step_out"]);

    //     assert.deepEqual(http_nivc_compute.step_out, body_hash.out);
    // });
});