import { circomkit, WitnessTester, generateDescription, toByte } from "../common";
import { readHTTPInputFile } from "../common/http";

describe("HTTP :: Interpreter", async () => {
    describe("MethodMatch", async () => {
        let circuit: WitnessTester<["data", "method", "index"], []>;

        function generatePassCase(input: number[], method: number[], index: number, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                circuit = await circomkit.WitnessTester(`LockRequestLineData`, {
                    file: "http/interpreter",
                    template: "MethodMatch",
                    params: [input.length, method.length],
                });
                console.log("#constraints:", await circuit.getConstraintCount());

                await circuit.expectPass({ data: input, method: method, index: index }, {});
            });
        }

        function generateFailCase(input: number[], method: number[], index: number, desc: string) {
            const description = generateDescription(input);

            it(`(invalid) witness: ${description} ${desc}`, async () => {
                circuit = await circomkit.WitnessTester(`LockRequestLineData`, {
                    file: "http/interpreter",
                    template: "MethodMatch",
                    params: [input.length, method.length],
                });
                console.log("#constraints:", await circuit.getConstraintCount());

                await circuit.expectFail({ data: input, method: method, index: index });
            });
        }

        let parsedHttp = readHTTPInputFile("get_request.http");
        generatePassCase(parsedHttp.input, toByte("GET"), 0, "");
        generateFailCase(parsedHttp.input, toByte("POST"), 0, "");
    });
});

// 320 bytes in the HTTP response
let http_response_plaintext = [
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

describe("HeaderFieldNameValueMatchPadded", async () => {
    let circuit: WitnessTester<["data", "headerName", "nameLen", "headerValue", "valueLen", "index"], ["out"]>;

    let DATA_BYTES = 320;
    let MAX_NAME_LENGTH = 20;
    let MAX_VALUE_LENGTH = 35;

    before(async () => {
        circuit = await circomkit.WitnessTester(`HeaderFieldNameValueMatchPadded`, {
            file: "http/interpreter",
            template: "HeaderFieldNameValueMatchPadded",
            params: [DATA_BYTES, MAX_NAME_LENGTH, MAX_VALUE_LENGTH],
        });
    });

    function generatePassCase(input: any, expected: any, desc: string) {
        const description = generateDescription(input);
        input["headerName"] = input["headerName"].concat(Array(MAX_NAME_LENGTH - input["headerName"].length).fill(0));
        input["headerValue"] = input["headerValue"].concat(Array(MAX_VALUE_LENGTH - input["headerValue"].length).fill(0));

        it(`(valid) witness: ${desc}`, async () => {
            // console.log(JSON.stringify(await circuit.compute(input, ["step_out"])))
            await circuit.expectPass(input, expected);
        });

    }

    let header_name = toByte("content-type");
    let header_value = toByte("application/json; charset=utf-8");

    let input = {
        data: http_response_plaintext,
        headerName: header_name,
        nameLen: header_name.length,
        headerValue: header_value,
        valueLen: header_value.length,
        index: 17,
    }
    generatePassCase(input, { out: 1 }, "header name and value matches");

    let input2 = {
        data: http_response_plaintext,
        headerName: header_name,
        nameLen: header_name.length,
        headerValue: header_value,
        valueLen: header_value.length,
        index: 16,
    }
    generatePassCase(input2, { out: 0 }, "incorrect index");
});