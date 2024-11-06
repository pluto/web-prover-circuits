import { circomkit, WitnessTester, toByte } from "../../common";
import { readHTTPInputFile } from "../../common/http";

describe("HTTPLockHeader", async () => {
    let httpParseAndLockStartLineCircuit: WitnessTester<["step_in", "beginning", "beginning_length", "middle", "middle_length", "final", "final_length"], ["step_out"]>;
    let lockHeaderCircuit: WitnessTester<["step_in", "header", "headerNameLength", "value", "headerValueLength"], ["step_out"]>;

    const DATA_BYTES = 320;
    const TOTAL_BYTES_ACROSS_NIVC = DATA_BYTES * 2 + 4;

    const MAX_BEGINNING_LENGTH = 10;
    const MAX_MIDDLE_LENGTH = 50;
    const MAX_FINAL_LENGTH = 10;
    const MAX_HEADER_NAME_LENGTH = 20;
    const MAX_HEADER_VALUE_LENGTH = 35;

    before(async () => {
        httpParseAndLockStartLineCircuit = await circomkit.WitnessTester(`ParseAndLockStartLine`, {
            file: "http/nivc/parse_and_lock_start_line",
            template: "ParseAndLockStartLine",
            params: [DATA_BYTES, MAX_BEGINNING_LENGTH, MAX_MIDDLE_LENGTH, MAX_FINAL_LENGTH],
        });
        console.log("#constraints:", await httpParseAndLockStartLineCircuit.getConstraintCount());

        lockHeaderCircuit = await circomkit.WitnessTester(`LockHeader`, {
            file: "http/nivc/lock_header",
            template: "LockHeader",
            params: [DATA_BYTES, MAX_HEADER_NAME_LENGTH, MAX_HEADER_VALUE_LENGTH],
        });
        console.log("#constraints:", await lockHeaderCircuit.getConstraintCount());
    });

    function generatePassCase(input: number[], beginning: number[], middle: number[], final: number[], headerName: number[], headerValue: number[], desc: string) {
        it(`should pass: \"${headerName}: ${headerValue}\", ${desc}`, async () => {
            let extendedInput = input.concat(Array(Math.max(0, TOTAL_BYTES_ACROSS_NIVC - input.length)).fill(0));

            let beginningPadded = beginning.concat(Array(MAX_BEGINNING_LENGTH - beginning.length).fill(0));
            let middlePadded = middle.concat(Array(MAX_MIDDLE_LENGTH - middle.length).fill(0));
            let finalPadded = final.concat(Array(MAX_FINAL_LENGTH - final.length).fill(0));

            let headerNamePadded = headerName.concat(Array(MAX_HEADER_NAME_LENGTH - headerName.length).fill(0));
            let headerValuePadded = headerValue.concat(Array(MAX_HEADER_VALUE_LENGTH - headerValue.length).fill(0));

            let parseAndLockStartLine = await httpParseAndLockStartLineCircuit.compute({ step_in: extendedInput, beginning: beginningPadded, beginning_length: beginning.length, middle: middlePadded, middle_length: middle.length, final: finalPadded, final_length: final.length }, ["step_out"]);

            await lockHeaderCircuit.expectPass({ step_in: parseAndLockStartLine.step_out, header: headerNamePadded, headerNameLength: headerName.length, value: headerValuePadded, headerValueLength: headerValue.length });
        });
    }

    function generateFailCase(input: number[], beginning: number[], middle: number[], final: number[], headerName: number[], headerValue: number[], desc: string) {
        it(`should fail: ${desc}`, async () => {
            let extendedInput = input.concat(Array(Math.max(0, TOTAL_BYTES_ACROSS_NIVC - input.length)).fill(0));

            let beginningPadded = beginning.concat(Array(MAX_BEGINNING_LENGTH - beginning.length).fill(0));
            let middlePadded = middle.concat(Array(MAX_MIDDLE_LENGTH - middle.length).fill(0));
            let finalPadded = final.concat(Array(MAX_FINAL_LENGTH - final.length).fill(0));

            let headerNamePadded = headerName.concat(Array(MAX_HEADER_NAME_LENGTH - headerName.length).fill(0));
            let headerValuePadded = headerValue.concat(Array(MAX_HEADER_VALUE_LENGTH - headerValue.length).fill(0));

            let parseAndLockStartLine = await httpParseAndLockStartLineCircuit.compute({ step_in: extendedInput, beginning: beginningPadded, beginning_length: beginning.length, middle: middlePadded, middle_length: middle.length, final: finalPadded, final_length: final.length }, ["step_out"]);

            await lockHeaderCircuit.expectFail({ step_in: parseAndLockStartLine.step_out, header: headerNamePadded, headerNameLength: headerName.length, value: headerValuePadded, headerValueLength: headerValue.length });
        });
    }

    describe("request", async () => {
        let { input, headers } = readHTTPInputFile("post_request.http");

        let beginning = toByte("POST");
        let middle = toByte("/contact_form.php");
        let final = toByte("HTTP/1.1");

        let headerName = toByte("Host");
        let headerValue = toByte("developer.mozilla.org");

        for (const [key, value] of Object.entries(headers)) {
            generatePassCase(input, beginning, middle, final, toByte(key), toByte(value), "request");
        }
        let incorrectHeaderValue = toByte("application/json");
        generateFailCase(input, beginning, middle, final, headerName, incorrectHeaderValue, "incorrect header value");
    });

    describe("response", async () => {
        let { input, headers } = readHTTPInputFile("spotify_top_artists_response.http");
        let beginning = toByte("HTTP/1.1");
        let middle = toByte("200");
        let final = toByte("OK");

        for (const [key, value] of Object.entries(headers)) {
            generatePassCase(input, beginning, middle, final, toByte(key), toByte(value), "response");
        }

        let headerName = toByte("content-encoding");
        let invalidHeaderValue = toByte("chunked");
        generateFailCase(input, beginning, middle, final, headerName, invalidHeaderValue, "should fail: invalid header value");
    });
});