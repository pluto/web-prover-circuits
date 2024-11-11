import { circomkit, WitnessTester, toByte } from "../../common";
import { readHTTPInputFile } from "../../common/http";
import { DataHasher } from "../../common/poseidon";

describe("HTTPParseAndLockStartLine", async () => {
    let httpParseAndLockStartLineCircuit: WitnessTester<["step_in", "data", "beginning", "beginning_length", "middle", "middle_length", "final", "final_length"], ["step_out"]>;

    const DATA_BYTES = 336;

    const MAX_BEGINNING_LENGTH = 10;
    const MAX_MIDDLE_LENGTH = 50;
    const MAX_FINAL_LENGTH = 10;

    before(async () => {
        httpParseAndLockStartLineCircuit = await circomkit.WitnessTester(`ParseAndLockStartLine`, {
            file: "http/nivc/parse_and_lock_start_line",
            template: "ParseAndLockStartLine",
            params: [DATA_BYTES, MAX_BEGINNING_LENGTH, MAX_MIDDLE_LENGTH, MAX_FINAL_LENGTH],
        });
        console.log("#constraints:", await httpParseAndLockStartLineCircuit.getConstraintCount());
    });

    function generatePassCase(input: number[], beginning: number[], middle: number[], final: number[], desc: string) {
        it(`(valid) witness: ${desc}`, async () => {
            let extendedInput = input.concat(Array(Math.max(0, DATA_BYTES - input.length)).fill(0));
            const http_response_hash = DataHasher(extendedInput);

            let beginningPadded = beginning.concat(Array(MAX_BEGINNING_LENGTH - beginning.length).fill(0));
            let middlePadded = middle.concat(Array(MAX_MIDDLE_LENGTH - middle.length).fill(0));
            let finalPadded = final.concat(Array(MAX_FINAL_LENGTH - final.length).fill(0));

            await httpParseAndLockStartLineCircuit.expectPass({ step_in: [http_response_hash], data: extendedInput, beginning: beginningPadded, beginning_length: beginning.length, middle: middlePadded, middle_length: middle.length, final: finalPadded, final_length: final.length });
        });
    }

    function generateFailCase(input: number[], beginning: number[], middle: number[], final: number[], desc: string) {
        it(`(valid) witness: ${desc}`, async () => {
            let extendedInput = input.concat(Array(Math.max(0, DATA_BYTES - input.length)).fill(0));
            const http_response_hash = DataHasher(extendedInput);


            let beginningPadded = beginning.concat(Array(MAX_BEGINNING_LENGTH - beginning.length).fill(0));
            let middlePadded = middle.concat(Array(MAX_MIDDLE_LENGTH - middle.length).fill(0));
            let finalPadded = final.concat(Array(MAX_FINAL_LENGTH - final.length).fill(0));

            await httpParseAndLockStartLineCircuit.expectFail({ step_in: [http_response_hash], data: extendedInput, beginning: beginningPadded, beginning_length: beginning.length, middle: middlePadded, middle_length: middle.length, final: finalPadded, final_length: final.length });
        });
    }

    describe("request", async () => {
        let { input, } = readHTTPInputFile("spotify_top_artists_request.http");

        let beginning = toByte("GET");
        let middle = toByte("/v1/me/top/artists?time_range=medium_term&limit=1");
        let final = toByte("HTTP/1.1");

        generatePassCase(input, beginning, middle, final, "should pass request");

        let incorrectBeginning = toByte("DELETE");
        generateFailCase(input, incorrectBeginning, middle, final, "should fail: incorrect BEGINNING");

        let incorrectMiddle = toByte("/contact_form.php");
        generateFailCase(input, beginning, incorrectMiddle, final, "should fail: incorrect MIDDLE");

        let incorrectFinal = toByte("HTTP/2");
        generateFailCase(input, beginning, middle, incorrectFinal, "should fail: incorrect FINAL");
    })

    describe("response", async () => {
        let { input, } = readHTTPInputFile("spotify_top_artists_response.http");
        let beginning = toByte("HTTP/1.1");
        let middle = toByte("200");
        let final = toByte("OK");

        generatePassCase(input, beginning, middle, final, "should pass response"); it

        let incorrectBeginning = toByte("HTTP/2");
        generateFailCase(input, incorrectBeginning, middle, final, "should fail: incorrect BEGINNING");

        let incorrectMiddle = toByte("2000");
        generateFailCase(input, beginning, incorrectMiddle, final, "should fail: incorrect MIDDLE");

        let incorrectFinal = toByte("INVALID");
        generateFailCase(input, beginning, middle, incorrectFinal, "should fail: incorrect FINAL");
    });
});