import { CircuitSignals } from "circomkit";
import { circomkit, WitnessTester, toByte } from "../common";

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

describe("NIVC_FULL", async () => {
    let aesCircuit: WitnessTester<["key", "iv", "aad", "ctr", "plainText", "step_in"], ["step_out"]>;
    let httpParseAndLockStartLineCircuit: WitnessTester<["step_in", "data", "beginning", "beginning_length", "middle", "middle_length", "final", "final_length"], ["step_out"]>;
    let lockHeaderCircuit: WitnessTester<["step_in", "data", "header", "headerNameLength", "value", "headerValueLength"], ["step_out"]>;
    // let bodyMaskCircuit: WitnessTester<["step_in"], ["step_out"]>;
    // let parse_circuit: WitnessTester<["step_in"], ["step_out"]>;
    // let json_mask_object_circuit: WitnessTester<["step_in", "key", "keyLen"], ["step_out"]>;
    // let json_mask_arr_circuit: WitnessTester<["step_in", "index"], ["step_out"]>;
    // let extract_value_circuit: WitnessTester<["step_in"], ["step_out"]>;

    const DATA_BYTES = 320;
    const MAX_STACK_HEIGHT = 5;
    const TOTAL_BYTES_ACROSS_NIVC = 1;

    const MAX_HEADER_NAME_LENGTH = 20;
    const MAX_HEADER_VALUE_LENGTH = 35;
    const MAX_BEGINNING_LENGTH = 10;
    const MAX_MIDDLE_LENGTH = 30;
    const MAX_FINAL_LENGTH = 10;

    const beginning = [72, 84, 84, 80, 47, 49, 46, 49]; // HTTP/1.1
    const middle = [50, 48, 48]; // 200
    const final = [79, 75]; // OK

    const MAX_KEY_LENGTH = 8;
    const MAX_VALUE_LENGTH = 35;

    before(async () => {
        // aesCircuit = await circomkit.WitnessTester("AESGCTRFOLD", {
        //     file: "aes-gcm/nivc/aes-gctr-nivc",
        //     template: "AESGCTRFOLD",
        // });
        // console.log("#constraints (AES-GCTR):", await aesCircuit.getConstraintCount());

        httpParseAndLockStartLineCircuit = await circomkit.WitnessTester(`ParseAndLockStartLine`, {
            file: "http/nivc/parse_and_lock_start_line",
            template: "ParseAndLockStartLine",
            params: [DATA_BYTES, MAX_BEGINNING_LENGTH, MAX_MIDDLE_LENGTH, MAX_FINAL_LENGTH],
        });
        console.log("#constraints (HTTP-PARSE-AND-LOCK-START-LINE):", await httpParseAndLockStartLineCircuit.getConstraintCount());

        lockHeaderCircuit = await circomkit.WitnessTester(`LockHeader`, {
            file: "http/nivc/lock_header",
            template: "LockHeader",
            params: [DATA_BYTES, MAX_HEADER_NAME_LENGTH, MAX_HEADER_VALUE_LENGTH],
        });
        console.log("#constraints (HTTP-LOCK-HEADER):", await lockHeaderCircuit.getConstraintCount());

        // bodyMaskCircuit = await circomkit.WitnessTester(`BodyMask`, {
        //     file: "http/nivc/body_mask",
        //     template: "HTTPMaskBodyNIVC",
        //     params: [DATA_BYTES],
        // });
        // console.log("#constraints (HTTP-BODY-MASK):", await bodyMaskCircuit.getConstraintCount());

        // json_mask_arr_circuit = await circomkit.WitnessTester(`JsonMaskArrayIndexNIVC`, {
        //     file: "json/nivc/masker",
        //     template: "JsonMaskArrayIndexNIVC",
        //     params: [DATA_BYTES, MAX_STACK_HEIGHT],
        // });
        // console.log("#constraints (JSON-MASK-ARRAY-INDEX):", await json_mask_arr_circuit.getConstraintCount());

        // json_mask_object_circuit = await circomkit.WitnessTester(`JsonMaskObjectNIVC`, {
        //     file: "json/nivc/masker",
        //     template: "JsonMaskObjectNIVC",
        //     params: [DATA_BYTES, MAX_STACK_HEIGHT, MAX_KEY_LENGTH],
        // });
        // console.log("#constraints (JSON-MASK-OBJECT):", await json_mask_object_circuit.getConstraintCount());

        // extract_value_circuit = await circomkit.WitnessTester(`JsonMaskExtractFinal`, {
        //     file: "json/nivc/extractor",
        //     template: "MaskExtractFinal",
        //     params: [DATA_BYTES, MAX_VALUE_LENGTH],
        // });
        // console.log("#constraints (JSON-MASK-EXTRACT-FINAL):", await extract_value_circuit.getConstraintCount());
    });


    let headerName = toByte("content-type")
    let headerValue = toByte("application/json; charset=utf-8");

    let headerNamePadded = headerName.concat(Array(MAX_HEADER_NAME_LENGTH - headerName.length).fill(0));
    let headerValuePadded = headerValue.concat(Array(MAX_HEADER_VALUE_LENGTH - headerValue.length).fill(0));
    let beginningPadded = beginning.concat(Array(MAX_BEGINNING_LENGTH - beginning.length).fill(0));
    let middlePadded = middle.concat(Array(MAX_MIDDLE_LENGTH - middle.length).fill(0));
    let finalPadded = final.concat(Array(MAX_FINAL_LENGTH - final.length).fill(0));
    it("NIVC_CHAIN", async () => {
        // Run the 0th chunk of plaintext
        // let ctr = [0x00, 0x00, 0x00, 0x01];
        // const init_nivc_input = 0;

        // let pt = http_response_plaintext.slice(0, 16);
        // let aes_gcm = await aesCircuit.compute({ key: Array(16).fill(0), iv: Array(12).fill(0), ctr: ctr, plainText: pt, aad: Array(16).fill(0), step_in: init_nivc_input }, ["step_out"]);
        // let i = 0;
        // console.log("AES step_out[", i, "]: ", i, aes_gcm.step_out);
        // for (i = 1; i < (DATA_BYTES / 16); i++) {
        //     ctr[3] += 1; // This will work since we don't run a test that overlows a byte
        //     let pt = http_response_plaintext.slice(i * 16, i * 16 + 16);
        //     aes_gcm = await aesCircuit.compute({ key: Array(16).fill(0), iv: Array(12).fill(0), ctr: ctr, plainText: pt, aad: Array(16).fill(0), step_in: aes_gcm.step_out }, ["step_out"]);
        //     console.log("AES step_out[", i, "]: ", i, aes_gcm.step_out);
        // }
        // temp
        let temp_step_in = [BigInt("2195365663909569734943279727560535141179588918483111718403427949138562480675")];

        // console.log(temp_step_in);
        let parseAndLockStartLine = await httpParseAndLockStartLineCircuit.compute({ step_in: temp_step_in, data: http_response_plaintext, beginning: beginningPadded, beginning_length: beginning.length, middle: middlePadded, middle_length: middle.length, final: finalPadded, final_length: final.length }, ["step_out"]);
        // let parseAndLockStartLine = await httpParseAndLockStartLineCircuit.compute({ step_in: aes_gcm.step_out, data: http_response_plaintext, beginning: beginningPadded, beginning_length: beginning.length, middle: middlePadded, middle_length: middle.length, final: finalPadded, final_length: final.length }, ["step_out"]);
        // let parseAndLockStartLine = await httpParseAndLockStartLineCircuit.calculateWitness
        //     ({ step_in: temp_step_in, data: http_response_plaintext, beginning: beginningPadded, beginning_length: beginning.length, middle: middlePadded, middle_length: middle.length, final: finalPadded, final_length: final.length });
        // console.log(parseAndLockStartLine.entries);
        // const entriesArray = Array.from(parseAndLockStartLine.entries());
        // entriesArray.slice(0, 20).forEach(([index, value]) => {
        //     console.log(`Index ${index}: ${value.toString()}`);
        // });
        // console.log(await httpParseAndLockStartLineCircuit.readWitnessSignals(parseAndLockStartLine, ["step_in"]));
        // readWitnessSignals(witness: Readonly<WitnessType>, signals: string[] | OUT): Promise<CircuitSignals>;
        // console.log("Start Line step_out: ", parseAndLockStartLine);
        // let lockHeader = await lockHeaderCircuit.compute({ step_in: parseAndLockStartLine.step_out, data: http_response_plaintext, header: headerNamePadded, headerNameLength: headerName.length, value: headerValuePadded, headerValueLength: headerValue.length }, ["step_out"]);
        // let lockHeader = await lockHeaderCircuit.compute({
        //     step_in: temp_step_in, data: http_response_plaintext, header: headerNamePadded, headerNameLength: headerName.length, value: headerValuePadded, headerValueLength: headerValue.length
        // }, ["step_out"]);

        // console.log("Lock Header step_out: ", lockHeader.step_out);

        // let bodyMask = await bodyMaskCircuit.compute({ step_in: lockHeader.step_out }, ["step_out"]);

        // let bodyMaskOut = bodyMask.step_out as number[];
        // let idx = bodyMaskOut.indexOf('{'.charCodeAt(0));

        // let maskedInput = extendedJsonInput.fill(0, 0, idx);
        // maskedInput = maskedInput.fill(0, 320);

        // let key0 = [100, 97, 116, 97, 0, 0, 0, 0]; // "data"
        // let key0Len = 4;
        // let key1 = [105, 116, 101, 109, 115, 0, 0, 0]; // "items"
        // let key1Len = 5;
        // let key2 = [112, 114, 111, 102, 105, 108, 101, 0]; // "profile"
        // let key2Len = 7;
        // let key3 = [110, 97, 109, 101, 0, 0, 0, 0]; // "name"
        // let key3Len = 4;

        // let value = toByte("\"Taylor Swift\"");

        // let json_extract_key0 = await json_mask_object_circuit.compute({ step_in: bodyMaskOut, key: key0, keyLen: key0Len }, ["step_out"]);

        // let json_num = json_extract_key0.step_out as number[];
        // console.log("json_extract_key0", json_num);
        // let json_extract_key1 = await json_mask_object_circuit.compute({ step_in: json_extract_key0.step_out, key: key1, keyLen: key1Len }, ["step_out"]);

        // let json_extract_arr = await json_mask_arr_circuit.compute({ step_in: json_extract_key1.step_out, index: 0 }, ["step_out"]);

        // let json_extract_key2 = await json_mask_object_circuit.compute({ step_in: json_extract_arr.step_out, key: key2, keyLen: key2Len }, ["step_out"]);

        // let json_extract_key3 = await json_mask_object_circuit.compute({ step_in: json_extract_key2.step_out, key: key3, keyLen: key3Len }, ["step_out"]);

        // await extract_value_circuit.expectPass({ step_in: json_extract_key3.step_out }, { step_out: value });
    });
});