import { circomkit, WitnessTester, toByte } from "../common";
import { readHTTPInputFile, readLockFile, getHeaders, Request, Response } from "../common/http";
import { join } from "path";
import { spawn } from "child_process";


export function executeCodegen(circuitName: string, inputFileName: string, lockfileName: string) {
    return new Promise((resolve, reject) => {
        const inputFilePath = join(__dirname, "..", "..", "..", "examples", "http", inputFileName);
        const lockfilePath = join(__dirname, "..", "..", "..", "examples", "http", "lockfile", lockfileName);

        const codegen = spawn("cargo", ["run", "codegen", "http", "--circuit-name", circuitName, "--input-file", inputFilePath, "--lockfile", lockfilePath]);

        codegen.stdout.on('data', (data) => {
            console.log(`stdout: ${data}`);
        });

        codegen.stderr.on('data', (data) => {
            console.error(`stderr: ${data}`);
        });

        codegen.on('close', (code) => {
            if (code === 0) {
                resolve(`child process exited with code ${code}`); // Resolve the promise if the process exits successfully
            } else {
                reject(new Error(`Process exited with code ${code}`)); // Reject if there's an error
            }
        });
    });
}

describe("HTTP :: Codegen :: Request", async () => {
    let circuit: WitnessTester<["data", "method", "target", "version", "header1", "value1", "header2", "value2"], []>;

    it("(valid) GET:", async () => {
        let lockfile = "request.lock";
        let inputfile = "get_request.http";
        let circuitName = "get_request_test";

        // generate extractor circuit using codegen
        await executeCodegen(circuitName, inputfile, `${lockfile}.json`);

        const lockData = readLockFile<Request>(`${lockfile}.json`);
        console.log("lockData: ", JSON.stringify(lockData));

        const input = readHTTPInputFile(`${inputfile}`).input;

        const headers = getHeaders(lockData);
        const params = [input.length, lockData.method.length, lockData.target.length, lockData.version.length];
        headers.forEach(header => {
            params.push(header[0].length);
            params.push(header[1].length);
        });


        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/http_${circuitName}`,
            template: "LockHTTPRequest",
            params: params,
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        // match circuit output to original JSON value
        const circuitInput: any = {
            data: input,
            method: toByte(lockData.method),
            target: toByte(lockData.target),
            version: toByte(lockData.version),
        };

        headers.forEach((header, index) => {
            circuitInput[`header${index + 1}`] = toByte(header[0]);
            circuitInput[`value${index + 1}`] = toByte(header[1]);
        });
        await circuit.expectPass(circuitInput, {});
    });

    it("(invalid) GET:", async () => {
        let lockfile = "request.lock";
        let inputfile = "get_request.http";
        let circuitName = "get_request_test";

        // generate extractor circuit using codegen
        await executeCodegen(circuitName, inputfile, `${lockfile}.json`);

        const lockData = readLockFile<Request>(`${lockfile}.json`);

        const input = readHTTPInputFile(`${inputfile}`).input

        const headers = getHeaders(lockData);
        const params = [input.length, lockData.method.length, lockData.target.length, lockData.version.length];
        headers.forEach(header => {
            params.push(header[0].length);
            params.push(header[1].length);
        });


        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/http_${circuitName}`,
            template: "LockHTTPRequest",
            params: params,
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        const circuitInput: any = {
            data: input,
            method: toByte(lockData.method),
            target: toByte(lockData.target),
            version: toByte(lockData.version),
        };

        headers.forEach((header, index) => {
            circuitInput[`header${index + 1}`] = toByte(header[0]);
            circuitInput[`value${index + 1}`] = toByte(header[1]);
        });

        circuitInput.value1 = toByte("/aip");
        await circuit.expectFail(circuitInput);
    });
});

describe("HTTP :: Codegen :: Response", async () => {
    let circuit: WitnessTester<["data", "version", "status", "message", "header1", "value1", "header2", "value2"], ["body"]>;

    it("(valid) GET:", async () => {
        let lockfile = "response.lock";
        let inputfile = "get_response.http";
        let circuitName = "get_response_test";

        // generate extractor circuit using codegen
        await executeCodegen(circuitName, inputfile, `${lockfile}.json`);

        const lockData = readLockFile<Response>(`${lockfile}.json`);
        console.log("lockData: ", JSON.stringify(lockData));

        const http = readHTTPInputFile(`${inputfile}`);
        const input = http.input;

        const headers = getHeaders(lockData);

        const params = [input.length, parseInt(http.headers["Content-Length".toLowerCase()]), lockData.version.length, lockData.status.length, lockData.message.length];
        headers.forEach(header => {
            params.push(header[0].length);
            params.push(header[1].length);
        });


        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/http_${circuitName}`,
            template: "LockHTTPResponse",
            params: params,
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        // match circuit output to original JSON value
        const circuitInput: any = {
            data: input,
            version: toByte(lockData.version),
            status: toByte(lockData.status),
            message: toByte(lockData.message),
        };

        headers.forEach((header, index) => {
            circuitInput[`header${index + 1}`] = toByte(header[0]);
            circuitInput[`value${index + 1}`] = toByte(header[1]);
        });


        await circuit.expectPass(circuitInput, { body: http.bodyBytes });
    });

    it("(invalid) GET:", async () => {
        let lockfile = "response.lock";
        let inputfile = "get_response.http";
        let circuitName = "get_response_test";

        // generate extractor circuit using codegen
        await executeCodegen(circuitName, inputfile, `${lockfile}.json`);

        const lockData = readLockFile<Response>(`${lockfile}.json`);

        const http = readHTTPInputFile(`${inputfile}`);
        const input = http.input;

        const headers = getHeaders(lockData);

        const params = [input.length, parseInt(http.headers["Content-Length".toLowerCase()]), lockData.version.length, lockData.status.length, lockData.message.length];
        headers.forEach(header => {
            params.push(header[0].length);
            params.push(header[1].length);
        });


        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/http_${circuitName}`,
            template: "LockHTTPResponse",
            params: params,
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        const circuitInput: any = {
            data: input,
            version: toByte(lockData.version),
            status: toByte(lockData.status),
            message: toByte(lockData.message),
        };

        headers.forEach((header, index) => {
            circuitInput[`header${index + 1}`] = toByte(header[0]);
            circuitInput[`value${index + 1}`] = toByte(header[1]);
        });

        circuitInput.value1 = toByte("/aip");
        await circuit.expectFail(circuitInput);
    });
});

describe("spotify_top_artists_http", async () => {
    let http_circuit: WitnessTester<["data", "version", "status", "message", "header1", "value1"], ["body"]>;

    it("POST response body", async () => {
        let httpLockfile = "spotify.lock"
        let httpInputFile = "spotify_top_artists_response.http";
        let httpCircuitName = "spotify_top_artists";

        await executeCodegen(`${httpCircuitName}_test`, httpInputFile, `${httpLockfile}.json`);

        const lockData = readLockFile<Response>(`${httpLockfile}.json`);

        const http = readHTTPInputFile(`${httpInputFile}`);
        const inputHttp = http.input;

        const headers = getHeaders(lockData);

        const params = [inputHttp.length, http.bodyBytes.length, lockData.version.length, lockData.status.length, lockData.message.length];
        headers.forEach(header => {
            params.push(header[0].length);
            params.push(header[1].length);
        });

        http_circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/http_${httpCircuitName}_test`,
            template: "LockHTTPResponse",
            params: params,
        });
        console.log("#constraints:", await http_circuit.getConstraintCount());

        // match circuit output to original JSON value
        const circuitInput: any = {
            data: inputHttp,
            version: toByte(lockData.version),
            status: toByte(lockData.status),
            message: toByte(lockData.message),
        };

        headers.forEach((header, index) => {
            circuitInput[`header${index + 1}`] = toByte(header[0]);
            circuitInput[`value${index + 1}`] = toByte(header[1]);
        });

        await http_circuit.expectPass(circuitInput, { body: http.bodyBytes });
    });
});