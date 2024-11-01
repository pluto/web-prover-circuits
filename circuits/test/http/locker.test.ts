import { circomkit, WitnessTester, generateDescription, toByte } from "../common";
import { readHTTPInputFile } from "../common/http";

describe("HTTP :: Locker :: Request Line", async () => {
    let circuit: WitnessTester<["data", "beginning", "middle", "final"], []>;

    function generatePassCase(input: number[], beginning: number[], middle: number[], final: number[], desc: string) {
        const description = generateDescription(input);

        it(`(valid) witness: ${description} ${desc}`, async () => {
            circuit = await circomkit.WitnessTester(`LockStartLine`, {
                file: "http/locker",
                template: "LockStartLine",
                params: [input.length, beginning.length, middle.length, final.length],
            });
            console.log("#constraints:", await circuit.getConstraintCount());

            await circuit.expectPass({ data: input, beginning: beginning, middle: middle, final: final }, {});
        });
    }

    function generateFailCase(input: number[], beginning: number[], middle: number[], final: number[], desc: string) {
        const description = generateDescription(input);

        it(`(invalid) witness: ${description} ${desc}`, async () => {
            circuit = await circomkit.WitnessTester(`LockStartLine`, {
                file: "http/locker",
                template: "LockStartLine",
                params: [input.length, beginning.length, middle.length, final.length],
            });
            console.log("#constraints:", await circuit.getConstraintCount());

            await circuit.expectFail({ data: input, beginning: beginning, middle: middle, final: final });
        });
    }

    describe("GET", async () => {
        let parsedHttp = readHTTPInputFile("get_request.http");
        generatePassCase(parsedHttp.input, toByte("GET"), toByte("/api"), toByte("HTTP/1.1"), "");
        generateFailCase(parsedHttp.input.slice(0), toByte("POST"), toByte("/api"), toByte("HTTP/1.1"), "");
        generateFailCase(parsedHttp.input.slice(0), toByte("GET"), toByte("/"), toByte("HTTP/1.1"), "");
        generateFailCase(parsedHttp.input.slice(0), toByte("GET"), toByte("/api"), toByte("HTTP"), "");
    });

    describe("POST", async () => {
        let parsedHttp = readHTTPInputFile("post_request.http");
        generatePassCase(parsedHttp.input, toByte("POST"), toByte("/contact_form.php"), toByte("HTTP/1.1"), "");
        generateFailCase(parsedHttp.input.slice(0), toByte("GET"), toByte("/contact_form.php"), toByte("HTTP/1.1"), "");
        generateFailCase(parsedHttp.input.slice(0), toByte("POST"), toByte("/"), toByte("HTTP/1.1"), "");
        generateFailCase(parsedHttp.input.slice(0), toByte("POST"), toByte("/contact_form.php"), toByte("HTTP"), "");
    });
});

describe("HTTP :: Locker :: Status Line", async () => {
    let circuit: WitnessTester<["data", "beginning", "middle", "final"], []>;

    function generatePassCase(input: number[], beginning: number[], middle: number[], final: number[], desc: string) {
        const description = generateDescription(input);

        it(`(valid) witness: ${description} ${desc}`, async () => {
            circuit = await circomkit.WitnessTester(`LockStartLine`, {
                file: "http/locker",
                template: "LockStartLine",
                params: [input.length, beginning.length, middle.length, final.length],
            });
            console.log("#constraints:", await circuit.getConstraintCount());

            await circuit.expectPass({ data: input, beginning: beginning, middle: middle, final: final }, {});
        });
    }

    function generateFailCase(input: number[], beginning: number[], middle: number[], final: number[], desc: string) {
        const description = generateDescription(input);

        it(`(invalid) witness: ${description} ${desc}`, async () => {
            circuit = await circomkit.WitnessTester(`LockStartLine`, {
                file: "http/locker",
                template: "LockStartLine",
                params: [input.length, beginning.length, middle.length, final.length],
            });
            console.log("#constraints:", await circuit.getConstraintCount());

            await circuit.expectFail({ data: input, beginning: beginning, middle: middle, final: final });
        });
    }

    describe("GET", async () => {
        let parsedHttp = readHTTPInputFile("get_response.http");
        generatePassCase(parsedHttp.input, toByte("HTTP/1.1"), toByte("200"), toByte("OK"), "");
        generateFailCase(parsedHttp.input, toByte("HTTP"), toByte("200"), toByte("OK"), "");
        generateFailCase(parsedHttp.input, toByte("HTTP/1.1"), toByte("404"), toByte("OK"), "");
        generateFailCase(parsedHttp.input, toByte("HTTP/1.1"), toByte("200"), toByte("Not Found"), "");
    });
});

describe("HTTP :: Locker :: Header", async () => {
    let circuit: WitnessTester<["data", "header", "value"], []>;

    function generatePassCase(input: number[], header: number[], value: number[], desc: string) {
        const description = generateDescription(input);

        it(`(valid) witness: ${description} ${desc}`, async () => {
            circuit = await circomkit.WitnessTester(`LockHeader`, {
                file: "http/locker",
                template: "LockHeader",
                params: [input.length, header.length, value.length],
            });
            console.log("#constraints:", await circuit.getConstraintCount());

            await circuit.expectPass({ data: input, header: header, value: value }, {});
        });
    }

    function generateFailCase(input: number[], header: number[], value: number[], desc: string) {
        const description = generateDescription(input);

        it(`(invalid) witness: ${description} ${desc}`, async () => {
            circuit = await circomkit.WitnessTester(`LockHeader`, {
                file: "http/locker",
                template: "LockHeader",
                params: [input.length, header.length, value.length],
            });
            console.log("#constraints:", await circuit.getConstraintCount());

            await circuit.expectFail({ data: input, header: header, value: value });
        });
    }

    describe("GET", async () => {
        let parsedHttp = readHTTPInputFile("get_request.http");
        generatePassCase(parsedHttp.input, toByte("Host"), toByte("localhost"), "");
        generateFailCase(parsedHttp.input, toByte("Accept"), toByte("localhost"), "");
        generateFailCase(parsedHttp.input, toByte("Host"), toByte("venmo.com"), "");
        generateFailCase(parsedHttp.input, toByte("Connection"), toByte("keep-alive"), "");
    });
});