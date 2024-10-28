import { circomkit, WitnessTester, readJSONInputFile, toByte } from "../../common";
import { join } from "path";
import { spawn } from "child_process";


export function executeCodegen(circuitName: string, inputFileName: string, lockfileName: string) {
    return new Promise((resolve, reject) => {
        const inputFilePath = join(__dirname, "..", "..", "..", "..", "examples", "json", "test", inputFileName);
        const lockfilePath = join(__dirname, "..", "..", "..", "..", "examples", "json", "lockfile", lockfileName);

        const codegen = spawn("cargo", ["run", "codegen", "json", "--circuit-name", circuitName, "--input-file", inputFilePath, "--lockfile", lockfilePath]);

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

describe("ExtractValue", async () => {
    let circuit: WitnessTester<["data", "key1"], ["value"]>;

    it("value_string: {\"a\": \"b\"}", async () => {
        let filename = "value_string";

        // generate extractor circuit using codegen
        await executeCodegen(`${filename}_test`, `${filename}.json`, `${filename}.json`);

        // read JSON input file into bytes
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, ["k"]);

        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/json_${filename}_test`,
            template: "ExtractStringValue",
            params: [input.length, 1, 1, 0, 1],
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        // match circuit output to original JSON value
        await circuit.expectPass({
            data: input, key1: keyUnicode,
        }, {
            value: output,
        });
    });

    it("two_keys: {\"key1\": \"abc\", \"key2\": \"def\" }", async () => {
        let filename = "two_keys"
        await executeCodegen(`${filename}_test`, `${filename}.json`, `${filename}.json`);
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, ["key2"]);

        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/json_${filename}_test`,
            template: "ExtractStringValue",
            params: [input.length, 1, 4, 0, 3],
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        await circuit.expectPass({ data: input, key1: keyUnicode }, { value: output });
    });

    it("value_number: {\"k\": 69 }", async () => {
        let filename = "value_number";
        await executeCodegen(`${filename}_test`, `${filename}.json`, `${filename}.json`);
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, ["k"]);

        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/json_${filename}_test`,
            template: "ExtractNumValue",
            params: [input.length, 1, 1, 0, 2],
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        let num = parseInt(output.map(num => String.fromCharCode(num)).join(''), 10);

        await circuit.expectPass({ data: input, key1: keyUnicode }, { value: num });
    });

    it("value_array_string: { \"k\" : [   420 , 69 , 4200 , 600 ], \"b\": [ \"ab\" ,  \"ba\",  \"ccc\", \"d\" ] }", async () => {
        let filename = "value_array_string";
        let inputFileName = "value_array.json";
        await executeCodegen(`${filename}_test`, inputFileName, `${filename}.json`);

        for (let i = 0; i < 4; i++) {
            let [input, keyUnicode, output] = readJSONInputFile(inputFileName, ["b", i]);

            circuit = await circomkit.WitnessTester(`Extract`, {
                file: `main/json_${filename}_test`,
                template: "ExtractStringValue",
                params: [input.length, 2, 1, 0, i, 1, output.length],
            });
            console.log("#constraints:", await circuit.getConstraintCount());

            await circuit.expectPass({ data: input, key1: keyUnicode[0] }, { value: output });
        }
    });

    it("value_array_number: { \"k\" : [   420 , 69 , 4200 , 600 ], \"b\": [ \"ab\" ,  \"ba\",  \"ccc\", \"d\" ] }", async () => {
        let filename = "value_array_number";
        let inputFileName = "value_array.json";

        await executeCodegen(`${filename}_test`, inputFileName, `${filename}.json`);

        for (let i = 0; i < 4; i++) {
            let [input, keyUnicode, output] = readJSONInputFile(inputFileName, ["k", i]);

            circuit = await circomkit.WitnessTester(`Extract`, {
                file: `main/json_${filename}_test`,
                template: "ExtractNumValue",
                params: [input.length, 2, 1, 0, i, 1, output.length],
            });
            console.log("#constraints:", await circuit.getConstraintCount());

            let num = parseInt(output.map(num => String.fromCharCode(num)).join(''), 10);
            await circuit.expectPass({ data: input, key1: keyUnicode[0] }, { value: num });
        }
    });

    it("value_array_nested: { \"a\": [[1,0],[0,1,3]] }", async () => {
        let filename = "value_array_nested";
        await executeCodegen(`${filename}_test`, `${filename}.json`, `${filename}.json`);
        let index_0 = 1;
        let index_1 = 0;
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, ["a", index_0, index_1]);

        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/json_${filename}_test`,
            template: "ExtractNumValue",
            params: [input.length, 3, 1, 0, index_0, 1, index_1, 2, 1],
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        let num = parseInt(output.map(num => String.fromCharCode(num)).join(''), 10);

        // console.log("input", input, "key:", keyUnicode, "output:", output);
        await circuit.expectPass({ data: input, key1: keyUnicode[0] }, { value: num });
    });
});

describe("ExtractValueMultiDepth", () => {
    let circuit: WitnessTester<["data", "key1", "key2"], ["value"]>;

    it("value_object: { \"a\": { \"d\" : \"e\", \"e\": \"c\" }, \"e\": { \"f\": \"a\", \"e\": \"2\" } }", async () => {
        let filename = "value_object";

        await executeCodegen(`${filename}_test`, `${filename}.json`, `${filename}.json`);

        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, ["e", "e"]);

        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/json_${filename}_test`,
            template: "ExtractStringValue",
            params: [input.length, 3, 1, 0, 1, 1, 1],
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        await circuit.expectPass({ data: input, key1: keyUnicode[0], key2: keyUnicode[1] }, { value: output });

        let [input1, keyUnicode1, output1] = readJSONInputFile("value_object.json", ["e", "f"]);
        await circuit.expectPass({ data: input1, key1: keyUnicode1[0], key2: keyUnicode1[1] }, { value: output1 });
    });


});

describe("ExtractValueArrayObject", () => {
    let circuit: WitnessTester<["data", "key1", "key3"], ["value"]>;

    it("value_array_object: {\"a\":[{\"b\":[1,4]},{\"c\":\"b\"}]}", async () => {
        let filename = "value_array_object";

        await executeCodegen(`${filename}_test`, `${filename}.json`, `${filename}.json`);

        let index_0 = 0;
        let index_1 = 0;
        let [input, keyUnicode, output] = readJSONInputFile(`${filename}.json`, ["a", index_0, "b", index_1]);

        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/json_${filename}_test`,
            template: "ExtractNumValue",
            params: [input.length, 4, 1, 0, index_0, 1, 1, 2, index_1, 3, 1],
        });
        console.log("#constraints:", await circuit.getConstraintCount());

        let num = parseInt(output.map(num => String.fromCharCode(num)).join(''), 10);

        await circuit.expectPass({ data: input, key1: keyUnicode[0], key3: keyUnicode[2] }, { value: num });
    });
});

describe("spotify_top_artists_json", async () => {
    let json_circuit: WitnessTester<["data", "key1", "key2", "key4", "key5"], ["value"]>;

    it("response matcher", async () => {
        let jsonFilename = "spotify";

        await executeCodegen(`${jsonFilename}_test`, `${jsonFilename}.json`, `${jsonFilename}.json`);

        let index_0 = 0;

        let [inputJson, key, output] = readJSONInputFile(
            `${jsonFilename}.json`,
            [
                "data",
                "items",
                index_0,
                "profile",
                "name"
            ]
        );

        json_circuit = await circomkit.WitnessTester(`Extract`, {
            file: `main/json_${jsonFilename}_test`,
            template: "ExtractStringValue",
            params: [inputJson.length, 5, 4, 0, 5, 1, index_0, 2, 7, 3, 4, 4, 12],
        });
        console.log("#constraints:", await json_circuit.getConstraintCount());

        await json_circuit.expectPass({ data: inputJson, key1: key[0], key2: key[1], key4: key[3], key5: key[4] }, { value: output });
    });
});

describe("array-only", async () => {
    let circuit: WitnessTester<["data", "index"], ["value"]>;
    let jsonFilename = "array_only";
    let inputJson: number[] = [];
    let maxValueLen = 30;

    before(async () => {
        let [jsonFile, key, output] = readJSONInputFile(
            `${jsonFilename}.json`,
            [
                0
            ]
        );
        inputJson = jsonFile;

        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `json/extractor`,
            template: "ArrayIndexExtractor",
            params: [inputJson.length, 2, maxValueLen],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("response-matcher index: 0", async () => {
        let outputs = [52, 50, 44];
        outputs.fill(0, outputs.length, maxValueLen);

        await circuit.expectPass({ data: inputJson, index: 0 }, { value: outputs });
    });

    it("response-matcher index: 1", async () => {
        let outputs = [123, 10, 32, 32, 32, 32, 32, 32, 32, 32, 34, 97, 34, 58, 32, 34, 98, 34, 10, 32, 32, 32, 32, 125];
        outputs.fill(0, outputs.length, maxValueLen);

        await circuit.expectPass({ data: inputJson, index: 1 }, { value: outputs });
    });

    it("response-matcher index: 2", async () => {
        /*
    [
        0,
        1
    ]
        */
        let outputs = [91, 10, 32, 32, 32, 32, 32, 32, 32, 32, 48, 44, 10, 32, 32, 32, 32, 32, 32, 32, 32, 49, 10, 32, 32, 32, 32, 93];
        outputs.fill(0, outputs.length, maxValueLen);

        await circuit.expectPass({ data: inputJson, index: 2 }, { value: outputs });
    });

    it("response-matcher index: 3", async () => {
        // "foobar"
        let outputs = [34, 102, 111, 111, 98, 97, 114, 34];
        outputs.fill(0, outputs.length, maxValueLen);

        await circuit.expectPass({ data: inputJson, index: 3 }, { value: outputs });
    });
});

describe("object-extractor", async () => {
    let circuit: WitnessTester<["data", "key", "keyLen"], ["value"]>;
    let jsonFilename = "value_object";
    let jsonFile: number[] = [];
    let maxDataLen = 200;
    let maxKeyLen = 3;
    let maxValueLen = 30;

    before(async () => {
        let [inputJson, key, output] = readJSONInputFile(
            `${jsonFilename}.json`,
            [
                "a"
            ]
        );
        jsonFile = inputJson.concat(Array(maxDataLen - inputJson.length).fill(0));

        circuit = await circomkit.WitnessTester(`Extract`, {
            file: `json/extractor`,
            template: "ObjectExtractor",
            params: [maxDataLen, 3, maxKeyLen, maxValueLen],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    function generatePassCase(key: number[], output: number[]) {
        output = output.concat(Array(maxValueLen - output.length).fill(0));
        let padded_key = key.concat(Array(maxKeyLen - key.length).fill(0));

        it(`key: ${key}, output: ${output}`, async () => {
            await circuit.expectPass({ data: jsonFile, key: padded_key, keyLen: key.length }, { value: output });
        });
    }

    // { "d" : "e", "e": "c" }
    let output1 = [123, 32, 34, 100, 34, 32, 58, 32, 34, 101, 34, 44, 32, 34, 101, 34, 58, 32, 34, 99, 34, 32, 125];
    generatePassCase(toByte("a"), output1);

    // { "h": { "a": "c" }}
    let output2 = [123, 32, 34, 104, 34, 58, 32, 123, 32, 34, 97, 34, 58, 32, 34, 99, 34, 32, 125, 125];
    generatePassCase(toByte("g"), output2);

    // "foobar"
    let output3 = [34, 102, 111, 111, 98, 97, 114, 34];
    generatePassCase(toByte("ab"), output3);

    // "42"
    // TODO: currently number gives an extra byte. Fix this.
    let output4 = [52, 50, 44];
    generatePassCase(toByte("bc"), output4);

    // [ 0, 1, "a"]
    let output5 = [91, 32, 48, 44, 32, 49, 44, 32, 34, 97, 34, 93];
    generatePassCase(toByte("dc"), output5);
});