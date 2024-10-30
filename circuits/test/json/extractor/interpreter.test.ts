import { circomkit, WitnessTester, generateDescription, readJSONInputFile } from "../../common";

describe("Interpreter", async () => {
    describe("InsideKeyAtTop", async () => {
        let circuit: WitnessTester<["stack", "parsing_string", "parsing_number"], ["out"]>;

        before(async () => {
            circuit = await circomkit.WitnessTester(`InsideKeyAtTop`, {
                file: "json/interpreter",
                template: "InsideKeyAtTop",
                params: [4],
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        function generatePassCase(input: any, expected: any, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                await circuit.expectPass(input, expected);
            });
        }

        let input1 = { stack: [[1, 0], [2, 0], [3, 1], [1, 0]], parsing_string: 1, parsing_number: 0 };
        let output = { out: 1 };
        generatePassCase(input1, output, "");

        let input2 = { stack: [[1, 0], [2, 0], [1, 0], [0, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input2, output, "");

        let input3 = { stack: [[1, 0], [0, 0], [0, 0], [0, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input3, output, "");

        // fail cases

        let input4 = { stack: [[1, 0], [2, 0], [3, 1], [1, 1]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input4, { out: 0 }, "invalid stack");

        let input5 = { stack: [[1, 0], [2, 0], [3, 1], [1, 0]], parsing_string: 1, parsing_number: 1 };
        generatePassCase(input5, { out: 0 }, "parsing number as a key");
    });

    describe("InsideKey", async () => {
        let circuit: WitnessTester<["stack", "parsing_string", "parsing_number"], ["out"]>;

        before(async () => {
            circuit = await circomkit.WitnessTester(`InsideKey`, {
                file: "json/interpreter",
                template: "InsideKey",
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        function generatePassCase(input: any, expected: any, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                await circuit.expectPass(input, expected);
            });
        }

        let input1 = { stack: [1, 0], parsing_string: 1, parsing_number: 0 };
        let output = { out: 1 };
        generatePassCase(input1, output, "");

        // fail cases

        let input2 = { stack: [1, 1], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input2, { out: 0 }, "invalid stack");

        let input3 = { stack: [1, 0], parsing_string: 1, parsing_number: 1 };
        generatePassCase(input3, { out: 0 }, "parsing number as a key");
    });

    describe("InsideValueAtTop", async () => {
        let circuit: WitnessTester<["stack", "parsing_string", "parsing_number"], ["out"]>;

        before(async () => {
            circuit = await circomkit.WitnessTester(`InsideValueAtTop`, {
                file: "json/interpreter",
                template: "InsideValueAtTop",
                params: [4],
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        function generatePassCase(input: any, expected: any, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                await circuit.expectPass(input, expected);
            });
        }

        let input1 = { stack: [[1, 0], [2, 0], [3, 1], [1, 1]], parsing_string: 1, parsing_number: 0 };
        let output = { out: 1 };
        generatePassCase(input1, output, "");

        let input2 = { stack: [[1, 0], [2, 0], [1, 1], [0, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input2, output, "");

        let input3 = { stack: [[1, 1], [0, 0], [0, 0], [0, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input3, output, "");

        // fail cases

        let input4 = { stack: [[1, 0], [2, 0], [3, 1], [1, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input4, { out: 0 }, "invalid stack");

        let input5 = { stack: [[1, 0], [2, 0], [3, 1], [1, 1]], parsing_string: 1, parsing_number: 1 };
        generatePassCase(input5, { out: 0 }, "parsing number and key both");
    });

    describe("InsideValue", async () => {
        let circuit: WitnessTester<["stack", "parsing_string", "parsing_number"], ["out"]>;

        function generatePassCase(input: any, expected: any, depth: number, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                circuit = await circomkit.WitnessTester(`InsideValue`, {
                    file: "json/interpreter",
                    template: "InsideValue",
                });
                console.log("#constraints:", await circuit.getConstraintCount());

                input.stack = input.stack[depth];

                await circuit.expectPass(input, expected);
            });
        }

        let input1 = { stack: [[1, 0], [2, 0], [3, 1], [1, 1]], parsing_string: 1, parsing_number: 0 };
        let output = { out: 1 };
        generatePassCase(input1, output, 3, "");

        let input2 = { stack: [[1, 0], [2, 0], [1, 1], [1, 1]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input2, output, 2, "");

        let input3 = { stack: [[1, 1], [0, 0], [0, 0], [1, 1]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input3, output, 0, "");

        // fail cases

        let input4 = { stack: [[1, 0], [2, 0], [3, 1], [1, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input4, { out: 0 }, 0, "invalid stack");

        let input5 = { stack: [[1, 0], [2, 0], [3, 1], [1, 1]], parsing_string: 1, parsing_number: 1 };
        generatePassCase(input5, { out: 0 }, 3, "parsing number and key both");
    });

    describe("InsideArrayIndexAtTop", async () => {
        let circuit: WitnessTester<["stack", "parsing_string", "parsing_number"], ["out"]>;

        function generatePassCase(input: any, expected: any, index: number, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                circuit = await circomkit.WitnessTester(`InsideArrayIndexAtTop`, {
                    file: "json/interpreter",
                    template: "InsideArrayIndexAtTop",
                    params: [4, index],
                });
                console.log("#constraints:", await circuit.getConstraintCount());

                await circuit.expectPass(input, expected);
            });
        }

        let input1 = { stack: [[1, 0], [2, 0], [3, 1], [2, 1]], parsing_string: 1, parsing_number: 0 };
        let output = { out: 1 };
        generatePassCase(input1, output, 1, "");

        let input2 = { stack: [[1, 0], [2, 0], [2, 3], [0, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input2, output, 3, "");

        let input3 = { stack: [[2, 10], [0, 0], [0, 0], [0, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input3, output, 10, "");

        // fail cases

        let input4 = { stack: [[1, 0], [2, 0], [3, 1], [1, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input4, { out: 0 }, 4, "invalid stack");

        let input5 = { stack: [[1, 0], [2, 0], [3, 1], [1, 1]], parsing_string: 1, parsing_number: 1 };
        generatePassCase(input5, { out: 0 }, 4, "parsing number and key both");

        let input6 = { stack: [[1, 0], [2, 0], [3, 1], [2, 4]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input6, { out: 0 }, 3, "incorrect index");
    });

    describe("InsideArrayIndex", async () => {
        let circuit: WitnessTester<["stack", "parsing_string", "parsing_number"], ["out"]>;

        function generatePassCase(input: any, expected: any, index: number, depth: number, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                circuit = await circomkit.WitnessTester(`InsideArrayIndex`, {
                    file: "json/interpreter",
                    template: "InsideArrayIndex",
                    params: [index],
                });
                console.log("#constraints:", await circuit.getConstraintCount());

                input.stack = input.stack[depth]

                await circuit.expectPass(input, expected);
            });
        }

        let input1 = { stack: [[1, 0], [2, 0], [3, 1], [2, 1]], parsing_string: 1, parsing_number: 0 };
        let output = { out: 1 };
        generatePassCase(input1, output, 1, 3, "");

        let input2 = { stack: [[1, 0], [2, 0], [2, 3], [2, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input2, output, 3, 2, "");

        let input3 = { stack: [[2, 10], [0, 0], [1, 0], [0, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input3, output, 10, 0, "");

        // fail cases

        let input4 = { stack: [[1, 0], [2, 0], [3, 1], [1, 0]], parsing_string: 1, parsing_number: 0 };
        generatePassCase(input4, { out: 0 }, 4, 2, "invalid stack depth");

        let input5 = { stack: [[1, 0], [2, 0], [3, 1], [1, 1]], parsing_string: 1, parsing_number: 1 };
        generatePassCase(input5, { out: 0 }, 4, 1, "parsing number and key both");
    });

    describe("NextKVPair", async () => {
        let circuit: WitnessTester<["stack", "currByte"], ["out"]>;

        before(async () => {
            circuit = await circomkit.WitnessTester(`NextKVPair`, {
                file: "json/interpreter",
                template: "NextKVPair",
                params: [4],
            });
            console.log("#constraints:", await circuit.getConstraintCount());
        });

        function generatePassCase(input: any, expected: any, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                await circuit.expectPass(input, expected);
            });
        }

        let input1 = { stack: [[1, 0], [2, 0], [3, 1], [1, 0]], currByte: 44 };
        let output = { out: 1 };
        generatePassCase(input1, output, "");

        let input2 = { stack: [[1, 0], [2, 0], [1, 0], [0, 0]], currByte: 44 };
        generatePassCase(input2, output, "");

        let input3 = { stack: [[1, 0], [0, 0], [0, 0], [0, 0]], currByte: 44 };
        generatePassCase(input3, output, "");

        let input4 = { stack: [[1, 0], [2, 0], [3, 1], [1, 1]], currByte: 44 };
        generatePassCase(input4, { out: 0 }, "invalid stack");

        let input5 = { stack: [[1, 0], [2, 0], [3, 1], [1, 0]], currByte: 34 };
        generatePassCase(input5, { out: 0 }, "incorrect currByte");
    });

    describe("NextKVPairAtDepth", async () => {
        let circuit: WitnessTester<["stack", "currByte", "depth"], ["out"]>;

        function generatePassCase(input: any, expected: any, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                circuit = await circomkit.WitnessTester(`NextKVPairAtDepth`, {
                    file: "json/interpreter",
                    template: "NextKVPairAtDepth",
                    params: [4],
                });
                console.log("#constraints:", await circuit.getConstraintCount());

                await circuit.expectPass(input, expected);
            });
        }

        let input1 = { stack: [[1, 0], [2, 0], [3, 1], [1, 0]], currByte: 44, depth: 3 };
        // output = 1 represents correct execution
        let output = { out: 1 };
        generatePassCase(input1, output, "");

        // key depth is 2, and even if new-kv pair starts at depth greater than 2, it returns 0.
        let input2 = { stack: [[1, 0], [2, 0], [1, 1], [1, 0]], currByte: 44, depth: 2 };
        generatePassCase(input2, { out: 0 }, "");

        let input3 = { stack: [[1, 0], [1, 0], [0, 0], [0, 0]], currByte: 44, depth: 3 };
        generatePassCase(input3, output, "stack height less than specified");

        let input4 = { stack: [[1, 0], [2, 0], [1, 0], [0, 0]], currByte: 34, depth: 2 };
        generatePassCase(input4, { out: 0 }, "incorrect currByte");
    });

    describe("KeyMatch", async () => {
        let circuit: WitnessTester<["data", "key", "index", "parsing_key"], ["out"]>;

        function generatePassCase(input: any, expected: any, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                circuit = await circomkit.WitnessTester(`KeyMatch`, {
                    file: "json/interpreter",
                    template: "KeyMatch",
                    params: [input.data.length, input.key.length],
                });
                console.log("#constraints:", await circuit.getConstraintCount());

                await circuit.expectPass(input, expected);
            });
        }

        let input = readJSONInputFile("value_array_object.json", ["a"]);

        let output = { out: 1 };
        let input1 = { data: input[0], key: input[1][0], index: 2, parsing_key: 1 };
        generatePassCase(input1, output, "");

        let input2 = { data: input[0], key: [99], index: 20, parsing_key: 1 };
        generatePassCase(input2, output, "");

        // fail cases

        let input3 = { data: input[0], key: input[1][0], index: 3, parsing_key: 1 };
        generatePassCase(input3, { out: 0 }, "wrong index");

        let input4 = { data: input[0], key: [98], index: 2, parsing_key: 1 };
        generatePassCase(input4, { out: 0 }, "wrong key");

        let input5 = { data: input[0], key: [97], index: 2, parsing_key: 0 };
        generatePassCase(input5, { out: 0 }, "not parsing key");
    });

    describe("KeyMatchAtDepth", async () => {
        let circuit: WitnessTester<["data", "key", "index", "parsing_key", "stack"], ["out"]>;

        function generatePassCase(input: any, expected: any, depth: number, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                circuit = await circomkit.WitnessTester(`KeyMatchAtDepth`, {
                    file: "json/interpreter",
                    template: "KeyMatchAtDepth",
                    params: [input.data.length, 4, input.key.length, depth],
                });
                console.log("#constraints:", await circuit.getConstraintCount());

                await circuit.expectPass(input, expected);
            });
        }

        let input = readJSONInputFile("value_array_object.json", ["a", 0, "b", 0]);

        let output = { out: 1 };

        let input1 = { data: input[0], key: input[1][0], index: 2, parsing_key: 1, stack: [[1, 0], [0, 0], [0, 0], [0, 0]] };
        generatePassCase(input1, output, 0, "");

        let input2 = { data: input[0], key: input[1][2], index: 8, parsing_key: 1, stack: [[1, 1], [2, 0], [1, 0], [0, 0]] };
        generatePassCase(input2, output, 2, "");

        let input3 = { data: input[0], key: [99], index: 20, parsing_key: 1, stack: [[1, 1], [2, 1], [1, 1], [0, 0]] };
        generatePassCase(input3, output, 2, "wrong stack");

        // fail cases

        let input4 = { data: input[0], key: input[1][1], index: 3, parsing_key: 1, stack: [[1, 0], [2, 0], [1, 0], [0, 0]] };
        generatePassCase(input4, { out: 0 }, 2, "wrong key");

        let input5 = { data: input[0], key: [97], index: 12, parsing_key: 0, stack: [[1, 1], [2, 0], [1, 1], [0, 0]] };
        generatePassCase(input5, { out: 0 }, 3, "not parsing key");

        let input6Data = input[0].slice(0);
        input6Data.splice(1, 1, 35);
        let input6 = { data: input6Data, key: input[1][0], index: 2, parsing_key: 1, stack: [[1, 0], [0, 0], [0, 0], [0, 0]] };
        generatePassCase(input6, { out: 0 }, 0, "invalid key (not surrounded by quotes)");

        let input7 = { data: input[0], key: input[1][0], index: 2, parsing_key: 1, stack: [[1, 0], [0, 0], [0, 0], [0, 0]] };
        generatePassCase(input6, { out: 0 }, 1, "wrong depth");
    });

    describe("KeyMatchAtIndex", async () => {
        let circuit: WitnessTester<["data", "key", "keyLen", "parsing_key"], ["out"]>;
        let maxKeyLen = 3;

        function generatePassCase(input: any, expected: any, index: number, desc: string) {
            const description = generateDescription(input);

            it(`(valid) witness: ${description} ${desc}`, async () => {
                // pad key with 0's
                let padded_key = input.key.concat(Array(maxKeyLen - input.key.length).fill(0));
                input.key = padded_key;

                circuit = await circomkit.WitnessTester(`KeyMatchAtIndex`, {
                    file: "json/interpreter",
                    template: "KeyMatchAtIndex",
                    params: [input.data.length, maxKeyLen, index],
                });
                console.log("#constraints:", await circuit.getConstraintCount());

                await circuit.expectPass(input, expected);
            });
        }

        let input = readJSONInputFile("value_array_object.json", ["a", 0, "b", 0]);

        let output = { out: 1 };

        let key1 = input[1][0];
        let input1 = { data: input[0], key: key1, keyLen: key1.length, parsing_key: 1 };
        generatePassCase(input1, output, 2, "");

        let key2 = input[1][2];
        let input2 = { data: input[0], key: key2, keyLen: key2.length, parsing_key: 1 };
        generatePassCase(input2, output, 8, "");

        let input3 = { data: input[0], key: [99], keyLen: 1, parsing_key: 1 };
        generatePassCase(input3, output, 20, "wrong stack");

        // fail cases

        let failOutput = { out: 0 };
        let key4 = input[1][1];
        let input4 = { data: input[0], key: key4, keyLen: key4.length, parsing_key: 1 };
        generatePassCase(input4, failOutput, 3, "wrong key");

        let input5 = { data: input[0], key: [97], keyLen: 1, parsing_key: 0 };
        generatePassCase(input5, failOutput, 12, "not parsing key");

        let input6Data = input[0].slice(0);
        input6Data.splice(1, 1, 35);
        let input6 = { data: input6Data, key: input[1][0], keyLen: input[1][0].length, parsing_key: 1 };
        generatePassCase(input6, failOutput, 2, "invalid key (not surrounded by quotes)");

        let input7 = { data: input[0], key: input[1][0], keyLen: input[1][0].length, parsing_key: 1 };
        generatePassCase(input6, failOutput, 2, "wrong depth");
    });
});