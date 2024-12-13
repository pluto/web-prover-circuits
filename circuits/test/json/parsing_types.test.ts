import { circomkit, WitnessTester, generateDescription } from "../common";
import { Delimiters, WhiteSpace, INITIAL_IN, INITIAL_OUT } from '.';

describe("StateUpdate", () => {
    let circuit: WitnessTester<
        ["byte", "stack", "parsing_string", "parsing_number"],
        ["next_stack", "next_parsing_string", "next_parsing_number"]
    >;

    function generatePassCase(input: any, expected: any, desc: string) {
        const description = generateDescription(input);

        it(`(valid) witness: ${description}\n${desc}`, async () => {
            await circuit.expectPass(input, expected);
        });
    }

    before(async () => {
        circuit = await circomkit.WitnessTester(`StateUpdate`, {
            file: "json/machine",
            template: "StateUpdate",
            params: [4],
        });
    });

    //-TEST_1----------------------------------------------------------//
    // init: ZEROS then read `do_nothing` byte
    // expect: ZEROS
    generatePassCase(INITIAL_IN, INITIAL_OUT, ">>>> `NUL` read");


    //-TEST_2----------------------------------------------------------//
    // state:  stack == [[1, 0], [0, 0], [0, 0], [0, 0]]
    // read:   `"`
    // expect: parsing_string --> 1
    let in_object_find_key = { ...INITIAL_IN };
    in_object_find_key.stack = [[1, 0], [0, 0], [0, 0], [0, 0]];
    in_object_find_key.byte = Delimiters.QUOTE;
    let in_object_find_key_out = { ...INITIAL_OUT };
    in_object_find_key_out.next_stack = [[1, 0], [0, 0], [0, 0], [0, 0]];
    in_object_find_key_out.next_parsing_string = 1;
    generatePassCase(in_object_find_key,
        in_object_find_key_out,
        ">>>> `\"` read"
    );

    //-TEST_3----------------------------------------------------------//
    // state:  stack = [[1, 0], [0, 0], [0, 0], [0, 0]], parsing_string == 1
    // read:   ` `
    // expect: NIL
    let in_key = { ...INITIAL_IN };
    in_key.stack = [[1, 0], [0, 0], [0, 0], [0, 0]];
    in_key.parsing_string = 1;
    in_key.byte = WhiteSpace.SPACE;
    let in_key_out = { ...INITIAL_OUT };
    in_key_out.next_stack = [[1, 0], [0, 0], [0, 0], [0, 0]];
    in_key_out.next_parsing_string = 1;
    generatePassCase(in_key, in_key_out, ">>>> ` ` read");

    //-TEST_4----------------------------------------------------------//
    // init: stack == [[1, 0], [0, 0], [0, 0], [0, 0]]
    // read: `"`
    // expect: parsing_string --> 0
    //
    let in_key_to_exit = { ...INITIAL_IN };
    in_key_to_exit.stack = [[1, 0], [0, 0], [0, 0], [0, 0]];
    in_key_to_exit.parsing_string = 1
    in_key_to_exit.byte = Delimiters.QUOTE;
    let in_key_to_exit_out = { ...INITIAL_OUT };
    in_key_to_exit_out.next_stack = [[1, 0], [0, 0], [0, 0], [0, 0]];
    generatePassCase(in_key_to_exit, in_key_to_exit_out, "`\"` read");

    //-TEST_5----------------------------------------------------------//
    // state:  stack == [[1, 1], [0, 0], [0, 0], [0, 0]]
    // read:   `"`
    // expect: parsing_string --> 1
    let in_tree_find_value = { ...INITIAL_IN };
    in_tree_find_value.stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
    in_tree_find_value.byte = Delimiters.QUOTE;
    let in_tree_find_value_out = { ...INITIAL_OUT };
    in_tree_find_value_out.next_stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
    in_tree_find_value_out.next_parsing_string = 1;
    generatePassCase(in_tree_find_value,
        in_tree_find_value_out,
        ">>>> `\"` read"
    );

    //-TEST_6----------------------------------------------------------//
    // state:  stack == [[1, 1], [0, 0], [0, 0], [0, 0]];, parsing_string == 1
    // read:   `"`
    // expect: parsing_string == 0,
    let in_value_to_exit = { ...INITIAL_IN };
    in_value_to_exit.stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
    in_value_to_exit.parsing_string = 1;
    in_value_to_exit.byte = Delimiters.QUOTE;
    let in_value_to_exit_out = { ...INITIAL_OUT };
    in_value_to_exit_out.next_stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
    generatePassCase(in_value_to_exit,
        in_value_to_exit_out,
        ">>>> `\"` is read"
    );

});



