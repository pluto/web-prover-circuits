import { circomkit, WitnessTester, generateDescription } from "../common";
import { Delimiters, WhiteSpace, Numbers, Escape, INITIAL_IN, INITIAL_OUT } from '.';

describe("StateUpdate :: Values", () => {
    let circuit: WitnessTester<
        ["byte", "pointer", "stack", "parsing_string", "parsing_number"],
        ["next_pointer", "next_stack", "next_parsing_string", "next_parsing_number"]
    >;
    before(async () => {
        circuit = await circomkit.WitnessTester(`GetTopOfStack`, {
            file: "json/machine",
            template: "StateUpdate",
            params: [4],
        });
    });

    function generatePassCase(input: any, expected: any, desc: string) {
        const description = generateDescription(input);

        it(`(valid) witness: ${description}\n${desc}`, async () => {
            await circuit.expectPass(input, expected);
        });
    }

    describe("StateUpdate :: Values :: Number", () => {
        //-TEST_1----------------------------------------------------------//
        // idea:   Read a number value after a key in an object.
        // state:  stack == [[1, 1], [0, 0], [0, 0], [0, 0]]
        // read:   `0`
        // expect: stack          --> [[1, 1], [0, 0], [0, 0], [0, 0]]
        //         parsing_number --> 1
        let read_number = { ...INITIAL_IN };
        read_number.stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
        read_number.byte = Numbers.ZERO;
        let read_number_out = { ...INITIAL_OUT };
        read_number_out.next_stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
        read_number_out.next_parsing_number = 1;
        generatePassCase(read_number, read_number_out, ">>>> `0` read");

        // // TODO: Note that reading a space while reading a number will not throw an error!

        //-TEST_2----------------------------------------------------------//
        // idea:   Inside a number value after a key in an object.
        // state:  stack == [[1, 1], [0, 0], [0, 0], [0, 0]], parsing_number == 1
        // read:   `1`
        // expect: stack          --> [[1, 1], [0, 0], [0, 0], [0, 0]]
        //         parsing_number --> 0
        let inside_number_continue = { ...INITIAL_IN };
        inside_number_continue.stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
        inside_number_continue.parsing_number = 1;
        inside_number_continue.byte = Numbers.ONE;
        let inside_number_continue_out = { ...INITIAL_OUT };
        inside_number_continue_out.next_stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
        inside_number_continue_out.next_parsing_number = 1;
        generatePassCase(inside_number_continue, inside_number_continue_out, ">>>> `1` read");

        //-TEST_2----------------------------------------------------------//
        // idea:   Inside a number value after a key in an object.
        // state:  stack == [[1, 1], [0, 0], [0, 0], [0, 0]], parsing_number == 1
        // read:   `1`
        // expect: stack          --> [[1, 1], [0, 0], [0, 0], [0, 0]]
        //         parsing_number --> 0
        let inside_number_exit = { ...INITIAL_IN };
        inside_number_exit.stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
        inside_number_exit.parsing_number = 1;
        inside_number_exit.byte = WhiteSpace.SPACE;
        let inside_number_exit_out = { ...INITIAL_OUT };
        inside_number_exit_out.next_stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
        inside_number_exit_out.next_parsing_number = 0;
        generatePassCase(inside_number_exit, inside_number_exit_out, ">>>> ` ` read");

        //-TEST_3----------------------------------------------------------//
        // idea:   Inside a number value after a key in an object.
        // state:  stack == [[1, 1], [0, 0], [0, 0], [0, 0]], parsing_number == 1
        // read:   `$`
        // expect: stack          --> [[1, 1], [0, 0], [0, 0], [0, 0]]
        //         parsing_number --> 0
        let inside_number_exit2 = { ...INITIAL_IN };
        inside_number_exit2.stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
        inside_number_exit2.parsing_number = 1;
        inside_number_exit2.byte = 36; // Dollar sign `$`
        let inside_number_exit2_out = { ...INITIAL_OUT };
        inside_number_exit2_out.next_stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
        inside_number_exit2_out.next_parsing_number = 0;
        generatePassCase(inside_number_exit2, inside_number_exit2_out, ">>>> `$` read");
    });

    describe("StateUpdate :: Values :: String", () => {
        //-TEST_4----------------------------------------------------------//
        // idea:   Inside a string key inside an object
        // state:  stack == [[1, 0], [0, 0], [0, 0], [0, 0]], parsing_string == 1
        // read:   `,`
        // expect: stack          --> [[1, 0], [0, 0], [0, 0], [0, 0]]
        //         parsing_string --> 0
        let inside_number = { ...INITIAL_IN };
        inside_number.stack = [[1, 1], [0, 0], [0, 0], [0, 0]];
        inside_number.parsing_string = 1;
        inside_number.byte = Delimiters.COMMA;
        let inside_number_out = { ...INITIAL_OUT };
        inside_number_out.next_stack = [[1, 0], [0, 0], [0, 0], [0, 0]];
        inside_number_out.next_parsing_string = 1;
        generatePassCase(inside_number, inside_number_out, ">>>> `,` read");
    });

    describe("StateUpdate :: Values :: Array", () => {
        // Internal array parsing -----------------------------------------//

        //-TEST_10----------------------------------------------------------//
        // init:   stack  == [[1, 0], [2, 0], [0, 0], [0, 0]]
        // read:   `,`
        // expext: stack --> [[1, 0], [2, 1], [0, 0], [0, 0]]
        let in_arr = { ...INITIAL_IN };
        in_arr.stack = [[1, 0], [2, 0], [0, 0], [0, 0]];
        in_arr.byte = Delimiters.COMMA;
        let in_arr_out = { ...INITIAL_OUT };
        in_arr_out.next_stack = [[1, 0], [2, 1], [0, 0], [0, 0]];
        generatePassCase(in_arr, in_arr_out, ">>>> `,` read");

        //-TEST_10----------------------------------------------------------//
        // init:   stack  == [[1, 0], [2, 1], [0, 0], [0, 0]]
        // read:   `]`
        // expect: stack --> [[1, 0], [0, 0], [0, 0], [0, 0]]
        let in_arr_idx_to_leave = { ...INITIAL_IN };
        in_arr_idx_to_leave.stack = [[1, 0], [2, 1], [0, 0], [0, 0]];
        in_arr_idx_to_leave.byte = Delimiters.END_BRACKET;
        let in_arr_idx_to_leave_out = { ...INITIAL_OUT };
        in_arr_idx_to_leave_out.next_stack = [[1, 0], [0, 0], [0, 0], [0, 0]];
        generatePassCase(in_arr_idx_to_leave, in_arr_idx_to_leave_out, ">>>> `]` read");
    });
});