pragma circom 2.1.9;

include "machine.circom";

template Parser(DATA_BYTES, MAX_STACK_HEIGHT) {
    signal input data[DATA_BYTES];

    //--------------------------------------------------------------------------------------------//
    // Initialze the parser
    component State[DATA_BYTES];
    State[0] = StateUpdate(MAX_STACK_HEIGHT);
    State[0].byte           <== data[0];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [0,0];
    }
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                  = StateUpdate(MAX_STACK_HEIGHT);
        State[data_idx].byte           <== data[data_idx];
        State[data_idx].stack          <== State[data_idx - 1].next_stack;
        State[data_idx].parsing_string <== State[data_idx - 1].next_parsing_string;
        State[data_idx].parsing_number <== State[data_idx - 1].next_parsing_number;
    }

    // Constrain to have valid JSON
    State[DATA_BYTES - 1].next_parsing_string === 0;
    State[DATA_BYTES - 1].next_parsing_number === 0;
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[DATA_BYTES - 1].next_stack[i]   === [0,0];
    }
}
