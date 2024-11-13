pragma circom 2.1.9;

include "../../utils/bytes.circom";
include "hash_machine.circom";

template ParserHasher(DATA_BYTES, MAX_STACK_HEIGHT) {
    signal input data[DATA_BYTES];

    // TODO: Add assertions on the inputs here!

    //--------------------------------------------------------------------------------------------//
    //-CONSTRAINTS--------------------------------------------------------------------------------//
    //--------------------------------------------------------------------------------------------//
    component dataASCII = ASCII(DATA_BYTES);
    dataASCII.in <== data;
    //--------------------------------------------------------------------------------------------//
    // Initialze the parser
    component State[DATA_BYTES];
    State[0] = StateUpdateHasher(MAX_STACK_HEIGHT);
    State[0].byte           <== data[0];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [0,0];
        State[0].tree_hasher[i] <== PoseidonChainer()([0,0]);
    }
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;
    
    // Debugging
    for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
        log("State[", 0, "].next_stack[", i,"]    ", "= [",State[0].next_stack[i][0], "][", State[0].next_stack[i][1],"]" );
    }
    log("State[", 0, "].next_parsing_string", "= ", State[0].next_parsing_string);
    log("State[", 0, "].next_parsing_number", "= ", State[0].next_parsing_number);
    for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
        log("State[", 0, "].next_tree_hasher[", i,"]", "= ", State[0].next_tree_hasher[i]);
    }
    log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                  = StateUpdateHasher(MAX_STACK_HEIGHT);
        State[data_idx].byte           <== data[data_idx];
        State[data_idx].stack          <== State[data_idx - 1].next_stack;
        State[data_idx].parsing_string <== State[data_idx - 1].next_parsing_string;
        State[data_idx].parsing_number <== State[data_idx - 1].next_parsing_number;
        State[data_idx].tree_hasher    <== State[data_idx - 1].next_tree_hasher;

        // Debugging
        for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
            log("State[", data_idx, "].stack[", i,"]    ", "= [",State[data_idx].next_stack[i][0], "][", State[data_idx].next_stack[i][1],"]" );
        }
        log("State[", data_idx, "].next_parsing_string", "= ", State[data_idx].next_parsing_string);
        log("State[", data_idx, "].next_parsing_number", "= ", State[data_idx].next_parsing_number);
        for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
            log("State[", data_idx, "].next_tree_hasher[", i,"]", "= ", State[data_idx].next_tree_hasher[i]);
        }
        log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }

    // TODO: Constrain to have valid JSON 
    // State[DATA_BYTES - 1].next_tree_depth === 0;

        // Debugging
        for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
            log("State[", DATA_BYTES -1, "].next_stack[", i,"]    ", "= [",State[DATA_BYTES -1].next_stack[i][0], "][", State[DATA_BYTES - 1].next_stack[i][1],"]" );
        }
        log("State[", DATA_BYTES - 1, "].next_parsing_string", "= ", State[DATA_BYTES-1].next_parsing_string);
        log("State[", DATA_BYTES -1 , "].next_parsing_number", "= ", State[DATA_BYTES-1].next_parsing_number);
        for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
            log("State[", DATA_BYTES -1 , "].next_tree_hashe[", i,"]   ", "= ", State[DATA_BYTES-1].tree_hasher[i]);
        }
        log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}
