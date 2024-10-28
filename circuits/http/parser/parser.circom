pragma circom 2.1.9;

include "../../utils/bytes.circom";
include "machine.circom";


template Parser(DATA_BYTES) {
    signal input data[DATA_BYTES];

    signal output Method;

    //--------------------------------------------------------------------------------------------//
    //-CONSTRAINTS--------------------------------------------------------------------------------//
    //--------------------------------------------------------------------------------------------//
    component dataASCII = ASCII(DATA_BYTES);
    dataASCII.in <== data;
    //--------------------------------------------------------------------------------------------//

    // Initialze the parser
    component State[DATA_BYTES];
    State[0] = HttpStateUpdate();
    State[0].byte           <== data[0];
    State[0].parsing_start  <== 1;
    State[0].parsing_header <== 0;
    State[0].parsing_body   <== 0;
    State[0].line_status    <== 0;

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                  = HttpStateUpdate();
        State[data_idx].byte           <== data[data_idx];
        State[data_idx].parsing_start  <== State[data_idx - 1].next_parsing_start;
        State[data_idx].parsing_header <== State[data_idx - 1].next_parsing_header;
        State[data_idx].parsing_body   <== State[data_idx - 1].next_parsing_body;
        State[data_idx].line_status    <== State[data_idx - 1].next_line_status;

        // Debugging
        log("State[", data_idx, "].parsing_start ", "= ", State[data_idx].parsing_start);
        log("State[", data_idx, "].parsing_header", "= ", State[data_idx].parsing_header);
        log("State[", data_idx, "].parsing_body  ", "= ", State[data_idx].parsing_body);
        log("State[", data_idx, "].line_status   ", "= ", State[data_idx].line_status);
        log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }

        // Debugging
        log("State[", DATA_BYTES, "].parsing_start ", "= ", State[DATA_BYTES-1].next_parsing_start);
        log("State[", DATA_BYTES, "].parsing_header", "= ", State[DATA_BYTES-1].next_parsing_header);
        log("State[", DATA_BYTES, "].parsing_body  ", "= ", State[DATA_BYTES-1].next_parsing_body);
        log("State[", DATA_BYTES, "].line_status   ", "= ", State[DATA_BYTES-1].next_line_status);
        log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

}