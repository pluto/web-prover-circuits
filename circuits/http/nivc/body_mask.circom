pragma circom 2.1.9;

include "../parser/machine.circom";

template HTTPMaskBodyNIVC(DATA_BYTES) {
    // ------------------------------------------------------------------------------------------------------------------ //
    var TOTAL_BYTES_ACROSS_NIVC   = DATA_BYTES + 4; // aes ct/pt + ctr
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Unravel from previous NIVC step ~
    // Read in from previous NIVC step (HttpParseAndLockStartLine or HTTPLockHeader)
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC]; 
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];

    signal data[DATA_BYTES];
    // signal parsing_body[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i]         <== step_in[i];
        // parsing_body[i] <== step_in[DATA_BYTES + i * 5 + 4]; // `parsing_body` stored in every 5th slot of step_in/out
    }

    // ------------------------------------------------------------------------------------------------------------------ //
    // PARSE
    // Initialze the parser
    component State[DATA_BYTES];
    State[0]                     = HttpStateUpdate();
    State[0].byte                <== data[0];
    State[0].parsing_start       <== 1;
    State[0].parsing_header      <== 0;
    State[0].parsing_field_name  <== 0;
    State[0].parsing_field_value <== 0;
    State[0].parsing_body        <== 0;
    State[0].line_status         <== 0;

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                     = HttpStateUpdate();
        State[data_idx].byte                <== data[data_idx];
        State[data_idx].parsing_start       <== State[data_idx - 1].next_parsing_start;
        State[data_idx].parsing_header      <== State[data_idx - 1].next_parsing_header;
        State[data_idx].parsing_field_name  <== State[data_idx - 1].next_parsing_field_name;
        State[data_idx].parsing_field_value <== State[data_idx - 1].next_parsing_field_value;
        State[data_idx].parsing_body        <== State[data_idx - 1].next_parsing_body;
        State[data_idx].line_status         <== State[data_idx - 1].next_line_status;
    }
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Write out to next NIVC step
    for (var i = 0 ; i < TOTAL_BYTES_ACROSS_NIVC ; i++) {
        if(i < DATA_BYTES) {
            step_out[i] <== data[i] * State[i].next_parsing_body;
        } else {
            step_out[i] <== 0;
        }
    }
}

