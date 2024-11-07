pragma circom 2.1.9;

include "../parser/machine.circom";
include "../../utils/hash.circom";

template HTTPMaskBodyNIVC(DATA_BYTES) {
    signal input step_in[1];
    signal output step_out[1];
    
    // Authenticate the plaintext we are passing in
    signal input data[DATA_BYTES];
    signal data_hash <== DataHasher(DATA_BYTES)(data);
    data_hash === step_in[0];

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
    // Mask out just the JSON body
    signal bodyMasked[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
            bodyMasked[i] <== data[i] * State[i].next_parsing_body;
    }

    // Hash the new data so this can now be used in the chain later
    step_out[0] <== DataHasher(DATA_BYTES)(bodyMasked);
}

