pragma circom 2.1.9;

include "../parser/machine.circom";
include "../interpreter.circom";
include "../../utils/bytes.circom";

template HttpNIVC(DATA_BYTES, MAX_NUMBER_OF_HEADERS) {
    signal input step_in[1];
    signal output step_out[1];

    // Authenticate the plaintext we are passing in
    signal input data[DATA_BYTES];
    signal data_hash <== DataHasher(DATA_BYTES)(data);
    data_hash        === step_in[0];

    signal input start_line_hash;
    signal input header_hashes[MAX_NUMBER_OF_HEADERS];
    signal input body_hash;

    // TODO: could just have a parser template and reduce code here
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

    // Get the start line shit
    signal start_line[DATA_BYTES];
    signal not_start_line_mask[DATA_BYTES];
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        not_start_line_mask[i] <== IsZero()(State[i].parsing_start);
        start_line[i] <== data[i] * (1 - not_start_line_mask[i]);
    }
    signal inner_start_line_hash <== DataHasher(DATA_BYTES)(start_line);
    inner_start_line_hash        === start_line_hash;

    // Get the header shit
    signal header[MAX_NUMBER_OF_HEADERS][DATA_BYTES];
    signal header_masks[MAX_NUMBER_OF_HEADERS][DATA_BYTES];
    for(var i = 0 ; i < MAX_NUMBER_OF_HEADERS ; i++) {
        for(var j = 0 ; j < DATA_BYTES ; j++) {
            header_masks[i][j] <== IsEqual()([State[j].parsing_header, i + 1]);
            header[i][j]       <== data[j] * header_masks[i][j];
        }
    }
    signal inner_header_hashes[MAX_NUMBER_OF_HEADERS];
    signal header_is_unused[MAX_NUMBER_OF_HEADERS]; // If a header hash is passed in as 0, it is not used (no way to compute preimage of 0) 
    for(var i = 0 ; i < MAX_NUMBER_OF_HEADERS ; i++) {
        header_is_unused[i]    <== IsZero()(header_hashes[i]);
        inner_header_hashes[i] <== DataHasher(DATA_BYTES)(header[i]);
        (1 - header_is_unused[i]) * inner_header_hashes[i] === header_hashes[i];
    }

    // Get the body shit
    signal body[DATA_BYTES];
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        body[i]       <== data[i] * State[i].parsing_body;
    }
    signal inner_body_hash <== DataHasher(DATA_BYTES)(body);
    inner_body_hash === body_hash;
    step_out[0] <== inner_body_hash;
}
