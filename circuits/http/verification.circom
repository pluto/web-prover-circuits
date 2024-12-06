pragma circom 2.1.9;

include "machine.circom";
include "../utils/hash.circom";

template HTTPVerification(DATA_BYTES, MAX_NUMBER_OF_HEADERS) {
    signal input step_in[1];
    signal output step_out[1];

    // Authenticate the plaintext we are passing in
    signal input data[DATA_BYTES];
    signal data_hash <== DataHasher(DATA_BYTES)(data);
    data_hash        === step_in[0];

    signal input which_headers[MAX_NUMBER_OF_HEADERS]; // We could take this in as a field element and map it to bits for more efficiency
    signal input main_digest;
    signal input body_digest;

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

    // Mask leaving only selected headers and start line
    for(var i = 0 ; i < MAX_NUMBER_OF_HEADERS ; i++) {
        0 === which_headers[i] * (1 - which_headers[i]); // Assert this is a bit
    }
    signal include_header[DATA_BYTES];
    signal not_parsing_start[DATA_BYTES];

    signal main_monomials[DATA_BYTES];
    main_monomials[0] <== 1;

    signal is_line_change[DATA_BYTES];
    signal was_cleared[DATA_BYTES];
    signal start_line_or_chosen_header_and_not_line_change[DATA_BYTES];


    for(var i = 0 ; i < DATA_BYTES - 1 ; i++) {
        // log("------------------------------------------------------------------");
        is_line_change[i] <== Contains(2)(data[i + 1], [10, 13]); // capture if we hit an end line sequence

        not_parsing_start[i] <== IsZero()(State[i + 1].parsing_start);
        include_header[i] <== IndexSelector(MAX_NUMBER_OF_HEADERS)(which_headers, State[i + 1].parsing_header - 1);
        start_line_or_chosen_header_and_not_line_change[i] <== (1-is_line_change[i]) * ((1 - not_parsing_start[i]) + include_header[i]);

        // TODO: use `step_in[0]` in the future, testing with `2` now
        was_cleared[i] <== IsZero()(main_monomials[i]);
        main_monomials[i + 1] <==  start_line_or_chosen_header_and_not_line_change[i] * (main_monomials[i] * 2 + was_cleared[i]);
        // log("main_monomials[", i, "]           =", main_monomials[i]);
    }

    signal inner_main_digest[DATA_BYTES + 1];
    inner_main_digest[0] <== 0;
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        inner_main_digest[i+1] <== inner_main_digest[i] + data[i] * main_monomials[i];
        // log("inner_main_digest[", i + 1,"] = ", inner_main_digest[i+1]);
    }
    // log("inner_main_digest = ", inner_main_digest[DATA_BYTES]);
    inner_main_digest[DATA_BYTES] === main_digest;

    // BODY
    signal body_monomials[DATA_BYTES];
    body_monomials[0] <== 0;
    signal body_accum[DATA_BYTES];
    body_accum[0] <== 0;
    signal body_switch[DATA_BYTES -1];
    signal inner_body_digest[DATA_BYTES];
    inner_body_digest[0] <== 0;
    for(var i = 0 ; i < DATA_BYTES - 1 ; i++) {
        log("------------------------------------------------------------------");
        body_accum[i + 1] <== body_accum[i] + State[i + 1].parsing_body;
        body_switch[i] <== IsEqual()([body_accum[i + 1], 1]);
        log("data[", i+1,"]      =", data[i+1]);
        log("body_switch[", i,"] =", body_switch[i]);
        body_monomials[i + 1] <== body_monomials[i] * 2 + body_switch[i];
        log("body_monomials[", i+1,"] =", body_monomials[i+1]);
        inner_body_digest[i + 1] <== inner_body_digest[i] + body_monomials[i + 1] * data[i + 1];
    }
    log("inner_body_digest = ", inner_body_digest[DATA_BYTES - 1]);
    inner_body_digest[DATA_BYTES - 1] === body_digest;

    step_out[0] <== body_digest;

    // Verify machine ends in a valid state
    State[DATA_BYTES - 1].next_parsing_start       === 0;
    State[DATA_BYTES - 1].next_parsing_header      === 0;
    State[DATA_BYTES - 1].next_parsing_field_name  === 0;
    State[DATA_BYTES - 1].next_parsing_field_value === 0;
    State[DATA_BYTES - 1].next_parsing_body        === 1;
    State[DATA_BYTES - 1].next_line_status         === 0;
}
