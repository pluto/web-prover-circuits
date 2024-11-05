pragma circom 2.1.9;

include "../parser/machine.circom";
include "../interpreter.circom";
include "../../utils/bytes.circom";

template ParseAndLockStartLine(DATA_BYTES, MAX_STACK_HEIGHT, MAX_BEGINNING_LENGTH, MAX_MIDDLE_LENGTH, MAX_FINAL_LENGTH) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~
    // Total number of variables in the parser for each byte of data
    // var AES_BYTES                 = DATA_BYTES + 50; // TODO: Might be wrong, but good enough for now
    /* 5 is for the variables:
        next_parsing_start
        next_parsing_header
        next_parsing_field_name
        next_parsing_field_value
        State[i].next_parsing_body
    */
    var TOTAL_BYTES_HTTP_STATE    = DATA_BYTES * (5 + 1); // data + parser vars
    var PER_ITERATION_DATA_LENGTH = MAX_STACK_HEIGHT * 2 + 2;
    var TOTAL_BYTES_ACROSS_NIVC   = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1) + 1;
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Unravel from previous NIVC step ~
    // Read in from previous NIVC step (JsonParseNIVC)
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC];
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];

    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        // data[i] <== step_in[50 + i]; // THIS WAS OFFSET FOR AES, WHICH WE NEED TO TAKE INTO ACCOUNT
        data[i] <== step_in[i];
    }

    // // TODO: check if these needs to here or not
    // DON'T THINK WE NEED THIS SINCE AES SHOULD OUTPUT ASCII OR FAIL
    // component dataASCII = ASCII(DATA_BYTES);
    // dataASCII.in <== data;

    signal input beginning[MAX_BEGINNING_LENGTH];
    signal input beginningLen;
    signal input middle[MAX_MIDDLE_LENGTH];
    signal input middleLen;
    signal input final[MAX_FINAL_LENGTH];
    signal input finalLen;

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

    /*
    Note, because we know a beginning is the very first thing in a request
    we can make this more efficient by just comparing the first `beginningLen` bytes
    of the data ASCII against the beginning ASCII itself.
    */

    // Setup to check middle bytes
    signal startLineMask[DATA_BYTES];
    signal middleMask[DATA_BYTES];
    signal finalMask[DATA_BYTES];
    startLineMask[0] <== inStartLine()(State[0].parsing_start);
    middleMask[0]    <== inStartMiddle()(State[0].parsing_start);
    finalMask[0]     <== inStartEnd()(State[0].parsing_start);


    var middle_start_counter = 1;
    var middle_end_counter = 1;
    var final_end_counter = 1;
    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                     = HttpStateUpdate();
        State[data_idx].byte                <== data[data_idx];
        State[data_idx].parsing_start       <== State[data_idx - 1].next_parsing_start;
        State[data_idx].parsing_header      <== State[data_idx - 1].next_parsing_header;
        State[data_idx].parsing_field_name  <== State[data_idx - 1].next_parsing_field_name;
        State[data_idx].parsing_field_value <== State[data_idx - 1].next_parsing_field_value;
        State[data_idx].parsing_body        <== State[data_idx - 1].next_parsing_body;
        State[data_idx].line_status         <== State[data_idx - 1].next_line_status;

        // Set the masks based on parser state
        startLineMask[data_idx] <== inStartLine()(State[data_idx].parsing_start);
        middleMask[data_idx]    <== inStartMiddle()(State[data_idx].parsing_start);
        finalMask[data_idx]     <== inStartEnd()(State[data_idx].parsing_start);

        // Increment counters based on mask information
        middle_start_counter += startLineMask[data_idx] - middleMask[data_idx] - finalMask[data_idx];
        middle_end_counter   += startLineMask[data_idx] - finalMask[data_idx];
        final_end_counter    += startLineMask[data_idx];
    }

    // Additionally verify beginning had correct length
    beginningLen === middle_start_counter - 1;

    signal beginningMatch <== SubstringMatchWithIndexPadded(DATA_BYTES, MAX_BEGINNING_LENGTH)(data, beginning, beginningLen, 0);

    // Check middle is correct by substring match and length check
    signal middleMatch <== SubstringMatchWithIndexPadded(DATA_BYTES, MAX_MIDDLE_LENGTH)(data, middle, middleLen, middle_start_counter);
    middleMatch === 1;
    middleLen === middle_end_counter - middle_start_counter - 1;

    // Check final is correct by substring match and length check
    signal finalMatch <== SubstringMatchWithIndexPadded(DATA_BYTES, MAX_FINAL_LENGTH)(data, final, finalLen, middle_end_counter);
    finalMatch === 1;
    // -2 here for the CRLF
    finalLen === final_end_counter - middle_end_counter - 2;

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Write out to next NIVC step (Lock Header)
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        // add plaintext http input to step_out
        // step_out[i] <== step_in[50 + i]; // AGAIN, NEED TO ACCOUNT FOR AES VARIABLES POSSIBLY
        step_out[i] <== step_in[i];

        // add parser state
        step_out[DATA_BYTES + i * 5]     <== State[i].next_parsing_start;
        step_out[DATA_BYTES + i * 5 + 1] <== State[i].next_parsing_header;
        step_out[DATA_BYTES + i * 5 + 2] <== State[i].next_parsing_field_name;
        step_out[DATA_BYTES + i * 5 + 3] <== State[i].next_parsing_field_value;
        step_out[DATA_BYTES + i * 5 + 4] <== State[i].next_parsing_body;
    }
    // Pad remaining with zeros
    for (var i = TOTAL_BYTES_HTTP_STATE ; i < TOTAL_BYTES_ACROSS_NIVC ; i++ ) {
        step_out[i] <== 0;
    }
}
