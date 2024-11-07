pragma circom 2.1.9;

include "../parser/machine.circom";
include "../interpreter.circom";
include "../../utils/bytes.circom";

// TODO: Note that TOTAL_BYTES will match what we have for AESGCMFOLD step_out
// I have not gone through to double check the sizes of everything yet.
template ParseAndLockStartLine(DATA_BYTES, MAX_BEGINNING_LENGTH, MAX_MIDDLE_LENGTH, MAX_FINAL_LENGTH) {
    signal input step_in[1];
    signal output step_out[1];

    // Authenticate the plaintext we are passing in
    signal input data[DATA_BYTES];
    signal dataHash <== DataHasher(DATA_BYTES)(data);
    dataHash === step_in[0];
    step_out[0] <== step_in[0];

    signal input beginning[MAX_BEGINNING_LENGTH];
    signal input beginning_length;
    signal input middle[MAX_MIDDLE_LENGTH];
    signal input middle_length;
    signal input final[MAX_FINAL_LENGTH];
    signal input final_length;

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
    we can make this more efficient by just comparing the first `BEGINNING_LENGTH` bytes
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
    beginning_length === middle_start_counter - 1;

    signal beginningMatch <== SubstringMatchWithIndexPadded(DATA_BYTES, MAX_BEGINNING_LENGTH)(data, beginning, beginning_length, 0);

    // Check middle is correct by substring match and length check
    signal middleMatch <== SubstringMatchWithIndexPadded(DATA_BYTES, MAX_MIDDLE_LENGTH)(data, middle, middle_length, middle_start_counter);
    middleMatch === 1;
    middle_length === middle_end_counter - middle_start_counter - 1;

    // Check final is correct by substring match and length check
    signal finalMatch <== SubstringMatchWithIndexPadded(DATA_BYTES, MAX_FINAL_LENGTH)(data, final, final_length, middle_end_counter);
    finalMatch === 1;
    // -2 here for the CRLF
    final_length === final_end_counter - middle_end_counter - 2;
}

