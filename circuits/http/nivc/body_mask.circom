pragma circom 2.1.9;

include "../interpreter.circom";

template HTTPMaskBodyNIVC(DATA_BYTES, MAX_STACK_HEIGHT) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~
    // Total number of variables in the parser for each byte of data
    var PER_ITERATION_DATA_LENGTH = MAX_STACK_HEIGHT * 2 + 2;
    var TOTAL_BYTES_ACROSS_NIVC   = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1) + 1;
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Unravel from previous NIVC step ~
    // Read in from previous NIVC step (HttpParseAndLockStartLine or HTTPLockHeader)
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC]; 
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];

    signal data[DATA_BYTES];
    signal parsing_body[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i]         <== step_in[i];
        parsing_body[i] <== step_in[DATA_BYTES + i * 5 + 4]; // `parsing_body` stored in every 5th slot of step_in/out
    }

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Write out to next NIVC step
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        step_out[i] <== data[i] * parsing_body[i];
    }
    // Write out padded with zeros
    for (var i = DATA_BYTES ; i < TOTAL_BYTES_ACROSS_NIVC ; i++) {
        step_out[i] <== 0;
    }
}

