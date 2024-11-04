pragma circom 2.1.9;

include "circomlib/circuits/gates.circom";
include "@zk-email/circuits/utils/array.circom";

template MaskExtractFinal(DATA_BYTES, MAX_STACK_HEIGHT, MAX_VALUE_LENGTH) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~
    // Total number of variables in the parser for each byte of data
    assert(MAX_STACK_HEIGHT >= 2);
    var PER_ITERATION_DATA_LENGTH = MAX_STACK_HEIGHT * 2 + 2;
    var TOTAL_BYTES_ACROSS_NIVC   = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1) + 1;
    // ------------------------------------------------------------------------------------------------------------------ //
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC];
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];

    signal is_zero_mask[DATA_BYTES];
    signal is_prev_starting_index[DATA_BYTES];
    signal value_starting_index[DATA_BYTES];

    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }

    value_starting_index[0] <== 0;
    is_prev_starting_index[0] <== 0;
    is_zero_mask[0] <== IsZero()(step_in[0]);
    for (var i=1 ; i < DATA_BYTES ; i++) {
        is_zero_mask[i] <== IsZero()(step_in[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }
    // TODO: Clear step out?
    signal output value[MAX_VALUE_LENGTH] <== SelectSubArray(DATA_BYTES, MAX_VALUE_LENGTH)(data, value_starting_index[DATA_BYTES-1], MAX_VALUE_LENGTH);
    for (var i = 0 ; i < MAX_VALUE_LENGTH ; i++) {
        // log(i, value[i]);
        step_out[i] <== value[i];
    }
    for (var i = MAX_VALUE_LENGTH ; i < TOTAL_BYTES_ACROSS_NIVC ; i++) {
        step_out[i] <== 0;
    }
    // TODO: Do anything with last depth?
    // step_out[TOTAL_BYTES_ACROSS_NIVC - 1] <== 0;
}