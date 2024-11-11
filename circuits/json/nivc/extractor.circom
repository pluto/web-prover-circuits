pragma circom 2.1.9;

include "circomlib/circuits/gates.circom";
include "@zk-email/circuits/utils/array.circom";
include "../../utils/hash.circom";

template MaskExtractFinal(DATA_BYTES, MAX_VALUE_LENGTH) {
    // ------------------------------------------------------------------------------------------------------------------ //
    signal input step_in[1];
    signal input data[DATA_BYTES];

    signal output step_out[1];

    signal is_zero_mask[DATA_BYTES];
    signal is_prev_starting_index[DATA_BYTES];
    signal value_starting_index[DATA_BYTES];

    // for (var i = 0 ; i < DATA_BYTES ; i++) {
    //     data[i] <== step_in[i];
    // }
    signal data_hash <== DataHasher(DATA_BYTES)(data);
    data_hash === step_in[0];

    value_starting_index[0] <== 0;
    is_prev_starting_index[0] <== 0;
    is_zero_mask[0] <== IsZero()(data[0]);
    for (var i=1 ; i < DATA_BYTES ; i++) {
        is_zero_mask[i] <== IsZero()(data[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }
    // TODO: Clear step out?
    signal value[MAX_VALUE_LENGTH] <== SelectSubArray(DATA_BYTES, MAX_VALUE_LENGTH)(data, value_starting_index[DATA_BYTES-1], MAX_VALUE_LENGTH);

    step_out[0] <== DataHasher(MAX_VALUE_LENGTH)(value);
    // for (var i = 0 ; i < MAX_VALUE_LENGTH ; i++) {
    //     // log(i, value[i]);
    //     step_out[i] <== value[i];
    // }
    // for (var i = MAX_VALUE_LENGTH ; i < TOTAL_BYTES_ACROSS_NIVC ; i++) {
    //     step_out[i] <== 0;
    // }


    // TODO: Do anything with last depth?
    // step_out[TOTAL_BYTES_ACROSS_NIVC - 1] <== 0;
}