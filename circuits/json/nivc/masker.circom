pragma circom 2.1.9;

include "../interpreter.circom";
include "../../utils/array.circom";

template JsonMaskObjectNIVC(DATA_BYTES, MAX_STACK_HEIGHT, MAX_KEY_LENGTH) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~
    // Total number of variables in the parser for each byte of data
    assert(MAX_STACK_HEIGHT >= 2);
    var PER_ITERATION_DATA_LENGTH = MAX_STACK_HEIGHT * 2 + 2;
    var TOTAL_BYTES_ACROSS_NIVC   = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1) + 1;
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Unravel from previous NIVC step ~
    // Read in from previous NIVC step (JsonParseNIVC)
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC];
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];

    // Grab the raw data bytes from the `step_in` variable
    var paddedDataLen = DATA_BYTES + MAX_KEY_LENGTH + 1;
    signal data[paddedDataLen];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }
    for (var i = 0 ; i < MAX_KEY_LENGTH + 1 ; i++) {
        data[DATA_BYTES + i] <== 0;
    }

    // Decode the encoded data in `step_in` back into parser variables
    signal stack[DATA_BYTES][MAX_STACK_HEIGHT + 1][2];
    signal parsingData[DATA_BYTES][2];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        for (var j = 0 ; j < MAX_STACK_HEIGHT + 1 ; j++) {
            if (j < MAX_STACK_HEIGHT) {
                stack[i][j][0] <== step_in[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + j * 2];
                stack[i][j][1] <== step_in[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + j * 2 + 1];
            } else {
                // Add one extra stack element without doing this while parsing.
                // Stack under/overflow caught in parsing.
                stack[i][j][0] <== 0;
                stack[i][j][1] <== 0;
            }
            
        }
        parsingData[i][0] <== step_in[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + MAX_STACK_HEIGHT * 2];
        parsingData[i][1] <== step_in[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + MAX_STACK_HEIGHT * 2 + 1];
    }
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Object masking ~
    // Key data to use to point to which object to extract
    signal input key[MAX_KEY_LENGTH];
    signal input keyLen;

    // Signals to detect if we are parsing a key or value with initial setup
    signal parsing_key[DATA_BYTES];
    signal parsing_value[DATA_BYTES];

    // Flags at each byte to indicate if we are matching correct key and in subsequent value
    signal is_key_match[DATA_BYTES];
    signal is_value_match[DATA_BYTES];

    signal is_next_pair_at_depth[DATA_BYTES];
    signal is_key_match_for_value[DATA_BYTES + 1];
    is_key_match_for_value[0] <== 0;

    // Initialize values knowing 0th bit of data will never be a key/value
    parsing_key[0]   <== 0;
    parsing_value[0] <== 0;
    is_key_match[0]  <== 0;

    component stackSelector[DATA_BYTES];
    stackSelector[0]         = ArraySelector(MAX_STACK_HEIGHT + 1, 2);
    stackSelector[0].in    <== stack[0];
    stackSelector[0].index <== step_in[TOTAL_BYTES_ACROSS_NIVC - 1];

    component nextStackSelector[DATA_BYTES];
    nextStackSelector[0]         = ArraySelector(MAX_STACK_HEIGHT + 1, 2);
    nextStackSelector[0].in    <== stack[0];
    nextStackSelector[0].index <== step_in[TOTAL_BYTES_ACROSS_NIVC - 1] + 1;

    is_next_pair_at_depth[0]  <== NextKVPairAtDepth(MAX_STACK_HEIGHT + 1)(stack[0], data[0],step_in[TOTAL_BYTES_ACROSS_NIVC - 1]);
    is_key_match_for_value[1] <== Mux1()([is_key_match_for_value[0] * (1-is_next_pair_at_depth[0]), is_key_match[0] * (1-is_next_pair_at_depth[0])], is_key_match[0]);
    is_value_match[0]         <== parsing_value[0] * is_key_match_for_value[1];

    signal or[DATA_BYTES];
    or[0]       <== is_value_match[0];
    step_out[0] <== data[0] * or[0];

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        // Grab the stack at the indicated height (from `step_in`)
        stackSelector[data_idx]         = ArraySelector(MAX_STACK_HEIGHT + 1, 2);
        stackSelector[data_idx].in    <== stack[data_idx];
        stackSelector[data_idx].index <== step_in[TOTAL_BYTES_ACROSS_NIVC - 1];

        nextStackSelector[data_idx]         = ArraySelector(MAX_STACK_HEIGHT + 1, 2);
        nextStackSelector[data_idx].in    <== stack[data_idx];
        nextStackSelector[data_idx].index <== step_in[TOTAL_BYTES_ACROSS_NIVC - 1] + 1;

        // Detect if we are parsing
        parsing_key[data_idx]   <== InsideKey()(stackSelector[data_idx].out, parsingData[data_idx][0], parsingData[data_idx][1]);
        parsing_value[data_idx] <== InsideValueObject()(stackSelector[data_idx].out, nextStackSelector[data_idx].out, parsingData[data_idx][0], parsingData[data_idx][1]);

        // to get correct value, check:
        // - key matches at current index and depth of key is as specified
        // - whether next KV pair starts
        // - whether key matched for a value (propogate key match until new KV pair of lower depth starts)
        is_key_match[data_idx]             <== KeyMatchAtIndex(paddedDataLen, MAX_KEY_LENGTH, data_idx)(data, key, keyLen, parsing_key[data_idx]);
        is_next_pair_at_depth[data_idx]    <== NextKVPairAtDepth(MAX_STACK_HEIGHT + 1)(stack[data_idx], data[data_idx], step_in[TOTAL_BYTES_ACROSS_NIVC - 1]);

        is_key_match_for_value[data_idx+1] <== Mux1()([is_key_match_for_value[data_idx] * (1-is_next_pair_at_depth[data_idx]), is_key_match[data_idx] * (1-is_next_pair_at_depth[data_idx])], is_key_match[data_idx]);
        is_value_match[data_idx]           <== is_key_match_for_value[data_idx+1] * parsing_value[data_idx];

        // Set the next NIVC step to only have the masked data
        or[data_idx]       <== OR()(is_value_match[data_idx], is_value_match[data_idx -1]);
        step_out[data_idx] <== data[data_idx] * or[data_idx];
    }
    // Append the parser state back on `step_out`
    for (var i = DATA_BYTES ; i < TOTAL_BYTES_ACROSS_NIVC - 1 ; i++) {
        step_out[i] <== step_in[i];
    }
    // No need to pad as this is currently when TOTAL_BYTES == TOTAL_BYTES_ACROSS_NIVC

    // Finally, update the current depth we are extracting from
    step_out[TOTAL_BYTES_ACROSS_NIVC - 1] <== step_in[TOTAL_BYTES_ACROSS_NIVC - 1] + 1;
}

template JsonMaskArrayIndexNIVC(DATA_BYTES, MAX_STACK_HEIGHT) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~
    // Total number of variables in the parser for each byte of data
    assert(MAX_STACK_HEIGHT >= 2);
    var PER_ITERATION_DATA_LENGTH = MAX_STACK_HEIGHT * 2 + 2;
    var TOTAL_BYTES_ACROSS_NIVC   = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1) + 1;
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Unravel from previous NIVC step ~
    // Read in from previous NIVC step (JsonParseNIVC)
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC]; 
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];

    // Grab the raw data bytes from the `step_in` variable
    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }

    // Decode the encoded data in `step_in` back into parser variables
    signal stack[DATA_BYTES][MAX_STACK_HEIGHT + 1][2];
    signal parsingData[DATA_BYTES][2];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        for (var j = 0 ; j < MAX_STACK_HEIGHT + 1 ; j++) {
            if (j < MAX_STACK_HEIGHT) {
                stack[i][j][0] <== step_in[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + j * 2];
                stack[i][j][1] <== step_in[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + j * 2 + 1];
            } else {
                // Add one extra stack element without doing this while parsing.
                // Stack under/overflow caught in parsing.
                stack[i][j][0] <== 0;
                stack[i][j][1] <== 0;
            }
            
        }
        parsingData[i][0] <== step_in[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + MAX_STACK_HEIGHT * 2];
        parsingData[i][1] <== step_in[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + MAX_STACK_HEIGHT * 2 + 1];
    }
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Array index masking ~
    signal input index;

    signal parsing_array[DATA_BYTES]; 

    component stackSelector[DATA_BYTES];
    stackSelector[0]         = ArraySelector(MAX_STACK_HEIGHT + 1, 2);
    stackSelector[0].in    <== stack[0];
    stackSelector[0].index <== step_in[TOTAL_BYTES_ACROSS_NIVC - 1];

    component nextStackSelector[DATA_BYTES];
    nextStackSelector[0]         = ArraySelector(MAX_STACK_HEIGHT + 1, 2);
    nextStackSelector[0].in    <== stack[0];
    nextStackSelector[0].index <== step_in[TOTAL_BYTES_ACROSS_NIVC - 1] + 1;

    parsing_array[0] <== InsideArrayIndexObject()(stackSelector[0].out, nextStackSelector[0].out, parsingData[0][0], parsingData[0][1], index);

    signal or[DATA_BYTES];
    or[0]       <== parsing_array[0];
    step_out[0] <== data[0] * or[0];
    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        stackSelector[data_idx]         = ArraySelector(MAX_STACK_HEIGHT + 1, 2);
        stackSelector[data_idx].in    <== stack[data_idx];
        stackSelector[data_idx].index <== step_in[TOTAL_BYTES_ACROSS_NIVC - 1];

        nextStackSelector[data_idx]         = ArraySelector(MAX_STACK_HEIGHT + 1, 2);
        nextStackSelector[data_idx].in    <== stack[data_idx];
        nextStackSelector[data_idx].index <== step_in[TOTAL_BYTES_ACROSS_NIVC - 1] + 1;

        parsing_array[data_idx] <== InsideArrayIndexObject()(stackSelector[data_idx].out, nextStackSelector[data_idx].out, parsingData[data_idx][0], parsingData[data_idx][1], index);

        or[data_idx]   <== OR()(parsing_array[data_idx], parsing_array[data_idx - 1]);
        step_out[data_idx] <== data[data_idx] * or[data_idx];
    }

    // Write the `step_out` with masked data
    
    // Append the parser state back on `step_out`
    for (var i = DATA_BYTES ; i < TOTAL_BYTES_ACROSS_NIVC - 1 ; i++) {
        step_out[i] <== step_in[i];
    }
    // No need to pad as this is currently when TOTAL_BYTES == TOTAL_BYTES_USED
    step_out[TOTAL_BYTES_ACROSS_NIVC - 1] <== step_in[TOTAL_BYTES_ACROSS_NIVC - 1] + 1;
}
