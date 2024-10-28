pragma circom 2.1.9;

include "interpreter.circom";

template ObjectExtractor(DATA_BYTES, MAX_STACK_HEIGHT, maxKeyLen, maxValueLen) {
    assert(MAX_STACK_HEIGHT >= 2);

    // Declaration of signals.
    signal input data[DATA_BYTES];
    signal input key[maxKeyLen];
    signal input keyLen;

    signal output value[maxValueLen];

    // Constraints.
    signal value_starting_index[DATA_BYTES - maxKeyLen];
    // flag determining whether this byte is matched value
    signal is_value_match[DATA_BYTES - maxKeyLen];
    // final mask
    signal mask[DATA_BYTES - maxKeyLen];

    component State[DATA_BYTES - maxKeyLen];
    State[0] = StateUpdate(MAX_STACK_HEIGHT);
    State[0].byte           <== data[0];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [0,0];
    }
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;

    signal parsing_key[DATA_BYTES - maxKeyLen];
    signal parsing_value[DATA_BYTES - maxKeyLen];
    signal parsing_object_value[DATA_BYTES - maxKeyLen];
    signal is_key_match[DATA_BYTES - maxKeyLen];
    signal is_key_match_for_value[DATA_BYTES+1 - maxKeyLen];
    is_key_match_for_value[0] <== 0;
    signal is_next_pair_at_depth[DATA_BYTES - maxKeyLen];
    signal or[DATA_BYTES - maxKeyLen];

    // initialise first iteration

    // check inside key or value
    parsing_key[0] <== InsideKey()(State[0].next_stack[0], State[0].next_parsing_string, State[0].next_parsing_number);
    parsing_value[0] <== InsideValueObject()(State[0].next_stack[0], State[0].next_stack[1], State[0].next_parsing_string, State[0].next_parsing_number);

    is_key_match[0] <== 0;
    is_next_pair_at_depth[0] <== NextKVPairAtDepth(MAX_STACK_HEIGHT)(State[0].next_stack, data[0], 0);
    is_key_match_for_value[1] <== Mux1()([is_key_match_for_value[0] * (1-is_next_pair_at_depth[0]), is_key_match[0] * (1-is_next_pair_at_depth[0])], is_key_match[0]);
    is_value_match[0] <== parsing_value[0] * is_key_match_for_value[1];

    mask[0] <== data[0] * is_value_match[0];

    for(var data_idx = 1; data_idx < DATA_BYTES - maxKeyLen; data_idx++) {
        State[data_idx]                  = StateUpdate(MAX_STACK_HEIGHT);
        State[data_idx].byte           <== data[data_idx];
        State[data_idx].stack          <== State[data_idx - 1].next_stack;
        State[data_idx].parsing_string <== State[data_idx - 1].next_parsing_string;
        State[data_idx].parsing_number <== State[data_idx - 1].next_parsing_number;

        // - parsing key
        // - parsing value (different for string/numbers and array)
        // - key match (key 1, key 2)
        // - is next pair
        // - is key match for value
        // - value_mask
        // - mask

        // check if inside key or not
        parsing_key[data_idx] <== InsideKey()(State[data_idx].next_stack[0], State[data_idx].next_parsing_string, State[data_idx].next_parsing_number);
        // check if inside value
        parsing_value[data_idx] <== InsideValueObject()(State[data_idx].next_stack[0], State[data_idx].next_stack[1], State[data_idx].next_parsing_string, State[data_idx].next_parsing_number);

        // to get correct value, check:
        // - key matches at current index and depth of key is as specified
        // - whether next KV pair starts
        // - whether key matched for a value (propogate key match until new KV pair of lower depth starts)
        is_key_match[data_idx] <== KeyMatchAtIndex(DATA_BYTES, maxKeyLen, data_idx)(data, key, keyLen, parsing_key[data_idx]);
        is_next_pair_at_depth[data_idx] <== NextKVPairAtDepth(MAX_STACK_HEIGHT)(State[data_idx].next_stack, data[data_idx], 0);
        is_key_match_for_value[data_idx+1] <== Mux1()([is_key_match_for_value[data_idx] * (1-is_next_pair_at_depth[data_idx]), is_key_match[data_idx] * (1-is_next_pair_at_depth[data_idx])], is_key_match[data_idx]);
        is_value_match[data_idx] <== is_key_match_for_value[data_idx+1] * parsing_value[data_idx];

       or[data_idx] <== OR()(is_value_match[data_idx], is_value_match[data_idx - 1]);

        // mask = currently parsing value and all subsequent keys matched
        mask[data_idx] <== data[data_idx] * or[data_idx];
    }

    // find starting index of value in data by matching mask
    signal is_zero_mask[DATA_BYTES];
    signal is_prev_starting_index[DATA_BYTES];
    value_starting_index[0] <== 0;
    is_prev_starting_index[0] <== 0;
    is_zero_mask[0] <== IsZero()(mask[0]);
    for (var i=1 ; i<DATA_BYTES - maxKeyLen ; i++) {
        is_zero_mask[i] <== IsZero()(mask[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }

    log("value starting index", value_starting_index[DATA_BYTES-1 - maxKeyLen]);
    value <== SelectSubArray(DATA_BYTES - maxKeyLen, maxValueLen)(mask, value_starting_index[DATA_BYTES-1 - maxKeyLen], maxValueLen);
    for (var i = 0 ; i < maxValueLen ; i++) {
        log(i, value[i]);
    }
}

template ArrayIndexExtractor(DATA_BYTES, MAX_STACK_HEIGHT, maxValueLen) {
    assert(MAX_STACK_HEIGHT >= 2);

    signal input data[DATA_BYTES];
    signal input index;

    signal output value[maxValueLen];

    // value starting index in `data`
    signal value_starting_index[DATA_BYTES];
    // final mask
    signal mask[DATA_BYTES];

    component State[DATA_BYTES];
    State[0] = StateUpdate(MAX_STACK_HEIGHT);
    State[0].byte           <== data[0];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [0,0];
    }
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;

    signal parsing_array[DATA_BYTES];
    signal or[DATA_BYTES];

    parsing_array[0] <== InsideArrayIndexObject()(State[0].next_stack[0], State[0].next_stack[1], State[0].next_parsing_string, State[0].next_parsing_number, index);
    mask[0] <== data[0] * parsing_array[0];

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                  = StateUpdate(MAX_STACK_HEIGHT);
        State[data_idx].byte           <== data[data_idx];
        State[data_idx].stack          <== State[data_idx - 1].next_stack;
        State[data_idx].parsing_string <== State[data_idx - 1].next_parsing_string;
        State[data_idx].parsing_number <== State[data_idx - 1].next_parsing_number;

        parsing_array[data_idx] <== InsideArrayIndexObject()(State[data_idx].next_stack[0], State[data_idx].next_stack[1], State[data_idx].next_parsing_string, State[data_idx].next_parsing_number, index);

        or[data_idx] <== OR()(parsing_array[data_idx], parsing_array[data_idx - 1]);
        mask[data_idx] <== data[data_idx] * or[data_idx];
    }

    signal is_zero_mask[DATA_BYTES];
    signal is_prev_starting_index[DATA_BYTES];
    value_starting_index[0] <== 0;
    is_prev_starting_index[0] <== 0;
    is_zero_mask[0] <== IsZero()(mask[0]);
    for (var i=1 ; i<DATA_BYTES ; i++) {
        is_zero_mask[i] <== IsZero()(mask[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }

    log("value starting index", value_starting_index[DATA_BYTES-1]);
    value <== SelectSubArray(DATA_BYTES, maxValueLen)(mask, value_starting_index[DATA_BYTES-1], maxValueLen);
    for (var i = 0 ; i < maxValueLen ; i++) {
        log(i, value[i]);
    }
}
