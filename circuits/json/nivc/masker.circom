pragma circom 2.1.9;

include "../interpreter.circom";

template JsonMaskObjectNIVC(DATA_BYTES, MAX_STACK_HEIGHT, MAX_KEY_LENGTH) {
    // ------------------------------------------------------------------------------------------------------------------ //
    assert(MAX_STACK_HEIGHT >= 2); // TODO (autoparallel): idk if we need this now
    var TOTAL_BYTES_ACROSS_NIVC   = DATA_BYTES * 2 + 4; // aes ct/pt + ctr
    // ------------------------------------------------------------------------------------------------------------------ //
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC];
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];

    // Declaration of signals.
    signal data[DATA_BYTES];
    signal input key[MAX_KEY_LENGTH];
    signal input keyLen;

    for(var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }

    // flag determining whether this byte is matched value
    signal is_value_match[DATA_BYTES - MAX_KEY_LENGTH];

    component State[DATA_BYTES - MAX_KEY_LENGTH];
    State[0] = StateUpdate(MAX_STACK_HEIGHT);
    State[0].byte           <== data[0];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [0,0];
    }
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;

    signal parsing_key[DATA_BYTES - MAX_KEY_LENGTH];
    signal parsing_value[DATA_BYTES - MAX_KEY_LENGTH];
    signal is_key_match[DATA_BYTES - MAX_KEY_LENGTH];
    signal is_key_match_for_value[DATA_BYTES+1 - MAX_KEY_LENGTH];
    is_key_match_for_value[0] <== 0;
    signal is_next_pair_at_depth[DATA_BYTES - MAX_KEY_LENGTH];
    signal or[DATA_BYTES - MAX_KEY_LENGTH - 1];

    // initialise first iteration

    // check inside key or value
    parsing_key[0] <== InsideKey()(State[0].next_stack[0], State[0].next_parsing_string, State[0].next_parsing_number);
    parsing_value[0] <== InsideValueObject()(State[0].next_stack[0], State[0].next_stack[1], State[0].next_parsing_string, State[0].next_parsing_number);

    is_key_match[0] <== 0;
    is_next_pair_at_depth[0] <== NextKVPairAtDepth(MAX_STACK_HEIGHT)(State[0].next_stack, data[0], 0);
    is_key_match_for_value[1] <== Mux1()([is_key_match_for_value[0] * (1-is_next_pair_at_depth[0]), is_key_match[0] * (1-is_next_pair_at_depth[0])], is_key_match[0]);
    is_value_match[0] <== parsing_value[0] * is_key_match_for_value[1];

    step_out[0] <== data[0] * is_value_match[0];

    // TODO (autoparallel): it might be dumb to do this with the max key length but fuck it
    for(var data_idx = 1; data_idx < DATA_BYTES - MAX_KEY_LENGTH; data_idx++) {
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
        is_key_match[data_idx] <== KeyMatchAtIndex(DATA_BYTES, MAX_KEY_LENGTH, data_idx)(data, key, keyLen, parsing_key[data_idx]);
        is_next_pair_at_depth[data_idx] <== NextKVPairAtDepth(MAX_STACK_HEIGHT)(State[data_idx].next_stack, data[data_idx], 0);
        is_key_match_for_value[data_idx+1] <== Mux1()([is_key_match_for_value[data_idx] * (1-is_next_pair_at_depth[data_idx]), is_key_match[data_idx] * (1-is_next_pair_at_depth[data_idx])], is_key_match[data_idx]);
        is_value_match[data_idx] <== is_key_match_for_value[data_idx+1] * parsing_value[data_idx];

        or[data_idx - 1] <== OR()(is_value_match[data_idx], is_value_match[data_idx - 1]);

        // mask = currently parsing value and all subsequent keys matched
        step_out[data_idx] <== data[data_idx] * or[data_idx - 1];
    }
    for(var i = DATA_BYTES - MAX_KEY_LENGTH; i < 2 * DATA_BYTES + 4; i ++) {
        step_out[i] <== 0;
    }
}

template JsonMaskArrayIndexNIVC(DATA_BYTES, MAX_STACK_HEIGHT) {
    // ------------------------------------------------------------------------------------------------------------------ //
    assert(MAX_STACK_HEIGHT >= 2); // TODO (autoparallel): idk if we need this now
    var TOTAL_BYTES_ACROSS_NIVC   = DATA_BYTES * 2 + 4; // aes ct/pt + ctr
    // ------------------------------------------------------------------------------------------------------------------ //
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC];
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];

    // Declaration of signals.
    signal data[DATA_BYTES];
    signal input index;

    for(var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }

    component State[DATA_BYTES];
    State[0] = StateUpdate(MAX_STACK_HEIGHT);
    State[0].byte           <== data[0];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [0,0];
    }
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;

    signal parsing_array[DATA_BYTES];
    signal or[DATA_BYTES - 1];

    parsing_array[0] <== InsideArrayIndexObject()(State[0].next_stack[0], State[0].next_stack[1], State[0].next_parsing_string, State[0].next_parsing_number, index);
    step_out[0] <== data[0] * parsing_array[0]; // TODO (autoparallel): is this totally correcot or do we need an or, i think it's right


    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                  = StateUpdate(MAX_STACK_HEIGHT);
        State[data_idx].byte           <== data[data_idx];
        State[data_idx].stack          <== State[data_idx - 1].next_stack;
        State[data_idx].parsing_string <== State[data_idx - 1].next_parsing_string;
        State[data_idx].parsing_number <== State[data_idx - 1].next_parsing_number;

        parsing_array[data_idx] <== InsideArrayIndexObject()(State[data_idx].next_stack[0], State[data_idx].next_stack[1], State[data_idx].next_parsing_string, State[data_idx].next_parsing_number, index);

        or[data_idx - 1] <== OR()(parsing_array[data_idx], parsing_array[data_idx - 1]);
        step_out[data_idx] <== data[data_idx] * or[data_idx - 1];
    }
    for(var i = DATA_BYTES ; i < 2 * DATA_BYTES + 4; i++) {
        step_out[i] <== 0;
    }
}
