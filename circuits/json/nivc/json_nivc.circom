pragma circom 2.1.9;

include "../interpreter.circom";

template JsonMaskObjectNIVC(DATA_BYTES, MAX_STACK_HEIGHT, MAX_KEY_LENGTH, MAX_KEY_SIZE) {
    signal input step_in[1];
    signal output step_out[1];

    // Input a hash of the value we are extracting
    signal input value_hash[1];

    // use codified version of keys to get the json shitttt
    signal input keys[MAX_STACK_HEIGHT][MAX_KEY_LENGTH][1];
    //                   ^^^^^^^^       ^^^^^^^^^^^^^^  ^
    // max keys we could ever use      max key size     key_type: 0 is null, 1 is string, 2 is array index, 3 is value

    /*
        [["data",1], ["items", 1], [0,2], ["profile", 1], ["name", 1], ["Taylor Swift", 3], [0,0]]

        this is like the branch of the "tree" of the JSON that we want to prove exists 
    */

    // Authenticate the (potentially further masked) plaintext we are passing in
    signal input data[DATA_BYTES];
    signal data_hash <== DataHasher(DATA_BYTES)(data);
    data_hash        === step_in[0];

    // Run the JSON parser
    component State[DATA_BYTES - MAX_KEY_LENGTH];
    State[0] = StateUpdate(MAX_STACK_HEIGHT);
    State[0].byte           <== data[0];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [0,0];
    }
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        if(data_idx < DATA_BYTES - MAX_KEY_LENGTH) {
            State[data_idx]                  = StateUpdate(MAX_STACK_HEIGHT);
            State[data_idx].byte           <== data[data_idx];
            State[data_idx].stack          <== State[data_idx - 1].next_stack;
            State[data_idx].parsing_string <== State[data_idx - 1].next_parsing_string;
            State[data_idx].parsing_number <== State[data_idx - 1].next_parsing_number;
    }

    // -------------------------------------------------------------------------------------- //
    // Do some real shit here



    // -------------------------------------------------------------------------------------- //
    // TODO (autoparallel): No idea what to do here yet lol
    step_out[0] <== DataHasher(DATA_BYTES)(masked);
}

