pragma circom 2.1.9;

include "../utils/bits.circom";
include "hash_machine.circom";

template JSONExtraction(DATA_BYTES, MAX_STACK_HEIGHT) {
    signal input data[DATA_BYTES];
    signal input sequence_digest; 
    signal input ciphertext_digest;
    // TODO: we need like a `value_digest` here too.

    signal input step_in[1];
    signal output step_out[1];
    
    // TODO: Change this
    step_out[0] <== step_in[0];

    //--------------------------------------------------------------------------------------------//
    // Initialze the parser
    component State[DATA_BYTES];
    State[0] = StateUpdateHasher(MAX_STACK_HEIGHT);
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]       <== [0,0];
        State[0].tree_hash[i]   <== [0,0];
    }
    State[0].byte             <== data[0];
    State[0].polynomial_input <== ciphertext_digest;
    State[0].monomial         <== 0;
    State[0].parsing_string   <== 0;
    State[0].parsing_number   <== 0;

    // Set up monomials for stack/tree digesting
    signal monomials[4 * MAX_STACK_HEIGHT];
    monomials[0] <== 1;
    for(var i = 1 ; i < 4 * MAX_STACK_HEIGHT ; i++) {
        monomials[i] <== monomials[i - 1] * ciphertext_digest;
    }
    signal intermediate_digest[DATA_BYTES][4 * MAX_STACK_HEIGHT];
    signal state_digest[DATA_BYTES];
    
    // Debugging
    // for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
    //     log("State[", 0, "].next_stack[", i,"]      = [",State[0].next_stack[i][0], "][", State[0].next_stack[i][1],"]" );
    // }
    // for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
    //     log("State[", 0, "].next_tree_hash[", i,"]  = [",State[0].next_tree_hash[i][0], "][", State[0].next_tree_hash[i][1],"]" );
    // }
    // log("State[", 0, "].next_monomial        =", State[0].next_monomial);
    // log("State[", 0, "].next_parsing_string  =", State[0].next_parsing_string);
    // log("State[", 0, "].next_parsing_number  =", State[0].next_parsing_number);
    // log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    var total_matches = 0;
    signal is_matched[DATA_BYTES];
    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                    = StateUpdateHasher(MAX_STACK_HEIGHT);
        State[data_idx].byte             <== data[data_idx];
        State[data_idx].polynomial_input <== ciphertext_digest;
        State[data_idx].stack            <== State[data_idx - 1].next_stack;
        State[data_idx].parsing_string   <== State[data_idx - 1].next_parsing_string;
        State[data_idx].parsing_number   <== State[data_idx - 1].next_parsing_number;
        State[data_idx].monomial         <== State[data_idx - 1].next_monomial;
        State[data_idx].tree_hash        <== State[data_idx - 1].next_tree_hash;

        // Digest the whole stack and tree hash
        var accumulator = 0;
        for(var i = 0 ; i < MAX_STACK_HEIGHT ; i++) {
            intermediate_digest[data_idx][4 * i]     <== State[data_idx].next_stack[i][0] * monomials[4 * i];
            intermediate_digest[data_idx][4 * i + 1] <== State[data_idx].next_stack[i][1] * monomials[4 * i + 1];
            intermediate_digest[data_idx][4 * i + 2] <== State[data_idx].next_tree_hash[i][0] * monomials[4 * i + 2];
            intermediate_digest[data_idx][4 * i + 3] <== State[data_idx].next_tree_hash[i][1] * monomials[4 * i + 3];  
            accumulator += intermediate_digest[data_idx][4 * i] + intermediate_digest[data_idx][4 * i + 1] + intermediate_digest[data_idx][4 * i + 2] + intermediate_digest[data_idx][4 * i + 3];
        }
        state_digest[data_idx] <== accumulator;
        is_matched[data_idx] <== IsEqual()([state_digest[data_idx], sequence_digest]);
        total_matches += is_matched[data_idx];

        // Debugging
        // for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
        //     log("State[", data_idx, "].next_stack[", i,"]     = [",State[data_idx].next_stack[i][0], "][", State[data_idx].next_stack[i][1],"]" );
        // }
        // for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
        //     log("State[", data_idx, "].next_tree_hash[", i,"] = [",State[data_idx].next_tree_hash[i][0], "][", State[data_idx].next_tree_hash[i][1],"]" );
        // }
        // log("State[", data_idx, "].next_monomial       =", State[data_idx].next_monomial);
        // log("State[", data_idx, "].next_parsing_string =", State[data_idx].next_parsing_string);
        // log("State[", data_idx, "].next_parsing_number =", State[data_idx].next_parsing_number);
        // log("++++++++++++++++++++++++++++++++++++++++++++++++");
        // log("state_digest[", data_idx,"]              = ", state_digest[data_idx]);
        // log("total_matches                   = ", total_matches);
        // log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }

    // TODO: Assert something about total matches but keep in mind we should try to output the target value hash
    total_matches === 1;

    // Constrain to have valid JSON
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[DATA_BYTES - 1].next_stack[i]      === [0,0];
        State[DATA_BYTES - 1].next_tree_hash[i]  === [0,0];
    }

    // Verify we have now processed all the data properly
    // TODO: This data is now the HTTP body, consider renaming
    signal isPadding[DATA_BYTES]; // == 1 in the case we hit padding number
    signal zeroed_data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
      isPadding[i]   <== IsEqual()([data[i], -1]);
      zeroed_data[i] <== (1 - isPadding[i]) * data[i];
    }
    signal data_digest <== PolynomialDigest(DATA_BYTES)(zeroed_data, ciphertext_digest);
    signal sequence_digest_hashed <== Poseidon(1)([sequence_digest]);
    signal data_digest_hashed <== Poseidon(1)([data_digest]);

    log("circuit: json_step_in = ", step_in[0]);
    log("circuit: sequence_digest_hashed = ", sequence_digest_hashed);
    log("circuit: data_digest_hashed = ", data_digest_hashed);
    0 === step_in[0] - sequence_digest_hashed - data_digest_hashed;
}
